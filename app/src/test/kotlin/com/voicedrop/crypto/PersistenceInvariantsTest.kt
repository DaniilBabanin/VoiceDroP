package com.voicedrop.crypto

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.google.crypto.tink.subtle.X25519
import com.voicedrop.network.FrameCodec
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.ContactEntity
import com.voicedrop.storage.MessageEntity
import com.voicedrop.storage.PrekeyEpochEntity
import com.voicedrop.storage.TransportType
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * DR7 + DR8 — `PersistenceInvariantsTest` (encrypt-path + decrypt-path).
 *
 * The mutex-regression test `concurrent_twoEncryptsOnSameContact_noKeyReuse` is
 * load-bearing — see [dr7-encrypt-path.md] §8.3 and [00-overview.md §4]. Do not
 * delete it. If it stops working, ratchet AEAD keys are being reused under the
 * zero ChaCha20-Poly1305 nonce — catastrophic.
 *
 * Tests run under Robolectric so we can use a real in-memory Room without
 * pulling in Android KeyStore. A small AES-GCM + HMAC-SHA256 [TestWrapMac]
 * stands in for [KeyManager], honouring the DR2 wrap/MAC contract.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class PersistenceInvariantsTest {

    // Two DBs — one per device — mirrors production (Alice and Bob are on
    // separate phones with separate Room files). A single shared Room would
    // cause Alice's outbound `messages.uuid` row to collide with Bob's
    // dedup query (`RatchetDecryptAndPersist.isMessageInDb`), making Bob's
    // first receive of a fresh frame fall through `handleDuplicate` before
    // his ratchet has been advanced, throwing `AwaitingFirstReceive`.
    private lateinit var aliceDb: AppDatabase
    private lateinit var bobDb: AppDatabase
    private lateinit var wrapMac: TestWrapMac

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        aliceDb = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        bobDb = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        wrapMac = TestWrapMac()
        ContactMutexRegistry.clear()
    }

    @After
    fun tearDown() {
        aliceDb.close()
        bobDb.close()
        ContactMutexRegistry.clear()
    }

    // ---------- Tests ----------

    @Test
    fun encrypt_advancesChainAndPersistsOutbox() = runBlocking {
        val pair = bootstrapPair()
        seedAliceContact(pair)

        val transmitted = mutableListOf<ByteArray>()
        val sender = sender(pair, transmit = { _, bytes -> transmitted += bytes })

        val sent = sender.encryptAndSend(pair.aliceContactId, "hello".toByteArray()) { hex, _, now ->
            outboundMessage(hex, pair.aliceContactId, now)
        }

        assertEquals(0, sent.n)
        assertEquals(0, sent.pn)
        assertEquals(1, aliceDb.pendingOutboundFrameDao().countForContact(pair.aliceContactId))
        // Wire bytes ALSO went through transmit (post-commit).
        assertEquals(1, transmitted.size)
        assertArrayEquals(sent.wireBytes, transmitted.single())
        // Message row landed with delivery_state=PENDING.
        val msg = aliceDb.messageDao().getByUuid(sent.frameUuidHex)
        assertNotNull(msg); assertEquals(MessageEntity.DELIVERY_PENDING, msg!!.delivery_state)
        // Chain `n` consumed (next advance would be 1).
        val contactAfter = aliceDb.contactDao().getById(pair.aliceContactId)!!
        assertEquals(1, contactAfter.ns)
    }

    @Test
    fun encrypt_crashBeforeCommit_noStateChange() = runBlocking {
        val pair = bootstrapPair()
        seedAliceContact(pair)
        val beforeContact = aliceDb.contactDao().getById(pair.aliceContactId)!!

        // Force a crash inside the txn by making transmit a no-op but having buildMessage
        // throw. Room rolls back; ratchet state, outbox row, and message row must all be absent.
        val sender = sender(pair, transmit = { _, _ -> })
        try {
            sender.encryptAndSend(pair.aliceContactId, "boom".toByteArray()) { _, _, _ ->
                throw RuntimeException("simulated crash inside txn")
            }
            fail("expected crash")
        } catch (e: RuntimeException) {
            assertEquals("simulated crash inside txn", e.message)
        }

        val afterContact = aliceDb.contactDao().getById(pair.aliceContactId)!!
        assertEquals("ns must not advance on rollback", beforeContact.ns, afterContact.ns)
        assertArrayEquals(beforeContact.rk_wrapped, afterContact.rk_wrapped)
        // rk_hmac equality also confirms the wrap wasn't committed.
        assertArrayEquals(beforeContact.rk_hmac, afterContact.rk_hmac)
        assertEquals(0, aliceDb.pendingOutboundFrameDao().countForContact(pair.aliceContactId))
    }

    @Test
    fun encrypt_crashAfterCommit_outboxReplayable() = runBlocking {
        // Simulate post-commit crash: transmit throws AFTER the txn closes. The row
        // must stay in outbox and the chain `n` must have advanced ("consumed").
        val pair = bootstrapPair()
        seedAliceContact(pair)
        val sender = sender(pair, transmit = { _, _ -> error("network down") })

        val sent = sender.encryptAndSend(pair.aliceContactId, "queued".toByteArray()) { hex, _, now ->
            outboundMessage(hex, pair.aliceContactId, now)
        }

        // Row is persisted and recoverable: unwrap+verify the outbox blob and check
        // it matches the wire bytes the sender returned.
        val row = aliceDb.pendingOutboundFrameDao().getByUuid(sent.frameUuid)
        assertNotNull(row)
        val unwrapped = wrapMac.unwrapAndVerify(
            "pending_outbound_frames.wrapped_frame", row!!.uuid, row.wrapped_frame, row.frame_hmac
        )
        assertArrayEquals(sent.wireBytes, unwrapped)
        // Chain `n` consumed.
        assertEquals(1, aliceDb.contactDao().getById(pair.aliceContactId)!!.ns)
    }

    @Test
    fun expectingAck_throwsSessionResetInProgress() = runBlocking {
        val pair = bootstrapPair()
        seedAliceContact(pair, expectingAck = 1)
        val sender = sender(pair, transmit = { _, _ -> })
        try {
            sender.encryptAndSend(pair.aliceContactId, "blocked".toByteArray()) { hex, _, now ->
                outboundMessage(hex, pair.aliceContactId, now)
            }
            fail("expected SessionResetInProgress")
        } catch (_: SessionResetInProgress) { /* ok */ }
        assertEquals(0, aliceDb.pendingOutboundFrameDao().countForContact(pair.aliceContactId))
    }

    @Test
    fun bobRole_sendBeforeFirstReceive_throwsAwaitingFirstReceive() = runBlocking {
        val pair = bootstrapPair()
        seedBobContact(pair)
        val sender = sender(pair, db = bobDb, ownFp = pair.bobFingerprint, transmit = { _, _ -> })
        try {
            sender.encryptAndSend(pair.bobContactId, "too soon".toByteArray()) { hex, _, now ->
                outboundMessage(hex, pair.bobContactId, now)
            }
            fail("expected AwaitingFirstReceive")
        } catch (_: AwaitingFirstReceive) { /* ok */ }
        // Nothing leaked into outbox.
        assertEquals(0, bobDb.pendingOutboundFrameDao().countForContact(pair.bobContactId))
    }

    /**
     * §8.3 mutex regression guard. 50 parallel encrypts on the same contact must
     * produce 50 distinct chain positions and 50 distinct frames that the peer
     * can decrypt without any AEAD failure.
     *
     * Without the mutex, multiple coroutines would race to derive `mk` for the
     * same `n`, AEAD-seal under the same key+zero-nonce, and produce key reuse
     * under ChaCha20-Poly1305. Any duplicate `n` value below is that signal.
     */
    @Test
    fun concurrent_twoEncryptsOnSameContact_noKeyReuse() = runBlocking {
        val pair = bootstrapPair()
        seedAliceContact(pair)
        val transmitted = java.util.Collections.synchronizedList(mutableListOf<ByteArray>())
        val sender = sender(pair, transmit = { _, bytes -> transmitted += bytes })

        val N = 50
        val sents = (0 until N).map { i ->
            async(Dispatchers.IO) {
                sender.encryptAndSend(pair.aliceContactId, "msg-$i".toByteArray()) { hex, _, now ->
                    outboundMessage(hex, pair.aliceContactId, now)
                }
            }
        }.awaitAll()

        // All chain positions distinct, covering [0, N).
        val ns = sents.map { it.n }.toSortedSet()
        assertEquals((0 until N).toSet(), ns)
        // All under the same DHs.pub (no DH ratchet on the send side mid-batch).
        val dhPub0 = sents[0].dhPub
        for (s in sents) assertArrayEquals(dhPub0, s.dhPub)

        // Peer decrypts every frame; sort by `n` so Bob walks the chain in order and
        // we don't exercise the skipped-key path (that's a separate test).
        val bobState = pair.bobState
        val bobSkipped = SkippedKeyMap()
        val byN = sents.sortedBy { it.n }
        for (s in byN) {
            val decoded = (FrameCodec.decode(s.wireBytes) as FrameCodec.DecodeResult.Ok).frame
            val pt = Ratchet.decrypt(
                bobState, bobSkipped,
                decoded.dhPub, decoded.pn, decoded.n, decoded.ciphertext, decoded.aad
            )
            assertTrue(String(pt).startsWith("msg-"))
        }
        // And both sides agree the chain reached N.
        assertEquals(N, aliceDb.contactDao().getById(pair.aliceContactId)!!.ns)
        assertEquals(N, aliceDb.pendingOutboundFrameDao().countForContact(pair.aliceContactId))
    }

    // ---------- DR8: decrypt path ----------

    /**
     * Finding #2 / B1 — a duplicate DATA frame arriving while our RECEIPT is
     * STILL in the outbox is a pure no-op: the sending chain MUST NOT advance and
     * no second RECEIPT row may appear. (Replaces the pre-fix test that asserted
     * the now-fixed "ns advances per duplicate" behavior.)
     */
    @Test
    fun decrypt_duplicateWhileReceiptPending_isNoOp() = runBlocking {
        val pair = bootstrapPair()
        seedAliceContact(pair)
        seedBobContact(pair)

        val aliceTransmitted = mutableListOf<ByteArray>()
        val aliceSender = sender(pair, transmit = { _, b -> aliceTransmitted += b })
        aliceSender.encryptAndSend(pair.aliceContactId, "hello-bob".toByteArray()) { hex, _, now ->
            outboundMessage(hex, pair.aliceContactId, now)
        }
        val decoded = (FrameCodec.decode(aliceTransmitted.single()) as FrameCodec.DecodeResult.Ok).frame

        val receiver = receiver(pair)
        val first = receiver.receive(pair.bobContactId, decoded) { plaintext, hex, _, ts ->
            inboundMessage(hex, pair.bobContactId, plaintext, ts)
        }
        assertTrue(first is RatchetDecryptAndPersist.Result.Delivered)
        val afterFirst = bobDb.contactDao().getById(pair.bobContactId)!!
        assertEquals(1, afterFirst.nr)
        assertEquals(1, afterFirst.ns)
        assertEquals(1, bobDb.pendingOutboundFrameDao().countForContact(pair.bobContactId))

        // RECEIPT still pending (not drained). Replay the SAME frame twice.
        repeat(2) {
            val dup = receiver.receive(pair.bobContactId, decoded) { _, _, _, _ ->
                fail("buildInboundMessage must not be called on dedup path")
                throw IllegalStateException("unreachable")
            }
            assertTrue(dup is RatchetDecryptAndPersist.Result.DuplicateData)
        }

        val afterDup = bobDb.contactDao().getById(pair.bobContactId)!!
        assertEquals("nr unchanged", afterFirst.nr, afterDup.nr)
        assertEquals("ns MUST NOT advance while a RECEIPT is pending", 1, afterDup.ns)
        assertEquals("no second RECEIPT row", 1, bobDb.pendingOutboundFrameDao().countForContact(pair.bobContactId))
        assertEquals("still one message row", 1, bobDb.messageDao().getByContactList(pair.bobContactId).size)
    }

    /**
     * Finding #2 / recovery — once our RECEIPT has DRAINED from the outbox (peer
     * never got it), a re-delivered DATA legitimately re-enqueues exactly ONE
     * RECEIPT and advances Ns exactly once. Preserves "RECEIPT lost, peer retried".
     */
    @Test
    fun decrypt_duplicateAfterReceiptDrained_reEnqueuesOneReceipt_advancesNsOnce() = runBlocking {
        val pair = bootstrapPair()
        seedAliceContact(pair)
        seedBobContact(pair)

        val aliceTransmitted = mutableListOf<ByteArray>()
        val aliceSender = sender(pair, transmit = { _, b -> aliceTransmitted += b })
        aliceSender.encryptAndSend(pair.aliceContactId, "hello-bob".toByteArray()) { hex, _, now ->
            outboundMessage(hex, pair.aliceContactId, now)
        }
        val decoded = (FrameCodec.decode(aliceTransmitted.single()) as FrameCodec.DecodeResult.Ok).frame

        val receiver = receiver(pair)
        receiver.receive(pair.bobContactId, decoded) { plaintext, hex, _, ts ->
            inboundMessage(hex, pair.bobContactId, plaintext, ts)
        }
        // Simulate the replay worker transmitting + deleting the RECEIPT row.
        val pending = bobDb.pendingOutboundFrameDao().getByContact(pair.bobContactId).single()
        bobDb.pendingOutboundFrameDao().deleteByUuid(pending.uuid)
        assertEquals(0, bobDb.pendingOutboundFrameDao().countForContact(pair.bobContactId))

        val dup = receiver.receive(pair.bobContactId, decoded) { _, _, _, _ ->
            fail("buildInboundMessage must not be called on dedup path")
            throw IllegalStateException("unreachable")
        }
        assertTrue(dup is RatchetDecryptAndPersist.Result.DuplicateData)

        val after = bobDb.contactDao().getById(pair.bobContactId)!!
        assertEquals("ns advanced exactly once for the re-enqueued RECEIPT", 2, after.ns)
        assertEquals("exactly one fresh RECEIPT row", 1, bobDb.pendingOutboundFrameDao().countForContact(pair.bobContactId))
        // The re-enqueued RECEIPT acks the original DATA UUID.
        val row = bobDb.pendingOutboundFrameDao().getByContact(pair.bobContactId).single()
        assertArrayEquals(decoded.uuid, row.acked_uuid)
    }

    /**
     * Finding #2 / resend cap — after RECEIPT_RESEND_CAP genuine re-sends (each
     * following a drain), further re-deliveries are suppressed: no new RECEIPT,
     * Ns frozen. Bounds the patient-replay Ns drip.
     */
    @Test
    fun decrypt_resendCap_suppressesAfterK_andFreezesNs() = runBlocking {
        val pair = bootstrapPair()
        seedAliceContact(pair)
        seedBobContact(pair)

        val aliceTransmitted = mutableListOf<ByteArray>()
        val aliceSender = sender(pair, transmit = { _, b -> aliceTransmitted += b })
        aliceSender.encryptAndSend(pair.aliceContactId, "hello-bob".toByteArray()) { hex, _, now ->
            outboundMessage(hex, pair.aliceContactId, now)
        }
        val decoded = (FrameCodec.decode(aliceTransmitted.single()) as FrameCodec.DecodeResult.Ok).frame
        val dataUuidHex = decoded.uuid.joinToString("") { "%02x".format(it) }

        val receiver = receiver(pair)
        receiver.receive(pair.bobContactId, decoded) { plaintext, hex, _, ts ->
            inboundMessage(hex, pair.bobContactId, plaintext, ts)
        }

        // K genuine re-sends: drain then replay, each time.
        repeat(com.voicedrop.storage.OutboxMaintenance.RECEIPT_RESEND_CAP) {
            val row = bobDb.pendingOutboundFrameDao().getByContact(pair.bobContactId).single()
            bobDb.pendingOutboundFrameDao().deleteByUuid(row.uuid)
            receiver.receive(pair.bobContactId, decoded) { _, _, _, _ ->
                fail("dedup path must not build a message"); throw IllegalStateException()
            }
        }
        val nsAtCap = bobDb.contactDao().getById(pair.bobContactId)!!.ns
        assertEquals(com.voicedrop.storage.OutboxMaintenance.RECEIPT_RESEND_CAP,
            bobDb.messageDao().getByUuid(dataUuidHex)!!.receipt_resends)

        // One more drained replay — now over the cap, must be suppressed.
        val row = bobDb.pendingOutboundFrameDao().getByContact(pair.bobContactId).single()
        bobDb.pendingOutboundFrameDao().deleteByUuid(row.uuid)
        val over = receiver.receive(pair.bobContactId, decoded) { _, _, _, _ ->
            fail("dedup path must not build a message"); throw IllegalStateException()
        }
        assertTrue(over is RatchetDecryptAndPersist.Result.DuplicateData)
        assertEquals("ns frozen at the cap", nsAtCap, bobDb.contactDao().getById(pair.bobContactId)!!.ns)
        assertEquals("no new RECEIPT enqueued past the cap", 0,
            bobDb.pendingOutboundFrameDao().countForContact(pair.bobContactId))
        assertEquals("resend count frozen at K", com.voicedrop.storage.OutboxMaintenance.RECEIPT_RESEND_CAP,
            bobDb.messageDao().getByUuid(dataUuidHex)!!.receipt_resends)
    }

    /**
     * §4.4 clone-then-commit. A frame with valid header but tampered ciphertext
     * MUST leave the persisted state byte-for-byte identical. The DR14
     * consecutive-failure heuristic counter ticks up via an UPDATE OUTSIDE the
     * txn (§8.2) so AEAD-failure churn from an attacker can't lock the DB.
     */
    @Test
    fun aeadFailureLeavesStateUntouched() = runBlocking {
        val pair = bootstrapPair()
        seedAliceContact(pair)
        seedBobContact(pair)

        val transmitted = mutableListOf<ByteArray>()
        val aliceSender = sender(pair, transmit = { _, b -> transmitted += b })
        aliceSender.encryptAndSend(pair.aliceContactId, "valid".toByteArray()) { hex, _, now ->
            outboundMessage(hex, pair.aliceContactId, now)
        }
        val goodBytes = transmitted.single()

        // Flip a bit in the ciphertext body. FrameCodec.decode still succeeds
        // (header structure intact); AEAD verification fails.
        val badBytes = goodBytes.copyOf().also { bytes ->
            val ctStart = FrameCodec.AAD_LEN
            bytes[ctStart] = (bytes[ctStart].toInt() xor 0x01).toByte()
        }
        val tampered = (FrameCodec.decode(badBytes) as FrameCodec.DecodeResult.Ok).frame

        val bobBefore = bobDb.contactDao().getById(pair.bobContactId)!!
        val receiver = receiver(pair)
        try {
            receiver.receive(pair.bobContactId, tampered) { _, _, _, _ ->
                fail("buildInboundMessage must not be called on AEAD failure")
                throw IllegalStateException("unreachable")
            }
            fail("expected RatchetCryptoFailure")
        } catch (_: RatchetCryptoFailure) { /* ok */ }

        val bobAfter = bobDb.contactDao().getById(pair.bobContactId)!!
        // Persisted ratchet state byte-identical. Wrap IVs are random, so byte
        // equality on rk_wrapped is itself proof that saveRatchetState wasn't run.
        assertEquals(bobBefore.ns, bobAfter.ns)
        assertEquals(bobBefore.nr, bobAfter.nr)
        assertEquals(bobBefore.pn, bobAfter.pn)
        assertArrayEquals(bobBefore.dhs_pub, bobAfter.dhs_pub)
        assertArrayEquals(bobBefore.dhr_pub, bobAfter.dhr_pub)
        assertArrayEquals(bobBefore.rk_wrapped, bobAfter.rk_wrapped)
        assertArrayEquals(bobBefore.rk_hmac, bobAfter.rk_hmac)
        assertEquals(bobBefore.ckr_wrapped, bobAfter.ckr_wrapped)
        // No skipped-key rows leaked.
        assertEquals(0, bobDb.skippedMessageKeyDao().countForContact(pair.bobContactId))
        // No outbox row (no RECEIPT enqueued).
        assertEquals(0, bobDb.pendingOutboundFrameDao().countForContact(pair.bobContactId))
        // No message row.
        assertEquals(0, bobDb.messageDao().getByContactList(pair.bobContactId).size)
        // §8.2 counter ticked OUTSIDE the txn.
        assertEquals(1, bobAfter.consecutive_aead_failures)
    }

    /**
     * §8.3 mutex spans encrypt AND decrypt — DATA-receive (which enqueues a
     * RECEIPT, consuming a sending-chain step) racing against an outbound DATA
     * send must serialize. Assertion: post-batch Ns equals the count of ops
     * that consumed a sending-chain step, and every outbox row has a distinct
     * `n`. A duplicate `n` would mean key-reuse under the zero AEAD nonce.
     */
    @Test
    fun concurrent_encryptAndReceiptEnqueue_serializedByMutex() = runBlocking {
        val pair = bootstrapPair()
        seedAliceContact(pair)
        seedBobContact(pair)

        // Pre-generate Alice -> Bob frames so we can replay them on Bob in any order.
        val aliceTransmitted = java.util.Collections.synchronizedList(mutableListOf<ByteArray>())
        val aliceSender = sender(pair, transmit = { _, b -> aliceTransmitted += b })
        val nInbound = 4
        for (i in 0 until nInbound) {
            aliceSender.encryptAndSend(pair.aliceContactId, "alice-$i".toByteArray()) { hex, _, now ->
                outboundMessage(hex, pair.aliceContactId, now)
            }
        }
        val decoded = aliceTransmitted.map { (FrameCodec.decode(it) as FrameCodec.DecodeResult.Ok).frame }

        // Bob must decrypt at least the first frame BEFORE he can send (the role
        // wakes up his state.dhrPub + state.cks). Process frame[0] serially.
        val bobReceiver = receiver(pair)
        bobReceiver.receive(pair.bobContactId, decoded[0]) { plaintext, hex, _, ts ->
            inboundMessage(hex, pair.bobContactId, plaintext, ts)
        }

        // From here: 3 more inbound decrypts AND 3 Bob-originated sends racing.
        val bobOutboundTransmitted = java.util.Collections.synchronizedList(mutableListOf<ByteArray>())
        val bobSender = sender(pair, db = bobDb, ownFp = pair.bobFingerprint) { _, bytes -> bobOutboundTransmitted += bytes }
        val nOutbound = 3
        val nInboundParallel = 3  // frames[1..3]
        val totalOps = nInboundParallel + nOutbound

        val jobs = buildList<kotlinx.coroutines.Deferred<Any>> {
            for (i in 1..nInboundParallel) add(
                async(Dispatchers.IO) {
                    bobReceiver.receive(pair.bobContactId, decoded[i]) { plaintext, hex, _, ts ->
                        inboundMessage(hex, pair.bobContactId, plaintext, ts)
                    }
                }
            )
            for (i in 0 until nOutbound) add(
                async(Dispatchers.IO) {
                    bobSender.encryptAndSend(pair.bobContactId, "bob-$i".toByteArray()) { hex, _, now ->
                        outboundMessage(hex, pair.bobContactId, now)
                    }
                }
            )
        }
        jobs.awaitAll()

        // Bob's first frame[0] consumed one ns step (for its RECEIPT). Each of
        // the parallel inbound frames consumes one more (RECEIPT). Each of the
        // parallel sends consumes one more (DATA). Total ns = 1 + totalOps.
        val bobAfter = bobDb.contactDao().getById(pair.bobContactId)!!
        val expectedNs = 1 + totalOps
        assertEquals("ns advanced exactly once per send-chain consumer", expectedNs, bobAfter.ns)
        assertEquals("nr advanced once per inbound DATA", nInbound, bobAfter.nr)

        // Inspect Bob's outbox: 1 RECEIPT (frame[0]) + 3 RECEIPTs (parallel) + 3 DATAs (parallel) = 7 rows.
        val outbox = bobDb.pendingOutboundFrameDao().getByContact(pair.bobContactId)
        assertEquals(expectedNs, outbox.size)

        // No (dhPub, n) collision. All Bob-outbox frames share Bob's DHs.pub
        // since neither send nor inbound-receipt rotates his DHs without an
        // intervening dhRatchetReceive on a fresh peer DH — and Alice didn't
        // rotate in this batch. So they must form a distinct set on `n` alone.
        val outboxFrames = outbox.map { row ->
            val wire = wrapMac.unwrapAndVerify(
                "pending_outbound_frames.wrapped_frame", row.uuid, row.wrapped_frame, row.frame_hmac
            )
            (FrameCodec.decode(wire) as FrameCodec.DecodeResult.Ok).frame
        }
        val dhPub0 = outboxFrames[0].dhPub
        for (f in outboxFrames) assertArrayEquals(
            "all Bob's outbox frames must share his DHs.pub (no mid-batch rotation)", dhPub0, f.dhPub
        )
        val ns = outboxFrames.map { it.n }.toSortedSet()
        assertEquals(
            "distinct chain positions, no key reuse",
            (0 until expectedNs).toSet(),
            ns
        )
    }

    /**
     * DR16 §10.1 — `reset_divergentResetNonces_surfaceAsAeadFailure`.
     *
     * Force Alice and Bob to bootstrap with different `resetNonce` at the same
     * `R`. The DR5 nonce-mixing rule says `RK_0` then differs between the two
     * sides, and the property the test guards is that the divergence surfaces
     * as an AEAD failure on the FIRST post-reset DATA frame — never as a
     * silent corruption.
     *
     * Setup is synthetic (overwrite `rk` directly via [overwriteRk]) — we do
     * not drive [ResetReceive] through both sides because:
     *  - The convergence protocol (ACK exchange, `expecting_ack` clearance)
     *    is owned by [ResetReceiveTest].
     *  - The KDF correctness (`deriveResetRootKey` → distinct `RK_0` per
     *    nonce) is locked by `BootstrapTest.bootstrap_RK0_goldenVector_reset`.
     * This test owns ONLY the cryptographic property "divergent `RK_0` at
     * same `R` → AEAD failure".
     *
     * Also asserts the DR14 consecutive-failure heuristic counter advances —
     * if it didn't, the soft prompt would never trigger and the user couldn't
     * recover via manual reset.
     */
    @Test
    fun reset_divergentResetNonces_surfaceAsAeadFailure() = runBlocking {
        val pair = bootstrapPair()
        seedAliceContact(pair)
        seedBobContact(pair)

        // Synthetic idShared — both sides agree (it's peer-identity material
        // that survives resets). Value is irrelevant to the property under
        // test as long as the same bytes feed both KDF calls.
        val idShared = ByteArray(32) { (0xC0 + it).toByte() }
        val nonceA = ByteArray(16) { (0x10 + it).toByte() }
        val nonceB = ByteArray(16) { (0x80 + it).toByte() }
        val R = 1

        // Synthetic prekeySS — value doesn't matter for this nonce-divergence test,
        // only that both sides agree (mirrors how idShared is treated above).
        val prekeySS = ByteArray(32) { (0x55 + it).toByte() }
        val rkA = Bootstrap.deriveResetRootKey(idShared, prekeySS, R, nonceA)
        val rkB = Bootstrap.deriveResetRootKey(idShared, prekeySS, R, nonceB)
        assertFalse(
            "deriveResetRootKey must surface nonce differences in RK_0",
            rkA.contentEquals(rkB)
        )

        overwriteRk(pair.aliceContactId, aliceDb, rkA, pair.aliceInitial)
        overwriteRk(pair.bobContactId, bobDb, rkB, pair.bobInitial)

        val transmitted = mutableListOf<ByteArray>()
        val sender = sender(pair, transmit = { _, b -> transmitted += b })
        sender.encryptAndSend(pair.aliceContactId, "post-reset".toByteArray()) { hex, _, now ->
            outboundMessage(hex, pair.aliceContactId, now)
        }

        val frame = (FrameCodec.decode(transmitted.single()) as FrameCodec.DecodeResult.Ok).frame
        val receiver = receiver(pair)
        try {
            receiver.receive(pair.bobContactId, frame) { _, hex, _, ts ->
                inboundMessage(hex, pair.bobContactId, ByteArray(0), ts)
            }
            fail("expected RatchetCryptoFailure on divergent post-reset RK")
        } catch (_: RatchetCryptoFailure) {
            // expected — AEAD fired
        }

        val bob = bobDb.contactDao().getById(pair.bobContactId)!!
        assertEquals("DR14 counter must advance on AEAD failure", 1, bob.consecutive_aead_failures)
    }

    /**
     * DR16 §10.1 — `reset_lostThenAutoReset_convergesAtSameR`.
     *
     * Scenario test: Alice triggers a manual reset; her RESET frame is dropped
     * on the wire (so Bob never sees Alice's `resetNonce`). Bob's auto-reset
     * path independently fires at the SAME `R` with HIS own `resetNonce`.
     * Both sides agree on `R` but disagree on `RK_0` → first DATA AEAD-fails.
     *
     * The scenario is what [reset_divergentResetNonces_surfaceAsAeadFailure]
     * is REGRESSION-GUARDING. Kept as a separate named test because the DR16
     * catalog enumerates the scenario explicitly: if a future refactor breaks
     * the nonce-mixing property, both names will fail and the diagnostic is
     * unambiguous.
     */
    @Test
    fun reset_lostThenAutoReset_convergesAtSameR() = runBlocking {
        val pair = bootstrapPair()
        seedAliceContact(pair)
        seedBobContact(pair)

        val idShared = ByteArray(32) { (0xD0 + it).toByte() }
        val R = 1
        val aliceManualNonce = ByteArray(16) { (0x20 + it).toByte() }
        val bobAutoNonce = ByteArray(16) { (0x90 + it).toByte() }

        val prekeySS = ByteArray(32) { (0x55 + it).toByte() }
        val rkA = Bootstrap.deriveResetRootKey(idShared, prekeySS, R, aliceManualNonce)
        val rkB = Bootstrap.deriveResetRootKey(idShared, prekeySS, R, bobAutoNonce)
        assertFalse(rkA.contentEquals(rkB))

        // Both sides synthetically bootstrap to the same R via different
        // nonces — mirrors the lost-wire / independent-auto-reset scenario.
        overwriteRk(pair.aliceContactId, aliceDb, rkA, pair.aliceInitial)
        overwriteRk(pair.bobContactId, bobDb, rkB, pair.bobInitial)

        val transmitted = mutableListOf<ByteArray>()
        val sender = sender(pair, transmit = { _, b -> transmitted += b })
        sender.encryptAndSend(pair.aliceContactId, "lost-then-auto".toByteArray()) { hex, _, now ->
            outboundMessage(hex, pair.aliceContactId, now)
        }

        val frame = (FrameCodec.decode(transmitted.single()) as FrameCodec.DecodeResult.Ok).frame
        val receiver = receiver(pair)
        try {
            receiver.receive(pair.bobContactId, frame) { _, hex, _, ts ->
                inboundMessage(hex, pair.bobContactId, ByteArray(0), ts)
            }
            fail("expected AEAD failure on diverged auto-reset")
        } catch (_: RatchetCryptoFailure) {
            // expected
        }

        val bob = bobDb.contactDao().getById(pair.bobContactId)!!
        assertEquals(1, bob.consecutive_aead_failures)
    }

    /**
     * DR16 §10.1 — `reset_concurrentBothSides_handlesDivergence` (deferred from
     * DR16; landed in DR17 because it crosses two [ResetReceive] state
     * machines).
     *
     * Two-party flow: Alice and Bob each call [ResetReceive.manualResetInitiate]
     * within milliseconds of each other. Each persists its OWN fresh
     * `resetNonce`, advances `R` 0→1, sets `expecting_ack = 1`, and INSERTs an
     * initiator RESET row into its own outbox slot. The frames then cross on
     * the wire.
     *
     * Each inbound frame hits the `R_in == contact.R && expecting_ack != 0`
     * branch (`applyConvergence`). The peer's ack byte is the
     * initiator-marker, so the local side re-acks with its OWN persisted nonce
     * (`Outcome.Reacked`). State machine completes — both end at
     * `reset_epoch = 1`, but `rk` REMAINS DIVERGENT because each side kept its
     * own nonce.
     *
     * The DR13 spec calls this out explicitly:
     *   "Because [dr5] reset-RK_0 mixes resetNonce, the post-reset RK_0 is
     *    only identical when the same nonce was authenticated — silent
     *    forged-convergence collapses to an AEAD failure on the first
     *    post-reset DATA frame."
     *
     * Guarded properties:
     *  1. Both sides converge in the state machine (R advances, no stalls).
     *  2. Both produce a re-ack outbox row.
     *  3. `rk` diverges between the two sides — exactly the property
     *     `reset_divergentResetNonces_surfaceAsAeadFailure` then leans on to
     *     prove the divergence surfaces as AEAD failure.
     */
    @Test
    fun reset_concurrentBothSides_handlesDivergence() = runBlocking {
        val pair = bootstrapPair()
        seedAliceContact(pair)
        seedBobContact(pair)

        // The same idShared value on both sides — the test must agree with itself
        // about what X25519(idPriv, peerIdPub) returns. Real Android computes this
        // via [KeyManager]; here we just feed the constant through both lambdas.
        val idShared = ByteArray(32) { (0xA0 + it).toByte() }

        // Deterministic, distinct nonces — concurrent init is exactly the case
        // where the two sides each roll their own. We bypass
        // `manualResetInitiate` (which sources nonces from SecureRandom) and
        // persist the post-init state directly via `installPostInitState`.
        val aliceNonce = ByteArray(16) { (0x11 + it).toByte() }
        val bobNonce = ByteArray(16) { (0x77 + it).toByte() }
        // §3.2 — must match what Alice's / Bob's receive code derives from their
        // active prekey rows (seeded by [seedAliceContact]/[seedBobContact]).
        val prekeySS = pair.prekeySS
        val rkAlice = Bootstrap.deriveResetRootKey(idShared, prekeySS, 1, aliceNonce)
        val rkBob = Bootstrap.deriveResetRootKey(idShared, prekeySS, 1, bobNonce)
        assertFalse("RK_0 must differ across distinct nonces at same R",
            rkAlice.contentEquals(rkBob))

        // Bob's role (aliceFp < bobFp from bootstrapPair) means Bob must
        // generate a post-reset ephemeral on init, and include its pub in the
        // RESET plaintext slot. Alice's slot stays zero per [dr12] §6.1.
        val bobPostResetPriv = X25519.generatePrivateKey()
        val bobPostResetPub = X25519.publicFromPrivate(bobPostResetPriv)

        // Synthesize each side's POST-manualResetInitiate state: R=1,
        // expecting_ack=1, fresh rk_wrapped, our nonce persisted; Bob also
        // carries dhs (post-reset eph), Alice's dhs stays nil.
        installPostInitState(
            pair.aliceContactId, aliceDb, pair.aliceInitial, rkAlice, aliceNonce,
            postResetEphPriv = null, postResetEphPub = null
        )
        installPostInitState(
            pair.bobContactId, bobDb, pair.bobInitial, rkBob, bobNonce,
            postResetEphPriv = bobPostResetPriv, postResetEphPub = bobPostResetPub
        )

        // Build the inbound RESET frames each side would have transmitted.
        // Alice's slot is zero, Bob's carries his post-reset pub.
        val aliceFrame = buildInitiatorResetFrame(
            senderFp = pair.aliceFingerprint,
            recipFp = pair.bobFingerprint,
            idShared = idShared,
            prekeySS = pair.prekeySS,
            resetNonce = aliceNonce,
            r = 1,
            postResetEphPub = ByteArray(ResetCrypto.POST_RESET_EPH_PUB_BYTES)
        )
        val bobFrame = buildInitiatorResetFrame(
            senderFp = pair.bobFingerprint,
            recipFp = pair.aliceFingerprint,
            idShared = idShared,
            prekeySS = pair.prekeySS,
            resetNonce = bobNonce,
            r = 1,
            postResetEphPub = bobPostResetPub
        )

        val aliceReceiver = ResetReceive(
            db = aliceDb,
            wrapMac = wrapMac,
            ownFingerprint32 = pair.aliceFingerprint,
            idSharedSecretFor = { idShared.copyOf() },
            clock = { 1_000_000L }
        )
        val bobReceiver = ResetReceive(
            db = bobDb,
            wrapMac = wrapMac,
            ownFingerprint32 = pair.bobFingerprint,
            idSharedSecretFor = { idShared.copyOf() },
            clock = { 1_000_000L }
        )

        // Cross-deliver — each side hits applyConvergence on the peer's frame.
        val aliceOutcome = aliceReceiver.onResetFrame(pair.aliceContactId, bobFrame)
        val bobOutcome = bobReceiver.onResetFrame(pair.bobContactId, aliceFrame)
        assertSame("Alice re-acks Bob's concurrent init", ResetReceive.Outcome.Reacked, aliceOutcome)
        assertSame("Bob re-acks Alice's concurrent init", ResetReceive.Outcome.Reacked, bobOutcome)

        val aliceAfter = aliceDb.contactDao().getById(pair.aliceContactId)!!
        val bobAfter = bobDb.contactDao().getById(pair.bobContactId)!!
        assertEquals("Alice still at R=1", 1, aliceAfter.reset_epoch)
        assertEquals("Bob still at R=1", 1, bobAfter.reset_epoch)
        assertEquals("Alice still expecting ack on her own init", 1, aliceAfter.expecting_ack)
        assertEquals("Bob still expecting ack on his own init", 1, bobAfter.expecting_ack)

        // Divergence guard: rk_wrapped pairs must differ. wrap IVs are random so
        // byte equality on rk_wrapped is itself a proof they were sealed under
        // different plaintexts (different rk_0 values).
        assertFalse(
            "rk diverged — confirms each side kept its own nonce",
            aliceAfter.rk_wrapped!!.contentEquals(bobAfter.rk_wrapped)
        )
        // Independent confirmation via unwrap.
        val aliceRk = wrapMac.unwrapAndVerify(
            "contacts.rk_wrapped",
            pair.aliceContactId.toByteArray(Charsets.UTF_8),
            aliceAfter.rk_wrapped!!,
            aliceAfter.rk_hmac!!
        )
        val bobRk = wrapMac.unwrapAndVerify(
            "contacts.rk_wrapped",
            pair.bobContactId.toByteArray(Charsets.UTF_8),
            bobAfter.rk_wrapped!!,
            bobAfter.rk_hmac!!
        )
        assertArrayEquals("Alice keeps her own RK_0", rkAlice, aliceRk)
        assertArrayEquals("Bob keeps his own RK_0", rkBob, bobRk)

        // Both sides should have re-enqueued an acknowledger RESET row.
        assertTrue(
            "Alice's re-ack landed in outbox",
            aliceDb.pendingOutboundFrameDao().countForContact(pair.aliceContactId) >= 1
        )
        assertTrue(
            "Bob's re-ack landed in outbox",
            bobDb.pendingOutboundFrameDao().countForContact(pair.bobContactId) >= 1
        )
    }

    /**
     * Mirrors what `ResetReceive.initInsideTxn` writes: wipes ratchet, plants
     * the post-reset rk_wrapped derived from [resetNonce], bumps reset_epoch
     * to 1, and persists `reset_nonce + expecting_ack=1`. Used by the
     * concurrent-init test to bypass the [ResetReceive.manualResetInitiate]
     * call (whose SecureRandom-sourced nonce we can't pin from outside).
     */
    private fun installPostInitState(
        contactId: String,
        db: AppDatabase,
        fromBootstrap: Bootstrap.InitialState,
        rk0: ByteArray,
        resetNonce: ByteArray,
        postResetEphPriv: ByteArray?,
        postResetEphPub: ByteArray?
    ) = runBlocking {
        val state = RatchetState.fromBootstrap(fromBootstrap).also {
            it.rk = rk0.copyOf()
            it.dhsPriv = postResetEphPriv?.copyOf()
            it.dhsPub = postResetEphPub?.copyOf()
            it.dhrPub = null
            it.cks = null
            it.ckr = null
            it.ns = 0
            it.nr = 0
            it.pn = 0
            it.r = 1
        }
        val current = db.contactDao().getById(contactId)!!
        val saved = RatchetStatePersistence.saveRatchetState(current, state, wrapMac)
            .copy(
                reset_epoch = 1,
                reset_nonce = resetNonce.copyOf(),
                expecting_ack = 1
            )
        db.contactDao().upsert(saved)
    }

    /**
     * Build a wire-v2 RESET DecodedFrame the peer would have transmitted with
     * `ack=0` (initiator), the provided nonce, and an Alice-role
     * `postResetEphPub` slot (zero-filled per [dr12] §6.1 — Bob/Alice mapping
     * is irrelevant to the convergence-detection branch we exercise here).
     */
    private fun buildInitiatorResetFrame(
        senderFp: ByteArray,
        recipFp: ByteArray,
        idShared: ByteArray,
        prekeySS: ByteArray,
        resetNonce: ByteArray,
        r: Int,
        postResetEphPub: ByteArray
    ): FrameCodec.DecodedFrame {
        // §3.2 — `prekeySS` is what the recipient's receive code will derive from
        // its own active prekey row; X25519 symmetry means both sides see the
        // same 32 bytes. Caller passes `pair.prekeySS`. `stagedPrekeyPub` is
        // validated post-AEAD via [isValidX25519Public], so use a fresh real pub
        // rather than a fixed bit pattern that might collide with a low-order
        // point as the validator evolves.
        val plaintext = ResetCrypto.Plaintext(
            ack = ResetCrypto.ACK_INITIATOR,
            postResetEphPub = postResetEphPub.copyOf(),
            stagedPrekeyPub = X25519.publicFromPrivate(X25519.generatePrivateKey())
        )
        val kReset = ResetCrypto.deriveKReset(idShared, prekeySS, senderFp, recipFp, resetNonce, r)
        try {
            val frameUuid = ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }
            val wireBytes = ResetCrypto.encode(
                senderFp = senderFp,
                recipFp = recipFp,
                resetNonce = resetNonce,
                R = r,
                uuid = frameUuid,
                timestampMs = 1_000_000L,
                plaintext = plaintext,
                kReset = kReset
            )
            return (FrameCodec.decode(wireBytes) as FrameCodec.DecodeResult.Ok).frame
        } finally {
            kReset.fill(0)
        }
    }

    /**
     * Overwrite a contact's persisted ratchet `rk` while keeping the original
     * bootstrap DH state. Used by reset-divergence tests to install a synthetic
     * post-reset RK_0 without driving the [ResetReceive] state machine.
     */
    private fun overwriteRk(
        contactId: String,
        db: AppDatabase,
        newRk: ByteArray,
        fromBootstrap: Bootstrap.InitialState
    ) = runBlocking {
        val state = RatchetState.fromBootstrap(fromBootstrap).also { it.rk = newRk.copyOf() }
        val current = db.contactDao().getById(contactId)!!
        val updated = RatchetStatePersistence.saveRatchetState(current, state, wrapMac)
        db.contactDao().upsert(updated)
    }

    // ---------- Test fixtures ----------

    private class Pair(
        val aliceContactId: String,    // local row id == "Bob from Alice's POV" (hex of Bob's idPub)
        val bobContactId: String,      // local row id == "Alice from Bob's POV" (hex of Alice's idPub)
        val aliceFingerprint: ByteArray,
        val bobFingerprint: ByteArray,
        val aliceIdPub: ByteArray,
        val bobIdPub: ByteArray,
        val aliceInitial: Bootstrap.InitialState,
        val bobInitial: Bootstrap.InitialState,
        val bobState: RatchetState,
        // §3.2 — per-side active prekey keypair and the shared `prekeySS` they
        // both derive. Production's `ResetReceive.loadActivePrekeySS` reads from
        // `prekey_epochs.active`; both sides compute the same prekeySS by
        // X25519 symmetry, so frame-construction helpers in this test class
        // must use `prekeySS` whenever they synthesize a K_reset.
        val alicePrekey: Prekey.KeyPair,
        val bobPrekey: Prekey.KeyPair,
        val prekeySS: ByteArray
    )

    /** Roll a pair until the local side rolls into the ALICE role (sends first). */
    private fun bootstrapPair(): Pair {
        var aPriv: ByteArray; var aPub: ByteArray
        var bPriv: ByteArray; var bPub: ByteArray
        while (true) {
            aPriv = X25519.generatePrivateKey()
            aPub = X25519.publicFromPrivate(aPriv)
            bPriv = X25519.generatePrivateKey()
            bPub = X25519.publicFromPrivate(bPriv)
            if (Bootstrap.decideRole(aPub, bPub) == Bootstrap.Role.ALICE) break
        }
        val aEphPriv = X25519.generatePrivateKey()
        val aEphPub = X25519.publicFromPrivate(aEphPriv)
        val bEphPriv = X25519.generatePrivateKey()
        val bEphPub = X25519.publicFromPrivate(bEphPriv)

        val aBoot = Bootstrap.computeInitialBootstrap(aPriv, aPub, bPub, aEphPriv, aEphPub, bEphPub)
        val bBoot = Bootstrap.computeInitialBootstrap(bPriv, bPub, aPub, bEphPriv, bEphPub, aEphPub)

        val alicePrekey = Prekey.generate()
        val bobPrekey = Prekey.generate()
        return Pair(
            aliceContactId = bPub.joinToString("") { "%02x".format(it) },
            bobContactId = aPub.joinToString("") { "%02x".format(it) },
            aliceFingerprint = Bootstrap.fingerprintBytes(aPub),
            bobFingerprint = Bootstrap.fingerprintBytes(bPub),
            aliceIdPub = aPub,
            bobIdPub = bPub,
            aliceInitial = aBoot,
            bobInitial = bBoot,
            bobState = RatchetState.fromBootstrap(bBoot),
            alicePrekey = alicePrekey,
            bobPrekey = bobPrekey,
            prekeySS = Prekey.sharedSecret(alicePrekey.priv, bobPrekey.pub)
        )
    }

    private fun seedAliceContact(pair: Pair, expectingAck: Int = 0) {
        val initial = ContactEntity(
            id = pair.aliceContactId,
            name = "Bob",
            publicKeyBase64 = android.util.Base64.encodeToString(pair.bobIdPub, android.util.Base64.NO_WRAP),
            addedAt = 0L
        )
        val state = RatchetState.fromBootstrap(pair.aliceInitial)
        val withState = RatchetStatePersistence.saveRatchetState(initial, state, wrapMac)
            .copy(expecting_ack = expectingAck)
        runBlocking { aliceDb.contactDao().upsert(withState) }
        // §3.2 — Alice's active prekey: her own priv, peer = Bob's prekey pub.
        insertActivePrekey0(aliceDb, pair.aliceContactId, pair.alicePrekey, pair.bobPrekey.pub)
    }

    private fun seedBobContact(pair: Pair) {
        val initial = ContactEntity(
            id = pair.bobContactId,
            name = "Alice",
            publicKeyBase64 = android.util.Base64.encodeToString(pair.aliceIdPub, android.util.Base64.NO_WRAP),
            addedAt = 0L
        )
        val state = RatchetState.fromBootstrap(pair.bobInitial)
        val withState = RatchetStatePersistence.saveRatchetState(initial, state, wrapMac)
        runBlocking { bobDb.contactDao().upsert(withState) }
        // §3.2 — Bob's active prekey mirrors Alice's: prekeySS is symmetric.
        insertActivePrekey0(bobDb, pair.bobContactId, pair.bobPrekey, pair.alicePrekey.pub)
    }

    private fun insertActivePrekey0(
        db: AppDatabase,
        contactId: String,
        kp: Prekey.KeyPair,
        peerPrekeyPub: ByteArray
    ) = runBlocking {
        val rowId = PrekeyEpochEntity.rowIdFor(contactId, 0)
        val (privW, privH) = wrapMac.wrapAndMac(PrekeyEpochEntity.COL_MY_PRIV, rowId, kp.priv)
        db.prekeyEpochDao().insert(
            PrekeyEpochEntity(
                contact_id = contactId,
                epoch = 0,
                status = PrekeyEpochEntity.STATUS_ACTIVE,
                my_priv_wrapped = privW,
                my_priv_hmac = privH,
                my_pub = kp.pub,
                peer_pub = peerPrekeyPub,
                expires_at = null
            )
        )
    }

    /**
     * Sender bound to a specific device's DB. Defaults to Alice; pass [db] +
     * [ownFp] explicitly when the test exercises Bob's send path.
     */
    private fun sender(
        pair: Pair,
        db: AppDatabase = aliceDb,
        ownFp: ByteArray = pair.aliceFingerprint,
        transmit: suspend (String, ByteArray) -> Unit
    ): RatchetEncryptAndSend =
        RatchetEncryptAndSend(db, wrapMac, ownFp, transmit)

    /** Receiver bound to a specific device's DB. Defaults to Bob's side. */
    private fun receiver(
        pair: Pair,
        db: AppDatabase = bobDb,
        ownFp: ByteArray = pair.bobFingerprint
    ): RatchetDecryptAndPersist =
        RatchetDecryptAndPersist(db, wrapMac, ownFp)

    private fun outboundMessage(uuidHex: String, contactId: String, now: Long): MessageEntity =
        MessageEntity(
            uuid = uuidHex,
            contactId = contactId,
            direction = MessageEntity.DIRECTION_OUTBOUND,
            state = MessageEntity.STATE_OUTBOX,
            transport = TransportType.UNKNOWN,
            encryptedFilePath = null,
            durationMs = 0,
            deleteAfterMs = 0L,
            scheduledDeleteAt = 0L,
            transcription = null,
            createdAt = now,
            sentAt = 0L,
            deliveredAt = 0L
        )

    private fun inboundMessage(
        uuidHex: String,
        contactId: String,
        plaintext: ByteArray,
        wireTimestampMs: Long
    ): MessageEntity =
        MessageEntity(
            uuid = uuidHex,
            contactId = contactId,
            direction = MessageEntity.DIRECTION_INBOUND,
            state = MessageEntity.STATE_DELIVERED,
            transport = TransportType.UNKNOWN,
            encryptedFilePath = null,
            durationMs = plaintext.size,
            deleteAfterMs = 0L,
            scheduledDeleteAt = 0L,
            transcription = null,
            createdAt = wireTimestampMs,
            sentAt = 0L,
            deliveredAt = wireTimestampMs
        )

    /**
     * Honest-to-DR2 fake: AES-GCM wrap (random key, in-process), HMAC-SHA256 binding,
     * exact same `column || 0x00 || rowId || 0x00 || wrapped` layout. Sufficient to
     * exercise the encrypt path without AndroidKeyStore.
     */
    private class TestWrapMac : WrapMac {
        private val wrapKey: SecretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        private val macKey: SecretKey = SecretKeySpec(ByteArray(32).also { SecureRandom().nextBytes(it) }, "HmacSHA256")

        override fun wrapAndMac(columnName: String, rowId: ByteArray, plain: ByteArray): kotlin.Pair<ByteArray, ByteArray> {
            val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, wrapKey, GCMParameterSpec(128, iv))
            val ctAndTag = cipher.doFinal(plain)
            val wrapped = iv + ctAndTag
            val hmac = bindingHmac(columnName, rowId, wrapped)
            return wrapped to hmac
        }

        override fun unwrapAndVerify(columnName: String, rowId: ByteArray, wrapped: ByteArray, hmac: ByteArray): ByteArray {
            val expected = bindingHmac(columnName, rowId, wrapped)
            if (!MessageDigest.isEqual(expected, hmac)) throw WrapHmacMismatch()
            val iv = wrapped.copyOfRange(0, 12)
            val ctAndTag = wrapped.copyOfRange(12, wrapped.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, wrapKey, GCMParameterSpec(128, iv))
            return cipher.doFinal(ctAndTag)
        }

        private fun bindingHmac(column: String, rowId: ByteArray, wrapped: ByteArray): ByteArray =
            Mac.getInstance("HmacSHA256").run {
                init(macKey)
                update(column.toByteArray(Charsets.UTF_8))
                update(0x00.toByte())
                update(rowId)
                update(0x00.toByte())
                update(wrapped)
                doFinal()
            }
    }
}
