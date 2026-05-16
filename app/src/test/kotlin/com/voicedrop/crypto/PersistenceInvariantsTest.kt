package com.voicedrop.crypto

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.google.crypto.tink.subtle.X25519
import com.voicedrop.network.FrameCodec
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.ContactEntity
import com.voicedrop.storage.MessageEntity
import com.voicedrop.storage.PendingOutboundFrameEntity
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
import org.junit.Assert.assertNotNull
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

    private lateinit var db: AppDatabase
    private lateinit var wrapMac: TestWrapMac

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        db = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        wrapMac = TestWrapMac()
        ContactMutexRegistry.clear()
    }

    @After
    fun tearDown() {
        db.close()
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
        assertEquals(1, db.pendingOutboundFrameDao().countForContact(pair.aliceContactId))
        // Wire bytes ALSO went through transmit (post-commit).
        assertEquals(1, transmitted.size)
        assertArrayEquals(sent.wireBytes, transmitted.single())
        // Message row landed with delivery_state=PENDING.
        val msg = db.messageDao().getByUuid(sent.frameUuidHex)
        assertNotNull(msg); assertEquals(MessageEntity.DELIVERY_PENDING, msg!!.delivery_state)
        // Chain `n` consumed (next advance would be 1).
        val contactAfter = db.contactDao().getById(pair.aliceContactId)!!
        assertEquals(1, contactAfter.ns)
    }

    @Test
    fun encrypt_crashBeforeCommit_noStateChange() = runBlocking {
        val pair = bootstrapPair()
        seedAliceContact(pair)
        val beforeContact = db.contactDao().getById(pair.aliceContactId)!!

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

        val afterContact = db.contactDao().getById(pair.aliceContactId)!!
        assertEquals("ns must not advance on rollback", beforeContact.ns, afterContact.ns)
        assertArrayEquals(beforeContact.rk_wrapped, afterContact.rk_wrapped)
        // rk_hmac equality also confirms the wrap wasn't committed.
        assertArrayEquals(beforeContact.rk_hmac, afterContact.rk_hmac)
        assertEquals(0, db.pendingOutboundFrameDao().countForContact(pair.aliceContactId))
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
        val row = db.pendingOutboundFrameDao().getByUuid(sent.frameUuid)
        assertNotNull(row)
        val unwrapped = wrapMac.unwrapAndVerify(
            "pending_outbound_frames.wrapped_frame", row!!.uuid, row.wrapped_frame, row.frame_hmac
        )
        assertArrayEquals(sent.wireBytes, unwrapped)
        // Chain `n` consumed.
        assertEquals(1, db.contactDao().getById(pair.aliceContactId)!!.ns)
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
        assertEquals(0, db.pendingOutboundFrameDao().countForContact(pair.aliceContactId))
    }

    @Test
    fun bobRole_sendBeforeFirstReceive_throwsAwaitingFirstReceive() = runBlocking {
        val pair = bootstrapPair()
        seedBobContact(pair)
        val sender = sender(pair, ownFp = pair.bobFingerprint, transmit = { _, _ -> })
        try {
            sender.encryptAndSend(pair.bobContactId, "too soon".toByteArray()) { hex, _, now ->
                outboundMessage(hex, pair.bobContactId, now)
            }
            fail("expected AwaitingFirstReceive")
        } catch (_: AwaitingFirstReceive) { /* ok */ }
        // Nothing leaked into outbox.
        assertEquals(0, db.pendingOutboundFrameDao().countForContact(pair.bobContactId))
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
        assertEquals(N, db.contactDao().getById(pair.aliceContactId)!!.ns)
        assertEquals(N, db.pendingOutboundFrameDao().countForContact(pair.aliceContactId))
    }

    // ---------- DR8: decrypt path ----------

    /**
     * §8.2 — re-delivered DATA is dedup'd against the messages table. The
     * receiving chain MUST NOT re-advance, but a fresh RECEIPT MUST be enqueued
     * (to recover from a lost prior RECEIPT). The sending chain (Ns) advances
     * once per re-delivery because RECEIPT consumes a chain step.
     */
    @Test
    fun decrypt_idempotentByUuid_butReReceiptEnqueued() = runBlocking {
        val pair = bootstrapPair()
        // Alice's side persists for her encrypt path.
        seedAliceContact(pair)
        // Bob's side persists for the decrypt path. Bob is the receiver here.
        seedBobContact(pair)

        // Alice encrypts one DATA frame.
        val aliceTransmitted = mutableListOf<ByteArray>()
        val aliceSender = sender(pair, transmit = { _, b -> aliceTransmitted += b })
        aliceSender.encryptAndSend(pair.aliceContactId, "hello-bob".toByteArray()) { hex, _, now ->
            outboundMessage(hex, pair.aliceContactId, now)
        }
        val wireFromAlice = aliceTransmitted.single()
        val decoded = (FrameCodec.decode(wireFromAlice) as FrameCodec.DecodeResult.Ok).frame

        // First receive: ratchet advances; RECEIPT lands in outbox.
        val receiver = receiver(pair)
        val first = receiver.receive(pair.bobContactId, decoded) { plaintext, hex, _, ts ->
            inboundMessage(hex, pair.bobContactId, plaintext, ts)
        }
        assertTrue(first is RatchetDecryptAndPersist.Result.Delivered)
        val bobAfterFirst = db.contactDao().getById(pair.bobContactId)!!
        assertEquals("nr advanced once", 1, bobAfterFirst.nr)
        assertEquals("ns advanced once for the RECEIPT", 1, bobAfterFirst.ns)
        assertEquals(1, db.pendingOutboundFrameDao().countForContact(pair.bobContactId))
        assertEquals(1, db.messageDao().getByContactList(pair.bobContactId).size)

        // Second receive of the SAME wire frame: dedup branch.
        val dup = receiver.receive(pair.bobContactId, decoded) { _, _, _, _ ->
            fail("buildInboundMessage must not be called on dedup path")
            throw IllegalStateException("unreachable")
        }
        assertTrue(dup is RatchetDecryptAndPersist.Result.DuplicateData)

        val bobAfterDup = db.contactDao().getById(pair.bobContactId)!!
        assertEquals("nr unchanged — receiving chain MUST NOT re-advance", bobAfterFirst.nr, bobAfterDup.nr)
        assertEquals("ns DID advance once more (re-enqueued RECEIPT)", 2, bobAfterDup.ns)
        assertEquals("a second RECEIPT row exists", 2, db.pendingOutboundFrameDao().countForContact(pair.bobContactId))
        assertEquals("messages table still has exactly one row", 1, db.messageDao().getByContactList(pair.bobContactId).size)

        // Both RECEIPT outbox rows must ack the SAME DATA UUID, but be themselves
        // distinct frames (distinct frame UUIDs, distinct ciphertexts).
        val outboxRows = db.pendingOutboundFrameDao().getByContact(pair.bobContactId)
        assertEquals(2, outboxRows.size)
        assertEquals(
            "both RECEIPTs are RECEIPT frames",
            setOf(PendingOutboundFrameEntity.FRAME_KIND_RECEIPT),
            outboxRows.map { it.frame_kind }.toSet()
        )
        assertTrue(
            "RECEIPT frame UUIDs distinct",
            !outboxRows[0].uuid.contentEquals(outboxRows[1].uuid)
        )
        val chainPositions = outboxRows.map { row ->
            val wire = wrapMac.unwrapAndVerify(
                "pending_outbound_frames.wrapped_frame", row.uuid, row.wrapped_frame, row.frame_hmac
            )
            val d = (FrameCodec.decode(wire) as FrameCodec.DecodeResult.Ok).frame
            assertEquals(FrameCodec.FRAME_KIND_RECEIPT, d.kind)
            d.n
        }.toSortedSet()
        assertEquals("RECEIPT chain positions are 0 and 1 (no key reuse)", sortedSetOf(0, 1), chainPositions)
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

        val bobBefore = db.contactDao().getById(pair.bobContactId)!!
        val receiver = receiver(pair)
        try {
            receiver.receive(pair.bobContactId, tampered) { _, _, _, _ ->
                fail("buildInboundMessage must not be called on AEAD failure")
                throw IllegalStateException("unreachable")
            }
            fail("expected RatchetCryptoFailure")
        } catch (_: RatchetCryptoFailure) { /* ok */ }

        val bobAfter = db.contactDao().getById(pair.bobContactId)!!
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
        assertEquals(0, db.skippedMessageKeyDao().countForContact(pair.bobContactId))
        // No outbox row (no RECEIPT enqueued).
        assertEquals(0, db.pendingOutboundFrameDao().countForContact(pair.bobContactId))
        // No message row.
        assertEquals(0, db.messageDao().getByContactList(pair.bobContactId).size)
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
        val bobSender = RatchetEncryptAndSend(
            db, wrapMac, pair.bobFingerprint
        ) { _, bytes -> bobOutboundTransmitted += bytes }
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
        val bobAfter = db.contactDao().getById(pair.bobContactId)!!
        val expectedNs = 1 + totalOps
        assertEquals("ns advanced exactly once per send-chain consumer", expectedNs, bobAfter.ns)
        assertEquals("nr advanced once per inbound DATA", nInbound, bobAfter.nr)

        // Inspect Bob's outbox: 1 RECEIPT (frame[0]) + 3 RECEIPTs (parallel) + 3 DATAs (parallel) = 7 rows.
        val outbox = db.pendingOutboundFrameDao().getByContact(pair.bobContactId)
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
        val bobState: RatchetState
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

        return Pair(
            aliceContactId = bPub.joinToString("") { "%02x".format(it) },
            bobContactId = aPub.joinToString("") { "%02x".format(it) },
            aliceFingerprint = Bootstrap.fingerprintBytes(aPub),
            bobFingerprint = Bootstrap.fingerprintBytes(bPub),
            aliceIdPub = aPub,
            bobIdPub = bPub,
            aliceInitial = aBoot,
            bobInitial = bBoot,
            bobState = RatchetState.fromBootstrap(bBoot)
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
        runBlocking { db.contactDao().upsert(withState) }
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
        runBlocking { db.contactDao().upsert(withState) }
    }

    private fun sender(
        pair: Pair,
        ownFp: ByteArray = pair.aliceFingerprint,
        transmit: suspend (String, ByteArray) -> Unit
    ): RatchetEncryptAndSend =
        RatchetEncryptAndSend(db, wrapMac, ownFp, transmit)

    /** Decrypt-side wired up as Bob (DR8 entry under his fingerprint). */
    private fun receiver(pair: Pair, ownFp: ByteArray = pair.bobFingerprint): RatchetDecryptAndPersist =
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
