package com.voicedrop.crypto

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.google.crypto.tink.subtle.X25519
import com.voicedrop.network.FrameCodec
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.ContactEntity
import com.voicedrop.storage.MessageEntity
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
 * DR7 — `PersistenceInvariantsTest` (encrypt-path subset).
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
