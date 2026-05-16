package com.voicedrop.crypto

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.google.crypto.tink.subtle.X25519
import com.voicedrop.network.FrameCodec
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.ContactEntity
import com.voicedrop.storage.MessageEntity
import com.voicedrop.storage.SkippedKeyMaintenance
import com.voicedrop.storage.SkippedMessageKeyEntity
import com.voicedrop.storage.TransportType
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
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
 * DR9 — `SkippedKeyStoreTest`. Three cases from `plan/08-dr/dr9-skipped-keys.md`:
 *
 *   - `eviction_FIFOAt2000Entries` — DAO-level. The `(contact_id, created_at)`
 *     index from [dr3] §7.2 must order eviction by `created_at`, oldest first.
 *   - `expiry_sweepRemovesEntriesOlderThan7d` — DAO-level. `AppDatabase`
 *     open-time sweep deletes by `created_at < now - 7d`.
 *   - `eviction_dropsKeyBeforeFrameArrives_chainContinues` — pipeline. A
 *     skipped key evicted before its DATA frame arrives → AEAD fails, ratchet
 *     state stays intact (clone-then-commit, [dr6] §4.4), subsequent in-chain
 *     frames decrypt fine.
 *
 * Runs under Robolectric so we can use an in-memory Room with a fake
 * [TestWrapMac]; mirrors [PersistenceInvariantsTest]'s setup.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class SkippedKeyStoreTest {

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

    // ---------- Test 1: FIFO eviction ----------

    /**
     * Insert 2005 rows for one contact with monotonically increasing
     * `created_at`. [SkippedKeyMaintenance.enforceCap] must trim to 2000,
     * dropping the 5 oldest. Verifies the `(contact_id, created_at)` index
     * orders the delete correctly.
     */
    @Test
    fun eviction_FIFOAt2000Entries() = runBlocking {
        val contactId = seedBareContact("contact-a")
        val dhrPub = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val dao = db.skippedMessageKeyDao()

        val total = SkippedKeyMaintenance.CAP_PER_CONTACT + 5
        for (i in 0 until total) {
            dao.insertBlocking(
                SkippedMessageKeyEntity(
                    contact_id = contactId,
                    dhr_pub = dhrPub,
                    n = i,
                    mk_wrapped = ByteArray(32) { 0x11 },
                    mk_hmac = ByteArray(32) { 0x22 },
                    created_at = i.toLong()        // increasing → row 0 is oldest
                )
            )
        }
        assertEquals(total, dao.countForContactBlocking(contactId))

        SkippedKeyMaintenance.enforceCap(dao, contactId)

        assertEquals(
            SkippedKeyMaintenance.CAP_PER_CONTACT,
            dao.countForContactBlocking(contactId)
        )

        // The 5 oldest (n=0..4) must be gone; the youngest 2000 (n=5..2004) must remain.
        for (i in 0 until 5) {
            assertEquals(
                "n=$i should have been evicted",
                null,
                dao.getWrappedBlocking(contactId, dhrPub, i)
            )
        }
        for (i in 5 until total) {
            assertNotNull(
                "n=$i must remain after FIFO trim",
                dao.getWrappedBlocking(contactId, dhrPub, i)
            )
        }
    }

    // ---------- Test 2: 7-day expiry sweep ----------

    /**
     * Mixed-timestamp insert: rows older than 7d must be deleted by the
     * `AppDatabase` open-callback sweep; rows within 7d must remain.
     */
    @Test
    fun expiry_sweepRemovesEntriesOlderThan7d() = runBlocking {
        val contactId = seedBareContact("contact-b")
        val dhrPub = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val dao = db.skippedMessageKeyDao()
        val now = 1_000_000_000_000L
        val sevenDays = SkippedKeyMaintenance.EXPIRY_MS

        // 3 ancient rows (older than 7d) + 4 fresh rows (within 7d).
        val ancientCreatedAt = listOf(now - sevenDays - 5_000L, now - sevenDays - 1L, now - sevenDays - 60_000L)
        val freshCreatedAt = listOf(now - sevenDays + 1L, now - 60_000L, now - 1L, now)

        ancientCreatedAt.forEachIndexed { idx, ts ->
            dao.insertBlocking(
                SkippedMessageKeyEntity(
                    contact_id = contactId,
                    dhr_pub = dhrPub,
                    n = idx,
                    mk_wrapped = ByteArray(32) { 0x33 },
                    mk_hmac = ByteArray(32) { 0x44 },
                    created_at = ts
                )
            )
        }
        freshCreatedAt.forEachIndexed { idx, ts ->
            dao.insertBlocking(
                SkippedMessageKeyEntity(
                    contact_id = contactId,
                    dhr_pub = dhrPub,
                    n = idx + 100,   // distinct from ancient ns
                    mk_wrapped = ByteArray(32) { 0x55 },
                    mk_hmac = ByteArray(32) { 0x66 },
                    created_at = ts
                )
            )
        }
        assertEquals(7, dao.countForContactBlocking(contactId))

        val deleted = SkippedKeyMaintenance.sweepExpired(dao, now)
        assertEquals("only ancient rows swept", ancientCreatedAt.size, deleted)
        assertEquals(freshCreatedAt.size, dao.countForContactBlocking(contactId))

        // Ancient ns must be gone; fresh ns must remain.
        for (i in ancientCreatedAt.indices) {
            assertEquals(null, dao.getWrappedBlocking(contactId, dhrPub, i))
        }
        for (i in freshCreatedAt.indices) {
            assertNotNull(dao.getWrappedBlocking(contactId, dhrPub, i + 100))
        }
    }

    // ---------- Test 3: chain survives a pre-arrival eviction ----------

    /**
     * Alice sends frames 0, 1, 2. Bob receives only frame 2, which stashes
     * frame 0 + frame 1's keys into his `skipped_message_keys` row. The DR9
     * FIFO eviction then drops frame 0's row (we simulate the eviction by a
     * direct DELETE so the test stays fast — the cap mechanism itself is
     * covered by [eviction_FIFOAt2000Entries]).
     *
     * After eviction, attempting to deliver frame 0:
     *   - AEAD fails ([dr6] hits the slow path with the current chain CK,
     *     derives an MK that doesn't match frame 0's, AEAD-open throws).
     *   - The clone is discarded; Bob's persisted ratchet state is
     *     byte-identical to its pre-call state.
     *   - Frame 1 still decrypts cleanly via the surviving skipped-key row.
     */
    @Test
    fun eviction_dropsKeyBeforeFrameArrives_chainContinues() = runBlocking {
        val pair = bootstrapPair()
        seedAliceContact(pair)
        seedBobContact(pair)

        // Alice sends 3 DATA frames. No DH rotation mid-batch: same dhPub on all 3.
        val aliceTransmitted = mutableListOf<ByteArray>()
        val aliceSender = RatchetEncryptAndSend(
            db, wrapMac, pair.aliceFingerprint
        ) { _, bytes -> aliceTransmitted += bytes }
        repeat(3) { i ->
            aliceSender.encryptAndSend(pair.aliceContactId, "msg-$i".toByteArray()) { hex, _, now ->
                outboundMessage(hex, pair.aliceContactId, now)
            }
        }
        val frames = aliceTransmitted.map { (FrameCodec.decode(it) as FrameCodec.DecodeResult.Ok).frame }
        assertEquals(0, frames[0].n); assertEquals(1, frames[1].n); assertEquals(2, frames[2].n)
        val aliceDhPub = frames[0].dhPub
        for (f in frames) assertArrayEquals(aliceDhPub, f.dhPub)

        // Bob receives frame 2 first → frame 0 + frame 1 keys end up in his table.
        val receiver = RatchetDecryptAndPersist(db, wrapMac, pair.bobFingerprint)
        val r2 = receiver.receive(pair.bobContactId, frames[2]) { plaintext, hex, _, ts ->
            inboundMessage(hex, pair.bobContactId, plaintext, ts)
        }
        assertTrue(r2 is RatchetDecryptAndPersist.Result.Delivered)

        val dao = db.skippedMessageKeyDao()
        assertEquals("frames 0 + 1 stashed as skipped", 2, dao.countForContactBlocking(pair.bobContactId))
        assertNotNull(dao.getWrappedBlocking(pair.bobContactId, aliceDhPub, 0))
        assertNotNull(dao.getWrappedBlocking(pair.bobContactId, aliceDhPub, 1))

        // Simulate FIFO eviction of the oldest entry (frame 0). Cap-driven eviction
        // path is covered by Test 1; here we just need the post-eviction state.
        assertEquals(1, dao.deleteByKeyBlocking(pair.bobContactId, aliceDhPub, 0))
        assertEquals(null, dao.getWrappedBlocking(pair.bobContactId, aliceDhPub, 0))

        // Snapshot Bob's ratchet state so we can verify clone-then-commit on the
        // upcoming AEAD failure.
        val bobBefore = db.contactDao().getById(pair.bobContactId)!!

        // Deliver frame 0 → key was just evicted → AEAD fails. Ratchet rolls back.
        try {
            receiver.receive(pair.bobContactId, frames[0]) { _, _, _, _ ->
                fail("buildInboundMessage must not be called when AEAD fails")
                throw IllegalStateException("unreachable")
            }
            fail("expected RatchetCryptoFailure for evicted-skipped-key frame")
        } catch (_: RatchetCryptoFailure) { /* ok */ }

        val bobAfterFailure = db.contactDao().getById(pair.bobContactId)!!
        assertEquals("nr unchanged after AEAD failure", bobBefore.nr, bobAfterFailure.nr)
        assertEquals("ns unchanged after AEAD failure", bobBefore.ns, bobAfterFailure.ns)
        assertEquals("pn unchanged after AEAD failure", bobBefore.pn, bobAfterFailure.pn)
        assertArrayEquals(bobBefore.rk_wrapped, bobAfterFailure.rk_wrapped)
        assertArrayEquals(bobBefore.rk_hmac, bobAfterFailure.rk_hmac)
        assertArrayEquals(bobBefore.ckr_wrapped, bobAfterFailure.ckr_wrapped)
        assertArrayEquals(bobBefore.dhs_pub, bobAfterFailure.dhs_pub)
        assertArrayEquals(bobBefore.dhr_pub, bobAfterFailure.dhr_pub)
        // Frame 1's skipped row must still be present — failed AEAD on frame 0
        // does not collateral-damage frame 1's stash.
        assertNotNull(dao.getWrappedBlocking(pair.bobContactId, aliceDhPub, 1))

        // Deliver frame 1 → its skipped-key row is intact → succeeds cleanly.
        val r1 = receiver.receive(pair.bobContactId, frames[1]) { plaintext, hex, _, ts ->
            inboundMessage(hex, pair.bobContactId, plaintext, ts)
        }
        assertTrue("frame 1 still decryptable from surviving skipped key", r1 is RatchetDecryptAndPersist.Result.Delivered)
        assertArrayEquals("msg-1".toByteArray(), (r1 as RatchetDecryptAndPersist.Result.Delivered).plaintext)

        // The frame-1 row is consumed-and-deleted by Ratchet.decrypt (skipped fast-path
        // remove). No new skipped rows for the bob contact afterward.
        assertEquals(0, dao.countForContactBlocking(pair.bobContactId))
    }

    // ---------- Fixtures ----------

    /** Minimal contact row to satisfy the FK on `skipped_message_keys.contact_id`. */
    private fun seedBareContact(id: String): String {
        runBlocking {
            db.contactDao().upsert(
                ContactEntity(
                    id = id,
                    name = id,
                    publicKeyBase64 = "",
                    addedAt = 0L
                )
            )
        }
        return id
    }

    private class Pair(
        val aliceContactId: String,
        val bobContactId: String,
        val aliceFingerprint: ByteArray,
        val bobFingerprint: ByteArray,
        val aliceIdPub: ByteArray,
        val bobIdPub: ByteArray,
        val aliceInitial: Bootstrap.InitialState,
        val bobInitial: Bootstrap.InitialState
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
            bobInitial = bBoot
        )
    }

    private fun seedAliceContact(pair: Pair) {
        val initial = ContactEntity(
            id = pair.aliceContactId,
            name = "Bob",
            publicKeyBase64 = android.util.Base64.encodeToString(pair.bobIdPub, android.util.Base64.NO_WRAP),
            addedAt = 0L
        )
        val state = RatchetState.fromBootstrap(pair.aliceInitial)
        val withState = RatchetStatePersistence.saveRatchetState(initial, state, wrapMac)
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

    /** Honest-to-DR2 fake. Identical surface to [PersistenceInvariantsTest]'s. */
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
