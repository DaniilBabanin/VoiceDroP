package com.voicedrop.network

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.voicedrop.crypto.WrapHmacMismatch
import com.voicedrop.crypto.WrapMac
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.ContactEntity
import com.voicedrop.storage.MessageEntity
import com.voicedrop.storage.PendingOutboundFrameEntity
import com.voicedrop.storage.TransportType
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicLong
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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * DR11 §8.6 — `PendingOutboxReplay` per-kind clearance & give-up cap behaviour.
 *
 * Verifies the interaction between [com.voicedrop.storage.PendingOutboundFrameDao]
 * and the message-delivery_state pipeline under a real in-memory Room. Wrap layer
 * is exercised via a fake [TestWrapMac] (same shape as DR2 / `PersistenceInvariantsTest`).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class PendingOutboxReplayTest {

    private lateinit var db: AppDatabase
    private lateinit var wrapMac: TestWrapMac

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        db = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        wrapMac = TestWrapMac()
    }

    @After
    fun tearDown() {
        db.close()
    }

    // ---------- happy paths ----------

    @Test
    fun replay_dataSurvivesSuccessfulTransmit() = runBlocking {
        val contactId = "a".repeat(64)
        val uuid = ByteArray(16) { (it + 1).toByte() }
        val plaintext = "data frame".toByteArray()
        seedContact(contactId)
        seedOutboxRow(uuid, contactId, PendingOutboundFrameEntity.FRAME_KIND_DATA, plaintext, now = 0L)

        val transmitted = mutableListOf<Triple<Int, String, ByteArray>>()
        val replay = PendingOutboxReplay(
            db, wrapMac,
            transmit = { kind, cid, bytes -> transmitted += Triple(kind, cid, bytes); true },
            clock = { 1_000L },
            eventLog = {}
        )

        replay.replayAll()

        // DATA stays in the outbox even after a successful transmit — only an
        // authenticated RECEIPT clears it.
        val row = db.pendingOutboundFrameDao().getByUuid(uuid)
        assertNotNull("DATA row remains", row)
        assertEquals(1, row!!.attempts)
        assertEquals(1, transmitted.size)
        val (kind, cid, bytes) = transmitted.single()
        assertEquals(PendingOutboundFrameEntity.FRAME_KIND_DATA, kind)
        assertEquals(contactId, cid)
        assertArrayEquals(plaintext, bytes)
    }

    @Test
    fun replay_receiptDeletedOnSuccessfulTransmit() = runBlocking {
        val contactId = "b".repeat(64)
        val uuid = ByteArray(16) { (it + 2).toByte() }
        seedContact(contactId)
        seedOutboxRow(uuid, contactId, PendingOutboundFrameEntity.FRAME_KIND_RECEIPT, ByteArray(17), now = 0L)

        val replay = PendingOutboxReplay(
            db, wrapMac, transmit = { _, _, _ -> true }, clock = { 1_000L }, eventLog = {}
        )
        replay.replayAll()

        assertNull("RECEIPT row cleared on send-success", db.pendingOutboundFrameDao().getByUuid(uuid))
    }

    @Test
    fun replay_resetDeletedOnSuccessfulTransmit() = runBlocking {
        val contactId = "c".repeat(64)
        val uuid = ByteArray(16) { (it + 3).toByte() }
        seedContact(contactId)
        seedOutboxRow(uuid, contactId, PendingOutboundFrameEntity.FRAME_KIND_RESET, ByteArray(33), now = 0L)

        val replay = PendingOutboxReplay(
            db, wrapMac, transmit = { _, _, _ -> true }, clock = { 1_000L }, eventLog = {}
        )
        replay.replayAll()

        assertNull("RESET row cleared on send-success", db.pendingOutboundFrameDao().getByUuid(uuid))
    }

    @Test
    fun replay_dataFailure_bumpsAttempts_rowStays() = runBlocking {
        val contactId = "d".repeat(64)
        val uuid = ByteArray(16) { (it + 4).toByte() }
        seedContact(contactId)
        seedOutboxRow(uuid, contactId, PendingOutboundFrameEntity.FRAME_KIND_DATA, "x".toByteArray(), now = 0L)

        val replay = PendingOutboxReplay(
            db, wrapMac, transmit = { _, _, _ -> false }, clock = { 1_000L }, eventLog = {}
        )
        replay.replayAll(); replay.replayAll()

        val row = db.pendingOutboundFrameDao().getByUuid(uuid)
        assertNotNull(row)
        assertEquals("attempts bumped twice", 2, row!!.attempts)
    }

    @Test
    fun replay_transmitThrows_treatedAsFailure() = runBlocking {
        val contactId = "e".repeat(64)
        val uuid = ByteArray(16) { (it + 5).toByte() }
        seedContact(contactId)
        seedOutboxRow(uuid, contactId, PendingOutboundFrameEntity.FRAME_KIND_DATA, "x".toByteArray(), now = 0L)

        val replay = PendingOutboxReplay(
            db, wrapMac,
            transmit = { _, _, _ -> throw RuntimeException("connection refused") },
            clock = { 1_000L },
            eventLog = {}
        )
        replay.replayAll()  // must not throw

        val row = db.pendingOutboundFrameDao().getByUuid(uuid)
        assertNotNull(row)
        assertEquals(1, row!!.attempts)
    }

    // ---------- give-up: DATA ----------

    @Test
    fun data_giveUpAfterAttemptCap_deletesRow_marksMessageGaveUp_emitsEvent() = runBlocking {
        val contactId = "f".repeat(64)
        val uuid = ByteArray(16) { (it + 6).toByte() }
        val uuidHex = uuid.toHexLower()
        seedContact(contactId)
        seedOutboundMessage(uuidHex, contactId)
        seedOutboxRow(
            uuid, contactId, PendingOutboundFrameEntity.FRAME_KIND_DATA,
            plaintext = "data".toByteArray(), now = 0L,
            attempts = PendingOutboxReplay.DATA_GIVE_UP_ATTEMPTS
        )

        val events = mutableListOf<String>()
        var transmitCalls = 0
        val replay = PendingOutboxReplay(
            db, wrapMac,
            transmit = { _, _, _ -> transmitCalls++; true },
            clock = { 1_000L },
            eventLog = { events += it }
        )
        replay.replayAll()

        assertEquals("did not retransmit a gave-up row", 0, transmitCalls)
        assertNull(db.pendingOutboundFrameDao().getByUuid(uuid))
        assertEquals(
            MessageEntity.DELIVERY_GAVE_UP,
            db.messageDao().getByUuid(uuidHex)!!.delivery_state
        )
        assertTrue("emits outbox.give_up", events.any { it.startsWith("outbox.give_up") })
    }

    @Test
    fun data_giveUpAfterAgeCap_evenWithLowAttempts() = runBlocking {
        val contactId = "g".repeat(64)
        val uuid = ByteArray(16) { (it + 7).toByte() }
        val uuidHex = uuid.toHexLower()
        seedContact(contactId)
        seedOutboundMessage(uuidHex, contactId)
        seedOutboxRow(
            uuid, contactId, PendingOutboundFrameEntity.FRAME_KIND_DATA,
            plaintext = "data".toByteArray(), now = 0L, attempts = 0
        )

        val now = AtomicLong(PendingOutboxReplay.DATA_GIVE_UP_AGE_MS + 1L)
        val replay = PendingOutboxReplay(
            db, wrapMac, transmit = { _, _, _ -> true }, clock = { now.get() }, eventLog = {}
        )
        replay.replayAll()

        assertNull(db.pendingOutboundFrameDao().getByUuid(uuid))
        assertEquals(
            MessageEntity.DELIVERY_GAVE_UP,
            db.messageDao().getByUuid(uuidHex)!!.delivery_state
        )
    }

    // ---------- give-up: RECEIPT ----------

    @Test
    fun receipt_giveUpAfterAttemptCap_messageStateUnaffected() = runBlocking {
        val contactId = "h".repeat(64)
        val uuid = ByteArray(16) { (it + 8).toByte() }
        seedContact(contactId)
        seedOutboxRow(
            uuid, contactId, PendingOutboundFrameEntity.FRAME_KIND_RECEIPT,
            plaintext = ByteArray(17), now = 0L,
            attempts = PendingOutboxReplay.RECEIPT_GIVE_UP_ATTEMPTS
        )

        val replay = PendingOutboxReplay(
            db, wrapMac, transmit = { _, _, _ -> true }, clock = { 1_000L }, eventLog = {}
        )
        replay.replayAll()

        // Row removed but no message row associated with a RECEIPT (RECEIPT
        // plaintexts are not stored in messages — §8.7). No crash, no markGaveUp.
        assertNull(db.pendingOutboundFrameDao().getByUuid(uuid))
    }

    @Test
    fun receipt_giveUpAfterAgeCap_7d() = runBlocking {
        val contactId = "i".repeat(64)
        val uuid = ByteArray(16) { (it + 9).toByte() }
        seedContact(contactId)
        seedOutboxRow(
            uuid, contactId, PendingOutboundFrameEntity.FRAME_KIND_RECEIPT,
            plaintext = ByteArray(17), now = 0L, attempts = 0
        )

        val replay = PendingOutboxReplay(
            db, wrapMac, transmit = { _, _, _ -> true },
            clock = { PendingOutboxReplay.RECEIPT_GIVE_UP_AGE_MS + 1L },
            eventLog = {}
        )
        replay.replayAll()

        assertNull(db.pendingOutboundFrameDao().getByUuid(uuid))
    }

    // ---------- give-up: RESET ----------

    @Test
    fun reset_giveUpAfter10Min() = runBlocking {
        val contactId = "j".repeat(64)
        val uuid = ByteArray(16) { (it + 10).toByte() }
        seedContact(contactId)
        seedOutboxRow(
            uuid, contactId, PendingOutboundFrameEntity.FRAME_KIND_RESET,
            plaintext = ByteArray(33), now = 0L, attempts = 0
        )

        val replay = PendingOutboxReplay(
            db, wrapMac, transmit = { _, _, _ -> true },
            clock = { PendingOutboxReplay.RESET_GIVE_UP_AGE_MS + 1L },
            eventLog = {}
        )
        replay.replayAll()

        assertNull(db.pendingOutboundFrameDao().getByUuid(uuid))
    }

    @Test
    fun reset_giveUpAfter5Attempts() = runBlocking {
        val contactId = "k".repeat(64)
        val uuid = ByteArray(16) { (it + 11).toByte() }
        seedContact(contactId)
        seedOutboxRow(
            uuid, contactId, PendingOutboundFrameEntity.FRAME_KIND_RESET,
            plaintext = ByteArray(33), now = 0L,
            attempts = PendingOutboxReplay.RESET_GIVE_UP_ATTEMPTS
        )

        val replay = PendingOutboxReplay(
            db, wrapMac, transmit = { _, _, _ -> true }, clock = { 1_000L }, eventLog = {}
        )
        replay.replayAll()

        assertNull(db.pendingOutboundFrameDao().getByUuid(uuid))
    }

    // ---------- tamper signal ----------

    @Test
    fun replay_wrapHmacMismatch_dropsRowAndEmitsEvent() = runBlocking {
        val contactId = "l".repeat(64)
        val uuid = ByteArray(16) { (it + 12).toByte() }
        seedContact(contactId)
        // Wrap with a DIFFERENT WrapMac so the row's HMAC won't verify against `wrapMac`.
        val tamperWrap = TestWrapMac()
        val (wrapped, hmac) = tamperWrap.wrapAndMac(
            "pending_outbound_frames.wrapped_frame", uuid, "data".toByteArray()
        )
        db.pendingOutboundFrameDao().insertBlocking(
            PendingOutboundFrameEntity(
                uuid = uuid,
                contact_id = contactId,
                frame_kind = PendingOutboundFrameEntity.FRAME_KIND_DATA,
                wrapped_frame = wrapped,
                frame_hmac = hmac,
                created_at = 0L,
                attempts = 0
            )
        )

        val events = mutableListOf<String>()
        var transmits = 0
        val replay = PendingOutboxReplay(
            db, wrapMac,
            transmit = { _, _, _ -> transmits++; true },
            clock = { 1_000L },
            eventLog = { events += it }
        )
        replay.replayAll()

        assertFalse("transmit must NOT be called on tampered row", transmits > 0)
        assertNull("tampered row deleted", db.pendingOutboundFrameDao().getByUuid(uuid))
        assertTrue(
            "emits wrap.hmac_mismatch, was: $events",
            events.any { it.startsWith("wrap.hmac_mismatch") }
        )
    }

    // ---------- helpers ----------

    private suspend fun seedContact(id: String) {
        db.contactDao().upsert(ContactEntity(id = id, name = "x", publicKeyBase64 = "dGVzdA==", addedAt = 0L))
    }

    private fun seedOutboxRow(
        uuid: ByteArray,
        contactId: String,
        kind: Int,
        plaintext: ByteArray,
        now: Long,
        attempts: Int = 0
    ) {
        val (wrapped, hmac) = wrapMac.wrapAndMac(
            "pending_outbound_frames.wrapped_frame", uuid, plaintext
        )
        db.pendingOutboundFrameDao().insertBlocking(
            PendingOutboundFrameEntity(
                uuid = uuid,
                contact_id = contactId,
                frame_kind = kind,
                wrapped_frame = wrapped,
                frame_hmac = hmac,
                created_at = now,
                attempts = attempts
            )
        )
    }

    private suspend fun seedOutboundMessage(
        uuidHex: String,
        contactId: String,
        deliveryState: Int = MessageEntity.DELIVERY_PENDING
    ) {
        db.messageDao().insert(
            MessageEntity(
                uuid = uuidHex,
                contactId = contactId,
                direction = MessageEntity.DIRECTION_OUTBOUND,
                state = MessageEntity.STATE_SENT,
                transport = TransportType.UNKNOWN,
                encryptedFilePath = null,
                durationMs = 0,
                deleteAfterMs = 0L,
                scheduledDeleteAt = 0L,
                transcription = null,
                createdAt = 0L,
                sentAt = 0L,
                deliveredAt = 0L,
                delivery_state = deliveryState
            )
        )
    }

    private fun ByteArray.toHexLower(): String =
        joinToString("") { "%02x".format(it) }

    /**
     * Honest-to-DR2 fake WrapMac: AES-GCM `[iv:12 || ct || tag:16]` + HMAC-SHA256
     * binding over `column || 0x00 || rowId || 0x00 || wrapped`. Two instances
     * use independently-generated keys, so a row wrapped under instance A fails
     * verification under instance B — useful for the tamper test.
     */
    private class TestWrapMac : WrapMac {
        private val wrapKey: SecretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        private val macKey: SecretKey = SecretKeySpec(ByteArray(32).also { SecureRandom().nextBytes(it) }, "HmacSHA256")

        override fun wrapAndMac(columnName: String, rowId: ByteArray, plain: ByteArray): Pair<ByteArray, ByteArray> {
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
