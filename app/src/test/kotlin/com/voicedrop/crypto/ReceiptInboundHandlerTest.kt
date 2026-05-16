package com.voicedrop.crypto

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.ContactEntity
import com.voicedrop.storage.MessageEntity
import com.voicedrop.storage.PendingOutboundFrameEntity
import com.voicedrop.storage.TransportType
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * DR11 §8.7 — `ReceiptInboundHandler` clears the outbox + transitions delivery_state.
 *
 * Robolectric + in-memory Room to exercise the real DAOs and transaction
 * boundary. The handler is opaque to the wrap layer (RECEIPT bodies are already
 * decrypted upstream by [RatchetDecryptAndPersist]) so no [WrapMac] needed here.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class ReceiptInboundHandlerTest {

    private lateinit var db: AppDatabase

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        db = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        ContactMutexRegistry.clear()
    }

    @After
    fun tearDown() {
        db.close()
        ContactMutexRegistry.clear()
    }

    @Test
    fun receipt_clearsOutboxAndMarksDelivered() = runBlocking {
        val contactId = "a".repeat(64)
        val uuid = ByteArray(16) { (it + 1).toByte() }
        val uuidHex = uuid.toHexLower()
        seedContact(contactId)
        seedOutboundMessage(uuid = uuidHex, contactId = contactId, createdAt = 1000L)
        seedOutboxRow(uuid = uuid, contactId = contactId, kind = PendingOutboundFrameEntity.FRAME_KIND_DATA, createdAt = 1000L)

        val events = mutableListOf<String>()
        val handler = ReceiptInboundHandler(db, clock = { 2000L }, eventLog = { events += it })

        val outcome = handler.onReceiptDecrypted(contactId, uuid)

        assertSame(ReceiptInboundHandler.Outcome.Delivered, outcome)
        assertNull("outbox row deleted", db.pendingOutboundFrameDao().getByUuid(uuid))
        val msg = db.messageDao().getByUuid(uuidHex)
        assertNotNull(msg)
        assertEquals(MessageEntity.DELIVERY_DELIVERED, msg!!.delivery_state)
        assertEquals(2000L, msg.deliveredAt)
        assertEquals(1, events.size)
        assertTrue("emits outbox.delivered, was: ${events[0]}", events[0].startsWith("outbox.delivered"))
    }

    @Test
    fun receipt_secondInvocation_isNoOp() = runBlocking {
        val contactId = "b".repeat(64)
        val uuid = ByteArray(16) { (it + 2).toByte() }
        val uuidHex = uuid.toHexLower()
        seedContact(contactId)
        seedOutboundMessage(uuid = uuidHex, contactId = contactId, createdAt = 1000L)
        seedOutboxRow(uuid = uuid, contactId = contactId, kind = PendingOutboundFrameEntity.FRAME_KIND_DATA, createdAt = 1000L)

        val events = mutableListOf<String>()
        val handler = ReceiptInboundHandler(db, clock = { 2000L }, eventLog = { events += it })

        val first = handler.onReceiptDecrypted(contactId, uuid)
        val second = handler.onReceiptDecrypted(contactId, uuid)

        assertSame(ReceiptInboundHandler.Outcome.Delivered, first)
        assertSame(ReceiptInboundHandler.Outcome.NoChange, second)
        // Only one outbox.delivered event — the second pass emits nothing because
        // the outbox row is already gone AND the message is already DELIVERED.
        assertEquals("only first call emits", 1, events.size)
        // deliveredAt did NOT get overwritten by the second pass.
        assertEquals(2000L, db.messageDao().getByUuid(uuidHex)!!.deliveredAt)
    }

    @Test
    fun receipt_noMatchingRows_isNoOp() = runBlocking {
        val contactId = "c".repeat(64)
        seedContact(contactId)
        val phantomUuid = ByteArray(16) { 0x33.toByte() }

        val events = mutableListOf<String>()
        val handler = ReceiptInboundHandler(db, clock = { 4000L }, eventLog = { events += it })

        val outcome = handler.onReceiptDecrypted(contactId, phantomUuid)

        assertSame(ReceiptInboundHandler.Outcome.NoChange, outcome)
        assertTrue("no event emitted", events.isEmpty())
    }

    @Test
    fun receipt_gaveUpMessage_isNotResurrected() = runBlocking {
        // A late RECEIPT arriving after the outbox already gave up must NOT pull
        // the message back to DELIVERED — the `delivery_state = PENDING` guard
        // in markDeliveredBlocking protects this terminal transition.
        val contactId = "d".repeat(64)
        val uuid = ByteArray(16) { (it + 4).toByte() }
        val uuidHex = uuid.toHexLower()
        seedContact(contactId)
        seedOutboundMessage(
            uuid = uuidHex, contactId = contactId, createdAt = 1000L,
            deliveryState = MessageEntity.DELIVERY_GAVE_UP
        )

        val events = mutableListOf<String>()
        val handler = ReceiptInboundHandler(db, clock = { 5000L }, eventLog = { events += it })

        val outcome = handler.onReceiptDecrypted(contactId, uuid)

        assertSame(ReceiptInboundHandler.Outcome.NoChange, outcome)
        assertEquals(
            MessageEntity.DELIVERY_GAVE_UP,
            db.messageDao().getByUuid(uuidHex)!!.delivery_state
        )
    }

    // ---------- helpers ----------

    private suspend fun seedContact(id: String) {
        db.contactDao().upsert(ContactEntity(id = id, name = "x", publicKeyBase64 = "dGVzdA==", addedAt = 0L))
    }

    private fun seedOutboxRow(uuid: ByteArray, contactId: String, kind: Int, createdAt: Long, attempts: Int = 0) {
        db.pendingOutboundFrameDao().insertBlocking(
            PendingOutboundFrameEntity(
                uuid = uuid,
                contact_id = contactId,
                frame_kind = kind,
                wrapped_frame = ByteArray(0),
                frame_hmac = ByteArray(0),
                created_at = createdAt,
                attempts = attempts
            )
        )
    }

    private suspend fun seedOutboundMessage(
        uuid: String,
        contactId: String,
        createdAt: Long,
        deliveryState: Int = MessageEntity.DELIVERY_PENDING
    ) {
        db.messageDao().insert(
            MessageEntity(
                uuid = uuid,
                contactId = contactId,
                direction = MessageEntity.DIRECTION_OUTBOUND,
                state = MessageEntity.STATE_SENT,
                transport = TransportType.UNKNOWN,
                encryptedFilePath = null,
                durationMs = 0,
                deleteAfterMs = 0L,
                scheduledDeleteAt = 0L,
                transcription = null,
                createdAt = createdAt,
                sentAt = createdAt,
                deliveredAt = 0L,
                delivery_state = deliveryState
            )
        )
    }

    private fun ByteArray.toHexLower(): String =
        joinToString("") { "%02x".format(it) }
}
