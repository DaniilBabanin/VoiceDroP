package com.voicedrop.storage

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Phase B (Finding #2) — schema + DAO contract for the new `acked_uuid` outbox
 * column and the `messages.receipt_resends` counter. Pure storage-layer test;
 * no ratchet crypto involved.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class OutboxSchemaDaoTest {

    private lateinit var db: AppDatabase

    @Before
    fun setUp() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        db = Room.inMemoryDatabaseBuilder(ctx, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
    }

    @After
    fun tearDown() = db.close()

    private fun seedContact(id: String) = runBlocking {
        db.contactDao().upsert(
            ContactEntity(
                id = id,
                name = "peer",
                publicKeyBase64 = "AAAA",
                addedAt = 0L
            )
        )
    }

    private fun receiptRow(uuid: ByteArray, contactId: String, ackedUuid: ByteArray?) =
        PendingOutboundFrameEntity(
            uuid = uuid,
            contact_id = contactId,
            frame_kind = PendingOutboundFrameEntity.FRAME_KIND_RECEIPT,
            wrapped_frame = ByteArray(8),
            frame_hmac = ByteArray(8),
            created_at = 1L,
            attempts = 0,
            acked_uuid = ackedUuid
        )

    @Test
    fun existsPendingReceiptForAcked_trueOnlyWhenReceiptWithThatAckedUuidPresent() = runBlocking {
        seedContact("c1")
        seedContact("c2")
        val acked = ByteArray(16) { 0x11 }
        val other = ByteArray(16) { 0x22 }
        val dao = db.pendingOutboundFrameDao()

        assertFalse(dao.existsPendingReceiptForAckedBlocking("c1", acked))

        dao.insertBlocking(receiptRow(ByteArray(16) { 0xA1.toByte() }, "c1", acked))
        assertTrue(dao.existsPendingReceiptForAckedBlocking("c1", acked))
        assertFalse("different acked uuid does not match", dao.existsPendingReceiptForAckedBlocking("c1", other))
        assertFalse("different contact does not match", dao.existsPendingReceiptForAckedBlocking("c2", acked))
    }

    @Test
    fun countPendingReceiptsForContact_countsOnlyReceiptRows() = runBlocking {
        seedContact("c1")
        seedContact("c2")
        val dao = db.pendingOutboundFrameDao()
        dao.insertBlocking(receiptRow(ByteArray(16) { 0x01 }, "c1", ByteArray(16) { 0x01 }))
        dao.insertBlocking(receiptRow(ByteArray(16) { 0x02 }, "c1", ByteArray(16) { 0x02 }))
        // a DATA row (acked_uuid null) must NOT be counted
        dao.insertBlocking(
            PendingOutboundFrameEntity(
                uuid = ByteArray(16) { 0x03 },
                contact_id = "c1",
                frame_kind = PendingOutboundFrameEntity.FRAME_KIND_DATA,
                wrapped_frame = ByteArray(8),
                frame_hmac = ByteArray(8),
                created_at = 1L,
                acked_uuid = null
            )
        )
        // a RECEIPT for a DIFFERENT contact must NOT be counted (contact_id scoping)
        dao.insertBlocking(receiptRow(ByteArray(16) { 0x04 }, "c2", ByteArray(16) { 0x04 }))
        assertEquals(2, dao.countPendingReceiptsForContactBlocking("c1"))
        assertEquals(1, dao.countPendingReceiptsForContactBlocking("c2"))
    }

    @Test
    fun receiptResends_defaultsZero_andIncrements() = runBlocking {
        seedContact("c1")
        val mdao = db.messageDao()
        mdao.insert(
            MessageEntity(
                uuid = "msg-1",
                contactId = "c1",
                direction = MessageEntity.DIRECTION_INBOUND,
                state = MessageEntity.STATE_DELIVERED,
                transport = TransportType.UNKNOWN,
                encryptedFilePath = null,
                durationMs = 0,
                deleteAfterMs = 0L,
                scheduledDeleteAt = 0L,
                transcription = null,
                createdAt = 0L,
                sentAt = 0L,
                deliveredAt = 0L
            )
        )
        assertEquals(0, mdao.getReceiptResendsBlocking("msg-1"))
        assertEquals(1, mdao.incrementReceiptResendsBlocking("msg-1"))
        assertEquals(1, mdao.getReceiptResendsBlocking("msg-1"))
        mdao.incrementReceiptResendsBlocking("msg-1")
        assertEquals(2, mdao.getReceiptResendsBlocking("msg-1"))
    }
}
