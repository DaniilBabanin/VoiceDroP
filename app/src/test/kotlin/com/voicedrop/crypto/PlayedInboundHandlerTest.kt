package com.voicedrop.crypto

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.ContactEntity
import com.voicedrop.storage.MessageEntity
import com.voicedrop.storage.TransportType
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Spec `16-played-receipt.md` §2 — `PlayedInboundHandler` flips outbound rows
 * to STATE_PLAYED on incoming KIND_PLAYED frames. Robolectric + in-memory Room
 * exercises the real DAO + transaction boundary. Mirrors [ReceiptInboundHandlerTest].
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class PlayedInboundHandlerTest {

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
    fun delivered_to_played_flips_state() = runBlocking {
        val contactId = "a".repeat(64)
        val (hex32, uuid) = uuidPair(0x11)
        seedContact(contactId)
        seedOutboundMessage(uuid = hex32, contactId = contactId, state = MessageEntity.STATE_DELIVERED, deliveredAt = 1500L)

        val events = mutableListOf<String>()
        val handler = PlayedInboundHandler(db, clock = { 2000L }, eventLog = { events += it })

        val outcome = handler.onPlayedDecrypted(contactId, uuid)

        assertSame(PlayedInboundHandler.Outcome.Played, outcome)
        val row = db.messageDao().getByUuid(hex32)!!
        assertEquals(MessageEntity.STATE_PLAYED, row.state)
        assertEquals("deliveredAt preserved", 1500L, row.deliveredAt)
        assertEquals(1, events.size)
        assertTrue("emits played.applied, was: ${events[0]}", events[0].startsWith("played.applied"))
    }

    @Test
    fun sent_to_played_flips_state_and_backfills_deliveredAt() = runBlocking {
        val contactId = "b".repeat(64)
        val (hex32, uuid) = uuidPair(0x22)
        seedContact(contactId)
        seedOutboundMessage(uuid = hex32, contactId = contactId, state = MessageEntity.STATE_SENT, deliveredAt = 0L)

        val handler = PlayedInboundHandler(db, clock = { 3000L })
        val outcome = handler.onPlayedDecrypted(contactId, uuid)

        assertSame(PlayedInboundHandler.Outcome.Played, outcome)
        val row = db.messageDao().getByUuid(hex32)!!
        assertEquals(MessageEntity.STATE_PLAYED, row.state)
        assertEquals("deliveredAt backfilled", 3000L, row.deliveredAt)
    }

    @Test
    fun played_to_played_is_noop_returns_NoChange() = runBlocking {
        val contactId = "c".repeat(64)
        val (hex32, uuid) = uuidPair(0x33)
        seedContact(contactId)
        seedOutboundMessage(uuid = hex32, contactId = contactId, state = MessageEntity.STATE_PLAYED, deliveredAt = 1500L)

        val handler = PlayedInboundHandler(db, clock = { 4000L })
        val outcome = handler.onPlayedDecrypted(contactId, uuid)

        assertSame(PlayedInboundHandler.Outcome.NoChange, outcome)
        assertEquals(MessageEntity.STATE_PLAYED, db.messageDao().getByUuid(hex32)!!.state)
    }

    @Test
    fun deleted_stays_deleted() = runBlocking {
        val contactId = "d".repeat(64)
        val (hex32, uuid) = uuidPair(0x44)
        seedContact(contactId)
        seedOutboundMessage(uuid = hex32, contactId = contactId, state = MessageEntity.STATE_DELETED, deliveredAt = 1500L)

        val handler = PlayedInboundHandler(db, clock = { 5000L })
        val outcome = handler.onPlayedDecrypted(contactId, uuid)

        assertSame(PlayedInboundHandler.Outcome.NoChange, outcome)
        assertEquals(MessageEntity.STATE_DELETED, db.messageDao().getByUuid(hex32)!!.state)
    }

    @Test
    fun undeliverable_stays_undeliverable() = runBlocking {
        val contactId = "e".repeat(64)
        val (hex32, uuid) = uuidPair(0x55)
        seedContact(contactId)
        seedOutboundMessage(uuid = hex32, contactId = contactId, state = MessageEntity.STATE_UNDELIVERABLE, deliveredAt = 0L)

        val handler = PlayedInboundHandler(db, clock = { 6000L })
        val outcome = handler.onPlayedDecrypted(contactId, uuid)

        assertSame(PlayedInboundHandler.Outcome.NoChange, outcome)
        assertEquals(MessageEntity.STATE_UNDELIVERABLE, db.messageDao().getByUuid(hex32)!!.state)
    }

    @Test
    fun outbox_stays_outbox() = runBlocking {
        val contactId = "f".repeat(64)
        val (hex32, uuid) = uuidPair(0x66)
        seedContact(contactId)
        seedOutboundMessage(uuid = hex32, contactId = contactId, state = MessageEntity.STATE_OUTBOX, deliveredAt = 0L)

        val handler = PlayedInboundHandler(db, clock = { 7000L })
        val outcome = handler.onPlayedDecrypted(contactId, uuid)

        assertSame(PlayedInboundHandler.Outcome.NoChange, outcome)
        assertEquals(MessageEntity.STATE_OUTBOX, db.messageDao().getByUuid(hex32)!!.state)
    }

    @Test
    fun wrong_contactId_is_noop() = runBlocking {
        val rightContact = "1".repeat(64)
        val wrongContact = "2".repeat(64)
        val (hex32, uuid) = uuidPair(0x77)
        seedContact(rightContact); seedContact(wrongContact)
        seedOutboundMessage(uuid = hex32, contactId = rightContact, state = MessageEntity.STATE_DELIVERED, deliveredAt = 1500L)

        val handler = PlayedInboundHandler(db, clock = { 8000L })
        val outcome = handler.onPlayedDecrypted(wrongContact, uuid)

        assertSame(PlayedInboundHandler.Outcome.NoChange, outcome)
        assertEquals("state untouched", MessageEntity.STATE_DELIVERED, db.messageDao().getByUuid(hex32)!!.state)
    }

    @Test
    fun inbound_row_is_noop() = runBlocking {
        // A KIND_PLAYED frame targeting an inbound row (our own received voice)
        // should never happen, but if it does it must not flip state. Use the
        // dashed-UUID form here because inbound rows store uuid in that shape;
        // the handler should still no-op due to the `direction = OUTBOUND` guard.
        val contactId = "3".repeat(64)
        val (hex32, uuid) = uuidPair(0x88.toByte())
        val inboundUuidStr = uuid.toString()   // dashed form (matches inbound-row format)
        seedContact(contactId)
        db.messageDao().insert(MessageEntity(
            uuid = inboundUuidStr, contactId = contactId,
            direction = MessageEntity.DIRECTION_INBOUND,
            state = MessageEntity.STATE_DELIVERED,
            transport = TransportType.UNKNOWN,
            encryptedFilePath = null, durationMs = 0, deleteAfterMs = 0L,
            scheduledDeleteAt = 0L, transcription = null,
            createdAt = 1000L, sentAt = 0L, deliveredAt = 1500L,
        ))

        val handler = PlayedInboundHandler(db, clock = { 9000L })
        val outcome = handler.onPlayedDecrypted(contactId, uuid)

        assertSame(PlayedInboundHandler.Outcome.NoChange, outcome)
        // No outbound row exists with `hex32` either — handler matches zero rows.
        assertEquals(MessageEntity.STATE_DELIVERED, db.messageDao().getByUuid(inboundUuidStr)!!.state)
    }

    @Test
    fun duplicate_played_under_mutex_is_idempotent() = runBlocking {
        val contactId = "4".repeat(64)
        val (hex32, uuid) = uuidPair(0x99.toByte())
        seedContact(contactId)
        seedOutboundMessage(uuid = hex32, contactId = contactId, state = MessageEntity.STATE_DELIVERED, deliveredAt = 1500L)

        val events = mutableListOf<String>()
        val handler = PlayedInboundHandler(db, clock = { 10_000L }, eventLog = { events += it })

        val first = handler.onPlayedDecrypted(contactId, uuid)
        val second = handler.onPlayedDecrypted(contactId, uuid)

        assertSame(PlayedInboundHandler.Outcome.Played, first)
        assertSame(PlayedInboundHandler.Outcome.NoChange, second)
        assertEquals(MessageEntity.STATE_PLAYED, db.messageDao().getByUuid(hex32)!!.state)
        assertEquals("second pass emits nothing", 1, events.size)
    }

    // ---------- helpers ----------

    /**
     * Generate a matched (32-char hex, java.util.UUID) pair from a single byte
     * filler. Mirrors how the wire path produces both forms from the same 16
     * source bytes: outbound rows store the hex form (MultiRecipientSender.kt:85),
     * inbound rows store the dashed form (ConnectionManager.kt:553).
     */
    private fun uuidPair(filler: Byte): Pair<String, java.util.UUID> {
        val bytes = ByteArray(16) { filler }
        val hex32 = bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }
        val bb = java.nio.ByteBuffer.wrap(bytes)
        val uuid = java.util.UUID(bb.long, bb.long)
        return hex32 to uuid
    }

    private suspend fun seedContact(id: String) {
        db.contactDao().upsert(ContactEntity(id = id, name = "x", publicKeyBase64 = "dGVzdA==", addedAt = 0L))
    }

    private suspend fun seedOutboundMessage(
        uuid: String,
        contactId: String,
        state: Int,
        deliveredAt: Long
    ) {
        db.messageDao().insert(MessageEntity(
            uuid = uuid, contactId = contactId,
            direction = MessageEntity.DIRECTION_OUTBOUND,
            state = state,
            transport = TransportType.UNKNOWN,
            encryptedFilePath = null, durationMs = 0, deleteAfterMs = 0L,
            scheduledDeleteAt = 0L, transcription = null,
            createdAt = 1000L, sentAt = 1000L, deliveredAt = deliveredAt,
        ))
    }
}
