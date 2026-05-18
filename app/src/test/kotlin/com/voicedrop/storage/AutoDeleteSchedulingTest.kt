package com.voicedrop.storage

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class AutoDeleteSchedulingTest {

    private lateinit var db: AppDatabase
    private lateinit var repository: MessageRepository

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        db = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        repository = MessageRepository(db.contactDao(), db.messageDao(), db.pendingActionDao())
    }

    @After
    fun tearDown() {
        db.close()
    }

    private fun contact(id: String, autoDeleteAfterMs: Long = 0L) = ContactEntity(
        id = id,
        name = "Test $id",
        publicKeyBase64 = "dGVzdA==",
        addedAt = 0L,
        autoDeleteAfterMs = autoDeleteAfterMs
    )

    private fun message(
        uuid: String,
        contactId: String,
        state: Int = MessageEntity.STATE_DELIVERED,
        createdAt: Long = 0L,
        deleteAfterMs: Long = 0L,
        scheduledDeleteAt: Long = 0L
    ) = MessageEntity(
        uuid = uuid,
        contactId = contactId,
        direction = MessageEntity.DIRECTION_INBOUND,
        state = state,
        transport = TransportType.UNKNOWN,
        encryptedFilePath = null,
        durationMs = 0,
        deleteAfterMs = deleteAfterMs,
        scheduledDeleteAt = scheduledDeleteAt,
        transcription = null,
        createdAt = createdAt,
        sentAt = 0L,
        deliveredAt = 0L
    )

    @Test
    fun scheduledDeleteAt_persistsAsCreatedAtPlusDeleteAfterMs() = runBlocking {
        val contactId = "a".repeat(64)
        val autoDelete = 60_000L
        repository.upsertContact(contact(contactId, autoDeleteAfterMs = autoDelete))

        val now = 1_000_000L
        repository.insertMessage(
            message(
                uuid = "scheduled-msg",
                contactId = contactId,
                createdAt = now,
                deleteAfterMs = autoDelete,
                scheduledDeleteAt = now + autoDelete
            )
        )

        val stored = repository.getMessage("scheduled-msg")
        assertNotNull(stored)
        assertEquals(autoDelete, stored!!.deleteAfterMs)
        assertEquals(now + autoDelete, stored.scheduledDeleteAt)
    }

    @Test
    fun getScheduledDeletes_returnsOnlyOverdueRows() = runBlocking {
        val contactId = "b".repeat(64)
        repository.upsertContact(contact(contactId, autoDeleteAfterMs = 60_000L))

        val now = 1_000_000L
        repository.insertMessage(
            message(uuid = "overdue", contactId = contactId, scheduledDeleteAt = now - 1)
        )
        repository.insertMessage(
            message(uuid = "due-now", contactId = contactId, scheduledDeleteAt = now)
        )
        repository.insertMessage(
            message(uuid = "future", contactId = contactId, scheduledDeleteAt = now + 60_000L)
        )
        repository.insertMessage(
            message(uuid = "no-schedule", contactId = contactId, scheduledDeleteAt = 0L)
        )

        val overdue = repository.getScheduledDeletes(now).map { it.uuid }.toSet()
        assertEquals(setOf("overdue", "due-now"), overdue)
    }

    @Test
    fun getScheduledDeletes_excludesAlreadyDeletedMessages() = runBlocking {
        val contactId = "c".repeat(64)
        repository.upsertContact(contact(contactId))

        val now = 1_000_000L
        repository.insertMessage(
            message(
                uuid = "already-deleted",
                contactId = contactId,
                state = MessageEntity.STATE_DELETED,
                scheduledDeleteAt = now - 1
            )
        )
        repository.insertMessage(
            message(
                uuid = "still-alive",
                contactId = contactId,
                state = MessageEntity.STATE_DELIVERED,
                scheduledDeleteAt = now - 1
            )
        )

        val overdue = repository.getScheduledDeletes(now).map { it.uuid }
        assertEquals(listOf("still-alive"), overdue)
    }

    @Test
    fun outboxExpiry_transitionsOldOutboxToUndeliverable() = runBlocking {
        val contactId = "d".repeat(64)
        repository.upsertContact(contact(contactId))

        val sevenDaysMs = 7L * 24 * 60 * 60 * 1000
        val now = 100L * sevenDaysMs
        val cutoff = now - sevenDaysMs

        repository.insertMessage(
            message(
                uuid = "old-outbox",
                contactId = contactId,
                state = MessageEntity.STATE_OUTBOX,
                createdAt = cutoff - 1
            )
        )
        repository.insertMessage(
            message(
                uuid = "fresh-outbox",
                contactId = contactId,
                state = MessageEntity.STATE_OUTBOX,
                createdAt = cutoff + 1
            )
        )
        repository.insertMessage(
            message(
                uuid = "old-sent",
                contactId = contactId,
                state = MessageEntity.STATE_SENT,
                createdAt = cutoff - 1
            )
        )

        val expired = repository.getExpiredOutbox(cutoff).map { it.uuid }
        assertEquals(listOf("old-outbox"), expired)

        for (m in expired) {
            repository.updateMessageState(m, MessageEntity.STATE_UNDELIVERABLE)
        }

        assertEquals(MessageEntity.STATE_UNDELIVERABLE, repository.getMessage("old-outbox")!!.state)
        assertEquals(MessageEntity.STATE_OUTBOX, repository.getMessage("fresh-outbox")!!.state)
        assertEquals(MessageEntity.STATE_SENT, repository.getMessage("old-sent")!!.state)
    }
}
