package com.voicedrop.storage

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.flow.first
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
class MessageRepositoryTest {

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

    private fun contact(id: String, name: String) = ContactEntity(
        id = id,
        name = name,
        publicKeyBase64 = "dGVzdA==",
        sharedSecretWrapped = ByteArray(0),
        addedAt = System.currentTimeMillis()
        // autoDeleteAfterMs defaults to 0L
    )

    private fun message(uuid: String, contactId: String, direction: Int = MessageEntity.DIRECTION_INBOUND) =
        MessageEntity(
            uuid = uuid,
            contactId = contactId,
            direction = direction,
            state = MessageEntity.STATE_OUTBOX,
            transport = TransportType.UNKNOWN,
            encryptedFilePath = null,
            durationMs = 0,
            deleteAfterMs = 0L,
            scheduledDeleteAt = 0L,
            transcription = null,
            createdAt = System.currentTimeMillis(),
            sentAt = 0L,
            deliveredAt = 0L
        )

    @Test
    fun insertAndRetrieveContact() = runBlocking {
        repository.upsertContact(contact("a".repeat(64), "Alice"))
        val contacts = repository.getAllContacts().first()
        assertEquals(1, contacts.size)
        assertEquals("Alice", contacts[0].name)
    }

    @Test
    fun insertAndQueryMessage() = runBlocking {
        repository.upsertContact(contact("b".repeat(64), "Bob"))
        repository.insertMessage(message("test-uuid-1234", "b".repeat(64)))
        val messages = repository.getMessages("b".repeat(64)).first()
        assertEquals(1, messages.size)
        assertEquals("test-uuid-1234", messages[0].uuid)
    }

    @Test
    fun updateMessageState() = runBlocking {
        repository.upsertContact(contact("c".repeat(64), "Charlie"))
        repository.insertMessage(message("state-uuid", "c".repeat(64), MessageEntity.DIRECTION_OUTBOUND))
        repository.updateMessageState("state-uuid", MessageEntity.STATE_SENT)
        val messages = repository.getMessages("c".repeat(64)).first()
        assertEquals(MessageEntity.STATE_SENT, messages[0].state)
    }

    @Test
    fun deleteContactCascadesMessages() = runBlocking {
        val c = contact("d".repeat(64), "Dave")
        repository.upsertContact(c)
        repeat(3) { i -> repository.insertMessage(message("msg-$i", c.id)) }
        repository.deleteContact(c)
        val messages = repository.getMessages(c.id).first()
        assertTrue(messages.isEmpty())
    }

    @Test
    fun getMessageByUuid() = runBlocking {
        repository.upsertContact(contact("e".repeat(64), "Eve"))
        repository.insertMessage(message("find-this-uuid", "e".repeat(64)))
        val found = repository.getMessage("find-this-uuid")
        assertNotNull(found)
        assertEquals("find-this-uuid", found!!.uuid)
    }
}
