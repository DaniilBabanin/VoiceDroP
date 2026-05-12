package com.voicedrop.storage

import kotlinx.coroutines.flow.Flow

class MessageRepository(
    private val contactDao: ContactDao,
    private val messageDao: MessageDao,
    private val pendingActionDao: PendingActionDao
) {
    // Contacts
    fun getAllContacts(): Flow<List<ContactEntity>> = contactDao.getAll()

    suspend fun getContact(id: String): ContactEntity? = contactDao.getById(id)

    suspend fun upsertContact(contact: ContactEntity) = contactDao.upsert(contact)

    suspend fun deleteContact(contact: ContactEntity) = contactDao.delete(contact)

    // Messages
    fun getMessages(contactId: String): Flow<List<MessageEntity>> =
        messageDao.getByContact(contactId)

    suspend fun insertMessage(message: MessageEntity) = messageDao.insert(message)

    suspend fun updateMessageState(uuid: String, state: Int) =
        messageDao.updateState(uuid, state)

    suspend fun updateMessageStateSent(uuid: String, state: Int, sentAt: Long) =
        messageDao.updateStateSent(uuid, state, sentAt)

    suspend fun updateMessageStateDelivered(uuid: String, state: Int, deliveredAt: Long) =
        messageDao.updateStateDelivered(uuid, state, deliveredAt)

    suspend fun updateTranscription(uuid: String, transcription: String) =
        messageDao.updateTranscription(uuid, transcription)

    suspend fun updateTransport(uuid: String, transport: Int) =
        messageDao.updateTransport(uuid, transport)

    suspend fun markDeleted(uuid: String) = messageDao.markDeleted(uuid)

    suspend fun getMessage(uuid: String): MessageEntity? = messageDao.getByUuid(uuid)

    suspend fun getScheduledDeletes(now: Long): List<MessageEntity> =
        messageDao.getScheduledDeletes(now)

    suspend fun getExpiredOutbox(olderThanMs: Long): List<MessageEntity> =
        messageDao.getExpiredOutbox(olderThanMs)

    // Pending actions
    suspend fun insertPendingAction(action: PendingActionEntity): Long =
        pendingActionDao.insert(action)

    suspend fun deletePendingAction(id: Long) = pendingActionDao.deleteById(id)

    suspend fun getPendingActionsForContact(contactId: String): List<PendingActionEntity> =
        pendingActionDao.getByContact(contactId)

    suspend fun getAllPendingActions(): List<PendingActionEntity> =
        pendingActionDao.getAll()

    suspend fun getExpiredPendingActions(olderThanMs: Long): List<PendingActionEntity> =
        pendingActionDao.getExpired(olderThanMs)

    suspend fun incrementRetryCount(id: Long) = pendingActionDao.incrementRetry(id)
}
