package com.voicedrop.storage

import kotlinx.coroutines.flow.Flow
import java.io.File

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

    suspend fun updateTransport(uuid: String, transport: TransportType) =
        messageDao.updateTransport(uuid, transport)

    suspend fun updateWaveformPeaks(uuid: String, peaks: ByteArray): Int =
        messageDao.updateWaveformPeaks(uuid, peaks)

    suspend fun markDeleted(uuid: String) = messageDao.markDeleted(uuid)

    suspend fun getMessage(uuid: String): MessageEntity? = messageDao.getByUuid(uuid)

    suspend fun getMessagesForContact(contactId: String): List<MessageEntity> =
        messageDao.getByContactList(contactId)

    suspend fun getScheduledDeletes(now: Long): List<MessageEntity> =
        messageDao.getScheduledDeletes(now)

    suspend fun getExpiredOutbox(olderThanMs: Long): List<MessageEntity> =
        messageDao.getExpiredOutbox(olderThanMs)

    /**
     * Hard-delete a message row and, if no other row references the same
     * on-disk opus file, secure-delete the file. The refcount makes fan-out
     * safe: N rows can share one file; only the last delete removes the bytes.
     */
    suspend fun deleteMessageWithBlobCleanup(message: MessageEntity) {
        val path = message.encryptedFilePath
        messageDao.deleteByUuid(message.uuid)
        if (path != null) {
            val remaining = messageDao.countByEncryptedFilePath(path)
            if (remaining == 0) secureDeleteFile(File(path))
        }
    }

    /**
     * Used by the contact-delete cascade: enumerate every message row for the
     * contact and hard-delete each via [deleteMessageWithBlobCleanup] so any
     * fanned-out opus files referenced by another contact's row are preserved.
     */
    suspend fun deleteAllMessagesForContactWithBlobCleanup(contactId: String) {
        val messages = messageDao.getByContactList(contactId)
        for (m in messages) deleteMessageWithBlobCleanup(m)
    }

    /**
     * Soft-delete a single message row (sets STATE_DELETED, nulls path) and,
     * if no other row still references the same on-disk opus file, secure-wipe
     * the file. Refcount-safe replacement for the bare `secureDelete(file)` +
     * `markDeleted(uuid)` pair used by per-message deletes (notification swipe,
     * scheduled auto-delete) — without this, a fanned-out blob shared by N
     * recipients would be wiped on the first recipient's delete, breaking
     * playback for the rest.
     */
    suspend fun markDeletedWithBlobRefcount(message: MessageEntity) {
        val path = message.encryptedFilePath
        messageDao.markDeleted(message.uuid)
        if (path != null) {
            val remaining = messageDao.countByEncryptedFilePath(path)
            if (remaining == 0) secureDeleteFile(File(path))
        }
    }

    private fun secureDeleteFile(file: File) {
        if (!file.exists()) return
        try {
            val length = file.length()
            if (length > 0) {
                file.outputStream().use { out ->
                    val zeros = ByteArray(minOf(length, 65536).toInt())
                    var remaining = length
                    while (remaining > 0) {
                        val toWrite = minOf(remaining, zeros.size.toLong()).toInt()
                        out.write(zeros, 0, toWrite)
                        remaining -= toWrite
                    }
                }
            }
        } finally {
            file.delete()
        }
    }

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
