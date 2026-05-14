package com.voicedrop.storage

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface MessageDao {
    @Insert
    suspend fun insert(message: MessageEntity)

    @Query("UPDATE messages SET state = :state WHERE uuid = :uuid")
    suspend fun updateState(uuid: String, state: Int)

    @Query("UPDATE messages SET state = :state, sentAt = :sentAt WHERE uuid = :uuid")
    suspend fun updateStateSent(uuid: String, state: Int, sentAt: Long)

    @Query("UPDATE messages SET state = :state, deliveredAt = :deliveredAt WHERE uuid = :uuid")
    suspend fun updateStateDelivered(uuid: String, state: Int, deliveredAt: Long)

    @Query("UPDATE messages SET transcription = :transcription WHERE uuid = :uuid")
    suspend fun updateTranscription(uuid: String, transcription: String)

    @Query("UPDATE messages SET transport = :transport WHERE uuid = :uuid")
    suspend fun updateTransport(uuid: String, transport: TransportType)

    @Query("SELECT * FROM messages WHERE contactId = :contactId ORDER BY createdAt ASC")
    fun getByContact(contactId: String): Flow<List<MessageEntity>>

    @Query("SELECT * FROM messages WHERE scheduledDeleteAt > 0 AND scheduledDeleteAt <= :now AND state != ${MessageEntity.STATE_DELETED}")
    suspend fun getScheduledDeletes(now: Long): List<MessageEntity>

    @Query("UPDATE messages SET state = ${MessageEntity.STATE_DELETED}, encryptedFilePath = NULL WHERE uuid = :uuid")
    suspend fun markDeleted(uuid: String)

    @Query("SELECT * FROM messages WHERE state = ${MessageEntity.STATE_OUTBOX} AND createdAt < :olderThanMs")
    suspend fun getExpiredOutbox(olderThanMs: Long): List<MessageEntity>

    @Query("SELECT * FROM messages WHERE uuid = :uuid")
    suspend fun getByUuid(uuid: String): MessageEntity?

    @Query("SELECT * FROM messages WHERE contactId = :contactId")
    suspend fun getByContactList(contactId: String): List<MessageEntity>
}
