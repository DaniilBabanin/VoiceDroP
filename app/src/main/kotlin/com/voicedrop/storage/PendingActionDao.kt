package com.voicedrop.storage

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query

@Dao
interface PendingActionDao {
    @Insert
    suspend fun insert(action: PendingActionEntity): Long

    @Query("DELETE FROM pending_actions WHERE id = :id")
    suspend fun deleteById(id: Long)

    @Query("SELECT * FROM pending_actions WHERE contactId = :contactId ORDER BY createdAt ASC")
    suspend fun getByContact(contactId: String): List<PendingActionEntity>

    @Query("SELECT * FROM pending_actions ORDER BY createdAt ASC")
    suspend fun getAll(): List<PendingActionEntity>

    @Query("SELECT * FROM pending_actions WHERE createdAt < :olderThanMs ORDER BY createdAt ASC")
    suspend fun getExpired(olderThanMs: Long): List<PendingActionEntity>

    @Query("UPDATE pending_actions SET retryCount = retryCount + 1 WHERE id = :id")
    suspend fun incrementRetry(id: Long)
}
