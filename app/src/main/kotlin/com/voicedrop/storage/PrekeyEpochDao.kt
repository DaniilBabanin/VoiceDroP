package com.voicedrop.storage

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import androidx.room.Update

@Dao
interface PrekeyEpochDao {

    @Insert
    suspend fun insert(row: PrekeyEpochEntity)

    @Insert
    fun insertBlocking(row: PrekeyEpochEntity)

    @Update
    suspend fun update(row: PrekeyEpochEntity)

    @Query("SELECT * FROM prekey_epochs WHERE contact_id = :contactId AND status = :status LIMIT 1")
    suspend fun byStatus(contactId: String, status: String): PrekeyEpochEntity?

    @Query("SELECT * FROM prekey_epochs WHERE contact_id = :contactId AND status = :status LIMIT 1")
    fun byStatusBlocking(contactId: String, status: String): PrekeyEpochEntity?

    @Query("SELECT * FROM prekey_epochs WHERE contact_id = :contactId AND epoch = :epoch")
    suspend fun byEpoch(contactId: String, epoch: Int): PrekeyEpochEntity?

    @Query("DELETE FROM prekey_epochs WHERE contact_id = :contactId AND epoch = :epoch")
    suspend fun deleteEpoch(contactId: String, epoch: Int)

    @Query("DELETE FROM prekey_epochs WHERE status = 'previous' AND expires_at IS NOT NULL AND expires_at < :now")
    suspend fun sweepExpiredPrevious(now: Long): Int

    @Query("SELECT * FROM prekey_epochs WHERE contact_id = :contactId ORDER BY epoch ASC")
    suspend fun all(contactId: String): List<PrekeyEpochEntity>
}
