package com.voicedrop.storage

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.Query
import androidx.room.Update

/**
 * Outbox DAO. The encrypt path ([dr7]) inserts; the replay worker ([dr11])
 * reads, increments `attempts`, and deletes on RECEIPT.
 *
 * `attempts` increments are owned by the replay worker, not by encrypt — a row
 * is born with `attempts=0` and stays until a RECEIPT lands or per-kind give-up
 * caps fire ([dr11] §6.6).
 */
@Dao
interface PendingOutboundFrameDao {

    @Insert
    suspend fun insert(row: PendingOutboundFrameEntity)

    @Insert
    fun insertBlocking(row: PendingOutboundFrameEntity)

    @Update
    suspend fun update(row: PendingOutboundFrameEntity)

    @Delete
    suspend fun delete(row: PendingOutboundFrameEntity)

    @Query("DELETE FROM pending_outbound_frames WHERE uuid = :uuid")
    suspend fun deleteByUuid(uuid: ByteArray)

    @Query("SELECT * FROM pending_outbound_frames WHERE uuid = :uuid LIMIT 1")
    suspend fun getByUuid(uuid: ByteArray): PendingOutboundFrameEntity?

    @Query("SELECT * FROM pending_outbound_frames WHERE contact_id = :contactId ORDER BY created_at ASC")
    suspend fun getByContact(contactId: String): List<PendingOutboundFrameEntity>

    @Query("SELECT * FROM pending_outbound_frames ORDER BY created_at ASC")
    suspend fun getAll(): List<PendingOutboundFrameEntity>

    @Query("SELECT COUNT(*) FROM pending_outbound_frames WHERE contact_id = :contactId")
    suspend fun countForContact(contactId: String): Int
}
