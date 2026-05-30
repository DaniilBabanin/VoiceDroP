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

    /**
     * Blocking variant used from inside `runInTransaction(Callable {...})`:
     *   - [dr11] RECEIPT inbound handler ([com.voicedrop.crypto.ReceiptInboundHandler]),
     *     where deleteByUuid + markDeliveredBlocking on `messages` must commit atomically.
     */
    @Query("DELETE FROM pending_outbound_frames WHERE uuid = :uuid")
    fun deleteByUuidBlocking(uuid: ByteArray): Int

    @Query("UPDATE pending_outbound_frames SET attempts = attempts + 1 WHERE uuid = :uuid")
    fun incrementAttemptsBlocking(uuid: ByteArray): Int

    @Query("SELECT * FROM pending_outbound_frames WHERE uuid = :uuid LIMIT 1")
    suspend fun getByUuid(uuid: ByteArray): PendingOutboundFrameEntity?

    @Query("SELECT * FROM pending_outbound_frames WHERE contact_id = :contactId ORDER BY created_at ASC")
    suspend fun getByContact(contactId: String): List<PendingOutboundFrameEntity>

    @Query("SELECT * FROM pending_outbound_frames ORDER BY created_at ASC")
    suspend fun getAll(): List<PendingOutboundFrameEntity>

    /** Blocking variant for the DR11 replay loop — read inside `runInTransaction`. */
    @Query("SELECT * FROM pending_outbound_frames ORDER BY created_at ASC")
    fun getAllBlocking(): List<PendingOutboundFrameEntity>

    @Query("SELECT COUNT(*) FROM pending_outbound_frames WHERE contact_id = :contactId")
    suspend fun countForContact(contactId: String): Int

    /**
     * B1 idempotency: true iff a RECEIPT row acking [ackedUuid] is already queued
     * for [contactId]. Blocking — runs inside the decrypt-path transaction.
     */
    @Query(
        "SELECT EXISTS(SELECT 1 FROM pending_outbound_frames " +
            "WHERE contact_id = :contactId " +
            "AND frame_kind = ${PendingOutboundFrameEntity.FRAME_KIND_RECEIPT} " +
            "AND acked_uuid = :ackedUuid)"
    )
    fun existsPendingReceiptForAckedBlocking(contactId: String, ackedUuid: ByteArray): Boolean

    /**
     * B2 backstop: number of pending RECEIPT rows for [contactId]. Blocking —
     * runs inside the decrypt-path transaction.
     */
    @Query(
        "SELECT COUNT(*) FROM pending_outbound_frames " +
            "WHERE contact_id = :contactId " +
            "AND frame_kind = ${PendingOutboundFrameEntity.FRAME_KIND_RECEIPT}"
    )
    fun countPendingReceiptsForContactBlocking(contactId: String): Int
}
