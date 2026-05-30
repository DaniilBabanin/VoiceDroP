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

    /**
     * DR11 §8.7 — RECEIPT clears the sender-side `delivery_state` from PENDING to DELIVERED.
     * Idempotent: the `delivery_state = DELIVERY_PENDING` guard prevents a late / duplicate
     * RECEIPT from overwriting a row that already gave up (terminal GAVE_UP). Blocking
     * variant runs inside the [ReceiptInboundHandler] transaction with deleteByUuidBlocking.
     */
    @Query(
        "UPDATE messages SET delivery_state = ${MessageEntity.DELIVERY_DELIVERED}, deliveredAt = :deliveredAt " +
            "WHERE uuid = :uuid AND delivery_state = ${MessageEntity.DELIVERY_PENDING}"
    )
    fun markDeliveredBlocking(uuid: String, deliveredAt: Long): Int

    /**
     * DR11 §8.6 — outbox give-up path for DATA marks the sender-side message as
     * GAVE_UP (terminal). UI surfaces the per-message red dot + retry button.
     * Idempotent under the same PENDING guard.
     */
    @Query(
        "UPDATE messages SET delivery_state = ${MessageEntity.DELIVERY_GAVE_UP} " +
            "WHERE uuid = :uuid AND delivery_state = ${MessageEntity.DELIVERY_PENDING}"
    )
    fun markGaveUpBlocking(uuid: String): Int

    /**
     * Played-receipt (spec `16-played-receipt.md` §2) — flips a delivered outbound
     * row to `STATE_PLAYED` when a `KIND_PLAYED` frame arrives from the recipient.
     * Guards:
     *   - `direction = DIRECTION_OUTBOUND` blocks accidental writes to inbound rows.
     *   - `contactId = :contactId` blocks cross-contact spoof (paired contact A flipping
     *     a message addressed to paired contact B).
     *   - `state IN (STATE_SENT, STATE_DELIVERED)` accepts the racy "PLAYED before
     *     our own RECEIPT" path and rejects `DELETED`/`UNDELIVERABLE` terminal states
     *     and idempotent `PLAYED → PLAYED` no-ops.
     * Blocking variant runs inside the [PlayedInboundHandler] transaction.
     */
    @Query(
        "UPDATE messages SET state = ${MessageEntity.STATE_PLAYED} " +
            "WHERE uuid = :uuid AND contactId = :contactId " +
            "AND direction = ${MessageEntity.DIRECTION_OUTBOUND} " +
            "AND state IN (${MessageEntity.STATE_SENT}, ${MessageEntity.STATE_DELIVERED})"
    )
    fun markPlayedBlocking(uuid: String, contactId: String): Int

    /**
     * Backfill `deliveredAt` for the `SENT → PLAYED` race case (PLAYED arrived
     * before our own wire-RECEIPT for the corresponding VOICE). Only writes if
     * `deliveredAt = 0` so a legitimate prior RECEIPT timestamp is preserved.
     * Blocking variant runs inside the same [PlayedInboundHandler] transaction.
     */
    @Query(
        "UPDATE messages SET deliveredAt = :deliveredAt " +
            "WHERE uuid = :uuid AND direction = ${MessageEntity.DIRECTION_OUTBOUND} " +
            "AND deliveredAt = 0"
    )
    fun backfillDeliveredAtBlocking(uuid: String, deliveredAt: Long): Int

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

    @Query("SELECT COUNT(*) FROM messages WHERE encryptedFilePath = :path")
    suspend fun countByEncryptedFilePath(path: String): Int

    @Query("DELETE FROM messages WHERE uuid = :uuid")
    suspend fun deleteByUuid(uuid: String): Int

    /**
     * §D — lazy backfill of cached waveform peaks on first playback. The
     * `waveformPeaks IS NULL` guard makes the update idempotent against
     * concurrent playbacks (only the first writer wins; the rest no-op).
     */
    @Query("UPDATE messages SET waveformPeaks = :peaks WHERE uuid = :uuid AND waveformPeaks IS NULL")
    suspend fun updateWaveformPeaks(uuid: String, peaks: ByteArray): Int

    /**
     * Finding #2 resend cap — read the per-message re-emit count (blocking, in-txn).
     * Returns null only when no `messages` row with [uuid] exists; the column itself
     * is NOT NULL DEFAULT 0. Callers on the dedup path treat the message as having
     * zero re-emits when absent (`?: 0`).
     */
    @Query("SELECT receipt_resends FROM messages WHERE uuid = :uuid")
    fun getReceiptResendsBlocking(uuid: String): Int?

    /** Finding #2 resend cap — increment the per-message re-emit count; returns rows updated. */
    @Query("UPDATE messages SET receipt_resends = receipt_resends + 1 WHERE uuid = :uuid")
    fun incrementReceiptResendsBlocking(uuid: String): Int
}
