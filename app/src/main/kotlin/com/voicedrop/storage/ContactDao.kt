package com.voicedrop.storage

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Query
import androidx.room.Upsert
import kotlinx.coroutines.flow.Flow

@Dao
interface ContactDao {
    @Upsert
    suspend fun upsert(contact: ContactEntity)

    @Delete
    suspend fun delete(contact: ContactEntity)

    @Query("SELECT * FROM contacts WHERE id = :id")
    suspend fun getById(id: String): ContactEntity?

    @Query("SELECT * FROM contacts ORDER BY addedAt DESC")
    fun getAll(): Flow<List<ContactEntity>>

    @Query("SELECT * FROM contacts ORDER BY addedAt DESC")
    suspend fun getAllList(): List<ContactEntity>

    /**
     * §A — contact-list row projection. Each subselect runs once per contact
     * (sqlite's planner caches them). `unreadCount` counts inbound messages that
     * arrived but haven't been played; `STATE_PLAYED` is the "user has seen this"
     * terminal state so it is correctly excluded from the badge.
     */
    @Query(
        """
        SELECT
          c.*,
          (SELECT MAX(createdAt) FROM messages m WHERE m.contactId = c.id) AS lastMessageAt,
          (SELECT m.direction FROM messages m
             WHERE m.contactId = c.id ORDER BY m.createdAt DESC LIMIT 1) AS lastMessageDirection,
          (SELECT m.state FROM messages m
             WHERE m.contactId = c.id ORDER BY m.createdAt DESC LIMIT 1) AS lastMessageState,
          (SELECT m.durationMs FROM messages m
             WHERE m.contactId = c.id ORDER BY m.createdAt DESC LIMIT 1) AS lastMessageDurationMs,
          (SELECT COUNT(*) FROM messages m
             WHERE m.contactId = c.id
               AND m.direction = ${MessageEntity.DIRECTION_INBOUND}
               AND m.state IN (${MessageEntity.STATE_SENT}, ${MessageEntity.STATE_DELIVERED})) AS unreadCount
        FROM contacts c
        ORDER BY c.addedAt DESC
        """
    )
    fun getAllWithMeta(): Flow<List<ContactRowMeta>>

    /** §3.1 — writes verification state. Called from pair-time auto-write and the in-chat Verify panel. */
    @Query("UPDATE contacts SET verified_at = :at, verified_fp_pair_hash = :hash WHERE id = :id")
    suspend fun setVerified(id: String, at: Long, hash: ByteArray)

    /** §3.1 — clears verification state. Called from the "Clear verification" button. */
    @Query("UPDATE contacts SET verified_at = NULL, verified_fp_pair_hash = NULL WHERE id = :id")
    suspend fun clearVerified(id: String)
}
