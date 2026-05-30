package com.voicedrop.storage

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query

/**
 * DR8 — basic CRUD on `skipped_message_keys`. The blocking variants are wired
 * from inside the decrypt-path `runInTransaction(Callable {...})` and therefore
 * never suspend. DR9 layers FIFO eviction + 7-day expiry sweep on top.
 */
@Dao
interface SkippedMessageKeyDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insertBlocking(row: SkippedMessageKeyEntity)

    @Query(
        "SELECT mk_wrapped FROM skipped_message_keys WHERE contact_id = :contactId AND dhr_pub = :dhrPub AND n = :n LIMIT 1"
    )
    fun getWrappedBlocking(contactId: String, dhrPub: ByteArray, n: Int): ByteArray?

    @Query(
        "SELECT mk_hmac FROM skipped_message_keys WHERE contact_id = :contactId AND dhr_pub = :dhrPub AND n = :n LIMIT 1"
    )
    fun getHmacBlocking(contactId: String, dhrPub: ByteArray, n: Int): ByteArray?

    @Query(
        "DELETE FROM skipped_message_keys WHERE contact_id = :contactId AND dhr_pub = :dhrPub AND n = :n"
    )
    fun deleteByKeyBlocking(contactId: String, dhrPub: ByteArray, n: Int): Int

    @Query("SELECT COUNT(*) FROM skipped_message_keys WHERE contact_id = :contactId")
    fun countForContactBlocking(contactId: String): Int

    @Query(
        """DELETE FROM skipped_message_keys WHERE rowid IN (
            SELECT rowid FROM skipped_message_keys
            WHERE contact_id = :contactId
            ORDER BY created_at ASC
            LIMIT :limit
        )"""
    )
    fun deleteOldestForContactBlocking(contactId: String, limit: Int): Int

    /**
     * DR9 §8.5 — process-wide expiry sweep. Fired off `AppDatabase` open in a
     * background thread; cutoff is `now - SkippedKeyMaintenance.EXPIRY_MS`. Not
     * contact-scoped: the 7-day rule applies uniformly. Volume is bounded at
     * 2000 rows × N contacts (~hundreds at most), so a full scan is fine.
     */
    @Query("DELETE FROM skipped_message_keys WHERE created_at < :cutoff")
    fun deleteExpiredBlocking(cutoff: Long): Int

    @Query("SELECT * FROM skipped_message_keys WHERE contact_id = :contactId ORDER BY created_at ASC")
    suspend fun getByContact(contactId: String): List<SkippedMessageKeyEntity>

    @Query("SELECT COUNT(*) FROM skipped_message_keys WHERE contact_id = :contactId")
    suspend fun countForContact(contactId: String): Int
}
