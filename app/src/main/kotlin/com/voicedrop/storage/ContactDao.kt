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

    /** §3.1 — writes verification state. Called from pair-time auto-write and the in-chat Verify panel. */
    @Query("UPDATE contacts SET verified_at = :at, verified_fp_pair_hash = :hash WHERE id = :id")
    suspend fun setVerified(id: String, at: Long, hash: ByteArray)

    /** §3.1 — clears verification state. Called from the "Clear verification" button. */
    @Query("UPDATE contacts SET verified_at = NULL, verified_fp_pair_hash = NULL WHERE id = :id")
    suspend fun clearVerified(id: String)
}
