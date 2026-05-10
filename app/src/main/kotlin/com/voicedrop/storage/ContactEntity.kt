package com.voicedrop.storage

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "contacts")
data class ContactEntity(
    @PrimaryKey val id: String,
    val name: String,
    val publicKeyBase64: String,
    val sharedSecretWrapped: ByteArray,
    val addedAt: Long,
    val autoDeleteAfterMs: Long = 0L
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ContactEntity) return false
        return id == other.id
    }

    override fun hashCode(): Int = id.hashCode()
}
