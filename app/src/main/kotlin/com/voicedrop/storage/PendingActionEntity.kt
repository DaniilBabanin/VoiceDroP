package com.voicedrop.storage

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "pending_actions")
data class PendingActionEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val contactId: String,
    val type: Int,
    val payload: ByteArray,
    val createdAt: Long,
    val retryCount: Int = 0
) {
    companion object {
        const val TYPE_SEND_MESSAGE = 0
        const val TYPE_SEND_DELETE = 1
        const val TYPE_SEND_PING = 2
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PendingActionEntity) return false
        return id == other.id
    }

    override fun hashCode(): Int = id.hashCode()
}
