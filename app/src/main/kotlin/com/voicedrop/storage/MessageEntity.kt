package com.voicedrop.storage

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "messages",
    foreignKeys = [ForeignKey(
        entity = ContactEntity::class,
        parentColumns = ["id"],
        childColumns = ["contactId"],
        onDelete = ForeignKey.CASCADE
    )],
    indices = [Index("contactId")]
)
data class MessageEntity(
    @PrimaryKey val uuid: String,
    val contactId: String,
    val direction: Int,
    val state: Int,
    val encryptedFilePath: String?,
    val durationMs: Int,
    val deleteAfterMs: Long,
    val scheduledDeleteAt: Long,
    val transcription: String?,
    val createdAt: Long,
    val sentAt: Long,
    val deliveredAt: Long
) {
    companion object {
        const val DIRECTION_INBOUND = 0
        const val DIRECTION_OUTBOUND = 1

        const val STATE_OUTBOX = 0
        const val STATE_SENT = 1
        const val STATE_DELIVERED = 2
        const val STATE_PLAYED = 3
        const val STATE_DELETED = 4
        const val STATE_UNDELIVERABLE = 5
    }
}
