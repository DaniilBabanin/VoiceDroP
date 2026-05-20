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
    val transport: TransportType,
    val encryptedFilePath: String?,
    val durationMs: Int,
    val deleteAfterMs: Long,
    val scheduledDeleteAt: Long,
    val transcription: String?,
    val createdAt: Long,
    val sentAt: Long,
    val deliveredAt: Long,
    // DR3: sender-side ratchet delivery state. Receiver rows skip this entirely (always 0).
    // Transitions: 0 PENDING -> 1 DELIVERED on matching RECEIPT (dr11);
    //              0 PENDING -> 2 GAVE_UP on outbox give-up. Terminal once non-zero.
    val delivery_state: Int = DELIVERY_PENDING,
    // §D — cached waveform peaks for the playback bar. Lazily backfilled on first
    // playback via MessageDao.updateWaveformPeaks; null until then. Compact byte
    // encoding (one byte per peak); see WaveformPeaks for the codec.
    val waveformPeaks: ByteArray? = null
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

        const val DELIVERY_PENDING = 0
        const val DELIVERY_DELIVERED = 1
        const val DELIVERY_GAVE_UP = 2
    }
}
