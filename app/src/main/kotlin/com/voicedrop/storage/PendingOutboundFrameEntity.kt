package com.voicedrop.storage

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * Outbox row: persists an outbound DATA / RECEIPT / RESET frame between commit and authenticated
 * acknowledgement so a crash between "ratchet advanced" and "frame on the wire" is recoverable.
 * Replayed on startup and on `NetworkCallback.onAvailable`. See plan/08-dr/dr3-db-schema-v3.md §7.3
 * and dr11-outbox-and-receipt.md / dr15-reset-retransmit.md for replay policy and give-up caps.
 *
 * `frame_kind` mirrors the wire `frameKind` byte (overview §7) and is stored unencrypted so the
 * replay loop can apply per-kind retry/give-up caps without unwrapping every row.
 *
 * The serialized frame itself is wrapped under voicedrop_wrap_v2 + HMAC-bound per DR2 so DB-file
 * exfiltration leaks neither the in-AAD fingerprints / dhPub / chain positions nor the ciphertext.
 */
@Entity(
    tableName = "pending_outbound_frames",
    foreignKeys = [ForeignKey(
        entity = ContactEntity::class,
        parentColumns = ["id"],
        childColumns = ["contact_id"],
        onDelete = ForeignKey.CASCADE
    )],
    indices = [Index(value = ["contact_id", "created_at"])]
)
data class PendingOutboundFrameEntity(
    @PrimaryKey val uuid: ByteArray,
    val contact_id: String,
    val frame_kind: Int,
    val wrapped_frame: ByteArray,
    val frame_hmac: ByteArray,
    val created_at: Long,
    val attempts: Int = 0
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PendingOutboundFrameEntity) return false
        return uuid.contentEquals(other.uuid)
    }

    override fun hashCode(): Int = uuid.contentHashCode()

    companion object {
        const val FRAME_KIND_DATA = 0
        const val FRAME_KIND_RESET = 1
        const val FRAME_KIND_RECEIPT = 2
    }
}
