package com.voicedrop.storage

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index

/**
 * §3.2 — per-pair rotating prekey row. Three-state lifecycle:
 *   - `active`   : currently used for the next RESET cycle's prekeySS derivation
 *   - `pending`  : Alice has initiated, peer's pub not yet known (peer_pub IS NULL)
 *   - `previous` : recently superseded; kept for 10 minutes for retransmit fallback
 *
 * Invariants (enforced by state-machine code in ResetReceive.kt / QrPairActivity.kt,
 * not by the DAO/entity layer — see spec §5.5):
 *   - At most one row per (contact_id, status) for each of the three statuses.
 *   - active.peer_pub is non-NULL whenever any row exists.
 *   - pending.peer_pub IS NULL while status='pending'.
 *   - previous.expires_at is non-NULL and > 0.
 *
 * Wrapped priv binding: HMAC over column tag "prekey_epochs.my_priv_wrapped" plus
 * rowId = contact_id.toByteArray(UTF_8) || 0x00 || be32(epoch). Moving a wrapped
 * blob between epochs invalidates the HMAC (dr2 column/row binding analogue).
 */
@Entity(
    tableName = "prekey_epochs",
    primaryKeys = ["contact_id", "epoch"],
    foreignKeys = [ForeignKey(
        entity = ContactEntity::class,
        parentColumns = ["id"],
        childColumns = ["contact_id"],
        onDelete = ForeignKey.CASCADE
    )],
    indices = [Index(value = ["contact_id", "status"])]
)
data class PrekeyEpochEntity(
    val contact_id: String,
    val epoch: Int,
    val status: String,
    val my_priv_wrapped: ByteArray,
    val my_priv_hmac: ByteArray,
    val my_pub: ByteArray,
    val peer_pub: ByteArray?,
    val expires_at: Long?
) {
    companion object {
        const val STATUS_ACTIVE = "active"
        const val STATUS_PENDING = "pending"
        const val STATUS_PREVIOUS = "previous"

        /** Column tag used as the first WrapMac input on `my_priv_wrapped`. */
        const val COL_MY_PRIV = "prekey_epochs.my_priv_wrapped"

        /** rowId = contact_id.utf8 || 0x00 || be32(epoch). */
        fun rowIdFor(contactId: String, epoch: Int): ByteArray {
            val idBytes = contactId.toByteArray(Charsets.UTF_8)
            val out = ByteArray(idBytes.size + 1 + 4)
            idBytes.copyInto(out, 0)
            out[idBytes.size] = 0x00
            out[idBytes.size + 1] = (epoch ushr 24).toByte()
            out[idBytes.size + 2] = (epoch ushr 16).toByte()
            out[idBytes.size + 3] = (epoch ushr 8).toByte()
            out[idBytes.size + 4] = epoch.toByte()
            return out
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PrekeyEpochEntity) return false
        return contact_id == other.contact_id &&
            epoch == other.epoch &&
            status == other.status &&
            my_priv_wrapped.contentEquals(other.my_priv_wrapped) &&
            my_priv_hmac.contentEquals(other.my_priv_hmac) &&
            my_pub.contentEquals(other.my_pub) &&
            ((peer_pub == null && other.peer_pub == null) ||
                (peer_pub != null && other.peer_pub != null && peer_pub.contentEquals(other.peer_pub))) &&
            expires_at == other.expires_at
    }

    override fun hashCode(): Int {
        var result = contact_id.hashCode()
        result = 31 * result + epoch
        result = 31 * result + status.hashCode()
        result = 31 * result + my_priv_wrapped.contentHashCode()
        result = 31 * result + my_priv_hmac.contentHashCode()
        result = 31 * result + my_pub.contentHashCode()
        result = 31 * result + (peer_pub?.contentHashCode() ?: 0)
        result = 31 * result + (expires_at?.hashCode() ?: 0)
        return result
    }
}
