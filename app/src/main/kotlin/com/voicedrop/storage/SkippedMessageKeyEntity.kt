package com.voicedrop.storage

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index

/**
 * Holds out-of-order ratchet message keys until the matching DATA frame arrives or the entry expires.
 * See plan/08-dr/dr3-db-schema-v3.md §7.2 and dr9-skipped-keys.md (FIFO eviction at 2000/contact,
 * MAX_SKIP=1000 per chain, 7-day expiry sweep on AppDatabase open).
 *
 * `mk_wrapped` follows the DR2 wrap layout; `mk_hmac` binds it to (column, primary-key) so a DB-level
 * row swap is detected as crypto-tamper.
 *
 * The composite index `(contact_id, created_at)` supports both FIFO eviction and the contact-scoped
 * expiry sweep.
 */
@Entity(
    tableName = "skipped_message_keys",
    primaryKeys = ["contact_id", "dhr_pub", "n"],
    foreignKeys = [ForeignKey(
        entity = ContactEntity::class,
        parentColumns = ["id"],
        childColumns = ["contact_id"],
        onDelete = ForeignKey.CASCADE
    )],
    indices = [Index(value = ["contact_id", "created_at"])]
)
data class SkippedMessageKeyEntity(
    val contact_id: String,
    val dhr_pub: ByteArray,
    val n: Int,
    val mk_wrapped: ByteArray,
    val mk_hmac: ByteArray,
    val created_at: Long
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SkippedMessageKeyEntity) return false
        return contact_id == other.contact_id &&
                dhr_pub.contentEquals(other.dhr_pub) &&
                n == other.n
    }

    override fun hashCode(): Int {
        var h = contact_id.hashCode()
        h = 31 * h + dhr_pub.contentHashCode()
        h = 31 * h + n
        return h
    }
}
