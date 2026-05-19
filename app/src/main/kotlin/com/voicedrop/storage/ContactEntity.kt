package com.voicedrop.storage

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Per-contact row in DB v3.
 *
 * Identity columns (id, name, publicKeyBase64, addedAt, autoDeleteAfterMs) carry over from v1.x.
 * Everything else is new for the Double Ratchet (plan/08-dr/dr3-db-schema-v3.md).
 *
 * The ratchet/reset fields default to a "pre-bootstrap" state so callers from earlier phases (e.g.
 * the v1.x QR pairing flow before DR5 lands) can construct a row without populating them. Real
 * values are written by the DR5 bootstrap path and read/updated by DR6+.
 *
 * All `*_wrapped` BLOBs follow the DR2 layout `[iv:12 || ct || tag:16]` and pair with a sibling
 * `*_hmac` column carrying `HMAC_SHA256(column || 0x00 || rowId || 0x00 || wrapped)`. `rk_wrapped`
 * and `rk_hmac` are NOT NULL at the schema level; the pre-bootstrap sentinel is an empty ByteArray
 * (size 0), not SQL NULL.
 */
@Entity(tableName = "contacts")
data class ContactEntity(
    @PrimaryKey val id: String,
    val name: String,
    val publicKeyBase64: String,
    val addedAt: Long,
    val autoDeleteAfterMs: Long = 0L,
    val pending_repair: Int = 0,

    // --- Ratchet state ---
    val dhs_priv_wrapped: ByteArray? = null,
    val dhs_priv_hmac: ByteArray? = null,
    val dhs_pub: ByteArray? = null,
    val dhr_pub: ByteArray? = null,
    val rk_wrapped: ByteArray = ByteArray(0),
    val rk_hmac: ByteArray = ByteArray(0),
    val cks_wrapped: ByteArray? = null,
    val cks_hmac: ByteArray? = null,
    val ckr_wrapped: ByteArray? = null,
    val ckr_hmac: ByteArray? = null,
    val ns: Int = 0,
    val nr: Int = 0,
    val pn: Int = 0,

    // --- Reset / session-management ---
    val reset_epoch: Int = 0,
    val reset_nonce: ByteArray? = null,
    val expecting_ack: Int = 0,
    val auto_reset_window_start: Long = 0L,
    val auto_reset_count_24h: Int = 0,
    val last_auto_reset_at: Long = 0L,
    val inbound_reset_window_start: Long = 0L,
    val inbound_reset_count_24h: Int = 0,
    val budget_exhausted_until: Long = 0L,
    val consecutive_aead_failures: Int = 0,
    val consecutive_aead_failures_window_start: Long = 0L,
    val soft_prompt_dismissed_until: Long = 0L,

    // --- Identity verification (NEW in v4 — plan/09-security-frontier/3.1-sas-verification-ux.md) ---
    val verified_at: Long? = null,
    val verified_fp_pair_hash: ByteArray? = null
) {
    // Equality by id only — ByteArray's reference-equality would break DiffUtil and dedup helpers.
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ContactEntity) return false
        return id == other.id
    }

    override fun hashCode(): Int = id.hashCode()
}

/**
 * §3.1 — true iff this row was marked verified AND the stored binding still matches
 * the current pair of identity keys. Returns false on any rotation of either party's
 * identity key — that's the auto-invalidation §3.2 will rely on.
 */
fun ContactEntity.isVerifiedAgainst(myIdPub: ByteArray, theirIdPub: ByteArray): Boolean {
    val storedHash = verified_fp_pair_hash ?: return false
    if (verified_at == null) return false
    return storedHash.contentEquals(com.voicedrop.crypto.Sas.fpPairBinding(myIdPub, theirIdPub))
}
