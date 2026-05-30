package com.voicedrop.crypto

import android.database.Cursor
import com.voicedrop.storage.ContactEntity

/**
 * Materialize a [ContactEntity] from a raw SQLite [Cursor] positioned on a
 * `contacts` row.
 *
 * The ratchet pipeline reads contacts through hand-rolled cursors rather than
 * Room DAOs so the read stays synchronous inside `db.runInTransaction { ... }`
 * — the [dr7] strict-commit-ordering invariant forbids the suspension points a
 * Room query would introduce. This is the single definition shared by
 * [RatchetEncryptAndSend], [RatchetDecryptAndPersist], and [ResetReceive] so
 * the (large) column list cannot drift between them when the schema changes.
 */
internal fun loadContactFromCursor(c: Cursor): ContactEntity {
    fun str(col: String) = c.getString(c.getColumnIndexOrThrow(col))
    fun lng(col: String) = c.getLong(c.getColumnIndexOrThrow(col))
    fun ints(col: String) = c.getInt(c.getColumnIndexOrThrow(col))
    fun blobOrNull(col: String): ByteArray? {
        val i = c.getColumnIndexOrThrow(col)
        return if (c.isNull(i)) null else c.getBlob(i)
    }
    fun blob(col: String): ByteArray = blobOrNull(col) ?: ByteArray(0)
    return ContactEntity(
        id = str("id"),
        name = str("name"),
        publicKeyBase64 = str("publicKeyBase64"),
        addedAt = lng("addedAt"),
        autoDeleteAfterMs = lng("autoDeleteAfterMs"),
        pending_repair = ints("pending_repair"),
        dhs_priv_wrapped = blobOrNull("dhs_priv_wrapped"),
        dhs_priv_hmac = blobOrNull("dhs_priv_hmac"),
        dhs_pub = blobOrNull("dhs_pub"),
        dhr_pub = blobOrNull("dhr_pub"),
        rk_wrapped = blob("rk_wrapped"),
        rk_hmac = blob("rk_hmac"),
        cks_wrapped = blobOrNull("cks_wrapped"),
        cks_hmac = blobOrNull("cks_hmac"),
        ckr_wrapped = blobOrNull("ckr_wrapped"),
        ckr_hmac = blobOrNull("ckr_hmac"),
        ns = ints("ns"),
        nr = ints("nr"),
        pn = ints("pn"),
        reset_epoch = ints("reset_epoch"),
        reset_nonce = blobOrNull("reset_nonce"),
        expecting_ack = ints("expecting_ack"),
        auto_reset_window_start = lng("auto_reset_window_start"),
        auto_reset_count_24h = ints("auto_reset_count_24h"),
        last_auto_reset_at = lng("last_auto_reset_at"),
        inbound_reset_window_start = lng("inbound_reset_window_start"),
        inbound_reset_count_24h = ints("inbound_reset_count_24h"),
        budget_exhausted_until = lng("budget_exhausted_until"),
        consecutive_aead_failures = ints("consecutive_aead_failures"),
        consecutive_aead_failures_window_start = lng("consecutive_aead_failures_window_start"),
        soft_prompt_dismissed_until = lng("soft_prompt_dismissed_until")
    )
}
