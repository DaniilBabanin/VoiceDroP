package com.voicedrop.storage

import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

/**
 * §3.2 — adds the prekey_epochs table and forces re-pair on every existing contact.
 *
 * The v1.2 → v1.3 wire-format and derivation changes (info strings bump /v1 → /v2,
 * RESET plaintext grows 33→66 bytes, K_reset / RK_0 now mix prekeySS) mean any
 * existing ratchet state is incompatible with the new derivations. We could try
 * to preserve it but there's no peer prekey to feed the new RK_0 derivation —
 * the prekey only enters the system via QR exchange, which means re-pairing.
 *
 * This migration:
 *   - Creates the new prekey_epochs table.
 *   - Wipes all ratchet / skipped / outbox state for every contact.
 *   - Sets pending_repair = 1 so the UI surfaces "Re-pair {name}" prompts.
 *   - Preserves id, name, publicKeyBase64, addedAt, autoDeleteAfterMs.
 *   - Preserves verified_at and verified_fp_pair_hash (§3.1 verification history —
 *     they'll be auto-invalidated by isVerifiedAgainst once the user re-pairs and
 *     either side's identity key changes; otherwise they stay valid).
 *   - Preserves the messages table (user-owned plaintext).
 */
val Migration_4_5 = object : Migration(4, 5) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL("""
            CREATE TABLE prekey_epochs (
                contact_id      TEXT NOT NULL,
                epoch           INTEGER NOT NULL,
                status          TEXT NOT NULL,
                my_priv_wrapped BLOB NOT NULL,
                my_priv_hmac    BLOB NOT NULL,
                my_pub          BLOB NOT NULL,
                peer_pub        BLOB,
                expires_at      INTEGER,
                PRIMARY KEY (contact_id, epoch),
                FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
            )
        """.trimIndent())
        db.execSQL("CREATE INDEX idx_prekey_epochs_status ON prekey_epochs(contact_id, status)")

        // Wipe ratchet/reset state on every existing contact. The pending_repair=1 flag
        // surfaces the re-pair UI; the user re-scans QR which regenerates everything.
        db.execSQL("""
            UPDATE contacts SET
                pending_repair = 1,
                dhs_priv_wrapped = NULL, dhs_priv_hmac = NULL, dhs_pub = NULL,
                dhr_pub = NULL,
                rk_wrapped = X'', rk_hmac = X'',
                cks_wrapped = NULL, cks_hmac = NULL,
                ckr_wrapped = NULL, ckr_hmac = NULL,
                ns = 0, nr = 0, pn = 0,
                reset_epoch = 0, reset_nonce = NULL, expecting_ack = 0,
                auto_reset_window_start = 0, auto_reset_count_24h = 0, last_auto_reset_at = 0,
                inbound_reset_window_start = 0, inbound_reset_count_24h = 0,
                budget_exhausted_until = 0,
                consecutive_aead_failures = 0, consecutive_aead_failures_window_start = 0,
                soft_prompt_dismissed_until = 0
        """.trimIndent())

        // Drop child rows that referenced the wiped ratchet state.
        db.execSQL("DELETE FROM skipped_message_keys")
        db.execSQL("DELETE FROM pending_outbound_frames")
    }
}
