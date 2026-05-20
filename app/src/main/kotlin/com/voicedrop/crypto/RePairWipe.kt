package com.voicedrop.crypto

import com.voicedrop.storage.AppDatabase
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.util.concurrent.Callable

/**
 * DR15 — Re-pair wipe primitive (§6.5).
 *
 * Identity-key compromise is unrecoverable via session reset: an attacker holding
 * `idSharedSecret` can decrypt every post-reset `RK_0` and every RESET frame.
 * The only recovery is to delete the contact's ratchet/outbox/skipped-key state,
 * regenerate the local identity key, and re-pair via fresh QR.
 *
 * This class owns the data-layer side of that flow. UI components
 * (`QrPairActivity.kt`, "Identity key compromised? Re-pair instead" affordance
 * in contact details) call [wipe] inside a destructive-action confirm, then
 * launch the pairing screen. Identity-key regeneration is the UI's job; it
 * runs after this wipe commits.
 *
 * Invariants:
 *   - **Messages preserved**: the user already owns the decrypted plaintext
 *     and the `messages` table sits independently of the ratchet — leaving
 *     it alone matches the §6.5 contract.
 *   - **One Room transaction**: ratchet column clear + skipped-key delete +
 *     outbox delete + `pending_repair=1` flip commit atomically. A crash
 *     mid-wipe leaves the contact either fully wiped or unchanged.
 *   - **Per-contact mutex held**: serializes against in-flight DR7 encrypts /
 *     DR8 decrypts / DR13 resets. They will see either pre- or post-wipe state.
 *   - **`pending_repair=1`**: surfaces "Pair again" UI; until the user
 *     completes the new QR scan, the contact is unusable. Cleared by the
 *     pairing flow on success.
 *   - **`rk_wrapped`/`rk_hmac` set to empty `ByteArray(0)`**: the DR3
 *     pre-bootstrap sentinel. `RatchetStatePersistence.loadRatchetState`
 *     reads this and throws `RatchetNotBootstrapped`, which the DR7 encrypt
 *     path translates to `SessionResetInProgress` UI gating.
 */
class RePairWipe(
    private val db: AppDatabase,
    private val eventLog: (String) -> Unit = { android.util.Log.i("RePairWipe", it) }
) {

    /**
     * Wipe all crypto state for [contactId]. Preserves `messages` rows. Sets
     * `pending_repair = 1` so the UI surfaces a "Pair again" affordance.
     *
     * No-op if [contactId] is not found.
     */
    suspend fun wipe(contactId: String) {
        ContactMutexRegistry.forContact(contactId).withLock {
            withContext(Dispatchers.IO) {
                db.runInTransaction(Callable { wipeInsideTxn(contactId) })
            }
        }
    }

    private fun wipeInsideTxn(contactId: String) {
        val raw = db.openHelper.writableDatabase

        // Foreign-key CASCADE from contacts would handle these on a contact delete,
        // but we're keeping the contact row (and its messages) — explicit DELETEs.
        raw.execSQL(
            "DELETE FROM skipped_message_keys WHERE contact_id = ?",
            arrayOf<Any>(contactId)
        )
        raw.execSQL(
            "DELETE FROM pending_outbound_frames WHERE contact_id = ?",
            arrayOf<Any>(contactId)
        )
        raw.execSQL(
            "DELETE FROM prekey_epochs WHERE contact_id = ?",
            arrayOf<Any>(contactId)
        )

        // Clear every ratchet / reset / counter column; reset RK to the
        // DR3 pre-bootstrap sentinel (empty ByteArray). pending_repair=1 surfaces
        // the "Pair again" UI gate.
        val emptyBlob = ByteArray(0)
        raw.execSQL(
            "UPDATE contacts SET " +
                "dhs_priv_wrapped = NULL, dhs_priv_hmac = NULL, " +
                "dhs_pub = NULL, dhr_pub = NULL, " +
                "rk_wrapped = ?, rk_hmac = ?, " +
                "cks_wrapped = NULL, cks_hmac = NULL, " +
                "ckr_wrapped = NULL, ckr_hmac = NULL, " +
                "ns = 0, nr = 0, pn = 0, " +
                "reset_epoch = 0, reset_nonce = NULL, expecting_ack = 0, " +
                "auto_reset_window_start = 0, auto_reset_count_24h = 0, last_auto_reset_at = 0, " +
                "inbound_reset_window_start = 0, inbound_reset_count_24h = 0, " +
                "budget_exhausted_until = 0, " +
                "consecutive_aead_failures = 0, consecutive_aead_failures_window_start = 0, " +
                "soft_prompt_dismissed_until = 0, " +
                "pending_repair = 1 " +
                "WHERE id = ?",
            arrayOf<Any>(emptyBlob, emptyBlob, contactId)
        )

        eventLog("repair.wipe contact=${contactId.take(8)}")
    }
}
