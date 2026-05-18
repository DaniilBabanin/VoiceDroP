package com.voicedrop.storage

/**
 * DR9 — bounds and maintenance for `skipped_message_keys`.
 *
 * Two operations:
 *   - [enforceCap] — FIFO eviction down to [CAP_PER_CONTACT] entries, called
 *     from inside the DR8 decrypt-path txn after a successful AEAD open. Each
 *     skipped-key insert is single-source from there, so capping at the call
 *     site is sufficient.
 *   - [sweepExpired] — non-blocking 7-day expiry sweep, fired once per process
 *     from [AppDatabase.getInstance].
 *
 * `MAX_SKIP=1000` (per-chain in-flight cap) is intentionally in
 * `RatchetKdf` — it's a property of the pure ratchet, not the persistence layer.
 *
 * Forward-secrecy rationale for the 7-day expiry: a device snapshot recovers
 * any skipped-key row that hasn't aged out, so the worst-case leak window per
 * contact is `CAP_PER_CONTACT` rows × 7 days. See `plan/08-dr/00-overview.md` §1.
 */
object SkippedKeyMaintenance {

    /** §5 Bounds — per-contact FIFO cap. ~80 bytes/row × 2000 ≈ 160 KB per contact max. */
    const val CAP_PER_CONTACT: Int = 2000

    /** §5 Bounds — 7-day expiry. Reduced from 30d to narrow the FS leak window. */
    const val EXPIRY_MS: Long = 7L * 24L * 60L * 60L * 1000L

    /**
     * §8.5 — trim [contactId]'s skipped rows down to [CAP_PER_CONTACT] by deleting
     * the oldest entries by `created_at`. Idempotent. Caller runs inside the
     * decrypt-path SQLite txn so the eviction commits atomically with the insert.
     */
    fun enforceCap(dao: SkippedMessageKeyDao, contactId: String) {
        val count = dao.countForContactBlocking(contactId)
        if (count > CAP_PER_CONTACT) {
            dao.deleteOldestForContactBlocking(contactId, count - CAP_PER_CONTACT)
        }
    }

    /**
     * §8.5 — sweep rows with `created_at < now - EXPIRY_MS`. Runs in its own
     * background thread from [AppDatabase.getInstance]; never on the caller's
     * thread. Returns the count deleted (telemetry-friendly).
     */
    fun sweepExpired(dao: SkippedMessageKeyDao, now: Long): Int =
        dao.deleteExpiredBlocking(now - EXPIRY_MS)
}
