package com.voicedrop.crypto

import com.voicedrop.storage.AppDatabase
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * DR14 — AEAD-failure soft-prompt heuristic (§6.4).
 *
 * DR6 §4.4 leaves silent-divergence on the table: AEAD failures do NOT auto-reset
 * ([AutoResetTrigger] explicitly excludes them) but a genuinely divergent ratchet
 * would otherwise stay broken forever. This class implements the one-shot UI
 * prompt that nudges the user toward a manual reset after ≥10 consecutive AEAD
 * failures within a 10-minute rolling window.
 *
 * Persistence: the underlying counter columns are already bumped by
 * [RatchetDecryptAndPersist] — its outside-txn UPDATE increments
 * `contacts.consecutive_aead_failures` and sets
 * `consecutive_aead_failures_window_start` on first failure. A successful AEAD
 * decrypt zeroes both columns inside the success txn. We only READ those columns
 * here, plus manage `soft_prompt_dismissed_until` and stale-window cleanup.
 *
 * Counters survive an app restart on purpose: an attacker burst spread across a
 * crash window should still trip the prompt, not get amnesia-reset.
 */
class AeadFailureSoftPrompt(
    private val db: AppDatabase,
    private val clock: () -> Long = { System.currentTimeMillis() },
    private val eventLog: (String) -> Unit = { android.util.Log.i("AeadFailureSoftPrompt", it) }
) {

    /** Result of an [evaluate] call. Caller routes UI from here. */
    sealed class State {
        /** Counter is below the threshold (or window expired and counter was cleared). */
        object Idle : State()
        /** ≥[THRESHOLD] failures inside a [WINDOW_MS] rolling window and not currently suppressed. */
        data class ShouldPrompt(val failures: Int, val windowStart: Long) : State()
        /** Within the 24h dismissal-suppression window from a prior prompt. */
        data class Suppressed(val until: Long) : State()
    }

    /**
     * Inspect the persisted counter for [contactId] and decide whether the UI
     * should surface the soft prompt. Side effect: if the 10-minute window has
     * elapsed without hitting the threshold, the counter is reset so a fresh
     * window can open on the next failure.
     */
    suspend fun evaluate(contactId: String): State = withContext(Dispatchers.IO) {
        val now = clock()
        val row = readRow(contactId) ?: return@withContext State.Idle

        if (row.dismissedUntil > now) {
            return@withContext State.Suppressed(row.dismissedUntil)
        }

        if (row.windowStart > 0 && (now - row.windowStart) > WINDOW_MS) {
            // Stale window — clear counter so the next failure opens a fresh one.
            // Window-start reset to 0 mirrors DR8's "set on first failure if zero".
            clearCounter(contactId)
            return@withContext State.Idle
        }

        if (row.failures >= THRESHOLD && row.windowStart > 0) {
            eventLog("aead.fail_consecutive contact=$contactId count=${row.failures} window_start=${row.windowStart}")
            return@withContext State.ShouldPrompt(row.failures, row.windowStart)
        }

        State.Idle
    }

    /**
     * User dismissed the soft prompt — set the 24h suppression window and clear
     * the running counter so we don't immediately re-prompt once the dismissal
     * expires.
     */
    suspend fun dismiss(contactId: String) = withContext(Dispatchers.IO) {
        val now = clock()
        db.openHelper.writableDatabase.execSQL(
            "UPDATE contacts SET soft_prompt_dismissed_until = ?, " +
                "consecutive_aead_failures = 0, consecutive_aead_failures_window_start = 0 " +
                "WHERE id = ?",
            arrayOf<Any>(now + DISMISS_SUPPRESS_MS, contactId)
        )
        eventLog("aead.soft_prompt_dismissed contact=$contactId until=${now + DISMISS_SUPPRESS_MS}")
    }

    // ----- raw-SQL accessors -----

    private data class CounterRow(
        val failures: Int,
        val windowStart: Long,
        val dismissedUntil: Long
    )

    private fun readRow(contactId: String): CounterRow? {
        return db.openHelper.writableDatabase.query(
            "SELECT consecutive_aead_failures, consecutive_aead_failures_window_start, " +
                "soft_prompt_dismissed_until FROM contacts WHERE id = ?",
            arrayOf(contactId)
        ).use { c ->
            if (!c.moveToFirst()) null
            else CounterRow(
                failures = c.getInt(0),
                windowStart = c.getLong(1),
                dismissedUntil = c.getLong(2)
            )
        }
    }

    private fun clearCounter(contactId: String) {
        db.openHelper.writableDatabase.execSQL(
            "UPDATE contacts SET consecutive_aead_failures = 0, " +
                "consecutive_aead_failures_window_start = 0 WHERE id = ?",
            arrayOf<Any>(contactId)
        )
    }

    companion object {
        const val THRESHOLD = 10
        const val WINDOW_MS = 10L * 60 * 1000
        const val DISMISS_SUPPRESS_MS = 24L * 60 * 60 * 1000
    }
}
