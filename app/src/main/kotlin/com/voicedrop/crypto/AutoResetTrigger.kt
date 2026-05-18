package com.voicedrop.crypto

import com.voicedrop.storage.AppDatabase
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.Callable

/**
 * DR14 — Auto-reset trigger (§6.4).
 *
 * Decides whether a failure observed in the decrypt / load path warrants firing
 * an automatic session reset. The classifier is strict by design: ONLY structural
 * state corruption (e.g. [RatchetStatePersistence.RatchetStateCorrupt], DB read
 * errors with invariant violations) is eligible. AEAD failures
 * ([RatchetCryptoFailure]) and wrap-binding tampers ([WrapHmacMismatch]) are
 * EXPLICITLY excluded so an attacker cannot induce resets by injecting tampered
 * frames or scrambling wrapped columns. See [dr14-reset-triggers.md].
 *
 * Eligible structural failures are gated by a 4-per-24h rate limit with
 * exponential backoff (30s → 5m → 30m → 4h between attempts). Hitting the cap
 * arms a 7-day `budget_exhausted_until` refuse window — both auto-resets and
 * inbound RESET frames are refused until the window expires.
 *
 * On a "fire" decision the actual reset machinery delegates to
 * [ResetReceive.manualResetInitiate] (same atomic txn shape, same outbox shape
 * as a user-triggered reset). The pre-flight rate gate runs in its own small
 * txn first so increments survive even if the manualResetInitiate retry path
 * (DR15) crashes mid-flight.
 *
 * Not wired into the inbound dispatcher yet — that lives in the v2 cutover of
 * `ConnectionManager.processFrame`. Callers will be DR8's load-path and the
 * v2 dispatcher; both `catch` structural exceptions and feed them here.
 */
class AutoResetTrigger(
    private val db: AppDatabase,
    private val resetReceive: ResetReceive,
    private val clock: () -> Long = { System.currentTimeMillis() },
    private val eventLog: (String) -> Unit = { android.util.Log.i("AutoResetTrigger", it) }
) {

    /** Outcome of an [onStructuralCorruption] call. Caller routes UI / telemetry from it. */
    sealed class Decision {
        /** Rate gate passed; [ResetReceive.manualResetInitiate] was invoked. */
        data class Triggered(val resetOutcome: ResetReceive.Outcome) : Decision()
        /** Failure class isn't structural (AEAD, WrapHmacMismatch, etc.) — no reset. */
        object SkippedNotStructural : Decision()
        /** Within the per-step backoff window since `last_auto_reset_at`. */
        data class SkippedRateLimited(val nextEligibleAt: Long) : Decision()
        /** 4/24h cap already hit; `budget_exhausted_until` is armed. */
        data class SkippedBudgetExhausted(val until: Long) : Decision()
        /** This call hit the 4th attempt; armed the 7d budget refuse window. */
        data class BudgetExhaustedNow(val until: Long) : Decision()
    }

    /**
     * Failure classification. Only [STRUCTURAL] is eligible for auto-reset.
     *
     * [CRYPTO_TAMPER] surfaces a UI banner ("possible tamper") but does NOT
     * increment any reset counters — the threat model treats DB tamper as
     * already-compromised and refuses to escalate to a key roll the attacker
     * may be trying to provoke.
     *
     * [AEAD] is the silent-divergence case. Soft-prompt heuristic lives in
     * [AeadFailureSoftPrompt]; auto-reset does not fire.
     */
    enum class FailureClass { STRUCTURAL, CRYPTO_TAMPER, AEAD, OTHER }

    suspend fun onStructuralCorruption(contactId: String, cause: Throwable? = null): Decision {
        val klass = classify(cause)
        if (klass != FailureClass.STRUCTURAL) {
            eventLog("auto_reset.skipped_not_structural contact=$contactId class=$klass")
            return Decision.SkippedNotStructural
        }
        val now = clock()
        val gate = withContext(Dispatchers.IO) {
            db.runInTransaction(Callable { evaluateAndArmInsideTxn(contactId, now) })
        }
        return when (gate) {
            is GateOutcome.RateLimited -> {
                eventLog("auto_reset.rate_limited contact=$contactId next=${gate.nextEligibleAt}")
                Decision.SkippedRateLimited(gate.nextEligibleAt)
            }
            is GateOutcome.AlreadyBudgetExhausted -> {
                eventLog("auto_reset.budget_exhausted contact=$contactId until=${gate.until}")
                Decision.SkippedBudgetExhausted(gate.until)
            }
            is GateOutcome.BudgetExhaustedNow -> {
                eventLog("reset.budget_exhausted contact=$contactId until=${gate.until}")
                Decision.BudgetExhaustedNow(gate.until)
            }
            is GateOutcome.Fire -> {
                eventLog("reset.structural contact=$contactId attempt=${gate.attemptNumber} cause=${cause?.javaClass?.simpleName ?: "null"}")
                val outcome = resetReceive.manualResetInitiate(contactId)
                Decision.Triggered(outcome)
            }
        }
    }

    // ----- gate logic (pure-ish; runs inside a Room txn) -----

    private sealed class GateOutcome {
        data class Fire(val attemptNumber: Int) : GateOutcome()
        data class RateLimited(val nextEligibleAt: Long) : GateOutcome()
        data class AlreadyBudgetExhausted(val until: Long) : GateOutcome()
        data class BudgetExhaustedNow(val until: Long) : GateOutcome()
    }

    private fun evaluateAndArmInsideTxn(contactId: String, now: Long): GateOutcome {
        val row = readGateRow(contactId)

        if (row.budgetExhaustedUntil > now) {
            return GateOutcome.AlreadyBudgetExhausted(row.budgetExhaustedUntil)
        }

        // Roll 24h window: a non-zero start older than 24h means the prior window
        // closed without hitting the cap; start fresh.
        val windowActive = row.windowStart > 0 && (now - row.windowStart) < WINDOW_24H_MS
        val effectiveCount = if (windowActive) row.count24h else 0
        val effectiveWindowStart = if (windowActive) row.windowStart else now

        // Cap check BEFORE backoff so a fourth attempt arms budget rather than
        // sitting in rate-limit limbo forever.
        if (effectiveCount >= MAX_PER_24H) {
            val until = now + BUDGET_EXHAUSTED_MS
            writeGateRow(contactId, GateRow(
                windowStart = effectiveWindowStart,
                count24h = effectiveCount,
                lastAt = row.lastAt,
                budgetExhaustedUntil = until
            ))
            return GateOutcome.BudgetExhaustedNow(until)
        }

        // Backoff between attempts within the window. Index = how many attempts
        // ALREADY happened in this window (0..3). After 4 → handled above.
        if (effectiveCount > 0 && row.lastAt > 0) {
            val backoffMs = BACKOFF_SCHEDULE_MS[(effectiveCount - 1).coerceAtMost(BACKOFF_SCHEDULE_MS.size - 1)]
            val nextEligibleAt = row.lastAt + backoffMs
            if (now < nextEligibleAt) {
                return GateOutcome.RateLimited(nextEligibleAt)
            }
        }

        // Arm and fire.
        writeGateRow(contactId, GateRow(
            windowStart = effectiveWindowStart,
            count24h = effectiveCount + 1,
            lastAt = now,
            budgetExhaustedUntil = row.budgetExhaustedUntil
        ))
        return GateOutcome.Fire(attemptNumber = effectiveCount + 1)
    }

    // ----- raw-SQL accessors (in-txn so the gate update is atomic) -----

    private data class GateRow(
        val windowStart: Long,
        val count24h: Int,
        val lastAt: Long,
        val budgetExhaustedUntil: Long
    )

    private fun readGateRow(contactId: String): GateRow {
        return db.openHelper.writableDatabase.query(
            "SELECT auto_reset_window_start, auto_reset_count_24h, last_auto_reset_at, budget_exhausted_until " +
                "FROM contacts WHERE id = ?",
            arrayOf(contactId)
        ).use { c ->
            if (!c.moveToFirst()) throw IllegalStateException("contact $contactId not found")
            GateRow(
                windowStart = c.getLong(0),
                count24h = c.getInt(1),
                lastAt = c.getLong(2),
                budgetExhaustedUntil = c.getLong(3)
            )
        }
    }

    private fun writeGateRow(contactId: String, row: GateRow) {
        db.openHelper.writableDatabase.execSQL(
            "UPDATE contacts SET auto_reset_window_start = ?, auto_reset_count_24h = ?, " +
                "last_auto_reset_at = ?, budget_exhausted_until = ? WHERE id = ?",
            arrayOf<Any>(row.windowStart, row.count24h, row.lastAt, row.budgetExhaustedUntil, contactId)
        )
    }

    companion object {
        const val MAX_PER_24H = 4
        const val WINDOW_24H_MS = 24L * 60 * 60 * 1000
        const val BUDGET_EXHAUSTED_MS = 7L * 24 * 60 * 60 * 1000

        /**
         * Backoff between attempts within a 24h window, indexed by the number of
         * prior attempts already counted. Last entry (4h) is reachable only if
         * the cap check were ever loosened past 4/24h — kept here for spec
         * completeness so the schedule reads as written in §6.4.
         */
        val BACKOFF_SCHEDULE_MS: LongArray = longArrayOf(
            30L * 1000,        // after attempt #1 → wait 30s for #2
            5L * 60 * 1000,    // after attempt #2 → wait 5min for #3
            30L * 60 * 1000,   // after attempt #3 → wait 30min for #4
            4L * 60 * 60 * 1000 // after attempt #4 → wait 4h (unused; cap fires first)
        )

        /**
         * Map a Throwable into a [FailureClass]. ONLY [FailureClass.STRUCTURAL]
         * is eligible for auto-reset. Caller is expected to feed us only
         * load-path / persistence exceptions; UI / coroutine errors classify as
         * [FailureClass.OTHER] and are ignored.
         */
        fun classify(t: Throwable?): FailureClass = when (t) {
            null -> FailureClass.STRUCTURAL // explicit-call form: caller already classified
            is RatchetStatePersistence.RatchetStateCorrupt -> FailureClass.STRUCTURAL
            is WrapHmacMismatch -> FailureClass.CRYPTO_TAMPER
            is RatchetCryptoFailure -> FailureClass.AEAD
            is RatchetStatePersistence.RatchetNotBootstrapped -> FailureClass.OTHER
            else -> FailureClass.OTHER
        }
    }
}
