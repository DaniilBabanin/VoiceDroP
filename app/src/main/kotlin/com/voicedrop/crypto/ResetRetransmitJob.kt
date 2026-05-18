package com.voicedrop.crypto

import com.voicedrop.network.PendingOutboxReplay
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.PendingOutboundFrameEntity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap

/**
 * DR15 — Reset retransmit scheduler (§6.3 retransmit).
 *
 * After [ResetReceive.manualResetInitiate] inserts a RESET outbox row, this job
 * schedules retransmit attempts at fixed offsets (5s / 15s / 45s / 120s / 300s)
 * AFTER the initial send. Each tick calls [PendingOutboxReplay.replayAll] which
 * walks the outbox; the existing DR11 give-up cap (5 attempts OR 10 min
 * wall-clock for RESET rows) terminates the loop naturally once the cap fires.
 *
 * Termination paths:
 *   - Peer acks: [ResetReceive] clears `expecting_ack` AND deletes the RESET
 *     outbox row in the same txn. Next tick sees no row → exits.
 *   - Give-up cap fires: [PendingOutboxReplay] deletes the row on tick #6
 *     (attempts >= 5). Next tick sees no row → exits.
 *   - 10-min wall-clock cap on the row's `created_at`: same path as attempts cap.
 *   - App death: the schedule dies with the process. Restart recovery runs
 *     [PendingOutboxReplay.replayAll] from `App.onCreate` and re-fires the
 *     outbox row exactly once (no in-memory schedule resumes — the row's
 *     `created_at` + `attempts` are persisted so the give-up cap still applies).
 *
 * Connectivity-handover trigger: [onConnectivityAvailable] is wired to
 * `ConnectivityManager.NetworkCallback.onAvailable` and fires an
 * out-of-schedule [PendingOutboxReplay.replayAll]. Same persisted give-up
 * cap applies — it can't extend the 5-attempt or 10-min budget.
 *
 * Per-contact concurrency: [start] cancels any prior in-flight schedule for the
 * same contact before launching a new one. This handles back-to-back manual
 * inits and recipient-side retries cleanly.
 */
class ResetRetransmitJob(
    private val db: AppDatabase,
    private val replay: PendingOutboxReplay,
    private val scope: CoroutineScope,
    private val clock: () -> Long = { System.currentTimeMillis() },
    private val delayMs: suspend (Long) -> Unit = { delay(it) },
    private val schedule: LongArray = DEFAULT_SCHEDULE_MS,
    private val eventLog: (String) -> Unit = { android.util.Log.i("ResetRetransmitJob", it) }
) {

    private val activeJobs = ConcurrentHashMap<String, Job>()

    /**
     * Launch a retransmit schedule for [contactId]. Cancels any prior in-flight
     * job for the same contact. Returns the [Job] so callers (tests, lifecycle
     * owners) can await or cancel it.
     */
    fun start(contactId: String): Job {
        activeJobs.remove(contactId)?.cancel()
        val job = scope.launch { runSchedule(contactId) }
        activeJobs[contactId] = job
        job.invokeOnCompletion {
            activeJobs.remove(contactId, job)
        }
        return job
    }

    /** Cancel the in-flight schedule (if any) for [contactId]. */
    fun cancel(contactId: String) {
        activeJobs.remove(contactId)?.cancel()
    }

    /** Cancel every in-flight schedule. Invoke from the owning scope's teardown. */
    fun cancelAll() {
        val snapshot = activeJobs.values.toList()
        activeJobs.clear()
        snapshot.forEach { it.cancel() }
    }

    /**
     * Hook for `ConnectivityManager.NetworkCallback.onAvailable`: fires an
     * out-of-schedule [PendingOutboxReplay.replayAll]. Per-kind caps still apply
     * — a network change can't extend the 5-attempt or 10-min RESET budget.
     */
    suspend fun onConnectivityAvailable() {
        eventLog("reset.retransmit_connectivity")
        replay.replayAll()
    }

    private suspend fun runSchedule(contactId: String) {
        for (idx in schedule.indices) {
            delayMs(schedule[idx])
            val rowExists = hasOutboundReset(contactId)
            val expectingAck = isExpectingAck(contactId)

            if (!rowExists) {
                eventLog("reset.retransmit_complete contact=${contactId.take(8)} idx=$idx reason=no_row")
                return
            }
            if (!expectingAck) {
                // Row exists but the peer's ack already cleared expecting_ack —
                // [ResetReceive] should have deleted the row in that same txn; the
                // ordering here is belt-and-braces in case wiring drifts.
                eventLog("reset.retransmit_complete contact=${contactId.take(8)} idx=$idx reason=ack_cleared")
                return
            }

            eventLog(
                "reset.retransmit_fire contact=${contactId.take(8)} idx=$idx " +
                    "offsetMs=${schedule[idx]} at=${clock()}"
            )
            replay.replayAll()
        }
        eventLog("reset.retransmit_schedule_complete contact=${contactId.take(8)}")
    }

    private suspend fun hasOutboundReset(contactId: String): Boolean = withContext(Dispatchers.IO) {
        db.openHelper.writableDatabase.query(
            "SELECT 1 FROM pending_outbound_frames WHERE contact_id = ? AND frame_kind = ? LIMIT 1",
            arrayOf<Any>(contactId, PendingOutboundFrameEntity.FRAME_KIND_RESET)
        ).use { it.moveToFirst() }
    }

    private suspend fun isExpectingAck(contactId: String): Boolean = withContext(Dispatchers.IO) {
        db.openHelper.writableDatabase.query(
            "SELECT expecting_ack FROM contacts WHERE id = ? LIMIT 1",
            arrayOf<Any>(contactId)
        ).use { c -> c.moveToFirst() && c.getInt(0) != 0 }
    }

    companion object {
        /**
         * Per §6.3: 5s / 15s / 45s / 120s / 300s after the initial send. The DR11
         * give-up cap (5 attempts OR 10-min wall-clock) is the hard upper bound;
         * with `attempts=0` at insert, ticks #1–#5 transmit (attempts → 1..5) and
         * any subsequent tick fires give-up before any sixth transmit goes out.
         */
        val DEFAULT_SCHEDULE_MS: LongArray = longArrayOf(
            5_000L,
            15_000L,
            45_000L,
            120_000L,
            300_000L
        )
    }
}
