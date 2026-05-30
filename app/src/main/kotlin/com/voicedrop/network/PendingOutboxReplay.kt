package com.voicedrop.network

import android.util.Log
import com.voicedrop.crypto.WrapMac
import com.voicedrop.crypto.WrapHmacMismatch
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.PendingOutboundFrameEntity
import com.voicedrop.util.bytesToHex
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * DR11 — §8.6 outbox replay worker.
 *
 * Drains [com.voicedrop.storage.PendingOutboundFrameEntity] (the v2 outbox).
 * Triggered from `VoiceDropService.onCreate` (startup), the
 * `ConnectivityManager.NetworkCallback.onAvailable` callback, LAN/presence
 * peer-appearance hooks, and the active-backoff retry loop inside
 * `ConnectionManager`. The post-DR17.5 wire path uses [com.voicedrop.crypto.RatchetEncryptAndSend]
 * (encrypt) + [com.voicedrop.crypto.RatchetDecryptAndPersist] (decrypt) — the
 * v1 frame builder/parser is gone (`MessageCrypto.kt` deleted on the cutover).
 *
 * Lifecycle per row:
 *
 *   1. If the per-kind give-up cap fires (attempts or age), delete the row and —
 *      for DATA — mark the message GAVE_UP. Emit `outbox.give_up`. Continue.
 *   2. Otherwise, increment `attempts`, unwrap the frame ([WrapMac]) and hand it
 *      to [transmit].
 *   3. On `transmit` success: RECEIPT / RESET rows are deleted (peer received and
 *      will not RECEIPT them — RECEIPTs aren't acked; resets clear via
 *      `expecting_ack` in [dr13]). DATA rows are left in place — only an
 *      authenticated peer RECEIPT clears them.
 *   4. On `transmit` failure: the row stays. The next replay tick will retry,
 *      and the bumped `attempts` will eventually trip the cap.
 *
 * Per-kind caps (canonical values live in [00-overview.md] §2):
 *
 *   | kind    | attempts | age           |
 *   |---------|---------:|---------------|
 *   | DATA    |       30 | 30 days       |
 *   | RECEIPT |       10 | 7 days        |
 *   | RESET   |        5 | 10 min        |
 *
 * The replay loop holds [replayMutex] so concurrent `replayAll` invocations (e.g.
 * app foreground + network callback firing back-to-back) serialize. Per-contact
 * ratchet mutex is NOT taken — rows are opaque ciphertext from the replay's
 * perspective; ratchet state belongs to [dr7] / [dr8].
 *
 * **Tamper signal:** if [WrapMac.unwrapAndVerify] throws [WrapHmacMismatch] on a
 * row, the row is dropped silently and an event is emitted — the row body has
 * been corrupted at the DB layer and cannot be transmitted. This is not a
 * structural-corruption / auto-reset trigger ([dr14]).
 */
class PendingOutboxReplay(
    private val db: AppDatabase,
    private val wrapMac: WrapMac,
    private val transmit: suspend (frameKind: Int, contactId: String, frameBytes: ByteArray) -> Boolean,
    private val clock: () -> Long = { System.currentTimeMillis() },
    private val eventLog: (String) -> Unit = ::defaultLog
) {
    private val replayMutex = Mutex()

    /**
     * Replay every row in `pending_outbound_frames` ordered by `created_at ASC`.
     * Idempotent and safe to call concurrently — [replayMutex] serializes runs.
     */
    suspend fun replayAll() = replayMutex.withLock {
        val rows = withContext(Dispatchers.IO) { db.pendingOutboundFrameDao().getAllBlocking() }
        for (row in rows) {
            try {
                replayOne(row)
            } catch (t: Throwable) {
                eventLog(
                    "outbox.replay_error contact=${row.contact_id.take(8)} " +
                        "kind=${row.frame_kind} uuid=${bytesToHex(row.uuid).take(8)} err=${t::class.simpleName}"
                )
            }
        }
    }

    private suspend fun replayOne(row: PendingOutboundFrameEntity) {
        // §3.2 invariant: do NOT re-derive K_reset on the retransmit path. The wrapped
        // frame bytes were keyed under prekeySS at enqueue time; the active prekey may
        // have rotated since. Re-derivation would silently key the replay under the
        // wrong epoch. Replay the persisted bytes verbatim.
        val now = clock()
        if (hasGivenUp(row, now)) {
            handleGiveUp(row, now)
            return
        }

        val frame = try {
            withContext(Dispatchers.IO) {
                wrapMac.unwrapAndVerify(
                    "pending_outbound_frames.wrapped_frame", row.uuid, row.wrapped_frame, row.frame_hmac
                )
            }
        } catch (e: WrapHmacMismatch) {
            // Tamper on the outbox column — drop the row, emit a wrap event. The
            // separate `wrap.hmac_mismatch` event ([dr2]) covers the contact-row
            // case; this one disambiguates the outbox row.
            withContext(Dispatchers.IO) { db.pendingOutboundFrameDao().deleteByUuidBlocking(row.uuid) }
            eventLog(
                "wrap.hmac_mismatch column=pending_outbound_frames.wrapped_frame " +
                    "contact=${row.contact_id.take(8)} uuid=${bytesToHex(row.uuid).take(8)}"
            )
            return
        }

        withContext(Dispatchers.IO) { db.pendingOutboundFrameDao().incrementAttemptsBlocking(row.uuid) }
        val attempt = row.attempts + 1
        eventLog(
            "outbox.replay_attempt contact=${row.contact_id.take(8)} kind=${row.frame_kind} " +
                "uuid=${bytesToHex(row.uuid).take(8)} attempt=$attempt"
        )

        val sent = try {
            transmit(row.frame_kind, row.contact_id, frame)
        } catch (t: Throwable) {
            eventLog(
                "outbox.transmit_error contact=${row.contact_id.take(8)} kind=${row.frame_kind} " +
                    "uuid=${bytesToHex(row.uuid).take(8)} err=${t::class.simpleName}"
            )
            false
        }

        if (sent && row.frame_kind != PendingOutboundFrameEntity.FRAME_KIND_DATA) {
            // RECEIPT / RESET: cleared on transmit success. DATA stays until the
            // peer's authenticated RECEIPT arrives (§8.7) or the give-up cap fires.
            withContext(Dispatchers.IO) { db.pendingOutboundFrameDao().deleteByUuidBlocking(row.uuid) }
        }
    }

    private fun hasGivenUp(row: PendingOutboundFrameEntity, now: Long): Boolean {
        val ageMs = now - row.created_at
        return when (row.frame_kind) {
            PendingOutboundFrameEntity.FRAME_KIND_DATA ->
                row.attempts >= DATA_GIVE_UP_ATTEMPTS || ageMs >= DATA_GIVE_UP_AGE_MS
            PendingOutboundFrameEntity.FRAME_KIND_RECEIPT ->
                row.attempts >= RECEIPT_GIVE_UP_ATTEMPTS || ageMs >= RECEIPT_GIVE_UP_AGE_MS
            PendingOutboundFrameEntity.FRAME_KIND_RESET ->
                row.attempts >= RESET_GIVE_UP_ATTEMPTS || ageMs >= RESET_GIVE_UP_AGE_MS
            else -> false
        }
    }

    private suspend fun handleGiveUp(row: PendingOutboundFrameEntity, now: Long) {
        val uuidHex = bytesToHex(row.uuid)
        withContext(Dispatchers.IO) {
            db.runInTransaction(java.util.concurrent.Callable {
                db.pendingOutboundFrameDao().deleteByUuidBlocking(row.uuid)
                if (row.frame_kind == PendingOutboundFrameEntity.FRAME_KIND_DATA) {
                    db.messageDao().markGaveUpBlocking(uuidHex)
                }
                Unit
            })
        }
        eventLog(
            "outbox.give_up contact=${row.contact_id.take(8)} kind=${row.frame_kind} " +
                "uuid=${uuidHex.take(8)} attempts=${row.attempts} ageMs=${now - row.created_at}"
        )
    }

    companion object {
        // Canonical values: plan/08-dr/00-overview.md §2.
        const val DATA_GIVE_UP_ATTEMPTS: Int = 30
        const val DATA_GIVE_UP_AGE_MS: Long = 30L * 24L * 60L * 60L * 1000L

        const val RECEIPT_GIVE_UP_ATTEMPTS: Int = 10
        const val RECEIPT_GIVE_UP_AGE_MS: Long = 7L * 24L * 60L * 60L * 1000L

        const val RESET_GIVE_UP_ATTEMPTS: Int = 5
        const val RESET_GIVE_UP_AGE_MS: Long = 10L * 60L * 1000L

        private const val TAG = "VoiceDrop/Outbox"

        private fun defaultLog(line: String) {
            Log.i(TAG, line)
        }
    }
}
