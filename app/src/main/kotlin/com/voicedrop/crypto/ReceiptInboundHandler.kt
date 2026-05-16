package com.voicedrop.crypto

import android.util.Log
import com.voicedrop.storage.AppDatabase
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.util.concurrent.Callable

/**
 * DR11 — §8.7 RECEIPT inbound handler.
 *
 * Runs AFTER [RatchetDecryptAndPersist] has opened a `frameKind = 0x02` frame and
 * returned [RatchetDecryptAndPersist.Result.ReceiptDecrypted]. Inside one Room
 * txn, under the per-contact ratchet mutex:
 *
 *  1. delete the matching `pending_outbound_frames` row (DATA UUID lookup; no-op
 *     if already cleared by a prior RECEIPT or by give-up),
 *  2. transition the sender-side `messages.delivery_state` PENDING → DELIVERED,
 *     stamping `deliveredAt = now`. Guarded by `delivery_state = PENDING` so a
 *     duplicate or late RECEIPT cannot overwrite a row that already gave up,
 *  3. emit `outbox.delivered` ([telemetry.md] §11.1).
 *
 * Mutex matches the encrypt/decrypt path ([ContactMutexRegistry]) so a concurrent
 * encrypt cannot race the message-row UPDATE.
 *
 * Idempotency:
 *  - re-delivered RECEIPT for an already-cleared `ackedUuid` → both DAO calls are
 *    no-ops (delete misses, UPDATE matches zero rows). Safe, returns [Outcome.NoChange].
 *  - the RECEIPT frame UUID itself is deduped upstream by [RatchetDecryptAndPersist]
 *    §8.2; this handler only sees RECEIPTs that already advanced the receiving chain.
 */
class ReceiptInboundHandler(
    private val db: AppDatabase,
    private val clock: () -> Long = { System.currentTimeMillis() },
    private val eventLog: (String) -> Unit = ::defaultLog
) {

    sealed class Outcome {
        /** Outbox row was cleared and / or the message transitioned to DELIVERED. */
        object Delivered : Outcome()
        /** Neither the outbox row nor the message row existed in a clearable state — late RECEIPT. */
        object NoChange : Outcome()
    }

    /**
     * Apply the RECEIPT for [ackedUuid] under [contactId].
     *
     * @param contactId originating contact (used for the mutex + event payload).
     * @param ackedUuid 16-byte UUID of the DATA frame being acknowledged
     *   (matches `pending_outbound_frames.uuid` BLOB and the hex-decoded
     *   `messages.uuid` String).
     */
    suspend fun onReceiptDecrypted(contactId: String, ackedUuid: ByteArray): Outcome {
        require(ackedUuid.size == 16) { "ackedUuid must be 16 bytes" }
        val ackedHex = bytesToHex(ackedUuid)
        val now = clock()
        return ContactMutexRegistry.forContact(contactId).withLock {
            val (outboxDeleted, messageMarked) = withContext(Dispatchers.IO) {
                db.runInTransaction(Callable {
                    val deleted = db.pendingOutboundFrameDao().deleteByUuidBlocking(ackedUuid)
                    val marked = db.messageDao().markDeliveredBlocking(ackedHex, now)
                    deleted to marked
                })
            }
            val changed = outboxDeleted > 0 || messageMarked > 0
            if (changed) {
                eventLog(
                    "outbox.delivered contact=${contactId.take(8)} acked=${ackedHex.take(8)} " +
                        "outboxDeleted=$outboxDeleted messageMarked=$messageMarked"
                )
                Outcome.Delivered
            } else {
                Outcome.NoChange
            }
        }
    }

    companion object {
        private const val TAG = "VoiceDrop/Receipt"

        private fun defaultLog(line: String) {
            Log.i(TAG, line)
        }

        private val HEX = charArrayOf('0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f')

        private fun bytesToHex(b: ByteArray): String {
            val sb = StringBuilder(b.size * 2)
            for (x in b) {
                val v = x.toInt() and 0xff
                sb.append(HEX[v ushr 4]); sb.append(HEX[v and 0x0f])
            }
            return sb.toString()
        }
    }
}

