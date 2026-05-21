package com.voicedrop.crypto

import android.util.Log
import com.voicedrop.storage.AppDatabase
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.util.UUID
import java.util.concurrent.Callable

/**
 * Spec `16-played-receipt.md` §2 — `KIND_PLAYED` inbound handler.
 *
 * Runs after [RatchetDecryptAndPersist] has opened a `frameKind = 0x00` (DATA)
 * frame whose inner-plaintext kind is `KIND_PLAYED = 0x03`. Inside one Room txn,
 * under the per-contact ratchet mutex:
 *
 *  1. UPDATE messages SET state = STATE_PLAYED WHERE the row is outbound, owned
 *     by [contactId], and in STATE_SENT or STATE_DELIVERED (idempotent guard).
 *  2. Backfill `deliveredAt` for the race case (STATE_SENT row whose PLAYED
 *     arrived before our own wire-RECEIPT for the corresponding VOICE).
 *  3. Emit `played.applied` telemetry.
 *
 * **UUID format invariant** — `messages.uuid` PK is 32-char undashed hex for
 * outbound rows (`MultiRecipientSender.kt:85` uses `frameUuidHex`) and 36-char
 * dashed UUID for inbound rows (`ConnectionManager.kt:553` uses
 * `uuidBytesToUuidString`). This handler targets outbound rows only, so it
 * converts the incoming [UUID] to its 32-char hex form before the DAO lookup.
 *
 * Mutex matches the encrypt/decrypt path ([ContactMutexRegistry]) so a concurrent
 * encrypt cannot race the message-row UPDATE. Closest analogue is
 * [ReceiptInboundHandler] — same shape, different effect.
 *
 * Idempotency:
 *  - re-delivered PLAYED for an already-flipped row → UPDATE matches zero rows.
 *    Safe, returns [Outcome.NoChange].
 *  - terminal states (STATE_DELETED, STATE_UNDELIVERABLE) reject by SQL guard —
 *    keep the sender's prior display (⌫ or !) rather than resurrecting.
 *  - PLAYED targeting an inbound row (shouldn't happen) is filtered by the
 *    `direction = DIRECTION_OUTBOUND` predicate AND the uuid-format mismatch
 *    (inbound rows store dashed UUIDs, not 32-char hex).
 *  - The frame UUID itself is deduped upstream by [RatchetDecryptAndPersist].
 */
class PlayedInboundHandler(
    private val db: AppDatabase,
    private val clock: () -> Long = { System.currentTimeMillis() },
    private val eventLog: (String) -> Unit = ::defaultLog
) {

    sealed class Outcome {
        /** Row transitioned to STATE_PLAYED. */
        object Played : Outcome()
        /** UPDATE matched zero rows — terminal state, idempotent, or unknown target. */
        object NoChange : Outcome()
    }

    /**
     * Apply KIND_PLAYED for [targetUuid] under [contactId].
     *
     * @param contactId originating contact (mutex key + cross-contact spoof guard).
     * @param targetUuid 16-byte UUID of the original VOICE message, as
     *   [java.util.UUID]. Converted to the 32-char hex PK form internally.
     */
    suspend fun onPlayedDecrypted(contactId: String, targetUuid: UUID): Outcome {
        val targetHex = targetUuid.toHex32()
        val now = clock()
        return ContactMutexRegistry.forContact(contactId).withLock {
            val flipped = withContext(Dispatchers.IO) {
                db.runInTransaction(Callable {
                    val rows = db.messageDao().markPlayedBlocking(targetHex, contactId)
                    if (rows > 0) {
                        db.messageDao().backfillDeliveredAtBlocking(targetHex, now)
                    }
                    rows
                })
            }
            if (flipped > 0) {
                eventLog(
                    "played.applied contact=${contactId.take(8)} target=${targetHex.take(8)} rows=$flipped"
                )
                Outcome.Played
            } else {
                Outcome.NoChange
            }
        }
    }

    companion object {
        private const val TAG = "VoiceDrop/Played"

        private fun defaultLog(line: String) {
            Log.i(TAG, line)
        }

        /** Convert a [UUID] to its 32-char lowercase undashed hex form. */
        private fun UUID.toHex32(): String =
            "%016x%016x".format(mostSignificantBits, leastSignificantBits)
    }
}
