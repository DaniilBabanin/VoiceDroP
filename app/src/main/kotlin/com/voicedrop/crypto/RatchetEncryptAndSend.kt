package com.voicedrop.crypto

import com.voicedrop.network.FrameCodec
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.MessageEntity
import com.voicedrop.storage.PendingOutboundFrameEntity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.nio.ByteBuffer
import java.util.UUID
import java.util.concurrent.Callable

/**
 * DR7 — Encrypt-and-send: persistence + concurrency wiring around the pure
 * [Ratchet.advanceSend] crypto.
 *
 * Order is load-bearing — see [dr7-encrypt-path.md] §8.1:
 *
 *   1. Acquire per-contact [ContactMutexRegistry] mutex.
 *   2. On [Dispatchers.IO], inside a Room `runInTransaction`:
 *        load contact -> check `expecting_ack` -> load ratchet state
 *        -> advance send chain -> persist new state -> seal frame -> wrap+HMAC
 *        -> INSERT pending_outbound_frames -> INSERT messages.
 *   3. AFTER commit (still under mutex): transmit. If the transmit fails the
 *      committed row is already in the outbox and will be replayed by [dr11].
 *
 * The mutex spans (2) AND (3) so a concurrent decrypt cannot observe a
 * half-applied state, AND so two encrypts cannot race to derive `mk` for the
 * same `n` and AEAD-reuse the zero nonce ([dr7] §8.3).
 */
class RatchetEncryptAndSend(
    private val db: AppDatabase,
    private val wrapMac: WrapMac,
    /** SHA-256(ownIdentityPub) — 32 bytes. See [Bootstrap.fingerprintBytes]. */
    private val ownFingerprint32: ByteArray,
    private val transmit: suspend (contactId: String, frameBytes: ByteArray) -> Unit,
    private val clock: () -> Long = { System.currentTimeMillis() },
    private val newUuid: () -> ByteArray = ::defaultUuidBytes
) {

    init {
        require(ownFingerprint32.size == 32) { "ownFingerprint32 must be 32 bytes" }
    }

    /**
     * Encrypts [plaintext] for [contactId], persists the new ratchet state +
     * outbox row + message row in a single SQLite transaction, then transmits
     * the frame.
     *
     * @param buildMessage caller-supplied factory for the user-visible
     *   [MessageEntity]. Receives the wire-frame UUID (both hex and bytes) and
     *   the same `now` timestamp that landed in the frame header so the row's
     *   `createdAt` lines up with the wire timestamp.
     *
     * Throws:
     *   - [SessionResetInProgress] — `contact.expecting_ack != 0`. UI gates send.
     *   - [AwaitingFirstReceive] — Bob has not yet decrypted Alice's first frame.
     *   - [RatchetStatePersistence.RatchetNotBootstrapped] — pre-bootstrap row.
     *   - [WrapHmacMismatch] — DB tamper on ratchet columns (DR2 §9).
     *   - [WrapBudgetExhausted] — 2^30 wrap budget reached (DR2 §9.5).
     */
    suspend fun encryptAndSend(
        contactId: String,
        plaintext: ByteArray,
        buildMessage: (frameUuidHex: String, frameUuidBytes: ByteArray, now: Long) -> MessageEntity
    ): SentFrame = ContactMutexRegistry.forContact(contactId).withLock {
        val frame = withContext(Dispatchers.IO) {
            db.runInTransaction(Callable { commitInsideTxn(contactId, plaintext, buildMessage) })
        }
        runCatching { transmit(contactId, frame.wireBytes) }
            .onFailure { /* outbox replay (dr11) owns retries; swallow here */ }
        frame
    }

    private fun commitInsideTxn(
        contactId: String,
        plaintext: ByteArray,
        buildMessage: (String, ByteArray, Long) -> MessageEntity
    ): SentFrame {
        // Room's @Dao suspend methods can't be called from a sync `runInTransaction`
        // block; use blocking equivalents (or @Query directly) here.
        val contact = db.openHelper.writableDatabase
            .query("SELECT * FROM contacts WHERE id = ?", arrayOf(contactId))
            .use { c ->
                if (!c.moveToFirst()) throw IllegalStateException("contact $contactId not found")
                loadContactFromCursor(c)
            }

        if (contact.expecting_ack != 0) throw SessionResetInProgress(contactId)

        val state = RatchetStatePersistence.loadRatchetState(contact, wrapMac)
        val sendResult: Ratchet.SendResult
        try {
            sendResult = Ratchet.advanceSend(state)  // throws AwaitingFirstReceive if DHr null
        } catch (t: Throwable) {
            state.zeroize()
            throw t
        }

        val updatedContact = RatchetStatePersistence.saveRatchetState(contact, state, wrapMac)
        // Hand-rolled UPDATE on the same SupportSQLiteDatabase keeps everything in
        // the active transaction; avoids the suspend-only ContactDao.upsert.
        upsertContactBlocking(updatedContact)

        val frameUuid = newUuid()
        require(frameUuid.size == 16) { "newUuid() must return 16 bytes" }
        val now = clock()
        val peerFp = Bootstrap.fingerprintBytes(
            android.util.Base64.decode(contact.publicKeyBase64, android.util.Base64.NO_WRAP)
        )

        val wireBytes = try {
            FrameCodec.encode(
                kind = FrameCodec.FRAME_KIND_DATA,
                senderFp = ownFingerprint32,
                recipFp = peerFp,
                dhPub = sendResult.dhPub,
                pn = sendResult.pn,
                n = sendResult.n,
                uuid = frameUuid,
                timestampMs = now,
                key = sendResult.mk,
                plaintext = plaintext
            )
        } finally {
            sendResult.mk.fill(0)
        }

        val (wrappedFrame, frameHmac) = wrapMac.wrapAndMac(
            "pending_outbound_frames.wrapped_frame", frameUuid, wireBytes
        )
        db.pendingOutboundFrameDao().insertBlocking(
            PendingOutboundFrameEntity(
                uuid = frameUuid,
                contact_id = contactId,
                frame_kind = PendingOutboundFrameEntity.FRAME_KIND_DATA,
                wrapped_frame = wrappedFrame,
                frame_hmac = frameHmac,
                created_at = now,
                attempts = 0
            )
        )

        val frameUuidHex = bytesToHex(frameUuid)
        val message = buildMessage(frameUuidHex, frameUuid, now)
        insertMessageBlocking(message)

        // State is now committed-on-commit. Caller transmits after the txn returns.
        return SentFrame(
            frameUuid = frameUuid,
            frameUuidHex = frameUuidHex,
            wireBytes = wireBytes,
            dhPub = sendResult.dhPub,
            pn = sendResult.pn,
            n = sendResult.n
        )
    }

    // --- Blocking DB helpers ---
    //
    // Room's suspend DAO methods detach from the active transaction (they post
    // back to a coroutine context), so we drop down to SupportSQLiteDatabase to
    // stay inside `runInTransaction`. Same connection, same txn.

    private fun upsertContactBlocking(c: com.voicedrop.storage.ContactEntity) {
        val raw = db.openHelper.writableDatabase
        val vals = android.content.ContentValues().apply {
            put("id", c.id); put("name", c.name); put("publicKeyBase64", c.publicKeyBase64)
            put("addedAt", c.addedAt); put("autoDeleteAfterMs", c.autoDeleteAfterMs)
            put("pending_repair", c.pending_repair)
            put("dhs_priv_wrapped", c.dhs_priv_wrapped); put("dhs_priv_hmac", c.dhs_priv_hmac)
            put("dhs_pub", c.dhs_pub); put("dhr_pub", c.dhr_pub)
            put("rk_wrapped", c.rk_wrapped); put("rk_hmac", c.rk_hmac)
            put("cks_wrapped", c.cks_wrapped); put("cks_hmac", c.cks_hmac)
            put("ckr_wrapped", c.ckr_wrapped); put("ckr_hmac", c.ckr_hmac)
            put("ns", c.ns); put("nr", c.nr); put("pn", c.pn)
            put("reset_epoch", c.reset_epoch); put("reset_nonce", c.reset_nonce)
            put("expecting_ack", c.expecting_ack)
            put("auto_reset_window_start", c.auto_reset_window_start)
            put("auto_reset_count_24h", c.auto_reset_count_24h)
            put("last_auto_reset_at", c.last_auto_reset_at)
            put("inbound_reset_window_start", c.inbound_reset_window_start)
            put("inbound_reset_count_24h", c.inbound_reset_count_24h)
            put("budget_exhausted_until", c.budget_exhausted_until)
            put("consecutive_aead_failures", c.consecutive_aead_failures)
            put("consecutive_aead_failures_window_start", c.consecutive_aead_failures_window_start)
            put("soft_prompt_dismissed_until", c.soft_prompt_dismissed_until)
        }
        raw.insert("contacts", android.database.sqlite.SQLiteDatabase.CONFLICT_REPLACE, vals)
    }

    private fun insertMessageBlocking(m: MessageEntity) {
        val raw = db.openHelper.writableDatabase
        val vals = android.content.ContentValues().apply {
            put("uuid", m.uuid); put("contactId", m.contactId)
            put("direction", m.direction); put("state", m.state)
            put("transport", m.transport.value)
            put("encryptedFilePath", m.encryptedFilePath)
            put("durationMs", m.durationMs)
            put("deleteAfterMs", m.deleteAfterMs)
            put("scheduledDeleteAt", m.scheduledDeleteAt)
            put("transcription", m.transcription)
            put("createdAt", m.createdAt)
            put("sentAt", m.sentAt)
            put("deliveredAt", m.deliveredAt)
            put("delivery_state", m.delivery_state)
        }
        raw.insert("messages", android.database.sqlite.SQLiteDatabase.CONFLICT_ABORT, vals)
    }

    private fun loadContactFromCursor(c: android.database.Cursor): com.voicedrop.storage.ContactEntity {
        fun str(col: String) = c.getString(c.getColumnIndexOrThrow(col))
        fun lng(col: String) = c.getLong(c.getColumnIndexOrThrow(col))
        fun ints(col: String) = c.getInt(c.getColumnIndexOrThrow(col))
        fun blobOrNull(col: String): ByteArray? {
            val i = c.getColumnIndexOrThrow(col)
            return if (c.isNull(i)) null else c.getBlob(i)
        }
        fun blob(col: String): ByteArray = blobOrNull(col) ?: ByteArray(0)

        return com.voicedrop.storage.ContactEntity(
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

    companion object {
        // We deliberately do NOT use Room's `withTransaction` coroutine extension —
        // `runInTransaction(Callable {...})` on the IO dispatcher gives us strict
        // "commit completes before .also runs" ordering. See DR7 §8.1.

        private fun defaultUuidBytes(): ByteArray {
            val u = UUID.randomUUID()
            return ByteBuffer.allocate(16)
                .putLong(u.mostSignificantBits)
                .putLong(u.leastSignificantBits)
                .array()
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

/** Result of [RatchetEncryptAndSend.encryptAndSend]. */
class SentFrame(
    val frameUuid: ByteArray,
    val frameUuidHex: String,
    val wireBytes: ByteArray,
    val dhPub: ByteArray,
    val pn: Int,
    val n: Int
)

/**
 * Send blocked by an in-flight session reset. `contacts.expecting_ack != 0`.
 *
 * Owned-and-cleared by the reset state machine in [dr13]/[dr15]; DR7 only
 * raises the signal. UI surfaces this as a "session reset in progress" banner.
 */
class SessionResetInProgress(contactId: String) :
    RuntimeException("ratchet: session reset in progress for contact=$contactId")
