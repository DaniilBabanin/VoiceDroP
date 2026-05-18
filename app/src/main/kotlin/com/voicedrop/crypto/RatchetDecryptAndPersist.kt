package com.voicedrop.crypto

import com.voicedrop.network.FrameCodec
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.ContactEntity
import com.voicedrop.storage.MessageEntity
import com.voicedrop.storage.PendingOutboundFrameEntity
import com.voicedrop.storage.SkippedKeyMaintenance
import com.voicedrop.storage.SkippedMessageKeyEntity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID
import java.util.concurrent.Callable

/**
 * DR8 — Decrypt-and-persist: clone-then-commit machinery around the pure
 * [Ratchet.decrypt] crypto. Symmetric counterpart to [RatchetEncryptAndSend].
 *
 * Order is load-bearing — see [dr8-decrypt-path.md] §8.2:
 *
 *   1. Acquire per-contact [ContactMutexRegistry] mutex (same one DR7 uses).
 *   2. On [Dispatchers.IO], inside a Room `runInTransaction`:
 *        a. UUID dedup against `messages`. If hit and DATA → re-enqueue RECEIPT
 *           (recovers from a lost prior RECEIPT) and return without re-advancing
 *           the receiving chain.
 *        b. Load contact + ratchet state.
 *        c. [Ratchet.decrypt] (clone-then-commit). AEAD failure throws
 *           [RatchetCryptoFailure] and the txn rolls back leaving state untouched.
 *           Skipped-key inserts/removes during this call go DIRECTLY into the
 *           active txn via [TxnSkippedKeyStore]; they're already conditional on
 *           AEAD success because [Ratchet.decrypt] only calls put/remove after
 *           the AEAD seal opens.
 *        d. Save new ratchet state; reset the consecutive-AEAD-failure counter.
 *        e. DATA → insert message row, then `enqueueReceipt`. RECEIPT → just
 *           return the plaintext for the [dr11] inbound handler.
 *        f. `enforceSkippedCap` — FIFO eviction to 2000 (DR9 owns the constants
 *           and the open-time sweep; we keep the cap call here so the DR8 path
 *           is the single source of insert pressure).
 *   3. AEAD failure: the txn rolled back, but per spec the consecutive-AEAD
 *      counter is bumped OUTSIDE the txn so churn does not lock the DB. The
 *      [dr14] soft-prompt threshold check is the caller's job.
 *
 * RESET frames (`frameKind=0x01`) are NOT handled here — the dispatcher in
 * [dr13] routes them BEFORE entering this method.
 */
class RatchetDecryptAndPersist(
    private val db: AppDatabase,
    private val wrapMac: WrapMac,
    /** SHA-256(ownIdentityPub) — 32 bytes. Used as `senderFp` on enqueued RECEIPTs. */
    private val ownFingerprint32: ByteArray,
    private val clock: () -> Long = { System.currentTimeMillis() },
    private val newUuid: () -> ByteArray = ::defaultUuidBytes
) {

    init {
        require(ownFingerprint32.size == 32) { "ownFingerprint32 must be 32 bytes" }
    }

    /**
     * Outcome of [receive]. Callers route on the variant:
     *   - [Delivered] — DATA frame opened, message row persisted, RECEIPT in outbox.
     *   - [DuplicateData] — DATA frame already in DB; ratchet untouched, a fresh
     *     RECEIPT was re-enqueued (recovers from a lost prior RECEIPT).
     *   - [ReceiptDecrypted] — RECEIPT frame opened; caller hands `ackedUuid`
     *     and `plaintext` to the [dr11] inbound-RECEIPT handler.
     */
    sealed class Result {
        class Delivered(val plaintext: ByteArray, val messageUuidHex: String) : Result()
        class DuplicateData(val messageUuidHex: String) : Result()
        class ReceiptDecrypted(val ackedUuid: ByteArray, val plaintext: ByteArray) : Result()
        /** RECEIPT frame UUID collided with a stored message UUID — vanishingly rare; benign no-op. */
        object DuplicateReceipt : Result()
    }

    /**
     * Decrypt + persist a DATA or RECEIPT frame for [contactId].
     *
     * @param buildInboundMessage caller-supplied factory for the INBOUND
     *   [MessageEntity]. Only invoked on the DATA fresh-delivery path. Receives
     *   the decrypted plaintext, the frame UUID (hex + bytes), and the wire
     *   timestamp from the frame header. **Returning null skips the `messages`
     *   insert** — used by the DR17.5 inner-plaintext dispatcher for HELLO
     *   (sentinel, no UI row), DELETE (handles its own row delete inside the
     *   same txn), and unknown future kinds (per the forward-compat contract
     *   in dr17.5 §"Forward compatibility": RECEIPT enqueues, payload drops
     *   silently). The callback runs INSIDE the txn so any side-effects it
     *   performs (e.g. raw-SQL row delete via `db.openHelper.writableDatabase`)
     *   are atomic with state advance and RECEIPT enqueue. Throwing rolls back
     *   the txn and surfaces the exception to the caller.
     *
     * Throws:
     *   - [RatchetCryptoFailure] — AEAD failure (txn rolled back; state untouched).
     *   - [InvalidFrame] — malformed RECEIPT plaintext, bad frame kind for this entry.
     *   - [RatchetStatePersistence.RatchetNotBootstrapped] — pre-bootstrap row.
     *   - [WrapHmacMismatch] — DB tamper on ratchet columns.
     *   - [SkipLimitExceeded] — `n > Nr + MAX_SKIP` (DoS guard, [dr6] §4.5).
     */
    suspend fun receive(
        contactId: String,
        frame: FrameCodec.DecodedFrame,
        buildInboundMessage: (
            plaintext: ByteArray,
            frameUuidHex: String,
            frameUuidBytes: ByteArray,
            timestampMs: Long
        ) -> MessageEntity?
    ): Result = ContactMutexRegistry.forContact(contactId).withLock {
        try {
            withContext(Dispatchers.IO) {
                db.runInTransaction(Callable { commitInsideTxn(contactId, frame, buildInboundMessage) })
            }
        } catch (e: RatchetCryptoFailure) {
            // §8.2 — counter increment lives OUTSIDE the txn so AEAD-failure
            // churn from an attacker cannot lock the DB. [dr14] reads this
            // counter to decide whether to surface the soft prompt.
            withContext(Dispatchers.IO) {
                bumpConsecutiveAeadFailuresOutsideTxn(contactId, clock())
            }
            throw e
        }
    }

    // ----- inside-txn path -----

    private fun commitInsideTxn(
        contactId: String,
        frame: FrameCodec.DecodedFrame,
        buildInboundMessage: (ByteArray, String, ByteArray, Long) -> MessageEntity?
    ): Result {
        val frameUuidHex = bytesToHex(frame.uuid)

        // 1) UUID dedup against `messages` is cheap and lets us avoid even
        //    loading ratchet state on a re-delivery storm.
        val already = isMessageInDb(frameUuidHex)
        val contact = loadContactBlocking(contactId)
        val peerFp = peerFingerprintOf(contact)
        val now = clock()

        if (already) {
            return handleDuplicate(contact, frame, frameUuidHex, peerFp, now)
        }

        val state = RatchetStatePersistence.loadRatchetState(contact, wrapMac)
        val skippedStore = TxnSkippedKeyStore(
            dao = db.skippedMessageKeyDao(),
            wrapMac = wrapMac,
            contactId = contactId,
            now = now
        )

        // 2) Pure-crypto core. Mutates `state` in place AFTER AEAD success;
        //    AEAD failure throws RatchetCryptoFailure → txn rolls back.
        //    Skipped-key DB writes via `skippedStore` also only fire after
        //    AEAD success (Ratchet.decrypt guarantees this — see [dr6] §4.4).
        val plaintext = Ratchet.decrypt(
            state, skippedStore,
            frame.dhPub, frame.pn, frame.n, frame.ciphertext, frame.aad
        )

        // 3) Persist new ratchet state + zero the AEAD-failure heuristic counter.
        val contactAfterRecv = RatchetStatePersistence.saveRatchetState(contact, state, wrapMac)
            .copy(consecutive_aead_failures = 0, consecutive_aead_failures_window_start = 0L)

        return when (frame.kind) {
            FrameCodec.FRAME_KIND_DATA -> {
                val message = buildInboundMessage(plaintext, frameUuidHex, frame.uuid, frame.timestampMs)
                if (message != null) insertInboundMessageBlocking(message)

                // 4) Enqueue authenticated RECEIPT — advances Ns, writes outbox row.
                val contactAfterReceipt =
                    enqueueReceiptInsideTxn(state, frame.uuid, contactAfterRecv, peerFp, now)
                upsertContactBlocking(contactAfterReceipt)

                enforceSkippedCap(contactId)
                Result.Delivered(plaintext, frameUuidHex)
            }
            FrameCodec.FRAME_KIND_RECEIPT -> {
                upsertContactBlocking(contactAfterRecv)
                enforceSkippedCap(contactId)
                val ackedUuid = parseReceiptAcked(plaintext)
                Result.ReceiptDecrypted(ackedUuid, plaintext)
            }
            else -> throw InvalidFrame("unsupported frame.kind=${frame.kind} in DR8 path")
        }
    }

    private fun handleDuplicate(
        contact: ContactEntity,
        frame: FrameCodec.DecodedFrame,
        frameUuidHex: String,
        peerFp: ByteArray,
        now: Long
    ): Result {
        return when (frame.kind) {
            FrameCodec.FRAME_KIND_DATA -> {
                // §8.2: re-enqueue a fresh RECEIPT but do NOT re-advance the
                // receiving chain. The sender's prior DATA already landed in
                // our DB; this path repairs the "DATA delivered, RECEIPT lost"
                // window. RECEIPT advances ONLY our sending chain.
                val state = RatchetStatePersistence.loadRatchetState(contact, wrapMac)
                val updated = enqueueReceiptInsideTxn(state, frame.uuid, contact, peerFp, now)
                upsertContactBlocking(updated)
                Result.DuplicateData(frameUuidHex)
            }
            FrameCodec.FRAME_KIND_RECEIPT -> Result.DuplicateReceipt
            else -> throw InvalidFrame("unsupported frame.kind=${frame.kind} in DR8 dedup path")
        }
    }

    /**
     * Build, seal, wrap, and outbox a RECEIPT frame for [ackedUuid]. Mutates
     * [state] in place (Ns += 1). Returns a copy of [contact] with the new
     * ratchet state baked in — caller upserts it.
     */
    private fun enqueueReceiptInsideTxn(
        state: RatchetState,
        ackedUuid: ByteArray,
        contact: ContactEntity,
        peerFp: ByteArray,
        now: Long
    ): ContactEntity {
        require(ackedUuid.size == 16) { "ackedUuid must be 16 bytes" }
        val plaintext = ByteArray(17).also {
            it[0] = RECEIPT_VERSION
            ackedUuid.copyInto(it, 1)
        }
        val sendResult = Ratchet.advanceSend(state)
        val receiptUuid = newUuid().also { require(it.size == 16) { "newUuid() must return 16 bytes" } }

        val wireBytes = try {
            FrameCodec.encode(
                kind = FrameCodec.FRAME_KIND_RECEIPT,
                senderFp = ownFingerprint32,
                recipFp = peerFp,
                dhPub = sendResult.dhPub,
                pn = sendResult.pn,
                n = sendResult.n,
                uuid = receiptUuid,
                timestampMs = now,
                key = sendResult.mk,
                plaintext = plaintext
            )
        } finally {
            sendResult.mk.fill(0)
        }

        val (wrapped, hmac) = wrapMac.wrapAndMac(
            "pending_outbound_frames.wrapped_frame", receiptUuid, wireBytes
        )
        db.pendingOutboundFrameDao().insertBlocking(
            PendingOutboundFrameEntity(
                uuid = receiptUuid,
                contact_id = contact.id,
                frame_kind = PendingOutboundFrameEntity.FRAME_KIND_RECEIPT,
                wrapped_frame = wrapped,
                frame_hmac = hmac,
                created_at = now,
                attempts = 0
            )
        )
        return RatchetStatePersistence.saveRatchetState(contact, state, wrapMac)
    }

    /**
     * §8.5 cap — FIFO down to [SkippedKeyMaintenance.CAP_PER_CONTACT] on this
     * contact. Single-source insert-pressure pruner; runs in the same SQLite txn
     * as the insert. The complementary 7-day expiry sweep fires on
     * `AppDatabase` open (DR9).
     */
    private fun enforceSkippedCap(contactId: String) {
        SkippedKeyMaintenance.enforceCap(db.skippedMessageKeyDao(), contactId)
    }

    // ----- DB helpers (SupportSQLite-level so we stay inside the txn) -----

    private fun isMessageInDb(uuidHex: String): Boolean =
        db.openHelper.writableDatabase
            .query("SELECT 1 FROM messages WHERE uuid = ? LIMIT 1", arrayOf(uuidHex))
            .use { c -> c.moveToFirst() }

    private fun loadContactBlocking(contactId: String): ContactEntity =
        db.openHelper.writableDatabase
            .query("SELECT * FROM contacts WHERE id = ?", arrayOf(contactId))
            .use { c ->
                if (!c.moveToFirst()) throw IllegalStateException("contact $contactId not found")
                loadContactFromCursor(c)
            }

    private fun upsertContactBlocking(c: ContactEntity) {
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
        // UPDATE not INSERT-OR-REPLACE: SQLite's CONFLICT_REPLACE strategy is
        // DELETE-then-INSERT, which cascades through ForeignKey.CASCADE on
        // `pending_outbound_frames`, `messages`, and `skipped_message_keys` —
        // wiping out the rows this same transaction just inserted.
        val rows = raw.update(
            "contacts",
            android.database.sqlite.SQLiteDatabase.CONFLICT_ABORT,
            vals,
            "id = ?",
            arrayOf<Any>(c.id)
        )
        check(rows == 1) { "expected exactly one contact row updated, got $rows for id=${c.id}" }
    }

    private fun insertInboundMessageBlocking(m: MessageEntity) {
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

    private fun bumpConsecutiveAeadFailuresOutsideTxn(contactId: String, now: Long) {
        // Single-row UPDATE outside any txn — the contention concern in §8.2 is
        // that a long-running write txn would block the AEAD-failure churn, so
        // we keep this a one-shot write. The window-start is initialized lazily
        // by [dr14]; we only touch the counter here.
        val raw = db.openHelper.writableDatabase
        raw.execSQL(
            "UPDATE contacts SET consecutive_aead_failures = consecutive_aead_failures + 1, " +
                "consecutive_aead_failures_window_start = CASE WHEN consecutive_aead_failures_window_start = 0 " +
                "THEN ? ELSE consecutive_aead_failures_window_start END " +
                "WHERE id = ?",
            arrayOf<Any>(now, contactId)
        )
    }

    private fun peerFingerprintOf(contact: ContactEntity): ByteArray {
        val pub = android.util.Base64.decode(contact.publicKeyBase64, android.util.Base64.NO_WRAP)
        return Bootstrap.fingerprintBytes(pub)
    }

    private fun loadContactFromCursor(c: android.database.Cursor): ContactEntity {
        fun str(col: String) = c.getString(c.getColumnIndexOrThrow(col))
        fun lng(col: String) = c.getLong(c.getColumnIndexOrThrow(col))
        fun ints(col: String) = c.getInt(c.getColumnIndexOrThrow(col))
        fun blobOrNull(col: String): ByteArray? {
            val i = c.getColumnIndexOrThrow(col)
            return if (c.isNull(i)) null else c.getBlob(i)
        }
        fun blob(col: String): ByteArray = blobOrNull(col) ?: ByteArray(0)
        return ContactEntity(
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
        /** RECEIPT plaintext: `version:1 || ackedUuid:16` = 17 bytes (overview §2). */
        const val RECEIPT_VERSION: Byte = 0x01
        const val RECEIPT_PLAINTEXT_SIZE = 17

        // Visible to tests in the same module (DR16 §10.1
        // `receipt_versionByteRejected_ifNotOx01`). Never call from non-test
        // code outside this class.
        internal fun parseReceiptAcked(plaintext: ByteArray): ByteArray {
            if (plaintext.size != RECEIPT_PLAINTEXT_SIZE) {
                throw InvalidFrame("RECEIPT plaintext size=${plaintext.size} != $RECEIPT_PLAINTEXT_SIZE")
            }
            if (plaintext[0] != RECEIPT_VERSION) {
                throw InvalidFrame("RECEIPT plaintext version=${plaintext[0].toInt() and 0xff}")
            }
            return plaintext.copyOfRange(1, RECEIPT_PLAINTEXT_SIZE)
        }

        private fun defaultUuidBytes(): ByteArray {
            val u = UUID.randomUUID()
            return ByteBuffer.allocate(16)
                .order(ByteOrder.BIG_ENDIAN)
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

/**
 * Room-backed [SkippedKeyStore] scoped to a single contact + active SQLite txn.
 *
 * `get` returns the unwrapped mk (or null); `put` wraps-and-MACs then INSERTs;
 * `remove` DELETEs the row. All ops are synchronous and run on the caller's
 * thread inside `runInTransaction(Callable {...})`. AEAD failure in
 * [Ratchet.decrypt] throws before any `put` / `remove` fires, so the txn rolls
 * back with no skipped-key delta — staging buffer not needed.
 *
 * Row-id for HMAC binding is `contact_id || dhr_pub || be32(n)` per DR2 §9.2.
 */
class TxnSkippedKeyStore(
    private val dao: com.voicedrop.storage.SkippedMessageKeyDao,
    private val wrapMac: WrapMac,
    private val contactId: String,
    private val now: Long
) : SkippedKeyStore {

    override fun get(dhPub: ByteArray, n: Int): ByteArray? {
        val wrapped = dao.getWrappedBlocking(contactId, dhPub, n) ?: return null
        val hmac = dao.getHmacBlocking(contactId, dhPub, n) ?: return null
        val rowId = rowIdBytes(contactId, dhPub, n)
        return wrapMac.unwrapAndVerify(COL, rowId, wrapped, hmac)
    }

    override fun put(dhPub: ByteArray, n: Int, mk: ByteArray) {
        require(dhPub.size == 32) { "dhPub must be 32 bytes" }
        require(mk.size == 32) { "mk must be 32 bytes" }
        require(n >= 0) { "n must be non-negative" }
        val rowId = rowIdBytes(contactId, dhPub, n)
        val (wrapped, hmac) = wrapMac.wrapAndMac(COL, rowId, mk)
        dao.insertBlocking(
            SkippedMessageKeyEntity(
                contact_id = contactId,
                dhr_pub = dhPub.copyOf(),
                n = n,
                mk_wrapped = wrapped,
                mk_hmac = hmac,
                created_at = now
            )
        )
    }

    override fun remove(dhPub: ByteArray, n: Int): Boolean =
        dao.deleteByKeyBlocking(contactId, dhPub, n) > 0

    private companion object {
        private const val COL = "skipped_message_keys.mk_wrapped"

        private fun rowIdBytes(contactId: String, dhPub: ByteArray, n: Int): ByteArray {
            val idBytes = contactId.toByteArray(Charsets.UTF_8)
            val buf = ByteBuffer.allocate(idBytes.size + dhPub.size + 4).order(ByteOrder.BIG_ENDIAN)
            buf.put(idBytes); buf.put(dhPub); buf.putInt(n)
            return buf.array()
        }
    }
}
