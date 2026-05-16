package com.voicedrop.crypto

import com.google.crypto.tink.subtle.X25519
import com.voicedrop.network.FrameCodec
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.ContactEntity
import com.voicedrop.storage.PendingOutboundFrameEntity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.nio.ByteBuffer
import java.util.UUID
import java.util.concurrent.Callable

/**
 * DR13 — Reset receive logic (§6.3) and manual initiation.
 *
 * Inbound: [onResetFrame] runs the §6.3 pseudocode end-to-end on the per-contact
 * [ContactMutexRegistry] mutex inside a single Room transaction. Pre-AEAD drops
 * (replayed `R`, +16 jump cap, budget-exhausted window) short-circuit before any
 * crypto. Post-AEAD inbound rate limit (4 fresh-R / 24h) trips a 7-day budget
 * exhaustion window — applied AFTER AEAD so unauthenticated spam can't burn the
 * budget ([dr10] already bounds raw inbound rate).
 *
 * Outbound (manual): [manualResetInitiate] wipes ratchet state, bootstraps a new
 * `RK_0` via [Bootstrap.deriveResetRootKey], generates a fresh `dhs` ephemeral
 * (Bob-role only), persists `reset_nonce` + `expecting_ack=true`, and INSERTs a
 * RESET row into `pending_outbound_frames` — all inside one transaction. The
 * [dr15] retransmit loop owns redelivery.
 *
 * Identity-shared-secret retrieval is indirected via [idSharedSecretFor] so this
 * class stays decoupled from `AndroidKeyStore`. Production passes a lambda that
 * computes `X25519(idPriv, peerIdPub)` via [KeyManager]; tests inject a fixture.
 *
 * Not wired into [com.voicedrop.network] dispatch yet — that lives in the
 * v2 cutover of `ConnectionManager.processFrame`. See [dr13-reset-receive.md].
 */
class ResetReceive(
    private val db: AppDatabase,
    private val wrapMac: WrapMac,
    /** SHA-256(ownIdentityPub) — 32 bytes. */
    private val ownFingerprint32: ByteArray,
    /** Returns `X25519(ourIdentityPriv, contact.peerIdPub)`. Caller may pre-cache; we wipe the result. */
    private val idSharedSecretFor: suspend (contactId: String) -> ByteArray,
    private val clock: () -> Long = { System.currentTimeMillis() },
    private val newUuid: () -> ByteArray = ::defaultUuidBytes,
    private val newX25519: () -> X25519KeyPair = ::generateX25519KeyPair,
    private val eventLog: (String) -> Unit = { android.util.Log.i("ResetReceive", it) }
) {

    init {
        require(ownFingerprint32.size == FrameCodec.FP_BYTES) {
            "ownFingerprint32 must be ${FrameCodec.FP_BYTES} bytes"
        }
    }

    /** Result of [onResetFrame] / [manualResetInitiate]. Caller maps to UI banners + telemetry. */
    sealed class Outcome {
        /** Inbound `R_in > contact.R`: ratchet wiped, RK_0 rebootstrapped, ack=1 enqueued if needed. */
        object FreshReset : Outcome()
        /** Inbound `R_in == contact.R` && expecting_ack && ack==1: peer acked our init; expecting_ack cleared. */
        object Acknowledged : Outcome()
        /** Inbound `R_in == contact.R`: helpers ran, ack=1 enqueued (initiator retransmit OR concurrent init). */
        object Reacked : Outcome()
        /** Inbound `R_in == contact.R` && !expecting_ack && ack==1: dup ack-of-ack; no-op. */
        object DuplicateAck : Outcome()
        /** Inbound `R_in < contact.R`: replay or stale; ratchet untouched. */
        object Replayed : Outcome()
        /** Inbound `R_in > contact.R + 16`: jump-ahead cap; ratchet untouched. */
        object JumpAheadCapped : Outcome()
        /** Inbound during the 7d budget-exhausted refuse window; ratchet untouched. */
        object BudgetExhausted : Outcome()
        /** AEAD failed (wrong key, tamper, or bounce-back direction mismatch). State untouched. */
        object AeadFailure : Outcome()
        /** AEAD opened but plaintext size != 33 (§6.1). State untouched. */
        object InvalidPlaintext : Outcome()
        /** Bob-role peer presented all-zero or low-order `postResetEphPub`. State untouched. */
        object PostResetEphRejected : Outcome()
        /** 4-fresh-R-per-24h cap hit: 7d budget-exhausted window set; ratchet bump refused. */
        object InboundRateLimited : Outcome()
        /** Successful manual initiation: ratchet wiped, RK_0 rebootstrapped, RESET enqueued. */
        object InitiatedReset : Outcome()
        /** Manual initiation refused because the budget-exhausted window is active. */
        object InitiationRefusedBudget : Outcome()
    }

    /**
     * Handle an inbound RESET frame already structurally validated by
     * [FrameCodec.decode]. Caller routes on the returned [Outcome].
     *
     * Runs under the per-contact ratchet mutex so it serializes against DR7
     * encrypts and DR8 decrypts. The entire state mutation (R bump + ratchet
     * wipe + RK_0 derive + outbox INSERT) happens in one Room transaction — a
     * crash mid-reset cannot leave `R` ahead of the ratchet.
     */
    suspend fun onResetFrame(contactId: String, frame: FrameCodec.DecodedFrame): Outcome {
        require(frame.kind == FrameCodec.FRAME_KIND_RESET) { "frame.kind must be RESET" }
        val idShared = idSharedSecretFor(contactId)
        return try {
            ContactMutexRegistry.forContact(contactId).withLock {
                withContext(Dispatchers.IO) {
                    db.runInTransaction(Callable { processInsideTxn(contactId, frame, idShared) })
                }
            }
        } finally {
            idShared.fill(0)
        }
    }

    /**
     * Trigger a manual reset (user-initiated retry button per §6.4). Atomic:
     * wipe ratchet, bootstrap new `RK_0`, generate post-reset ephemeral if Bob,
     * persist `reset_nonce` + `expecting_ack=true`, INSERT outbound RESET row.
     */
    suspend fun manualResetInitiate(contactId: String): Outcome {
        val idShared = idSharedSecretFor(contactId)
        return try {
            ContactMutexRegistry.forContact(contactId).withLock {
                withContext(Dispatchers.IO) {
                    db.runInTransaction(Callable { initInsideTxn(contactId, idShared) })
                }
            }
        } finally {
            idShared.fill(0)
        }
    }

    // ----- inside-txn paths -----

    private fun processInsideTxn(
        contactId: String,
        frame: FrameCodec.DecodedFrame,
        idShared: ByteArray
    ): Outcome {
        val rIn = ResetCrypto.extractR(frame)
        val resetNonce = ResetCrypto.extractResetNonce(frame)
        val now = clock()
        val contact = loadContactBlocking(contactId)

        // §6.3 ordered pre-AEAD drops.
        if (contact.budget_exhausted_until > now) {
            eventLog("reset.dropped budget_exhausted contact=$contactId R_in=$rIn until=${contact.budget_exhausted_until}")
            return Outcome.BudgetExhausted
        }
        if (rIn < contact.reset_epoch) {
            eventLog("reset.dropped replayed R_in=$rIn current=${contact.reset_epoch}")
            return Outcome.Replayed
        }
        if (rIn > contact.reset_epoch + JUMP_AHEAD_CAP) {
            eventLog("reset.dropped jump_ahead_cap R_in=$rIn current=${contact.reset_epoch}")
            return Outcome.JumpAheadCapped
        }

        val kReset = ResetCrypto.deriveKReset(idShared, frame.senderFp, frame.recipFp, resetNonce, rIn)
        val plaintext = try {
            when (val out = ResetCrypto.decrypt(frame, kReset)) {
                is ResetCrypto.DecodeOutcome.Ok -> out.plaintext
                is ResetCrypto.DecodeOutcome.AeadFailure -> {
                    eventLog("reset.dropped aead_failure R_in=$rIn")
                    return Outcome.AeadFailure
                }
                is ResetCrypto.DecodeOutcome.InvalidPlaintextSize -> {
                    eventLog("reset.dropped invalid_plaintext R_in=$rIn")
                    return Outcome.InvalidPlaintext
                }
            }
        } finally {
            kReset.fill(0)
        }

        // Role split per [dr5] fingerprint-based ordering. From this side: peer = senderFp, me = recipFp.
        val peerIsBob = compareUnsignedBytes(frame.senderFp, frame.recipFp) >= 0
        val myRoleIsBob = !peerIsBob

        if (peerIsBob && !isValidX25519Public(plaintext.postResetEphPub)) {
            eventLog("reset.dropped post_reset_eph_invalid R_in=$rIn")
            return Outcome.PostResetEphRejected
        }

        // Three R_in cases per §6.3 pseudocode.
        return when {
            rIn > contact.reset_epoch -> applyFreshReset(
                contact = contact,
                rIn = rIn,
                resetNonce = resetNonce,
                plaintext = plaintext,
                peerIsBob = peerIsBob,
                myRoleIsBob = myRoleIsBob,
                idShared = idShared,
                now = now
            )
            // rIn == contact.reset_epoch — same-R cases.
            contact.expecting_ack != 0 -> applyConvergence(
                contact = contact,
                rIn = rIn,
                plaintext = plaintext,
                peerIsBob = peerIsBob,
                myRoleIsBob = myRoleIsBob,
                idShared = idShared,
                now = now
            )
            else -> applyLostAck(
                contact = contact,
                rIn = rIn,
                plaintext = plaintext,
                peerIsBob = peerIsBob,
                myRoleIsBob = myRoleIsBob,
                idShared = idShared,
                now = now
            )
        }
    }

    private fun applyFreshReset(
        contact: ContactEntity,
        rIn: Int,
        resetNonce: ByteArray,
        plaintext: ResetCrypto.Plaintext,
        peerIsBob: Boolean,
        myRoleIsBob: Boolean,
        idShared: ByteArray,
        now: Long
    ): Outcome {
        // Inbound rate limit — applied AFTER AEAD success so unauthenticated spam doesn't burn it.
        val (windowStart, count) = rollInboundWindow(contact, now)
        if (count >= INBOUND_MAX_PER_24H) {
            val budgetEnd = now + BUDGET_EXHAUSTED_MS
            eventLog("reset.inbound_rate_limited contact=${contact.id} R_in=$rIn until=$budgetEnd")
            upsertContactBlocking(
                contact.copy(
                    inbound_reset_window_start = windowStart,
                    inbound_reset_count_24h = INBOUND_MAX_PER_24H,
                    budget_exhausted_until = budgetEnd
                )
            )
            return Outcome.InboundRateLimited
        }

        // Wipe ratchet + bootstrap fresh RK_0.
        val rk0 = Bootstrap.deriveResetRootKey(idShared, rIn, resetNonce)
        val rowId = contact.id.toByteArray(Charsets.UTF_8)
        val (rkW, rkH) = wrapMac.wrapAndMac(COL_RK, rowId, rk0)
        rk0.fill(0)

        var wiped = contact.copy(
            // ensureMyPostResetEph: filled below if Bob.
            dhs_priv_wrapped = null,
            dhs_priv_hmac = null,
            dhs_pub = null,
            // ensurePeerPostResetEph: filled below if peerIsBob.
            dhr_pub = null,
            rk_wrapped = rkW,
            rk_hmac = rkH,
            cks_wrapped = null,
            cks_hmac = null,
            ckr_wrapped = null,
            ckr_hmac = null,
            ns = 0,
            nr = 0,
            pn = 0,
            reset_epoch = rIn,
            reset_nonce = resetNonce.copyOf(),
            // Pseudocode: contact.expecting_ack = (ack == 0). Stays TRUE on the recipient side
            // until peer's ack=1 arrives via the convergence branch — see §6.3 pseudocode.
            expecting_ack = if (plaintext.ack == ResetCrypto.ACK_INITIATOR) 1 else 0,
            inbound_reset_window_start = windowStart,
            inbound_reset_count_24h = count + 1,
            // Reset counter is cleared on every successful AEAD per the DR8 pattern.
            consecutive_aead_failures = 0,
            consecutive_aead_failures_window_start = 0L
        )
        wiped = ensureMyPostResetEph(wiped, myRoleIsBob)
        wiped = ensurePeerPostResetEph(wiped, peerIsBob, plaintext.postResetEphPub)

        upsertContactBlocking(wiped)

        if (plaintext.ack == ResetCrypto.ACK_INITIATOR) {
            enqueueAckOutbound(
                contact = wiped,
                idShared = idShared,
                resetNonce = resetNonce,
                rOut = rIn,
                myRoleIsBob = myRoleIsBob,
                now = now
            )
        }
        eventLog("reset.fresh contact=${contact.id} R=$rIn role=${if (myRoleIsBob) "bob" else "alice"} ack=${plaintext.ack.toInt() and 0xff}")
        return Outcome.FreshReset
    }

    private fun applyConvergence(
        contact: ContactEntity,
        rIn: Int,
        plaintext: ResetCrypto.Plaintext,
        peerIsBob: Boolean,
        myRoleIsBob: Boolean,
        idShared: ByteArray,
        now: Long
    ): Outcome {
        // Helpers fire idempotently (no-op if slots already populated).
        var updated = ensureMyPostResetEph(contact, myRoleIsBob)
        updated = ensurePeerPostResetEph(updated, peerIsBob, plaintext.postResetEphPub)

        return if (plaintext.ack == ResetCrypto.ACK_ACKNOWLEDGER) {
            // Peer acked our initiation: clear expecting_ack and unblock DATA.
            upsertContactBlocking(updated.copy(expecting_ack = 0))
            eventLog("reset.acknowledged contact=${contact.id} R=$rIn")
            Outcome.Acknowledged
        } else {
            // Peer retransmitted ack=0 (or concurrent init at same R): re-ack with OUR persisted nonce.
            upsertContactBlocking(updated)
            val nonce = contact.reset_nonce ?: error("reset_nonce missing while expecting_ack=true")
            enqueueAckOutbound(
                contact = updated,
                idShared = idShared,
                resetNonce = nonce,
                rOut = rIn,
                myRoleIsBob = myRoleIsBob,
                now = now
            )
            eventLog("reset.reacked contact=${contact.id} R=$rIn")
            Outcome.Reacked
        }
    }

    private fun applyLostAck(
        contact: ContactEntity,
        rIn: Int,
        plaintext: ResetCrypto.Plaintext,
        peerIsBob: Boolean,
        myRoleIsBob: Boolean,
        idShared: ByteArray,
        now: Long
    ): Outcome {
        // Adopt peer's pub if we hadn't yet (idempotent); do NOT mutate ratchet state.
        val updated = ensurePeerPostResetEph(contact, peerIsBob, plaintext.postResetEphPub)
        if (updated !== contact) upsertContactBlocking(updated)

        return if (plaintext.ack == ResetCrypto.ACK_INITIATOR) {
            val nonce = contact.reset_nonce
            if (nonce == null) {
                // Unsolicited ack=0 at our current R with no persisted nonce — happens
                // only on a freshly-paired contact where R==0 has never been touched.
                // We have no meaningful nonce to bind our re-ack to; drop silently.
                eventLog("reset.lost_ack_dropped_no_nonce contact=${contact.id} R=$rIn")
                return Outcome.Replayed
            }
            enqueueAckOutbound(
                contact = updated,
                idShared = idShared,
                resetNonce = nonce,
                rOut = rIn,
                myRoleIsBob = myRoleIsBob,
                now = now
            )
            eventLog("reset.lost_ack_reacked contact=${contact.id} R=$rIn")
            Outcome.Reacked
        } else {
            // ack==1 duplicate: already handled previously, no-op.
            eventLog("reset.duplicate_ack_dropped contact=${contact.id} R=$rIn")
            Outcome.DuplicateAck
        }
    }

    private fun initInsideTxn(contactId: String, idShared: ByteArray): Outcome {
        val now = clock()
        val contact = loadContactBlocking(contactId)
        if (contact.budget_exhausted_until > now) {
            eventLog("reset.init_refused budget_exhausted contact=$contactId until=${contact.budget_exhausted_until}")
            return Outcome.InitiationRefusedBudget
        }

        val newR = contact.reset_epoch + 1
        val resetNonce = ResetCrypto.newResetNonce()
        val rk0 = Bootstrap.deriveResetRootKey(idShared, newR, resetNonce)
        val rowId = contact.id.toByteArray(Charsets.UTF_8)
        val (rkW, rkH) = wrapMac.wrapAndMac(COL_RK, rowId, rk0)
        rk0.fill(0)

        // Role decided from on-disk peer identity, not the (absent) inbound header.
        val peerIdPub = android.util.Base64.decode(contact.publicKeyBase64, android.util.Base64.NO_WRAP)
        val peerFp = Bootstrap.fingerprintBytes(peerIdPub)
        val myRoleIsBob = compareUnsignedBytes(ownFingerprint32, peerFp) >= 0

        var wiped = contact.copy(
            dhs_priv_wrapped = null,
            dhs_priv_hmac = null,
            dhs_pub = null,
            dhr_pub = null,
            rk_wrapped = rkW,
            rk_hmac = rkH,
            cks_wrapped = null,
            cks_hmac = null,
            ckr_wrapped = null,
            ckr_hmac = null,
            ns = 0,
            nr = 0,
            pn = 0,
            reset_epoch = newR,
            reset_nonce = resetNonce.copyOf(),
            expecting_ack = 1
        )
        wiped = ensureMyPostResetEph(wiped, myRoleIsBob)
        upsertContactBlocking(wiped)

        enqueueInitiatorOutbound(
            contact = wiped,
            idShared = idShared,
            resetNonce = resetNonce,
            rOut = newR,
            peerFp = peerFp,
            myRoleIsBob = myRoleIsBob,
            now = now
        )
        eventLog("reset.init contact=$contactId R=$newR role=${if (myRoleIsBob) "bob" else "alice"}")
        return Outcome.InitiatedReset
    }

    // ----- helpers -----

    private fun ensureMyPostResetEph(contact: ContactEntity, myRoleIsBob: Boolean): ContactEntity {
        if (!myRoleIsBob) return contact
        if (contact.dhs_priv_wrapped != null) return contact
        val kp = newX25519()
        val rowId = contact.id.toByteArray(Charsets.UTF_8)
        val (privW, privH) = wrapMac.wrapAndMac(COL_DHS_PRIV, rowId, kp.priv)
        kp.priv.fill(0)
        return contact.copy(
            dhs_priv_wrapped = privW,
            dhs_priv_hmac = privH,
            dhs_pub = kp.pub.copyOf()
        )
    }

    private fun ensurePeerPostResetEph(
        contact: ContactEntity,
        peerIsBob: Boolean,
        postResetEphPub: ByteArray
    ): ContactEntity {
        if (!peerIsBob) return contact
        if (contact.dhr_pub != null) return contact
        return contact.copy(dhr_pub = postResetEphPub.copyOf())
    }

    /** Window roll per §6.3. Returns `(window_start, current_count_in_window)`. */
    private fun rollInboundWindow(contact: ContactEntity, now: Long): Pair<Long, Int> {
        val ws = contact.inbound_reset_window_start
        val active = ws > 0 && (now - ws) < INBOUND_WINDOW_MS
        return if (active) ws to contact.inbound_reset_count_24h else now to 0
    }

    private fun enqueueAckOutbound(
        contact: ContactEntity,
        idShared: ByteArray,
        resetNonce: ByteArray,
        rOut: Int,
        myRoleIsBob: Boolean,
        now: Long
    ) {
        enqueueResetOutbound(
            contact = contact,
            idShared = idShared,
            resetNonce = resetNonce,
            rOut = rOut,
            ack = ResetCrypto.ACK_ACKNOWLEDGER,
            myRoleIsBob = myRoleIsBob,
            peerFp = peerFingerprintOf(contact),
            now = now
        )
    }

    private fun enqueueInitiatorOutbound(
        contact: ContactEntity,
        idShared: ByteArray,
        resetNonce: ByteArray,
        rOut: Int,
        peerFp: ByteArray,
        myRoleIsBob: Boolean,
        now: Long
    ) {
        enqueueResetOutbound(
            contact = contact,
            idShared = idShared,
            resetNonce = resetNonce,
            rOut = rOut,
            ack = ResetCrypto.ACK_INITIATOR,
            myRoleIsBob = myRoleIsBob,
            peerFp = peerFp,
            now = now
        )
    }

    private fun enqueueResetOutbound(
        contact: ContactEntity,
        idShared: ByteArray,
        resetNonce: ByteArray,
        rOut: Int,
        ack: Byte,
        myRoleIsBob: Boolean,
        peerFp: ByteArray,
        now: Long
    ) {
        val postResetEphPub = if (myRoleIsBob) {
            requireNotNull(contact.dhs_pub) { "Bob-role outbound RESET requires dhs_pub" }.copyOf()
        } else {
            ByteArray(ResetCrypto.POST_RESET_EPH_PUB_BYTES) // 32 zero bytes
        }
        val uuid = newUuid().also { require(it.size == FrameCodec.UUID_BYTES) }
        val kReset = ResetCrypto.deriveKReset(idShared, ownFingerprint32, peerFp, resetNonce, rOut)
        val wire = try {
            ResetCrypto.encode(
                senderFp = ownFingerprint32,
                recipFp = peerFp,
                resetNonce = resetNonce,
                R = rOut,
                uuid = uuid,
                timestampMs = now,
                plaintext = ResetCrypto.Plaintext(ack = ack, postResetEphPub = postResetEphPub),
                kReset = kReset
            )
        } finally {
            kReset.fill(0)
        }
        val (wrapped, hmac) = wrapMac.wrapAndMac(
            COL_OUTBOUND_WRAPPED, uuid, wire
        )
        db.pendingOutboundFrameDao().insertBlocking(
            PendingOutboundFrameEntity(
                uuid = uuid,
                contact_id = contact.id,
                frame_kind = PendingOutboundFrameEntity.FRAME_KIND_RESET,
                wrapped_frame = wrapped,
                frame_hmac = hmac,
                created_at = now,
                attempts = 0
            )
        )
    }

    private fun peerFingerprintOf(contact: ContactEntity): ByteArray {
        val pub = android.util.Base64.decode(contact.publicKeyBase64, android.util.Base64.NO_WRAP)
        return Bootstrap.fingerprintBytes(pub)
    }

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
        raw.insert("contacts", android.database.sqlite.SQLiteDatabase.CONFLICT_REPLACE, vals)
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
        const val JUMP_AHEAD_CAP = 16
        const val INBOUND_MAX_PER_24H = 4
        const val INBOUND_WINDOW_MS = 24L * 60 * 60 * 1000
        const val BUDGET_EXHAUSTED_MS = 7L * 24 * 60 * 60 * 1000

        private const val COL_RK = "contacts.rk_wrapped"
        private const val COL_DHS_PRIV = "contacts.dhs_priv_wrapped"
        private const val COL_OUTBOUND_WRAPPED = "pending_outbound_frames.wrapped_frame"

        private fun defaultUuidBytes(): ByteArray {
            val u = UUID.randomUUID()
            return ByteBuffer.allocate(16)
                .putLong(u.mostSignificantBits)
                .putLong(u.leastSignificantBits)
                .array()
        }

        private fun generateX25519KeyPair(): X25519KeyPair {
            val priv = X25519.generatePrivateKey()
            val pub = X25519.publicFromPrivate(priv)
            return X25519KeyPair(priv = priv, pub = pub)
        }

        private fun isValidX25519Public(pub: ByteArray): Boolean {
            if (pub.size != FrameCodec.DH_PUB_BYTES) return false
            if (FrameCodec.isAllZero(pub)) return false
            if (FrameCodec.isLowOrderX25519(pub)) return false
            return true
        }

        private fun compareUnsignedBytes(a: ByteArray, b: ByteArray): Int {
            require(a.size == b.size) { "fingerprint size mismatch" }
            for (i in a.indices) {
                val av = a[i].toInt() and 0xff
                val bv = b[i].toInt() and 0xff
                if (av != bv) return av - bv
            }
            return 0
        }
    }

    /** Internal X25519 keypair holder. `priv` is zero-wiped by callers after use. */
    class X25519KeyPair(val priv: ByteArray, val pub: ByteArray)
}
