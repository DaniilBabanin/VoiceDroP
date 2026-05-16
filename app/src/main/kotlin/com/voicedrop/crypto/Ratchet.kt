package com.voicedrop.crypto

import com.google.crypto.tink.subtle.InsecureNonceChaCha20Poly1305
import com.google.crypto.tink.subtle.X25519
import com.voicedrop.network.FrameCodec
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * DR6 — Double-Ratchet core (Signal spec §3, §5). Pure crypto: no Android, no
 * persistence. Persistence wiring lives in [dr7-encrypt-path.md] / [dr8-decrypt-path.md].
 *
 * Design points worth keeping straight:
 *   - State is mutated in place under the per-contact mutex (see overview §4).
 *     The mutex is required for correctness, not optimization: two concurrent
 *     encrypts would both read `Ns`, both derive `mk` for the same n, both
 *     produce ciphertext under the same key — catastrophic AEAD nonce-reuse.
 *   - Decrypt operates on a clone of state. State is committed only after AEAD
 *     succeeds (Signal §3.4). A frame with a valid header but tampered
 *     ciphertext leaves state untouched — required to keep MITM from being
 *     able to permanently desync the receiver.
 *   - Skipped message keys are likewise staged into `pendingInserts` and
 *     applied only on AEAD success — so a forward-pointing frame that fails
 *     AEAD does NOT consume budget (see [dr9-skipped-keys.md]).
 *   - Forward secrecy: every chain-step zeros the old chain key. Old root keys
 *     are likewise overwritten on each DH ratchet step.
 *   - We use Tink's `InsecureNonceChaCha20Poly1305` with the all-zero 12-byte
 *     nonce — safe because every `mk` is unique (per Signal §5.2). See
 *     overview §5.
 */

class AwaitingFirstReceive :
    RuntimeException("ratchet: cannot encrypt before first receive (Bob role)")

class SkipLimitExceeded(val gap: Int) :
    RuntimeException("ratchet: receive-skip gap $gap > MAX_SKIP")

class InvalidFrame(reason: String) :
    RuntimeException("ratchet: invalid frame ($reason)")

class RatchetCryptoFailure(cause: Throwable) :
    RuntimeException("ratchet: AEAD decrypt failed", cause)

object RatchetKdf {
    /** Per-chain receive-side skip cap. Phase budgets layered on top: see [dr9]. */
    const val MAX_SKIP = 1000

    /** `voicedrop/rk/v1` — no field tail (salt = rk, ikm = dhOut). Overview §3. */
    private val INFO_RK = "voicedrop/rk/v1".toByteArray(Charsets.UTF_8)

    /** Signal §5.2 byte tags. Flipping these silently breaks interop with prior versions. */
    const val CK_NEXT_BYTE: Byte = 0x01
    const val CK_MK_BYTE: Byte = 0x02

    /**
     * `(newRK, newCK) = HKDF-SHA256(salt=rk, ikm=dhOut, info="voicedrop/rk/v1", L=64)`.
     * First half is the next root key; second half is the next chain key.
     */
    fun kdfRk(rk: ByteArray, dhOut: ByteArray): Pair<ByteArray, ByteArray> {
        require(rk.size == 32) { "rk must be 32 bytes" }
        require(dhOut.size == 32) { "dhOut must be 32 bytes" }
        val out = hkdfSha256(salt = rk, ikm = dhOut, info = INFO_RK, length = 64)
        val newRk = out.copyOfRange(0, 32)
        val newCk = out.copyOfRange(32, 64)
        out.fill(0)
        return newRk to newCk
    }

    /**
     * `newCK = HMAC-SHA256(ck, 0x01)`, `mk = HMAC-SHA256(ck, 0x02)`. The 0x01/0x02
     * split is locked by `kdfCk_constants_matchSignalSpec` — never flip on a tidy-up.
     */
    fun kdfCk(ck: ByteArray): Pair<ByteArray, ByteArray> {
        require(ck.size == 32) { "ck must be 32 bytes" }
        val mac = Mac.getInstance("HmacSHA256")
        val key = SecretKeySpec(ck, "HmacSHA256")
        mac.init(key); val newCk = mac.doFinal(byteArrayOf(CK_NEXT_BYTE))
        mac.init(key); val mk = mac.doFinal(byteArrayOf(CK_MK_BYTE))
        return newCk to mk
    }

    private fun hkdfSha256(salt: ByteArray, ikm: ByteArray, info: ByteArray, length: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        val actualSalt = if (salt.isEmpty()) ByteArray(32) else salt
        mac.init(SecretKeySpec(actualSalt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        val out = ByteArray(length)
        var t = ByteArray(0)
        var pos = 0
        var counter = 1
        while (pos < length) {
            mac.update(t); mac.update(info); mac.update(counter.toByte())
            t = mac.doFinal()
            val n = minOf(t.size, length - pos)
            t.copyInto(out, pos, 0, n)
            pos += n; counter++
        }
        return out
    }
}

/**
 * Per-contact ratchet state. Shape mirrors the [dr3] `contacts` ratchet columns 1:1.
 *
 * Plain class (not data) — `ByteArray` reference-equality on a data class is misleading;
 * callers compare per-field. `clone()` deep-copies; `assignFrom()` overwrites in place
 * (used for the clone-then-commit dance in [Ratchet.decrypt]).
 */
class RatchetState(
    var dhsPriv: ByteArray? = null,
    var dhsPub: ByteArray? = null,
    var dhrPub: ByteArray? = null,
    var rk: ByteArray = ByteArray(32),
    var cks: ByteArray? = null,
    var ckr: ByteArray? = null,
    var ns: Int = 0,
    var nr: Int = 0,
    var pn: Int = 0,
    var r: Int = 0
) {

    fun clone(): RatchetState = RatchetState(
        dhsPriv = dhsPriv?.copyOf(),
        dhsPub = dhsPub?.copyOf(),
        dhrPub = dhrPub?.copyOf(),
        rk = rk.copyOf(),
        cks = cks?.copyOf(),
        ckr = ckr?.copyOf(),
        ns = ns, nr = nr, pn = pn, r = r
    )

    /** In-place overwrite. Zeroes any prior secret-bearing fields before reassigning. */
    fun assignFrom(other: RatchetState) {
        dhsPriv?.fill(0); dhsPriv = other.dhsPriv?.copyOf()
        dhsPub = other.dhsPub?.copyOf()
        dhrPub = other.dhrPub?.copyOf()
        rk.fill(0); rk = other.rk.copyOf()
        cks?.fill(0); cks = other.cks?.copyOf()
        ckr?.fill(0); ckr = other.ckr?.copyOf()
        ns = other.ns; nr = other.nr; pn = other.pn; r = other.r
    }

    /** Best-effort wipe of all secret-bearing arrays. Caller drops the reference. */
    fun zeroize() {
        dhsPriv?.fill(0); dhsPriv = null
        dhsPub?.fill(0); dhsPub = null
        dhrPub?.fill(0); dhrPub = null
        rk.fill(0); rk = ByteArray(32)
        cks?.fill(0); cks = null
        ckr?.fill(0); ckr = null
        ns = 0; nr = 0; pn = 0; r = 0
    }

    companion object {
        /** Construct initial state directly from [Bootstrap.computeInitialBootstrap]. */
        fun fromBootstrap(b: Bootstrap.InitialState): RatchetState = RatchetState(
            dhsPriv = b.dhsPriv?.copyOf(),
            dhsPub = b.dhsPub?.copyOf(),
            dhrPub = b.dhrPub?.copyOf(),
            rk = b.rootKey.copyOf(),
            cks = null,
            ckr = null,
            ns = 0, nr = 0, pn = 0, r = 0
        )
    }
}

/**
 * Backing store for out-of-order ratchet message keys. Keyed by `(dhPub, n)`.
 *
 * Two implementations:
 *   - [SkippedKeyMap] — in-memory `HashMap`, used by DR6 unit tests.
 *   - [com.voicedrop.crypto.TxnSkippedKeyStore] — Room-backed, scoped to a
 *     single contact + active SQLite transaction. Used by DR8's decrypt path.
 *
 * `Ratchet.decrypt` calls `put` / `remove` ONLY after AEAD success; the
 * backing store can therefore mirror writes 1:1 to a SQLite txn that rolls back
 * on AEAD failure without the store needing its own staging buffer.
 */
interface SkippedKeyStore {
    fun get(dhPub: ByteArray, n: Int): ByteArray?
    fun put(dhPub: ByteArray, n: Int, mk: ByteArray)
    fun remove(dhPub: ByteArray, n: Int): Boolean
}

/**
 * In-memory [SkippedKeyStore]. The Room-backed impl in [dr8] / [dr9] has the
 * same surface plus a 7-day expiry sweep and a 2000-entry per-contact FIFO cap.
 */
class SkippedKeyMap : SkippedKeyStore {
    private val map: MutableMap<String, ByteArray> = HashMap()

    override fun get(dhPub: ByteArray, n: Int): ByteArray? = map[key(dhPub, n)]

    override fun put(dhPub: ByteArray, n: Int, mk: ByteArray) {
        require(dhPub.size == 32) { "dhPub must be 32 bytes" }
        require(mk.size == 32) { "mk must be 32 bytes" }
        require(n >= 0) { "n must be non-negative" }
        map[key(dhPub, n)] = mk
    }

    override fun remove(dhPub: ByteArray, n: Int): Boolean = map.remove(key(dhPub, n)) != null

    fun size(): Int = map.size

    fun isEmpty(): Boolean = map.isEmpty()

    private fun key(dhPub: ByteArray, n: Int): String {
        val sb = StringBuilder(dhPub.size * 2 + 12)
        for (b in dhPub) {
            val v = b.toInt() and 0xff
            sb.append(HEX[v ushr 4]); sb.append(HEX[v and 0x0f])
        }
        sb.append(':')
        sb.append(n)
        return sb.toString()
    }

    private companion object {
        private val HEX = charArrayOf('0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f')
    }
}

object Ratchet {

    /** Output of [advanceSend]. Caller AEAD-seals plaintext under [mk] using DR4 framing. */
    class SendResult(
        val dhPub: ByteArray,
        val pn: Int,
        val n: Int,
        val mk: ByteArray
    )

    /**
     * Advance the sending chain by one step. Mutates [state] in place; safe under
     * the per-contact mutex (overview §4).
     *
     * Throws:
     *   - [AwaitingFirstReceive] if local role is Bob and Alice hasn't sent yet
     *     (state.dhrPub is null at this point).
     *
     * Local crypto failure beyond that is a bug, not a runtime condition.
     */
    fun advanceSend(state: RatchetState): SendResult {
        if (state.dhrPub == null) throw AwaitingFirstReceive()
        if (state.cks == null) dhRatchetSend(state)
        val ck = state.cks!!
        val (newCks, mk) = RatchetKdf.kdfCk(ck)
        ck.fill(0)
        state.cks = newCks

        val result = SendResult(
            dhPub = state.dhsPub!!.copyOf(),
            pn = state.pn,
            n = state.ns,
            mk = mk
        )
        state.ns += 1
        return result
    }

    /**
     * Decrypt a wire frame using the clone-then-commit pattern (Signal spec §3.4).
     * On AEAD failure, [state] and [skipped] are left exactly as they were on entry —
     * required to keep an active MITM from being able to permanently desync the
     * receiver by injecting a forged ciphertext per chain step.
     *
     * Callers supply the decoded header fields + ciphertext + AAD (the 133-byte
     * slice from [FrameCodec.decode]).
     */
    fun decrypt(
        state: RatchetState,
        skipped: SkippedKeyStore,
        headerDhPub: ByteArray,
        headerPn: Int,
        headerN: Int,
        ciphertext: ByteArray,
        aad: ByteArray
    ): ByteArray {
        require(headerDhPub.size == 32) { "headerDhPub must be 32 bytes" }
        require(headerPn >= 0) { "headerPn must be non-negative" }
        require(headerN >= 0) { "headerN must be non-negative" }

        // Defense-in-depth: FrameCodec already filters these on the wire path, but
        // any caller that reaches Ratchet without going through FrameCodec must
        // not hand us junk inputs that would touch X25519 with attacker control.
        if (FrameCodec.isAllZero(headerDhPub)) throw InvalidFrame("dhPub all-zero")
        if (FrameCodec.isLowOrderX25519(headerDhPub)) throw InvalidFrame("dhPub low-order")

        // 1) Skipped-key fast path. By design this does NOT touch state — the entry
        //    is keyed by `(dhPub, n)` so it works even after the receive chain has
        //    rotated past the original DHr. See `oldChainSkippedKey_persistsAcrossDhRatchet`.
        val skippedMk = skipped.get(headerDhPub, headerN)
        if (skippedMk != null) {
            val pt = aeadOpen(skippedMk, ciphertext, aad)
            skipped.remove(headerDhPub, headerN)
            skippedMk.fill(0)
            return pt
        }

        // 2) Slow path: clone, derive, only commit on AEAD success.
        val clone = state.clone()
        val pendingInserts = mutableListOf<PendingInsert>()

        if (!byteArrayEqualsNullable(headerDhPub, clone.dhrPub)) {
            // Catch up old receiving chain BEFORE rotating DHr.
            skipMessageKeys(clone, headerPn, pendingInserts)
            dhRatchetReceive(clone, headerDhPub)
        }
        // Catch up current receiving chain (post-rotation if we rotated, otherwise current).
        skipMessageKeys(clone, headerN, pendingInserts)

        val ckr = clone.ckr ?: throw InvalidFrame("no receiving chain available")
        val (newCkr, mk) = RatchetKdf.kdfCk(ckr)
        ckr.fill(0)
        clone.ckr = newCkr
        clone.nr += 1

        // AEAD: throws on failure → clone discarded → state untouched.
        val plaintext = aeadOpen(mk, ciphertext, aad)
        mk.fill(0)

        // Commit.
        state.assignFrom(clone)
        for (ins in pendingInserts) skipped.put(ins.dhPub, ins.n, ins.mk)
        clone.zeroize()
        return plaintext
    }

    private class PendingInsert(val dhPub: ByteArray, val n: Int, val mk: ByteArray)

    /**
     * Stage skip up to (but not including) [untilN]. Each derived mk is appended to
     * [pending] under the current `state.dhrPub` — these get committed to the
     * SkippedKeyMap only after AEAD success in [decrypt].
     *
     * No-op when state.CKr is nil (first-ever receive for this role — there's no
     * receiving chain yet). MAX_SKIP cap still applies before the nil-check so a
     * flood of forward-pointing first frames cannot exhaust budget.
     */
    private fun skipMessageKeys(state: RatchetState, untilN: Int, pending: MutableList<PendingInsert>) {
        val gap = untilN - state.nr
        if (gap > RatchetKdf.MAX_SKIP) throw SkipLimitExceeded(gap)
        if (gap <= 0) return
        val ckr = state.ckr ?: return
        val dhrSnapshot = state.dhrPub ?: return

        var current = ckr
        while (state.nr < untilN) {
            val (nextCk, mk) = RatchetKdf.kdfCk(current)
            current.fill(0)
            current = nextCk
            pending.add(PendingInsert(dhrSnapshot.copyOf(), state.nr, mk))
            state.nr += 1
        }
        state.ckr = current
    }

    /**
     * Send-side DH ratchet step (first send by Alice; also runs if [advanceSend] is
     * ever entered with CKs == nil, though in normal flow [dhRatchetReceive] keeps
     * CKs populated after the first receive).
     */
    private fun dhRatchetSend(state: RatchetState) {
        val dhr = requireNotNull(state.dhrPub) { "dhRatchetSend without DHr" }
        val newPriv = X25519.generatePrivateKey()
        val newPub = X25519.publicFromPrivate(newPriv)
        state.dhsPriv?.fill(0)
        state.dhsPriv = newPriv
        state.dhsPub = newPub

        val dh = X25519.computeSharedSecret(newPriv, dhr)
        try {
            val (newRk, newCks) = RatchetKdf.kdfRk(state.rk, dh)
            state.rk.fill(0)
            state.rk = newRk
            state.cks?.fill(0)
            state.cks = newCks
        } finally {
            dh.fill(0)
        }
    }

    /**
     * Receive-side DH ratchet step. Per Signal spec: rotates DHr to the header's
     * dhPub, derives a fresh CKr, then regenerates DHs and derives a fresh CKs so
     * the local side is immediately ready to send on the new chain.
     *
     * Note `state.dhsPriv` may not be nil here — for Alice, her first send already
     * generated DHs; for Bob, his bootstrap-eph DHs is consumed on his first
     * receive (this function). Either way `state.dhsPriv` must be non-nil.
     */
    private fun dhRatchetReceive(state: RatchetState, newDhrPub: ByteArray) {
        state.pn = state.ns
        state.ns = 0
        state.nr = 0
        val dhrCopy = newDhrPub.copyOf()
        state.dhrPub?.fill(0)
        state.dhrPub = dhrCopy

        val dhsPriv = requireNotNull(state.dhsPriv) { "dhRatchetReceive without DHs.priv" }

        val dh1 = X25519.computeSharedSecret(dhsPriv, dhrCopy)
        try {
            val (rk1, newCkr) = RatchetKdf.kdfRk(state.rk, dh1)
            state.rk.fill(0)
            state.rk = rk1
            state.ckr?.fill(0)
            state.ckr = newCkr
        } finally {
            dh1.fill(0)
        }

        val newPriv = X25519.generatePrivateKey()
        val newPub = X25519.publicFromPrivate(newPriv)
        state.dhsPriv?.fill(0)
        state.dhsPriv = newPriv
        state.dhsPub = newPub

        val dh2 = X25519.computeSharedSecret(newPriv, dhrCopy)
        try {
            val (rk2, newCks) = RatchetKdf.kdfRk(state.rk, dh2)
            state.rk.fill(0)
            state.rk = rk2
            state.cks?.fill(0)
            state.cks = newCks
        } finally {
            dh2.fill(0)
        }
    }

    private fun aeadOpen(mk: ByteArray, ciphertext: ByteArray, aad: ByteArray): ByteArray {
        require(mk.size == 32) { "mk must be 32 bytes" }
        val aead = InsecureNonceChaCha20Poly1305(mk)
        return try {
            aead.decrypt(ZERO_NONCE, ciphertext, aad)
        } catch (e: Throwable) {
            throw RatchetCryptoFailure(e)
        }
    }

    private val ZERO_NONCE = ByteArray(12)

    private fun byteArrayEqualsNullable(a: ByteArray?, b: ByteArray?): Boolean {
        if (a === b) return true
        if (a == null || b == null) return false
        if (a.size != b.size) return false
        return a.contentEquals(b)
    }
}
