package com.voicedrop.crypto

import com.voicedrop.network.FrameCodec
import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * DR12 — Session-reset frame (§6.1, §6.2).
 *
 * Encoder/decoder + `K_reset` derivation. The outer wire shape is the same as
 * DATA (so [FrameCodec] does the structural parse / drops), but the DATA `dhPub`,
 * `pn`, `n` slots are repurposed:
 *
 *   - `dhPub[0..16]`   = `resetNonce`    (16 random bytes)
 *   - `dhPub[16..32]`  = zeros           ([FrameCodec] rejects non-zero tail)
 *   - `pn`             = 0               ([FrameCodec] rejects non-zero)
 *   - `n`              = `R`             (new reset epoch — participates in AAD)
 *
 * Inner plaintext is 33 bytes: `ack:1 || postResetEphPub:32`. Plaintext sizes
 * other than 33 are dropped post-AEAD without state effect (caller checks
 * [DecodeOutcome.InvalidPlaintextSize]).
 *
 * `K_reset` is direction-bound (senderFp||recipFp in HKDF info) AND nonce-bound
 * (resetNonce in HKDF salt) so:
 *   - A replay bounced back A→B as B→A under swapped header derives a different
 *     `K_reset` on A's side → AEAD failure → frame dropped.
 *   - Two resets at the same `R` with different `resetNonce` produce distinct
 *     `K_reset` → no same-key/same-nonce AEAD reuse.
 *
 * Retransmits of the *same* reset reuse the same `resetNonce` deliberately, so
 * the ciphertext is bit-identical and idempotent at the receiver — see [dr15].
 *
 * Receive logic, manual-init transaction, and rate caps live in [dr13]/[dr14].
 */
object ResetCrypto {

    /** Bytes 0..16 of the repurposed dhPub slot. */
    const val RESET_NONCE_BYTES = 16

    const val POST_RESET_EPH_PUB_BYTES = 32

    /** `ack:1 || postResetEphPub:32`. */
    const val PLAINTEXT_SIZE = 1 + POST_RESET_EPH_PUB_BYTES

    /** "I initiated this reset; you reset too." */
    const val ACK_INITIATOR: Byte = 0x00

    /** "I acknowledge your reset; I have rebootstrapped to your R." */
    const val ACK_ACKNOWLEDGER: Byte = 0x01

    /** HKDF info purpose label per plan/08-dr/00-overview.md §3. */
    private const val HKDF_PURPOSE = "voicedrop/reset/v1"

    /**
     * Derive `K_reset` per §6.2:
     *
     * ```
     * K_reset = HKDF(
     *   salt = resetNonce,
     *   ikm  = idSharedSecret,
     *   info = "voicedrop/reset/v1" || 0x00 || senderFp || recipFp || be32(R),
     *   L    = 32
     * )
     * ```
     *
     * Direction (senderFp / recipFp) is from the **sender's** point of view. The
     * receiver flips them so a bounce-back replay against the original sender
     * derives a different key — see `reset_directionBinding_bouncebackRejected`.
     */
    fun deriveKReset(
        idSharedSecret: ByteArray,
        senderFp: ByteArray,
        recipFp: ByteArray,
        resetNonce: ByteArray,
        R: Int
    ): ByteArray {
        require(idSharedSecret.size == 32) { "idSharedSecret must be 32 bytes" }
        require(senderFp.size == FrameCodec.FP_BYTES) { "senderFp must be ${FrameCodec.FP_BYTES} bytes" }
        require(recipFp.size == FrameCodec.FP_BYTES) { "recipFp must be ${FrameCodec.FP_BYTES} bytes" }
        require(resetNonce.size == RESET_NONCE_BYTES) { "resetNonce must be $RESET_NONCE_BYTES bytes" }
        require(R >= 0) { "R must be non-negative" }

        val info = buildInfo(senderFp, recipFp, R)
        return hkdfSha256(salt = resetNonce, ikm = idSharedSecret, info = info, length = 32)
    }

    /** Inner RESET plaintext. `postResetEphPub` is 32 zero bytes for Alice-role senders. */
    class Plaintext(val ack: Byte, val postResetEphPub: ByteArray) {
        init {
            require(ack == ACK_INITIATOR || ack == ACK_ACKNOWLEDGER) {
                "ack must be 0x00 (initiator) or 0x01 (acknowledger)"
            }
            require(postResetEphPub.size == POST_RESET_EPH_PUB_BYTES) {
                "postResetEphPub must be $POST_RESET_EPH_PUB_BYTES bytes"
            }
        }

        fun toBytes(): ByteArray {
            val out = ByteArray(PLAINTEXT_SIZE)
            out[0] = ack
            System.arraycopy(postResetEphPub, 0, out, 1, POST_RESET_EPH_PUB_BYTES)
            return out
        }
    }

    /**
     * Encode + seal a RESET frame under `K_reset`. The dhPub slot is set to
     * `resetNonce || zeros[16]` and `pn` to 0; `R` rides in the `n` slot so it
     * participates in the AAD (and can be range-checked before AEAD work — see
     * [dr13]).
     */
    fun encode(
        senderFp: ByteArray,
        recipFp: ByteArray,
        resetNonce: ByteArray,
        R: Int,
        uuid: ByteArray,
        timestampMs: Long,
        plaintext: Plaintext,
        kReset: ByteArray
    ): ByteArray {
        require(resetNonce.size == RESET_NONCE_BYTES) { "resetNonce must be $RESET_NONCE_BYTES bytes" }
        require(R >= 0) { "R must be non-negative" }
        require(kReset.size == 32) { "kReset must be 32 bytes" }

        val dhPubSlot = ByteArray(FrameCodec.DH_PUB_BYTES)
        System.arraycopy(resetNonce, 0, dhPubSlot, 0, RESET_NONCE_BYTES)

        return FrameCodec.encode(
            kind = FrameCodec.FRAME_KIND_RESET,
            senderFp = senderFp,
            recipFp = recipFp,
            dhPub = dhPubSlot,
            pn = 0,
            n = R,
            uuid = uuid,
            timestampMs = timestampMs,
            key = kReset,
            plaintext = plaintext.toBytes()
        )
    }

    sealed class DecodeOutcome {
        data class Ok(val plaintext: Plaintext) : DecodeOutcome()

        /** AEAD failed — wrong key, tamper, or direction-binding bounce-back. */
        object AeadFailure : DecodeOutcome()

        /** AEAD succeeded but inner plaintext is not exactly [PLAINTEXT_SIZE] bytes (§6.1). */
        object InvalidPlaintextSize : DecodeOutcome()
    }

    /**
     * Open the ciphertext of an already-decoded RESET frame under `K_reset`.
     * Caller has already validated structural shape via [FrameCodec.decode]
     * (which rejects non-zero `pn` and non-zero `dhPub[16..32]` for RESET
     * frames).
     *
     * On AEAD failure returns [DecodeOutcome.AeadFailure] — caller drops the
     * frame without state effect. On size mismatch returns
     * [DecodeOutcome.InvalidPlaintextSize] — drop after AEAD success per §6.1.
     */
    fun decrypt(frame: FrameCodec.DecodedFrame, kReset: ByteArray): DecodeOutcome {
        require(frame.kind == FrameCodec.FRAME_KIND_RESET) { "frame must be RESET kind" }
        require(kReset.size == 32) { "kReset must be 32 bytes" }

        val pt = try {
            FrameCodec.decrypt(frame, kReset)
        } catch (_: GeneralSecurityException) {
            return DecodeOutcome.AeadFailure
        }

        if (pt.size != PLAINTEXT_SIZE) {
            return DecodeOutcome.InvalidPlaintextSize
        }

        return DecodeOutcome.Ok(
            Plaintext(
                ack = pt[0],
                postResetEphPub = pt.copyOfRange(1, PLAINTEXT_SIZE)
            )
        )
    }

    /** Extract `resetNonce` from the dhPub slot of a decoded RESET frame. */
    fun extractResetNonce(frame: FrameCodec.DecodedFrame): ByteArray {
        require(frame.kind == FrameCodec.FRAME_KIND_RESET) { "frame must be RESET kind" }
        return frame.dhPub.copyOfRange(0, RESET_NONCE_BYTES)
    }

    /** Extract `R` (reset epoch) from the n slot of a decoded RESET frame. */
    fun extractR(frame: FrameCodec.DecodedFrame): Int {
        require(frame.kind == FrameCodec.FRAME_KIND_RESET) { "frame must be RESET kind" }
        return frame.n
    }

    /** Generate a fresh 16-byte CSPRNG resetNonce. */
    fun newResetNonce(): ByteArray {
        val bytes = ByteArray(RESET_NONCE_BYTES)
        SecureRandom().nextBytes(bytes)
        return bytes
    }

    private fun buildInfo(senderFp: ByteArray, recipFp: ByteArray, R: Int): ByteArray {
        // "voicedrop/reset/v1" || 0x00 || senderFp[32] || recipFp[32] || be32(R)
        val prefix = HKDF_PURPOSE.toByteArray(Charsets.UTF_8)
        val out = ByteArray(prefix.size + 1 + 32 + 32 + 4)
        var p = 0
        System.arraycopy(prefix, 0, out, p, prefix.size); p += prefix.size
        out[p++] = 0x00
        System.arraycopy(senderFp, 0, out, p, 32); p += 32
        System.arraycopy(recipFp, 0, out, p, 32); p += 32
        out[p++] = (R ushr 24).toByte()
        out[p++] = (R ushr 16).toByte()
        out[p++] = (R ushr 8).toByte()
        out[p] = R.toByte()
        return out
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
