package com.voicedrop.crypto

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * §3.1 — Identity-keyed Short Authentication String (SAS).
 *
 * Replaces the v1.2.0.x [ContactKey.computeVerificationCode] (`RK_0`-keyed, 4 bytes),
 * which was useful for pair-time only because `RK_0` rotates on every reset. This
 * derivation keys off the two X25519 identity public keys — stable for the lifetime
 * of those keys, which is "forever" until §3.2 (PCS via identity-key rotation) lands.
 *
 * Spec: `plan/09-security-frontier/3.1-sas-verification-ux.md` §3.
 *
 * Security level: 48 bits against active MITM grinding. Above Matrix (~42), below
 * Signal (~60). Pair-time comparison with the peer physically present is the
 * canonical trust gate; the chat-header subtitle and the in-chat Verify panel make
 * the same code visible afterwards for ongoing identity-stability checks.
 */
object Sas {
    private val DOMAIN_TAG = "VoiceDroP/SAS/v1".toByteArray(Charsets.UTF_8)
    private const val CODE_LENGTH = 6

    /** 6-emoji identity-continuity code. Symmetric, deterministic, palette-stable. */
    fun codeFor(idPubA: ByteArray, idPubB: ByteArray): List<String> {
        val (lo, hi) = sortedFps(idPubA, idPubB)
        val mac = Mac.getInstance("HmacSHA256").apply {
            init(SecretKeySpec(DOMAIN_TAG, "HmacSHA256"))
        }
        val out = mac.doFinal((lo + hi).toByteArray(Charsets.UTF_8))
        return SasEmojiPalette.getEmojisForBytes(out, CODE_LENGTH)
    }

    /**
     * 16-byte binding hash stored alongside `verified_at` so verification self-invalidates
     * if either identity key changes. Implementation is plain SHA-256 truncated to 16
     * bytes — no HMAC needed, this is a row-binding token not an authentication tag.
     */
    fun fpPairBinding(idPubA: ByteArray, idPubB: ByteArray): ByteArray {
        val (lo, hi) = sortedFps(idPubA, idPubB)
        return MessageDigest.getInstance("SHA-256")
            .digest((lo + hi).toByteArray(Charsets.UTF_8))
            .copyOf(16)
    }

    private fun sortedFps(idPubA: ByteArray, idPubB: ByteArray): Pair<String, String> {
        val fpA = ContactKey.fingerprint(idPubA)
        val fpB = ContactKey.fingerprint(idPubB)
        return if (fpA < fpB) fpA to fpB else fpB to fpA
    }
}
