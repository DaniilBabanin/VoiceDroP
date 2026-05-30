package com.voicedrop.network

import com.google.crypto.tink.subtle.X25519
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Pull-auth proof-of-possession (Finding #1 fix). The client proves it holds the
 * X25519 identity private key behind its fingerprint by completing a static-static
 * DH against the worker's persistent server key and MACing the server nonce.
 * Pure functions: no Android, no I/O — unit-testable. Wire format: see
 * plan/2026-05-29_A1-challenge-response-design.md §4.
 */
object PullAuth {
    private const val MAC_CONTEXT = "vdrop-pull-auth-v1"

    /** SHA-256 of the 32-byte X25519 public key — the raw bytes behind the hex fingerprint. */
    fun fingerprintBytes(identityPub: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(identityPub)

    /** ss = X25519(identityPriv, serverPub); mac = HMAC-SHA256(ss, CONTEXT || nonce || fpBytes). */
    fun computeProofMac(
        identityPriv: ByteArray,
        serverPub: ByteArray,
        nonce: ByteArray,
        fpBytes: ByteArray
    ): ByteArray {
        val ss = X25519.computeSharedSecret(identityPriv, serverPub)
        return macWithKey(ss, nonce, fpBytes)
    }

    /** HMAC over CONTEXT || nonce || fpBytes with `ss` as the key. Exposed for symmetry tests. */
    fun macWithKey(ss: ByteArray, nonce: ByteArray, fpBytes: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(ss, "HmacSHA256"))
        mac.update(MAC_CONTEXT.toByteArray(Charsets.US_ASCII))
        mac.update(nonce)
        mac.update(fpBytes)
        return mac.doFinal()
    }
}
