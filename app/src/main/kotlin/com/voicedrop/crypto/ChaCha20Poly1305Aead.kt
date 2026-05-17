package com.voicedrop.crypto

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * ChaCha20-Poly1305 AEAD with explicit (caller-supplied) nonce.
 *
 * Replaces Tink's `subtle.InsecureNonceChaCha20Poly1305`, which is not shipped
 * by the `tink-android` AAR (the JVM `tink` jar exposes it but the Android
 * variant strips the AEAD subtle classes; only `subtle.X25519` and the
 * higher-level keyset API are kept). We need explicit-nonce control because
 * the v2 wire format pins nonce=0 and relies on per-frame key uniqueness for
 * AEAD safety — see plan/08-dr/00-overview.md §5.
 *
 * Requires `minSdk` 28: `Cipher.getInstance("ChaCha20-Poly1305")` was added in
 * API 28 (Android 9, Conscrypt 2.x).
 */
object ChaCha20Poly1305Aead {
    private const val ALGO = "ChaCha20-Poly1305"
    private const val KEY_ALGO = "ChaCha20"

    fun encrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
        require(key.size == 32) { "key must be 32 bytes" }
        require(nonce.size == 12) { "nonce must be 12 bytes" }
        val cipher = Cipher.getInstance(ALGO)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, KEY_ALGO), IvParameterSpec(nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    fun decrypt(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray): ByteArray {
        require(key.size == 32) { "key must be 32 bytes" }
        require(nonce.size == 12) { "nonce must be 12 bytes" }
        val cipher = Cipher.getInstance(ALGO)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, KEY_ALGO), IvParameterSpec(nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }
}
