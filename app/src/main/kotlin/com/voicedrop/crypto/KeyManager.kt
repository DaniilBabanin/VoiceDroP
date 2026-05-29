package com.voicedrop.crypto

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.hybrid.HybridConfig
import com.google.crypto.tink.subtle.X25519
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** HMAC binding over a wrapped blob failed to match its (column, row) — DB tamper or wrong coordinates. */
class WrapHmacMismatch(message: String = "wrap-binding HMAC mismatch") : SecurityException(message)

/** 2^30 wrap budget reached on voicedrop_wrap_v2 (DR2 §9.5). Re-pair to regenerate the KeyStore key. */
class WrapBudgetExhausted(message: String = "AES-GCM wrap budget exhausted; re-pair required") : SecurityException(message)

class KeyManager(context: Context) : WrapMac, IdentityKeys {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("voicedrop_keys", Context.MODE_PRIVATE)

    private val privateKeyBytes: ByteArray
    private val publicKeyBytes: ByteArray

    init {
        AeadConfig.register()
        HybridConfig.register()
        ensureKeystoreKey()
        ensureWrapV2Keys()

        val storedPrivEnc = prefs.getString(PREF_PRIVATE_KEY_ENC, null)
        val storedPub = prefs.getString(PREF_PUBLIC_KEY, null)

        if (storedPrivEnc != null && storedPub != null) {
            privateKeyBytes = decryptWithKeystoreKey(
                android.util.Base64.decode(storedPrivEnc, android.util.Base64.NO_WRAP)
            )
            publicKeyBytes = android.util.Base64.decode(storedPub, android.util.Base64.NO_WRAP)
        } else {
            // Check for legacy plaintext key and migrate, or generate fresh
            val legacyPriv = prefs.getString(PREF_PRIVATE_KEY_LEGACY, null)
            val privKey = if (legacyPriv != null) {
                android.util.Base64.decode(legacyPriv, android.util.Base64.NO_WRAP)
            } else {
                X25519.generatePrivateKey()
            }
            val pubKey = X25519.publicFromPrivate(privKey)
            val encryptedPriv = encryptWithKeystoreKey(privKey)
            prefs.edit()
                .putString(PREF_PRIVATE_KEY_ENC, android.util.Base64.encodeToString(encryptedPriv, android.util.Base64.NO_WRAP))
                .putString(PREF_PUBLIC_KEY, android.util.Base64.encodeToString(pubKey, android.util.Base64.NO_WRAP))
                .remove(PREF_PRIVATE_KEY_LEGACY)
                .apply()
            privateKeyBytes = privKey
            publicKeyBytes = pubKey
        }
    }

    private fun ensureKeystoreKey() {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (!ks.containsAlias(KEYSTORE_ALIAS)) {
            val spec = KeyGenParameterSpec.Builder(
                KEYSTORE_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
                .apply { init(spec) }
                .generateKey()
        }
    }

    private fun encryptWithKeystoreKey(plaintext: ByteArray): ByteArray {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val secretKey = (ks.getEntry(KEYSTORE_ALIAS, null) as KeyStore.SecretKeyEntry).secretKey
        val cipher = Cipher.getInstance(AES_GCM_NO_PADDING)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plaintext)
        // Prepend 12-byte IV to ciphertext
        return iv + ciphertext
    }

    private fun decryptWithKeystoreKey(ivAndCiphertext: ByteArray): ByteArray {
        val iv = ivAndCiphertext.copyOfRange(0, GCM_IV_LENGTH)
        val ciphertext = ivAndCiphertext.copyOfRange(GCM_IV_LENGTH, ivAndCiphertext.size)
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val secretKey = (ks.getEntry(KEYSTORE_ALIAS, null) as KeyStore.SecretKeyEntry).secretKey
        val cipher = Cipher.getInstance(AES_GCM_NO_PADDING)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher.doFinal(ciphertext)
    }

    // --- DR2: wrap-and-MAC API for ratchet state and outbox frames ---
    //
    // Wrapping AEAD: AES-GCM under voicedrop_wrap_v2 (AndroidKeyStore, non-exportable).
    // Binding: HmacSHA256 under voicedrop_mac_v2 over (column || 0x00 || rowId || 0x00 || wrapped).
    // The HMAC defeats a DB-tamper attack where an attacker swaps a wrapped blob between rows
    // or columns — both would still AES-decrypt under the same key. See plan/08-dr/dr2-keymanager-wrap.md.

    private fun ensureWrapV2Keys() {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (!ks.containsAlias(KEYSTORE_ALIAS_WRAP_V2)) {
            val spec = KeyGenParameterSpec.Builder(
                KEYSTORE_ALIAS_WRAP_V2,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build()
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
                .apply { init(spec) }
                .generateKey()
        }
        if (!ks.containsAlias(KEYSTORE_ALIAS_MAC_V2)) {
            val spec = KeyGenParameterSpec.Builder(
                KEYSTORE_ALIAS_MAC_V2,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setKeySize(256)
                .build()
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, ANDROID_KEYSTORE)
                .apply { init(spec) }
                .generateKey()
        }
    }

    private fun wrapKeyV2(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return (ks.getEntry(KEYSTORE_ALIAS_WRAP_V2, null) as KeyStore.SecretKeyEntry).secretKey
    }

    private fun macKeyV2(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return (ks.getEntry(KEYSTORE_ALIAS_MAC_V2, null) as KeyStore.SecretKeyEntry).secretKey
    }

    private val wrapCountLock = Any()

    /** Pre-wrap gate: increments and persists the wrap counter, throwing if 2^30 reached. */
    private fun incrementAndCheckWrapBudget() {
        synchronized(wrapCountLock) {
            val next = prefs.getLong(PREF_WRAP_COUNT_V2, 0L) + 1L
            if (next > WRAP_HARD_STOP) throw WrapBudgetExhausted()
            prefs.edit().putLong(PREF_WRAP_COUNT_V2, next).apply()
        }
    }

    private fun computeBindingHmac(columnName: String, rowId: ByteArray, wrapped: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run {
            init(macKeyV2())
            update(columnName.toByteArray(Charsets.UTF_8))
            update(0x00.toByte())
            update(rowId)
            update(0x00.toByte())
            update(wrapped)
            doFinal()
        }

    /**
     * Wraps [plain] under voicedrop_wrap_v2 and returns (wrapped, hmac).
     *
     * wrapped layout: `[iv:12 || ciphertext:plain.size || tag:16]` — exactly what Cipher.doFinal emits.
     * hmac = HMAC_SHA256(voicedrop_mac_v2, column || 0x00 || rowId || 0x00 || wrapped).
     *
     * @throws WrapBudgetExhausted if the per-key 2^30 wrap budget is reached.
     */
    override fun wrapAndMac(columnName: String, rowId: ByteArray, plain: ByteArray): Pair<ByteArray, ByteArray> {
        incrementAndCheckWrapBudget()
        val cipher = Cipher.getInstance(AES_GCM_NO_PADDING)
        cipher.init(Cipher.ENCRYPT_MODE, wrapKeyV2())   // IV generated by KeyStore (DR2 §9.3)
        val iv = cipher.iv
        val ctAndTag = cipher.doFinal(plain)
        val wrapped = iv + ctAndTag
        val hmac = computeBindingHmac(columnName, rowId, wrapped)
        return wrapped to hmac
    }

    /**
     * Verifies the binding HMAC, then unwraps. The HMAC check is constant-time
     * (`MessageDigest.isEqual`) to avoid leaking row/column substitution attempts.
     *
     * @throws WrapHmacMismatch on tamper or coordinate substitution. Does NOT trigger auto-reset
     *   (dr14 distinguishes crypto-tamper from structural corruption).
     */
    override fun unwrapAndVerify(
        columnName: String,
        rowId: ByteArray,
        wrapped: ByteArray,
        hmac: ByteArray
    ): ByteArray {
        val expected = computeBindingHmac(columnName, rowId, wrapped)
        if (!MessageDigest.isEqual(expected, hmac)) throw WrapHmacMismatch()
        val iv = wrapped.copyOfRange(0, GCM_IV_LENGTH)
        val ctAndTag = wrapped.copyOfRange(GCM_IV_LENGTH, wrapped.size)
        val cipher = Cipher.getInstance(AES_GCM_NO_PADDING)
        cipher.init(Cipher.DECRYPT_MODE, wrapKeyV2(), GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher.doFinal(ctAndTag)
    }

    override fun getPublicKeyBytes(): ByteArray = publicKeyBytes.copyOf()

    override fun getPrivateKeyBytes(): ByteArray = privateKeyBytes.copyOf()

    fun getFingerprint(): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(publicKeyBytes)
        return hash.joinToString("") { "%02x".format(it) }
    }

    override fun getPublicKeyBase64(): String =
        android.util.Base64.encodeToString(publicKeyBytes, android.util.Base64.NO_WRAP)

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEYSTORE_ALIAS = "voicedrop_x25519_wrap"
        private const val AES_GCM_NO_PADDING = "AES/GCM/NoPadding"
        private const val GCM_IV_LENGTH = 12
        private const val GCM_TAG_BITS = 128

        // Legacy pref key (plaintext) — only used during one-time migration
        private const val PREF_PRIVATE_KEY_LEGACY = "x25519_private"
        private const val PREF_PRIVATE_KEY_ENC = "x25519_private_enc"
        private const val PREF_PUBLIC_KEY = "x25519_public"

        // DR2 v2 wrap-and-MAC aliases (separate from the legacy identity-key wrap above).
        const val KEYSTORE_ALIAS_WRAP_V2 = "voicedrop_wrap_v2"
        const val KEYSTORE_ALIAS_MAC_V2 = "voicedrop_mac_v2"
        private const val PREF_WRAP_COUNT_V2 = "wrap_v2_count"
        const val WRAP_HARD_STOP = 1L shl 30  // 2^30, DR2 §9.5
    }
}

/**
 * Unwrap, run [block] with the plaintext, then zero the buffer.
 * Zeroization is best-effort on the JVM (GC may have copied bytes) but
 * shrinks the heap-snapshot exposure window. See DR2 §9.4.
 */
inline fun <T> KeyManager.withUnwrapped(
    columnName: String,
    rowId: ByteArray,
    wrapped: ByteArray,
    hmac: ByteArray,
    block: (ByteArray) -> T
): T {
    val plain = unwrapAndVerify(columnName, rowId, wrapped, hmac)
    try {
        return block(plain)
    } finally {
        plain.fill(0)
    }
}
