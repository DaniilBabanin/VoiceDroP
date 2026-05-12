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
import javax.crypto.spec.GCMParameterSpec

class KeyManager(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("voicedrop_keys", Context.MODE_PRIVATE)

    private val privateKeyBytes: ByteArray
    private val publicKeyBytes: ByteArray

    init {
        AeadConfig.register()
        HybridConfig.register()
        ensureKeystoreKey()

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

    fun getPublicKeyBytes(): ByteArray = publicKeyBytes.copyOf()

    fun getPrivateKeyBytes(): ByteArray = privateKeyBytes.copyOf()

    fun getFingerprint(): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(publicKeyBytes)
        return hash.joinToString("") { "%02x".format(it) }
    }

    fun getPublicKeyBase64(): String =
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
    }
}
