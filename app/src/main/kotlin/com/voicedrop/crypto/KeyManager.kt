package com.voicedrop.crypto

import android.content.Context
import android.content.SharedPreferences
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.hybrid.HybridConfig
import com.google.crypto.tink.subtle.X25519
import java.security.MessageDigest

class KeyManager(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("voicedrop_keys", Context.MODE_PRIVATE)

    private val privateKeyBytes: ByteArray
    private val publicKeyBytes: ByteArray

    init {
        AeadConfig.register()
        HybridConfig.register()

        val storedPriv = prefs.getString(PREF_PRIVATE_KEY, null)
        val storedPub = prefs.getString(PREF_PUBLIC_KEY, null)

        if (storedPriv != null && storedPub != null) {
            privateKeyBytes = android.util.Base64.decode(storedPriv, android.util.Base64.NO_WRAP)
            publicKeyBytes = android.util.Base64.decode(storedPub, android.util.Base64.NO_WRAP)
        } else {
            privateKeyBytes = X25519.generatePrivateKey()
            publicKeyBytes = X25519.publicFromPrivate(privateKeyBytes)
            prefs.edit()
                .putString(PREF_PRIVATE_KEY, android.util.Base64.encodeToString(privateKeyBytes, android.util.Base64.NO_WRAP))
                .putString(PREF_PUBLIC_KEY, android.util.Base64.encodeToString(publicKeyBytes, android.util.Base64.NO_WRAP))
                .apply()
        }
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
        private const val PREF_PRIVATE_KEY = "x25519_private"
        private const val PREF_PUBLIC_KEY = "x25519_public"
    }
}
