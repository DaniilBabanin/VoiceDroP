package com.voicedrop.crypto

import com.google.crypto.tink.subtle.X25519
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object ContactKey {

    fun deriveSessionKey(myPrivateKey: ByteArray, theirPublicKey: ByteArray): ByteArray {
        val sharedSecret = X25519.computeSharedSecret(myPrivateKey, theirPublicKey)
        val myFingerprint = fingerprint(X25519.publicFromPrivate(myPrivateKey))
        val theirFingerprint = fingerprint(theirPublicKey)

        val (fp1, fp2) = if (myFingerprint < theirFingerprint) {
            myFingerprint to theirFingerprint
        } else {
            theirFingerprint to myFingerprint
        }

        val info = "voicedrop-v1".toByteArray(Charsets.UTF_8) +
                fp1.toByteArray(Charsets.UTF_8) +
                fp2.toByteArray(Charsets.UTF_8)

        return hkdfSha256(sharedSecret, ByteArray(0), info, 32)
    }

    fun computeVerificationCode(sessionKey: ByteArray, fingerprint1: String, fingerprint2: String): ByteArray {
        val (fp1, fp2) = if (fingerprint1 < fingerprint2) fingerprint1 to fingerprint2 else fingerprint2 to fingerprint1
        val data = (fp1 + fp2).toByteArray(Charsets.UTF_8)
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(javax.crypto.spec.SecretKeySpec(sessionKey, "HmacSHA256"))
        val result = mac.doFinal(data)
        return result.take(4).toByteArray()
    }

    private fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        val actualSalt = salt.ifEmpty { ByteArray(32) }
        mac.init(SecretKeySpec(actualSalt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        val result = ByteArray(length)
        var t = ByteArray(0)
        var pos = 0
        var counter = 1
        while (pos < length) {
            mac.update(t); mac.update(info); mac.update(counter.toByte())
            t = mac.doFinal()
            val len = minOf(t.size, length - pos)
            t.copyInto(result, pos, 0, len)
            pos += len; counter++
        }
        return result
    }

    fun fingerprint(publicKey: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(publicKey).joinToString("") { "%02x".format(it) }
    }
}
