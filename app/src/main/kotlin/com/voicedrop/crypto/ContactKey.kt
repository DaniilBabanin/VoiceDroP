package com.voicedrop.crypto

import java.security.MessageDigest

/**
 * Identity-key helpers that survive the v1 → v2 cutover. The v1 ECDH session-key
 * derivation (`deriveSessionKey`) was removed in DR17.5 — its session key is no
 * longer used at the wire layer; per-frame keys come from the Double Ratchet
 * (see [Ratchet]).
 *
 * [fingerprint] still names contacts and is the row key on [com.voicedrop.storage.ContactEntity].
 * [computeVerificationCode] still drives the SAS-emoji verification screen at pair
 * time, but the key it's HMAC'd under is now `RK_0` (from [Bootstrap.computeInitialBootstrap])
 * — see [com.voicedrop.ui.QrPairActivity.handleScannedCard].
 */
object ContactKey {

    /**
     * SAS-style verification code: 4 bytes of `HMAC-SHA256(secretKey, sortedFingerprints)`.
     * Caller supplies the key — historically the v1 ECDH session key, now the v2
     * post-bootstrap root key `RK_0`. Sorting the fingerprint inputs makes both
     * sides converge on the same code regardless of role.
     */
    fun computeVerificationCode(secretKey: ByteArray, fingerprint1: String, fingerprint2: String): ByteArray {
        val (fp1, fp2) = if (fingerprint1 < fingerprint2) fingerprint1 to fingerprint2 else fingerprint2 to fingerprint1
        val data = (fp1 + fp2).toByteArray(Charsets.UTF_8)
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(javax.crypto.spec.SecretKeySpec(secretKey, "HmacSHA256"))
        val result = mac.doFinal(data)
        return result.take(4).toByteArray()
    }

    /** Hex of SHA-256 of an X25519 identity public key. Matches the contacts.id primary key. */
    fun fingerprint(publicKey: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(publicKey).joinToString("") { "%02x".format(it) }
    }
}
