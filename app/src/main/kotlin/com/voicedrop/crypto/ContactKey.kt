package com.voicedrop.crypto

import java.security.MessageDigest

/**
 * Identity-key helpers that survive the v1 → v2 cutover. The v1 ECDH session-key
 * derivation was removed in DR17.5 — per-frame keys come from the Double Ratchet
 * (see [Ratchet]). SAS-emoji derivation moved to [Sas] in §3.1.
 *
 * [fingerprint] still names contacts and is the row key on [com.voicedrop.storage.ContactEntity].
 */
object ContactKey {
    /** Hex of SHA-256 of an X25519 identity public key. Matches the contacts.id primary key. */
    fun fingerprint(publicKey: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(publicKey).joinToString("") { "%02x".format(it) }
    }
}
