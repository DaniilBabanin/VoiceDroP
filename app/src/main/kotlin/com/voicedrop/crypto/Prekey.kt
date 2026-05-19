package com.voicedrop.crypto

import com.google.crypto.tink.subtle.X25519

/**
 * §3.2 — per-pair rotating prekey (X25519). Sits under stable identity:
 * identity authenticates RESETs; prekey adds post-compromise security so
 * an idPriv-only attacker can no longer derive K_reset or post-reset RK_0
 * after one completed rotation.
 *
 * Pure crypto primitives only. Lifecycle (insert/promote/sweep) lives in
 * `ResetReceive.kt` + `QrPairActivity.kt` + `storage/PrekeyEpochDao.kt`.
 */
object Prekey {

    const val PRIV_BYTES = 32
    const val PUB_BYTES = 32

    /** Fresh X25519 keypair. Caller owns `KeyPair.priv` and must `fill(0)` after wrap. */
    fun generate(): KeyPair {
        val priv = X25519.generatePrivateKey()
        val pub = X25519.publicFromPrivate(priv)
        return KeyPair(priv = priv, pub = pub)
    }

    /**
     * Computes `prekeySS = X25519(myPriv, peerPub)`. Symmetric by X25519:
     * both sides derive the same 32 bytes from their own active row.
     * Caller is responsible for `fill(0)` on the returned buffer.
     */
    fun sharedSecret(myPriv: ByteArray, peerPub: ByteArray): ByteArray {
        require(myPriv.size == PRIV_BYTES) { "myPriv must be $PRIV_BYTES bytes" }
        require(peerPub.size == PUB_BYTES) { "peerPub must be $PUB_BYTES bytes" }
        return X25519.computeSharedSecret(myPriv, peerPub)
    }

    class KeyPair(val priv: ByteArray, val pub: ByteArray)
}
