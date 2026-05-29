package com.voicedrop.crypto

/**
 * Minimal identity-key surface that network code needs (pull-auth handshake).
 * Implemented by [KeyManager]; lets tests supply a Tink-backed fake without the
 * AndroidKeyStore that KeyManager's init requires (unavailable under Robolectric).
 */
interface IdentityKeys {
    fun getPublicKeyBytes(): ByteArray
    fun getPrivateKeyBytes(): ByteArray
    fun getPublicKeyBase64(): String
}
