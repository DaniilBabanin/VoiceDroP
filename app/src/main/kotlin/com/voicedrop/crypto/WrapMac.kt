package com.voicedrop.crypto

/**
 * DR2 wrap-and-MAC surface, extracted to an interface so encrypt/decrypt paths
 * ([dr7], [dr8]) can be unit-tested under Robolectric without bringing up
 * AndroidKeyStore. The production implementation is [KeyManager].
 *
 * Contract is exactly DR2 §9.4:
 *   - `wrapped = [iv:12 || ct || tag:16]` (AES-GCM, KeyStore-generated IV).
 *   - `hmac = HMAC_SHA256(macKey, column || 0x00 || rowId || 0x00 || wrapped)`.
 *
 * Implementations MUST throw [WrapHmacMismatch] on tamper / coordinate mismatch
 * (distinguishes crypto-tamper from structural corruption — see [dr14]).
 */
interface WrapMac {
    fun wrapAndMac(columnName: String, rowId: ByteArray, plain: ByteArray): Pair<ByteArray, ByteArray>
    fun unwrapAndVerify(columnName: String, rowId: ByteArray, wrapped: ByteArray, hmac: ByteArray): ByteArray
}
