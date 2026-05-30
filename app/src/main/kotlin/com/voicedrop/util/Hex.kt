package com.voicedrop.util

private val HEX = charArrayOf('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f')

/**
 * Lowercase hex rendering of a byte array, used to turn byte identifiers
 * (UUIDs, key fingerprints) into stable strings for log/diagnostic output.
 *
 * Single definition shared across the crypto and network packages; it was
 * previously copy-pasted verbatim into five companion objects, so centralizing
 * it keeps the encoding from drifting. Not intended for comparing secret
 * material — use a constant-time comparator for that.
 */
internal fun bytesToHex(b: ByteArray): String {
    val sb = StringBuilder(b.size * 2)
    for (x in b) {
        val v = x.toInt() and 0xff
        sb.append(HEX[v ushr 4]); sb.append(HEX[v and 0x0f])
    }
    return sb.toString()
}
