package com.voicedrop.ui

/**
 * Formats a hex fingerprint string into two halves of 4-char groups joined by
 * " · ", e.g. "ABCDEF0123456789..." → "ABCD EF01 2345 6789 · ABCD EF01 2345 6789".
 * Falls back to space-separated 4-char groups if the input length is not a
 * multiple of 32 (avoids a midpoint dot for unexpected lengths).
 * See plan/11-visual-refresh.md §G #10.5.
 */
object FingerprintFormat {
    fun format(hex: String): String {
        val groups = hex.chunked(4)
        return when {
            groups.size == 8 -> {
                groups.subList(0, 4).joinToString(" ") + " · " +
                    groups.subList(4, 8).joinToString(" ")
            }
            groups.size % 8 == 0 -> {
                groups.chunked(4).joinToString("  ·  ") { half ->
                    half.joinToString(" ")
                }
            }
            else -> groups.joinToString(" ")
        }
    }
}
