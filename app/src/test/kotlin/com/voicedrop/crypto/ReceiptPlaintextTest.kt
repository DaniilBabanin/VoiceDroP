package com.voicedrop.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * DR16 §10.1 — RECEIPT plaintext schema validation.
 *
 * `RatchetDecryptAndPersist.parseReceiptAcked` is the only gatekeeper for the
 * RECEIPT body once AEAD has cleared it. The version byte is the sole knob
 * available to bump the on-wire RECEIPT format without a full session reset,
 * so the rejection path is load-bearing: anything that decodes RECEIPT with
 * `byte[0] != 0x01` is a foreign / corrupted frame and MUST surface as
 * [InvalidFrame].
 */
class ReceiptPlaintextTest {

    @Test
    fun receipt_versionByteRejected_ifNotOx01() {
        // Sanity — golden parse path strips the version byte and returns the
        // 16-byte acked UUID.
        val good = ByteArray(17).also {
            it[0] = RatchetDecryptAndPersist.RECEIPT_VERSION
            for (i in 1 until 17) it[i] = (0xA0 + i).toByte()
        }
        val acked = RatchetDecryptAndPersist.parseReceiptAcked(good)
        assertEquals(16, acked.size)
        assertArrayEquals(good.copyOfRange(1, 17), acked)

        // Version 0x00 — pre-version-byte schema; must reject.
        val v00 = ByteArray(17)
        try {
            RatchetDecryptAndPersist.parseReceiptAcked(v00)
            fail("expected InvalidFrame for version=0x00")
        } catch (e: InvalidFrame) {
            assertTrue(
                "message must surface offending version, was: ${e.message}",
                e.message?.contains("version=0") == true
            )
        }

        // Version 0x02 — speculative future-schema frame; current parser rejects.
        val v02 = ByteArray(17).also { it[0] = 0x02 }
        try {
            RatchetDecryptAndPersist.parseReceiptAcked(v02)
            fail("expected InvalidFrame for version=0x02")
        } catch (e: InvalidFrame) {
            assertTrue(
                "message must surface offending version, was: ${e.message}",
                e.message?.contains("version=2") == true
            )
        }

        // Version 0xFF — highest possible byte; same rejection.
        val vFF = ByteArray(17).also { it[0] = 0xFF.toByte() }
        try {
            RatchetDecryptAndPersist.parseReceiptAcked(vFF)
            fail("expected InvalidFrame for version=0xFF")
        } catch (e: InvalidFrame) {
            assertTrue(
                "message must surface offending version, was: ${e.message}",
                e.message?.contains("version=255") == true
            )
        }
    }

    @Test
    fun receipt_plaintextSizeRejected_ifNot17Bytes() {
        // Too short (missing trailing UUID bytes).
        val short = ByteArray(16).also { it[0] = RatchetDecryptAndPersist.RECEIPT_VERSION }
        try {
            RatchetDecryptAndPersist.parseReceiptAcked(short)
            fail("expected InvalidFrame for size=16")
        } catch (e: InvalidFrame) {
            assertTrue(
                "message must surface offending size, was: ${e.message}",
                e.message?.contains("size=16") == true
            )
        }

        // Too long (a trailing pad byte the spec doesn't allow).
        val long = ByteArray(18).also { it[0] = RatchetDecryptAndPersist.RECEIPT_VERSION }
        try {
            RatchetDecryptAndPersist.parseReceiptAcked(long)
            fail("expected InvalidFrame for size=18")
        } catch (e: InvalidFrame) {
            assertTrue(
                "message must surface offending size, was: ${e.message}",
                e.message?.contains("size=18") == true
            )
        }

        // Zero-length.
        try {
            RatchetDecryptAndPersist.parseReceiptAcked(ByteArray(0))
            fail("expected InvalidFrame for size=0")
        } catch (e: InvalidFrame) {
            assertTrue(e.message?.contains("size=0") == true)
        }
    }
}
