package com.voicedrop.audio

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-Kotlin coverage for [PeakAccumulator] (§D / Phase B). No Android deps,
 * so plain JUnit 4 — matches the crypto test suite shape (e.g. MessagePayloadTest).
 */
class PeakAccumulatorTest {

    private val frameSize = 320 // 16kHz / 50fps — same as AudioRecorder

    @Test
    fun silentInputProducesAllZeroBytes() {
        val acc = PeakAccumulator()
        val silent = ShortArray(frameSize) // all zeros
        repeat(80) { acc.feed(silent, frameSize) }

        val out = acc.finalize()
        assertEquals(80, out.size)
        for ((i, b) in out.withIndex()) {
            assertEquals("bucket $i should be 0 for silent input", 0.toByte(), b)
        }
    }

    @Test
    fun saturatedInputProducesBytesNearFf() {
        val acc = PeakAccumulator()
        val saturated = ShortArray(frameSize) { Short.MAX_VALUE }
        repeat(80) { acc.feed(saturated, frameSize) }

        val out = acc.finalize()
        assertEquals(80, out.size)
        for ((i, b) in out.withIndex()) {
            // Short.MAX_VALUE / 32768f = 0.99997 → * 255 = 254.99 → 254. Allow 254–255.
            val unsigned = b.toInt() and 0xff
            assertTrue(
                "bucket $i = $unsigned, expected near 0xff",
                unsigned >= 254 && unsigned <= 255
            )
        }
    }

    @Test
    fun shortInputPadsTrailingBucketsWithZero() {
        val acc = PeakAccumulator()
        val frame = ShortArray(frameSize) { Short.MAX_VALUE }
        // Only 10 frames — fewer than the default 80 buckets.
        repeat(10) { acc.feed(frame, frameSize) }

        val out = acc.finalize()
        assertEquals(80, out.size)
        // First 10 buckets carry the saturated peak.
        for (i in 0 until 10) {
            val unsigned = out[i].toInt() and 0xff
            assertTrue("bucket $i should be non-zero (was $unsigned)", unsigned >= 254)
        }
        // Remaining 70 buckets should be the silent-tail pad.
        for (i in 10 until 80) {
            assertEquals("bucket $i should be 0 (silent tail)", 0.toByte(), out[i])
        }
    }

    @Test
    fun rampInputProducesMonotonicallyNonDecreasingOutput() {
        val acc = PeakAccumulator()
        // 80 frames whose peak amplitude ramps linearly from ~0 to Short.MAX_VALUE.
        for (i in 0 until 80) {
            val amp = ((i.toFloat() / 79f) * Short.MAX_VALUE).toInt().toShort()
            val frame = ShortArray(frameSize) { amp }
            acc.feed(frame, frameSize)
        }

        val out = acc.finalize()
        assertEquals(80, out.size)
        var prev = -1
        for ((i, b) in out.withIndex()) {
            val unsigned = b.toInt() and 0xff
            assertTrue(
                "bucket $i = $unsigned must be >= prev ($prev)",
                unsigned >= prev
            )
            prev = unsigned
        }
        // Sanity: the ramp should actually span a meaningful range, not be a flat line.
        val first = out[0].toInt() and 0xff
        val last = out[79].toInt() and 0xff
        assertEquals("ramp should start at ~0", 0, first)
        assertTrue("ramp should end near 0xff (was $last)", last >= 250)
    }
}
