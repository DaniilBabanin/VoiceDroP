package com.voicedrop.network

import java.util.concurrent.atomic.AtomicLong
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * DR10 — IngestRateLimiter unit tests (§5 token bucket).
 *
 * Plain JUnit — the limiter has no Android dependencies on the tested paths
 * (production logging uses [android.util.Log] but every test injects a custom
 * [onDropsAggregated] callback so Log is never touched).
 */
class IngestRateLimiterTest {

    private val senderFp = ByteArray(32) { 0x11 }
    private val recipFp = ByteArray(32) { 0x22 }

    @Test
    fun burstWithinCapacity_allFramesAdmitted() {
        val now = AtomicLong(0L)
        val rl = IngestRateLimiter(
            clockMs = { now.get() },
            onDropsAggregated = { _, _, _ -> fail("no drops expected within burst capacity") }
        )

        // Spread 200 frames across ~50ms. Long ms cannot represent 0.25ms, so we
        // step the clock by 1ms every 4 frames — final clock = 49ms.
        for (k in 0 until 200) {
            now.set(k / 4L)
            assertTrue("frame $k must admit (within burst)", rl.tryAdmit(senderFp, recipFp))
        }
    }

    @Test
    fun sustainedAboveCeiling_excessDropped() {
        val now = AtomicLong(0L)
        val rl = IngestRateLimiter(
            clockMs = { now.get() },
            onDropsAggregated = { _, _, _ -> }
        )

        // 200/s sustained for 10s = 2000 frames at 5ms intervals.
        var admits = 0
        for (k in 0 until 2000) {
            now.set(5L * k)
            if (rl.tryAdmit(senderFp, recipFp)) admits++
        }
        // Spec: first 200 (burst) + 20×10 (refill over 10s) = 400.
        // Actual depends on which side of an integer boundary the bucket ends
        // up on; allow a small window.
        val drops = 2000 - admits
        assertTrue("expected ~400 admits, got $admits", admits in 395..405)
        assertTrue("expected ~1600 drops, got $drops", drops in 1595..1605)
    }

    @Test
    fun dropsAggregatedTo30sWindowEvent() {
        val events = mutableListOf<Triple<String, String, Long>>()
        val now = AtomicLong(0L)
        val rl = IngestRateLimiter(
            burstCapacity = 0.0,  // every call drops at t=0
            clockMs = { now.get() },
            onDropsAggregated = { s, r, c -> events.add(Triple(s, r, c)) }
        )

        // 1000 drops, all at t=0 — no refill, no window flush yet.
        for (k in 0 until 1000) {
            assertFalse(rl.tryAdmit(senderFp, recipFp))
        }
        assertTrue("no event expected before window closes, got $events", events.isEmpty())

        // Advance past the 30s window boundary; the next call triggers the
        // lazy flush of the accumulated drops.
        now.set(30_000L)
        rl.tryAdmit(senderFp, recipFp)

        assertEquals("exactly one aggregated event", 1, events.size)
        val (sender, recip, count) = events[0]
        assertEquals(1000L, count)
        assertEquals(senderFp.toHexLower(), sender)
        assertEquals(recipFp.toHexLower(), recip)
    }

    @Test
    fun independentBucketsPerSenderFp() {
        val now = AtomicLong(0L)
        val rl = IngestRateLimiter(
            clockMs = { now.get() },
            onDropsAggregated = { _, _, _ -> }
        )
        val senderA = ByteArray(32) { 0xA1.toByte() }
        val senderB = ByteArray(32) { 0xB2.toByte() }

        // Drain A's bucket; B's bucket should remain full.
        repeat(200) { assertTrue("A frame $it should admit", rl.tryAdmit(senderA, recipFp)) }
        assertFalse("A's 201st frame drops", rl.tryAdmit(senderA, recipFp))

        // B has its own bucket — 200 admits + 1 drop.
        repeat(200) { assertTrue("B frame $it should admit", rl.tryAdmit(senderB, recipFp)) }
        assertFalse("B's 201st frame drops", rl.tryAdmit(senderB, recipFp))
    }

    private fun ByteArray.toHexLower(): String =
        joinToString("") { "%02x".format(it) }
}
