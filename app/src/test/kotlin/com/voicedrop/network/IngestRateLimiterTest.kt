package com.voicedrop.network

import java.util.concurrent.atomic.AtomicLong
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * DR10 — IngestRateLimiter unit tests (§5 token bucket) + Finding #3 hardening:
 * key on senderFp alone and bound the bucket map.
 *
 * Plain JUnit — no Android dependency on the tested paths (production logging
 * uses android.util.Log but every test injects a custom onDropsAggregated).
 */
class IngestRateLimiterTest {

    private val senderFp = ByteArray(32) { 0x11 }

    private fun fpOf(k: Int): ByteArray = ByteArray(32).also {
        it[0] = (k and 0xff).toByte()
        it[1] = ((k ushr 8) and 0xff).toByte()
    }

    @Test
    fun burstWithinCapacity_allFramesAdmitted() {
        val now = AtomicLong(0L)
        val rl = IngestRateLimiter(
            clockMs = { now.get() },
            onDropsAggregated = { _, _ -> fail("no drops expected within burst capacity") }
        )
        for (k in 0 until 200) {
            now.set(k / 4L)
            assertTrue("frame $k must admit (within burst)", rl.tryAdmit(senderFp))
        }
    }

    @Test
    fun sustainedAboveCeiling_excessDropped() {
        val now = AtomicLong(0L)
        val rl = IngestRateLimiter(
            clockMs = { now.get() },
            onDropsAggregated = { _, _ -> }
        )
        var admits = 0
        for (k in 0 until 2000) {
            now.set(5L * k)
            if (rl.tryAdmit(senderFp)) admits++
        }
        val drops = 2000 - admits
        assertTrue("expected ~400 admits, got $admits", admits in 395..405)
        assertTrue("expected ~1600 drops, got $drops", drops in 1595..1605)
    }

    @Test
    fun dropsAggregatedTo30sWindowEvent() {
        val events = mutableListOf<Pair<String, Long>>()
        val now = AtomicLong(0L)
        val rl = IngestRateLimiter(
            burstCapacity = 0.0,
            clockMs = { now.get() },
            onDropsAggregated = { s, c -> events.add(s to c) }
        )
        for (k in 0 until 1000) assertFalse(rl.tryAdmit(senderFp))
        assertTrue("no event expected before window closes, got $events", events.isEmpty())
        now.set(30_000L)
        rl.tryAdmit(senderFp)
        assertEquals("exactly one aggregated event", 1, events.size)
        assertEquals(senderFp.toHexLower(), events[0].first)
        assertEquals(1000L, events[0].second)
    }

    @Test
    fun independentBucketsPerSenderFp() {
        val now = AtomicLong(0L)
        val rl = IngestRateLimiter(
            clockMs = { now.get() },
            onDropsAggregated = { _, _ -> }
        )
        val senderA = ByteArray(32) { 0xA1.toByte() }
        val senderB = ByteArray(32) { 0xB2.toByte() }
        repeat(200) { assertTrue("A frame $it should admit", rl.tryAdmit(senderA)) }
        assertFalse("A's 201st frame drops", rl.tryAdmit(senderA))
        repeat(200) { assertTrue("B frame $it should admit", rl.tryAdmit(senderB)) }
        assertFalse("B's 201st frame drops", rl.tryAdmit(senderB))
    }

    @Test
    fun mapBoundedAtMaxBuckets_underUniqueSenderFlood() {
        val now = AtomicLong(0L)  // fixed clock → no bucket becomes reap-eligible
        val rl = IngestRateLimiter(
            maxBuckets = 8,
            clockMs = { now.get() },
            onDropsAggregated = { _, _ -> }
        )
        for (k in 0 until 100) {
            rl.tryAdmit(fpOf(k))
            assertTrue("bucket count ${rl.bucketCount()} exceeded maxBuckets=8 at step $k",
                rl.bucketCount() <= 8)
        }
        // Fixed clock → nothing is reap-eligible, so every insert past the 8th evicts
        // one (LRU) and re-inserts: the map saturates at exactly the cap. Asserting
        // the exact value also rejects a degenerate no-op/evict-everything impl.
        assertEquals("map saturates at the cap under unique-sender flood", 8, rl.bucketCount())
    }

    @Test
    fun idleBucketsReaped_whenOverCapAndRefilled() {
        val now = AtomicLong(0L)
        val rl = IngestRateLimiter(
            maxBuckets = 4,
            burstCapacity = 10.0,
            sustainedRatePerSec = 10.0,   // idleFullTtlMs = ceil(10/10*1000) = 1000
            clockMs = { now.get() },
            onDropsAggregated = { _, _ -> }
        )
        for (k in 0 until 4) rl.tryAdmit(fpOf(k))
        assertEquals(4, rl.bucketCount())
        now.set(2000L)                    // all 4 idle past TTL → reap-eligible
        rl.tryAdmit(fpOf(100))
        assertEquals("idle buckets reaped before insert", 1, rl.bucketCount())
    }

    @Test
    fun activeSenderSurvives_lruEvictsIdle() {
        val now = AtomicLong(0L)
        val rl = IngestRateLimiter(
            maxBuckets = 3,
            burstCapacity = 100.0,
            sustainedRatePerSec = 100.0,  // idleFullTtlMs = 1000
            clockMs = { now.get() },
            onDropsAggregated = { _, _ -> }
        )
        val active = fpOf(1)
        rl.tryAdmit(active)
        rl.tryAdmit(fpOf(2))
        rl.tryAdmit(fpOf(3))
        now.set(500L)
        rl.tryAdmit(active)               // active.lastRefillMs = 500 (most recent)
        now.set(600L)
        rl.tryAdmit(fpOf(4))             // cap hit, none reap-eligible → LRU (fp2 or fp3 @0) evicted
        assertTrue("active bucket must survive LRU eviction", rl.hasBucket(active))
        assertTrue("new sender admitted", rl.hasBucket(fpOf(4)))
        assertEquals(3, rl.bucketCount())
    }

    @Test
    fun pendingDropsFlushedOnEviction() {
        val now = AtomicLong(0L)
        val events = mutableListOf<Pair<String, Long>>()
        val rl = IngestRateLimiter(
            maxBuckets = 2,
            burstCapacity = 1.0,
            sustainedRatePerSec = 1.0,    // idleFullTtlMs = 1000
            clockMs = { now.get() },
            onDropsAggregated = { s, c -> events.add(s to c) }
        )
        val victim = fpOf(1)
        rl.tryAdmit(victim)              // admit (burst=1 → token 0)
        rl.tryAdmit(victim)              // drop → pendingDrops=1
        rl.tryAdmit(victim)              // drop → pendingDrops=2
        rl.tryAdmit(fpOf(2))
        now.set(10L); rl.tryAdmit(fpOf(2))   // fp2.lastRefillMs=10 > victim's 0 → victim is LRU
        now.set(20L); rl.tryAdmit(fpOf(3))   // cap hit, no reap (idle<1000) → evict victim, flush its drops
        assertEquals(1, events.size)
        assertEquals(victim.toHexLower(), events[0].first)
        assertEquals(2L, events[0].second)
    }

    private fun ByteArray.toHexLower(): String =
        joinToString("") { "%02x".format(it) }
}
