package com.voicedrop.network

import android.util.Log
import java.util.concurrent.ConcurrentHashMap
import kotlin.jvm.Volatile
import kotlin.math.min

/**
 * DR10 — Per-sender ingest rate limit (token bucket).
 *
 * Receiver-side defence against the [dr9] MAX_SKIP amplification cost: every
 * inbound DATA / RECEIPT / RESET frame consumes one token, dropped when empty.
 * Drops happen at the deframer BEFORE any AEAD attempt or skip-key derivation.
 *
 * Finding #3 hardening:
 *  - Keyed on `senderFp` alone. The call site ([ConnectionManager.processFrame])
 *    drops any frame whose `recipFp != ownFingerprint` before calling tryAdmit,
 *    so the recipient is always us — keying on the (senderFp, recipFp) pair only
 *    added an unbounded, attacker-controllable key space.
 *  - The bucket map is bounded at [maxBuckets]. When full, fully-refilled (idle)
 *    buckets are reaped first (free — they carry no rate-limit state), then the
 *    least-recently-refilled bucket is evicted. This caps memory against a
 *    spoofed-fingerprint flood while preserving active legitimate peers.
 *
 * Sustained 20 frames/sec per sender with burst capacity 200 — covers legitimate
 * reconnect flushes while bounding sustained attack flux to a known CPU ceiling.
 * Drops aggregate to one [onDropsAggregated] callback per 30s window per bucket
 * (lazy flush at the next tryAdmit on that bucket once the window elapsed; also
 * flushed on eviction). Buckets are process-local, killed on app restart.
 */
class IngestRateLimiter(
    private val sustainedRatePerSec: Double = INGEST_RATE_SUSTAINED.toDouble(),
    private val burstCapacity: Double = INGEST_RATE_BURST.toDouble(),
    private val maxBuckets: Int = MAX_BUCKETS,
    private val clockMs: () -> Long = System::currentTimeMillis,
    private val onDropsAggregated: (senderFpHex: String, count: Long) -> Unit = ::logDrops
) {
    init {
        require(sustainedRatePerSec > 0.0) { "sustainedRatePerSec must be > 0" }
        require(burstCapacity >= 0.0) { "burstCapacity must be >= 0" }
        require(maxBuckets > 0) { "maxBuckets must be > 0" }
    }

    // A bucket idle this long has refilled to full burstCapacity and is
    // indistinguishable from a fresh one — reaping it loses no rate-limit state.
    // Derived from the injected params: time to refill an empty bucket to full.
    // (Degenerate burstCapacity == 0.0 → 0, reachable only from test configs where
    // the eviction path is never exercised; production defaults give 10_000 ms.)
    private val idleFullTtlMs: Long =
        Math.ceil(burstCapacity / sustainedRatePerSec * 1000.0).toLong()

    private class Bucket(
        var tokens: Double,
        // Volatile: reapAndEvict reads this while holding only evictionLock, but the
        // hot path writes it under synchronized(this). Different monitors give no
        // happens-before, so without volatile the reaper could act on a stale value
        // and evict an active sender. Volatile guarantees the read sees the latest write.
        @Volatile var lastRefillMs: Long,
        var pendingDrops: Long = 0L,
        var windowStartMs: Long = 0L
    )

    private val buckets = ConcurrentHashMap<String, Bucket>()
    // Guards only the new-bucket creation / eviction path. The hot path
    // (existing key) is lock-free apart from the per-bucket synchronized block.
    private val evictionLock = Any()

    /**
     * Returns true if the frame is admitted (a token was consumed), false if it
     * should be silently dropped. Thread-safe.
     */
    fun tryAdmit(senderFp: ByteArray): Boolean {
        require(senderFp.size == 32) { "senderFp must be 32 bytes" }
        val key = senderFp.toHexLower()
        val now = clockMs()
        var bucket = buckets[key]
        if (bucket == null) {
            synchronized(evictionLock) {
                bucket = buckets[key]                         // re-check under lock
                if (bucket == null) {
                    if (buckets.size >= maxBuckets) reapAndEvict(now)
                    val fresh = Bucket(tokens = burstCapacity, lastRefillMs = now, windowStartMs = now)
                    buckets[key] = fresh
                    bucket = fresh
                }
            }
        }
        val b = bucket!!
        // Benign race: if another thread evicts this key between the lock-free read
        // above and here, we mutate an orphaned Bucket and the sender simply gets one
        // fresh full burst on its next frame (a new bucket is created then). This is
        // bounded and non-amplifying — cheaper than re-checking map membership on
        // every admitted frame, which is the hot path.
        synchronized(b) {
            val elapsedMs = (now - b.lastRefillMs).coerceAtLeast(0L)
            val refill = elapsedMs * sustainedRatePerSec / 1000.0
            b.tokens = min(b.tokens + refill, burstCapacity)
            b.lastRefillMs = now

            if (b.pendingDrops > 0 && (now - b.windowStartMs) >= DROP_AGGREGATION_WINDOW_MS) {
                onDropsAggregated(key, b.pendingDrops)
                b.pendingDrops = 0L
                b.windowStartMs = now
            }

            return if (b.tokens >= 1.0) {
                b.tokens -= 1.0
                true
            } else {
                if (b.pendingDrops == 0L) b.windowStartMs = now
                b.pendingDrops++
                false
            }
        }
    }

    /**
     * Caller holds [evictionLock]. Reap every bucket idle past [idleFullTtlMs]
     * (free — fully refilled, no state). If still at capacity, evict the single
     * least-recently-refilled bucket. Flush pending drops before each removal.
     */
    private fun reapAndEvict(now: Long) {
        val it = buckets.entries.iterator()
        while (it.hasNext()) {
            val e = it.next()
            if (now - e.value.lastRefillMs >= idleFullTtlMs) {
                flushBucketDrops(e.key, e.value)
                it.remove()
            }
        }
        if (buckets.size >= maxBuckets) {
            val lru = buckets.entries.minByOrNull { it.value.lastRefillMs } ?: return
            flushBucketDrops(lru.key, lru.value)
            buckets.remove(lru.key)
        }
    }

    private fun flushBucketDrops(key: String, b: Bucket) {
        synchronized(b) {
            if (b.pendingDrops > 0) {
                onDropsAggregated(key, b.pendingDrops)
                b.pendingDrops = 0L
            }
        }
    }

    /**
     * Test / shutdown hook — emits any pending drop aggregates regardless of
     * window state and resets counts. Production code never needs this: the lazy
     * flush in [tryAdmit] (and on eviction) is sufficient under steady traffic.
     */
    fun flushPendingDrops() {
        for ((key, bucket) in buckets) flushBucketDrops(key, bucket)
    }

    /** Test/diagnostic hook: current number of live buckets. */
    internal fun bucketCount(): Int = buckets.size

    /** Test hook: whether a bucket exists for this sender. */
    internal fun hasBucket(senderFp: ByteArray): Boolean = buckets.containsKey(senderFp.toHexLower())

    private fun ByteArray.toHexLower(): String {
        val sb = StringBuilder(size * 2)
        for (b in this) {
            val v = b.toInt() and 0xff
            sb.append(HEX_DIGITS[v ushr 4])
            sb.append(HEX_DIGITS[v and 0x0f])
        }
        return sb.toString()
    }

    companion object {
        const val INGEST_RATE_SUSTAINED: Int = 20
        const val INGEST_RATE_BURST: Int = 200
        const val MAX_BUCKETS: Int = 2048
        const val DROP_AGGREGATION_WINDOW_MS: Long = 30_000L

        private const val TAG = "VoiceDrop/IngestRL"
        private val HEX_DIGITS = "0123456789abcdef".toCharArray()

        private fun logDrops(senderFp: String, count: Long) {
            Log.w(TAG, "ingest.rate_limited senderFp=${senderFp.take(8)} count=$count")
        }
    }
}
