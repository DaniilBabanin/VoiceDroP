package com.voicedrop.network

import android.util.Log
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.min

/**
 * DR10 — Per-contact ingest rate limit (token bucket).
 *
 * Receiver-side defence against the [dr9] MAX_SKIP amplification cost: every
 * inbound DATA / RECEIPT / RESET frame consumes one token, dropped when empty.
 * Drops happen at the deframer BEFORE any AEAD attempt or skip-key derivation.
 *
 * Sustained 20 frames/sec per `(senderFp, recipFp)` with burst capacity 200 —
 * covers legitimate reconnect flushes while bounding sustained attack flux to a
 * known CPU ceiling.
 *
 * Drops are aggregated to one [onDropsAggregated] callback per 30s window per
 * bucket (lazy flush — emitted at the next tryAdmit on the same bucket once the
 * window has elapsed). See [00-overview.md §2] and [telemetry.md] `ingest.rate_limited`.
 *
 * Buckets are process-local. Killed on app restart; the sender's outbox replay
 * then produces a fresh legitimate burst absorbed by the full bucket.
 */
class IngestRateLimiter(
    private val sustainedRatePerSec: Double = INGEST_RATE_SUSTAINED.toDouble(),
    private val burstCapacity: Double = INGEST_RATE_BURST.toDouble(),
    private val clockMs: () -> Long = System::currentTimeMillis,
    private val onDropsAggregated: (senderFpHex: String, recipFpHex: String, count: Long) -> Unit = ::logDrops
) {
    init {
        require(sustainedRatePerSec > 0.0) { "sustainedRatePerSec must be > 0" }
        require(burstCapacity >= 0.0) { "burstCapacity must be >= 0" }
    }

    private class Bucket(
        var tokens: Double,
        var lastRefillMs: Long,
        var pendingDrops: Long = 0L,
        var windowStartMs: Long = 0L
    )

    private val buckets = ConcurrentHashMap<String, Bucket>()

    /**
     * Returns true if the frame is admitted (a token was consumed), false if it
     * should be silently dropped. Thread-safe: per-bucket synchronization, no
     * suspension.
     */
    fun tryAdmit(senderFp: ByteArray, recipFp: ByteArray): Boolean {
        require(senderFp.size == 32) { "senderFp must be 32 bytes" }
        require(recipFp.size == 32) { "recipFp must be 32 bytes" }
        val senderHex = senderFp.toHexLower()
        val recipHex = recipFp.toHexLower()
        val key = "$senderHex|$recipHex"
        val now = clockMs()
        val bucket = buckets.computeIfAbsent(key) {
            Bucket(tokens = burstCapacity, lastRefillMs = now, windowStartMs = now)
        }
        synchronized(bucket) {
            val elapsedMs = (now - bucket.lastRefillMs).coerceAtLeast(0L)
            val refill = elapsedMs * sustainedRatePerSec / 1000.0
            bucket.tokens = min(bucket.tokens + refill, burstCapacity)
            bucket.lastRefillMs = now

            if (bucket.pendingDrops > 0 && (now - bucket.windowStartMs) >= DROP_AGGREGATION_WINDOW_MS) {
                onDropsAggregated(senderHex, recipHex, bucket.pendingDrops)
                bucket.pendingDrops = 0L
                bucket.windowStartMs = now
            }

            return if (bucket.tokens >= 1.0) {
                bucket.tokens -= 1.0
                true
            } else {
                if (bucket.pendingDrops == 0L) bucket.windowStartMs = now
                bucket.pendingDrops++
                false
            }
        }
    }

    /**
     * Test / shutdown hook — emits any pending drop aggregates regardless of
     * window state and resets counts. Production code never needs to call this:
     * the lazy flush in [tryAdmit] is sufficient under steady traffic.
     */
    fun flushPendingDrops() {
        for ((key, bucket) in buckets) {
            synchronized(bucket) {
                if (bucket.pendingDrops > 0) {
                    val parts = key.split("|", limit = 2)
                    onDropsAggregated(parts[0], parts[1], bucket.pendingDrops)
                    bucket.pendingDrops = 0L
                }
            }
        }
    }

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
        const val DROP_AGGREGATION_WINDOW_MS: Long = 30_000L

        private const val TAG = "VoiceDrop/IngestRL"
        private val HEX_DIGITS = "0123456789abcdef".toCharArray()

        private fun logDrops(senderFp: String, recipFp: String, count: Long) {
            Log.w(
                TAG,
                "ingest.rate_limited senderFp=${senderFp.take(8)} recipFp=${recipFp.take(8)} count=$count"
            )
        }
    }
}
