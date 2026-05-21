package com.voicedrop.audio

import kotlin.math.abs

/**
 * Record-time peak-per-frame collector. Accumulates one normalized peak per
 * audio frame in memory, then downsamples to a fixed-size byte array on
 * [build] for storage in `MessageEntity.waveformPeaks` (see §D of the
 * 2026-05 design refresh; produced in Phase B, consumed in Phase E).
 *
 * Pure: no Android imports so it's unit-testable. Memory scales linearly with
 * recording length (4 B per frame × 50 fps ≈ 12 KB per minute). Bounded only
 * by the caller's recording duration; this class imposes no cap.
 *
 * Output encoding: one unsigned byte per bucket spanning the recording, each
 * byte = `(peak * 255)` clamped 0..255 where `peak ∈ [0f, 1f]`.
 */
class PeakAccumulator(private val targetBuckets: Int = 80) {

    private val framePeaks: ArrayList<Float> = ArrayList()

    /**
     * Append `max(|samples[0..length-1]|) / 32768f` as one frame peak.
     * `length` may be shorter than `samples.size` (matches `AudioRecord.read`'s
     * "frames actually read" contract). A length of 0 contributes a zero peak.
     */
    fun feed(samples: ShortArray, length: Int) {
        var maxAbs = 0
        for (i in 0 until length) {
            // abs(Short.MIN_VALUE) overflows Short; promote to Int.
            val v = abs(samples[i].toInt())
            if (v > maxAbs) maxAbs = v
        }
        framePeaks.add(maxAbs / 32768f)
    }

    /**
     * Downsample the collected per-frame peaks into `targetBuckets` bytes via
     * simple averaging. If fewer frames were fed than `targetBuckets`, trailing
     * buckets are left at 0 (silent-tail padding) rather than stretched —
     * keeps short recordings honest about their length.
     */
    fun build(): ByteArray {
        val out = ByteArray(targetBuckets)
        val n = framePeaks.size
        if (n == 0) return out

        if (n <= targetBuckets) {
            // Short input: one frame per bucket, leave the rest as zero.
            for (i in 0 until n) {
                out[i] = floatToByte(framePeaks[i])
            }
            return out
        }

        // Average each bucket's slice of the source frames.
        for (b in 0 until targetBuckets) {
            val start = (b.toLong() * n / targetBuckets).toInt()
            val end = ((b + 1).toLong() * n / targetBuckets).toInt()
            var sum = 0f
            var count = 0
            for (i in start until end) {
                sum += framePeaks[i]
                count++
            }
            val avg = if (count > 0) sum / count else 0f
            out[b] = floatToByte(avg)
        }
        return out
    }

    private fun floatToByte(x: Float): Byte =
        (x * 255f).toInt().coerceIn(0, 255).toByte()
}
