package com.voicedrop.audio

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Pure-decode peak extraction for backfilling `MessageEntity.waveformPeaks`
 * on rows predating v1.4.0.3.
 *
 * Distinct from [AudioPlayer.play]: opens no AudioTrack, emits no progress,
 * and never advances message state. The only persistence is via the
 * `waveformPeaks IS NULL`-guarded DAO update at the caller. A row that has
 * never been played stays "unplayed" after extraction.
 */
class PeakExtractor {

    private val sampleRate = 16000

    /**
     * Decode the length-prefixed opus stream at [opusPath] and return a
     * downsampled peak array (same encoding as [PeakAccumulator.build]).
     * Returns null on missing file or malformed framing — callers should
     * leave the row unchanged in that case rather than writing zeros.
     */
    suspend fun extract(opusPath: String): ByteArray? = withContext(Dispatchers.IO) {
        val file = File(opusPath)
        if (!file.exists()) return@withContext null
        val opusBytes = file.readBytes()
        val decoder = OpusDecoder()
        decoder.init(sampleRate, 1)
        val accumulator = PeakAccumulator()
        var ok = false

        try {
            val input = ByteArrayInputStream(opusBytes)
            val lenBuf = ByteArray(4)
            while (isActive && input.available() > 0) {
                if (input.read(lenBuf) != 4) return@withContext null
                val packetSize = ByteBuffer.wrap(lenBuf).order(ByteOrder.LITTLE_ENDIAN).int
                if (packetSize <= 0 || packetSize > 65536) return@withContext null

                val packetBuf = ByteArray(packetSize)
                if (input.read(packetBuf) != packetSize) return@withContext null

                val pcm = decoder.decode(packetBuf)
                accumulator.feed(pcm, pcm.size)
            }
            // Only treat a fully drained stream as success; partial reads or
            // cancellation must not produce a peak array (we'd persist a
            // truncated waveform under the IS-NULL guard, locking it in).
            ok = isActive && input.available() == 0
        } finally {
            decoder.release()
        }

        if (ok) accumulator.build() else null
    }
}
