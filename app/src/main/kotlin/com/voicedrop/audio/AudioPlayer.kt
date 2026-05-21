package com.voicedrop.audio

import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioTrack
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

class AudioPlayer {

    private val sampleRate = 16000
    private var playJob: Job? = null

    /**
     * Decode an opus stream and play it through AudioTrack.
     *
     * @param onPeaksReady invoked once on **natural completion** (not cancellation)
     *   with a downsampled waveform built from per-packet PCM peaks. Skipped if
     *   null — callers pass null when the message already has peaks stored, so the
     *   accumulator stays cold for the hot path. See Phase F of the 2026-05 design
     *   refresh: this fuels lazy backfill for messages predating v1.4.0.3.
     */
    suspend fun play(
        opusStream: ByteArray,
        onProgress: (Float) -> Unit = {},
        onPeaksReady: ((ByteArray) -> Unit)? = null,
    ): Unit =
        withContext(Dispatchers.IO) {
            val decoder = OpusDecoder()
            decoder.init(sampleRate, 1)

            val minBufSize = AudioTrack.getMinBufferSize(
                sampleRate,
                AudioFormat.CHANNEL_OUT_MONO,
                AudioFormat.ENCODING_PCM_16BIT
            )

            val audioTrack = AudioTrack(
                AudioManager.STREAM_MUSIC,
                sampleRate,
                AudioFormat.CHANNEL_OUT_MONO,
                AudioFormat.ENCODING_PCM_16BIT,
                maxOf(minBufSize, 4096),
                AudioTrack.MODE_STREAM
            )

            audioTrack.play()

            val input = ByteArrayInputStream(opusStream)
            val totalSize = opusStream.size.toFloat()
            var consumed = 0
            val accumulator = if (onPeaksReady != null) PeakAccumulator() else null
            var reachedNaturalEnd = false

            try {
                val lenBuf = ByteArray(4)
                while (isActive && input.available() > 0) {
                    if (input.read(lenBuf) != 4) break
                    val packetSize = ByteBuffer.wrap(lenBuf).order(ByteOrder.LITTLE_ENDIAN).int
                    if (packetSize <= 0 || packetSize > 65536) break

                    val packetBuf = ByteArray(packetSize)
                    if (input.read(packetBuf) != packetSize) break

                    val pcm = decoder.decode(packetBuf)
                    accumulator?.feed(pcm, pcm.size)
                    val bytes = shortsToBytes(pcm)
                    audioTrack.write(bytes, 0, bytes.size)

                    consumed += 4 + packetSize
                    onProgress(consumed / totalSize)
                }
                // Loop exited because the stream is drained, not via cancellation
                // or a short read on a framing boundary. Only the drained case is
                // safe to treat as "we saw every frame" for the peak backfill.
                if (isActive && input.available() == 0) reachedNaturalEnd = true
            } finally {
                audioTrack.stop()
                audioTrack.release()
                decoder.release()
            }

            if (reachedNaturalEnd && accumulator != null && onPeaksReady != null) {
                onPeaksReady(accumulator.build())
            }
        }

    suspend fun stop() {
        playJob?.cancelAndJoin()
        playJob = null
    }

    private fun shortsToBytes(shorts: ShortArray): ByteArray {
        val buf = ByteBuffer.allocate(shorts.size * 2).order(ByteOrder.LITTLE_ENDIAN)
        for (s in shorts) buf.putShort(s)
        return buf.array()
    }
}
