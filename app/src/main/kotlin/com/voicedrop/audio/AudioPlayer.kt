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

    suspend fun play(opusStream: ByteArray, onProgress: (Float) -> Unit = {}): Unit =
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

            try {
                val lenBuf = ByteArray(4)
                while (isActive && input.available() > 0) {
                    if (input.read(lenBuf) != 4) break
                    val packetSize = ByteBuffer.wrap(lenBuf).order(ByteOrder.LITTLE_ENDIAN).int
                    if (packetSize <= 0 || packetSize > 65536) break

                    val packetBuf = ByteArray(packetSize)
                    if (input.read(packetBuf) != packetSize) break

                    val pcm = decoder.decode(packetBuf)
                    val bytes = shortsToBytes(pcm)
                    audioTrack.write(bytes, 0, bytes.size)

                    consumed += 4 + packetSize
                    onProgress(consumed / totalSize)
                }
            } finally {
                audioTrack.stop()
                audioTrack.release()
                decoder.release()
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
