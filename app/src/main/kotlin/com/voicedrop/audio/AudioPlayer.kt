package com.voicedrop.audio

import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioTrack
import android.media.PlaybackParams
import android.util.Log
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Spec 18-record-playback-ux.md §7. `play()` returns a [PlaybackHandle] the
 * caller holds to control seek / speed / pause / stop. The handle's
 * [PlaybackHandle.completion] resolves when playback ends naturally or via stop().
 *
 * Implementation notes:
 *   - Opus is stateful; seeks tear down and rebuild the decoder.
 *   - [AudioTrack.playbackParams] survives `flush()` from API 26+; minSdk is 28.
 *   - Pause is a busy-poll on a boolean to keep the existing single-loop shape.
 *   - [OpusDecoder.decode] is JNI-backed (kopus). The decode call is wrapped in
 *     try/catch so a malformed packet ends playback gracefully rather than
 *     crashing the coroutine — also makes the loop test-friendly under
 *     Robolectric where the native lib may be missing.
 */
class AudioPlayer {

    private val sampleRate = 16000

    fun play(
        opusStream: ByteArray,
        onProgress: (Float) -> Unit = {},
        onPeaksReady: ((ByteArray) -> Unit)? = null,
    ): PlaybackHandle {
        val handle = PlaybackHandle(opusStream, onProgress, onPeaksReady)
        handle.start()
        return handle
    }

    inner class PlaybackHandle internal constructor(
        private val opusStream: ByteArray,
        private val onProgress: (Float) -> Unit,
        private val onPeaksReady: ((ByteArray) -> Unit)?,
    ) {
        private val mutex = Mutex()
        private val paused = AtomicBoolean(false)
        private val cursor = AtomicInteger(0)
        private val targetSpeed = AtomicReference(1f)
        private val handleScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        private var playJob: Job? = null
        private var audioTrack: AudioTrack? = null
        private var decoder: OpusDecoder? = null
        val completion = CompletableDeferred<Unit>()

        internal fun start() {
            playJob = handleScope.launch { runLoop(this) }
        }

        private suspend fun runLoop(scope: CoroutineScope) {
            try {
                val minBufSize = AudioTrack.getMinBufferSize(
                    sampleRate,
                    AudioFormat.CHANNEL_OUT_MONO,
                    AudioFormat.ENCODING_PCM_16BIT
                )
                audioTrack = AudioTrack(
                    AudioManager.STREAM_MUSIC,
                    sampleRate,
                    AudioFormat.CHANNEL_OUT_MONO,
                    AudioFormat.ENCODING_PCM_16BIT,
                    maxOf(minBufSize, 4096),
                    AudioTrack.MODE_STREAM
                )
                decoder = OpusDecoder().also { it.init(sampleRate, 1) }
                audioTrack!!.play()

                val accumulator = if (onPeaksReady != null) PeakAccumulator() else null
                var reachedNaturalEnd = false

                try {
                    val lenBuf = ByteArray(4)
                    outer@ while (scope.isActive) {
                        while (paused.get() && scope.isActive) delay(20)
                        if (!scope.isActive) break
                        val ofs = cursor.get()
                        if (ofs + 4 > opusStream.size) {
                            reachedNaturalEnd = true
                            break@outer
                        }
                        mutex.withLock {
                            System.arraycopy(opusStream, ofs, lenBuf, 0, 4)
                        }
                        val packetSize = ByteBuffer.wrap(lenBuf).order(ByteOrder.LITTLE_ENDIAN).int
                        if (packetSize <= 0 || packetSize > 65536) break
                        if (ofs + 4 + packetSize > opusStream.size) break

                        val packetBuf = ByteArray(packetSize)
                        mutex.withLock {
                            System.arraycopy(opusStream, ofs + 4, packetBuf, 0, packetSize)
                            cursor.set(ofs + 4 + packetSize)
                        }
                        val pcm = try {
                            decoder!!.decode(packetBuf)
                        } catch (t: Throwable) {
                            Log.w(TAG, "decode failed at offset=$ofs size=$packetSize: ${t.message}")
                            break@outer
                        }
                        accumulator?.feed(pcm, pcm.size)
                        val bytes = shortsToBytes(pcm)
                        audioTrack!!.write(bytes, 0, bytes.size)
                        onProgress(cursor.get().toFloat() / opusStream.size.toFloat())
                    }
                } finally {
                    audioTrack?.runCatching { stop() }
                    audioTrack?.runCatching { release() }
                    audioTrack = null
                    decoder?.runCatching { release() }
                    decoder = null
                }

                if (reachedNaturalEnd && accumulator != null && onPeaksReady != null) {
                    onPeaksReady.invoke(accumulator.build())
                }
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.w(TAG, "playback failed", e)
            } finally {
                if (!completion.isCompleted) completion.complete(Unit)
            }
        }

        suspend fun seek(progress: Float): Unit = withContext(Dispatchers.IO) {
            val clamped = progress.coerceIn(0f, 1f)
            val targetByte = (clamped * opusStream.size).toInt()
            mutex.withLock {
                var i = 0
                val tmp = ByteArray(4)
                while (i + 4 <= opusStream.size) {
                    System.arraycopy(opusStream, i, tmp, 0, 4)
                    val sz = ByteBuffer.wrap(tmp).order(ByteOrder.LITTLE_ENDIAN).int
                    if (sz <= 0 || i + 4 + sz > opusStream.size) break
                    if (i + 4 + sz > targetByte) {
                        cursor.set(i)
                        break
                    }
                    i += 4 + sz
                }
                audioTrack?.runCatching { pause() }
                audioTrack?.runCatching { flush() }
                decoder?.runCatching { release() }
                decoder = OpusDecoder().also { it.init(sampleRate, 1) }
                audioTrack?.runCatching {
                    play()
                    // Re-apply target speed after restart since flush can reset params.
                    val s = targetSpeed.get()
                    if (s != 1f) {
                        playbackParams = (playbackParams ?: PlaybackParams()).setSpeed(s)
                    }
                }
            }
        }

        fun setSpeed(speed: Float) {
            require(speed in 0.5f..2f) { "speed out of range: $speed" }
            targetSpeed.set(speed)
            audioTrack?.runCatching {
                val params = playbackParams ?: PlaybackParams()
                playbackParams = params.setSpeed(speed)
            }
        }

        suspend fun pause() {
            paused.set(true)
            audioTrack?.runCatching { pause() }
        }

        suspend fun resume() {
            paused.set(false)
            audioTrack?.runCatching { play() }
        }

        suspend fun stop() {
            // pause()+flush() discards queued PCM and unblocks any in-flight
            // audioTrack.write() inside runLoop so cancellation is observed promptly.
            audioTrack?.runCatching { pause() }
            audioTrack?.runCatching { flush() }
            playJob?.cancel()
            playJob?.join()
            if (!completion.isCompleted) completion.complete(Unit)
            handleScope.coroutineContext[Job]?.cancel()
        }
    }

    private companion object {
        private const val TAG = "AudioPlayer"
    }
}
