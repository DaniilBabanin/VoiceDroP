package com.voicedrop.audio

import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

class AudioRecorder {

    private val sampleRate = 16000
    private val frameSize = sampleRate / 50
    private val frameSizeBytes = frameSize * 2

    @Volatile
    private var recording = false
    private var audioRecord: AudioRecord? = null

    suspend fun start(): Unit = withContext(Dispatchers.IO) {
        val minBufSize = AudioRecord.getMinBufferSize(
            sampleRate,
            AudioFormat.CHANNEL_IN_MONO,
            AudioFormat.ENCODING_PCM_16BIT
        )
        if (minBufSize == AudioRecord.ERROR_BAD_VALUE) {
            throw IllegalStateException("AudioRecord parameters not supported")
        }
        val bufSize = maxOf(minBufSize, frameSizeBytes * 2)

        audioRecord = AudioRecord(
            MediaRecorder.AudioSource.MIC,
            sampleRate,
            AudioFormat.CHANNEL_IN_MONO,
            AudioFormat.ENCODING_PCM_16BIT,
            bufSize
        ).also { ar ->
            check(ar.state == AudioRecord.STATE_INITIALIZED) {
                "AudioRecord failed to initialize"
            }
        }

        recording = true
        audioRecord!!.startRecording()
    }

    // Signal the recordLoop to stop; the Deferred returned by recordLoop() carries the result.
    fun stopRecording() {
        recording = false
    }

    /**
     * Result of one recording session: the length-prefixed opus stream for the
     * wire/disk, plus a fixed-size downsampled peak array for the cached
     * waveform bar (§D / Phase B).
     */
    data class RecordResult(val opus: ByteArray, val peaks: ByteArray)

    suspend fun recordLoop(onFrame: (ByteArray) -> Unit): RecordResult = withContext(Dispatchers.IO) {
        val ar = audioRecord ?: return@withContext RecordResult(ByteArray(0), ByteArray(0))
        val encoder = OpusEncoder()
        encoder.init(sampleRate, 1, 24000)

        val output = ByteArrayOutputStream()
        val buffer = ShortArray(frameSize)
        val peakAccumulator = PeakAccumulator()

        while (recording && isActive) {
            val read = ar.read(buffer, 0, frameSize)
            if (read > 0) {
                peakAccumulator.feed(buffer, read)
                val pcmBytes = shortsToBytes(buffer, read)
                val encoded = encoder.encode(pcmBytes)
                output.write(encoded.size.toLittleEndianBytes())
                output.write(encoded)
                onFrame(encoded)
            }
        }

        ar.stop()
        ar.release()
        encoder.release()
        RecordResult(opus = output.toByteArray(), peaks = peakAccumulator.build())
    }

    private fun Int.toLittleEndianBytes(): ByteArray =
        ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(this).array()
}
