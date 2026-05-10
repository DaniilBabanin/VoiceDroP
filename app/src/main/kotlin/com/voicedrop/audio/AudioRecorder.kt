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

    suspend fun stop(): ByteArray = withContext(Dispatchers.IO) {
        recording = false
        val ar = audioRecord ?: return@withContext ByteArray(0)
        audioRecord = null

        val encoder = OpusEncoder()
        encoder.init(sampleRate, 1, 24000)

        val output = ByteArrayOutputStream()
        val buffer = ShortArray(frameSize)

        // Drain remaining audio
        var read = ar.read(buffer, 0, frameSize)
        while (read > 0) {
            val pcmBytes = shortsToBytes(buffer, read)
            val encoded = encoder.encode(pcmBytes)
            output.write(encoded.size.toLittleEndianBytes())
            output.write(encoded)
            read = ar.read(buffer, 0, frameSize)
        }

        ar.stop()
        ar.release()
        encoder.release()
        output.toByteArray()
    }

    suspend fun recordLoop(onFrame: (ByteArray) -> Unit): ByteArray = withContext(Dispatchers.IO) {
        val ar = audioRecord ?: return@withContext ByteArray(0)
        val encoder = OpusEncoder()
        encoder.init(sampleRate, 1, 24000)

        val output = ByteArrayOutputStream()
        val buffer = ShortArray(frameSize)

        while (recording && isActive) {
            val read = ar.read(buffer, 0, frameSize)
            if (read > 0) {
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
        output.toByteArray()
    }

    private fun shortsToBytes(shorts: ShortArray, count: Int): ByteArray {
        val buf = ByteBuffer.allocate(count * 2).order(ByteOrder.LITTLE_ENDIAN)
        for (i in 0 until count) buf.putShort(shorts[i])
        return buf.array()
    }

    private fun Int.toLittleEndianBytes(): ByteArray =
        ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(this).array()
}
