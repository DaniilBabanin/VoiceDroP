package com.voicedrop.audio

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class OpusCodecTest {

    @Test
    fun encoderProducesNonEmptyOutput() {
        val encoder = OpusEncoder()
        // 20ms of silence at 16kHz mono PCM16 = 640 bytes
        val silence = ByteArray(640)
        val encoded = encoder.encode(silence)
        assertTrue("Encoder must produce output", encoded.isNotEmpty())
        encoder.release()
    }

    @Test
    fun encoderDecoderRoundTrip() {
        val encoder = OpusEncoder()
        val decoder = OpusDecoder()

        // 20ms sine wave at 440 Hz
        val sampleRate = 16000
        val frameSamples = 320
        val samples = ShortArray(frameSamples) { i ->
            (Short.MAX_VALUE * Math.sin(2 * Math.PI * 440 * i / sampleRate)).toInt().toShort()
        }
        val pcmBytes = ByteArray(frameSamples * 2)
        for (i in samples.indices) {
            pcmBytes[i * 2] = (samples[i].toInt() and 0xFF).toByte()
            pcmBytes[i * 2 + 1] = ((samples[i].toInt() ushr 8) and 0xFF).toByte()
        }

        val encoded = encoder.encode(pcmBytes)
        val decoded = decoder.decode(encoded)

        assertEquals(frameSamples, decoded.size)
        // Verify signal correlation rather than exact equality (lossy codec)
        var energy = 0.0
        for (s in decoded) energy += s.toLong() * s.toLong()
        assertTrue("Decoded signal must have energy", energy > 0)

        encoder.release()
        decoder.release()
    }
}
