package com.voicedrop.audio

import eu.buney.kopus.OpusApplication
import eu.buney.kopus.OpusEncoder as KopusEncoder
import java.nio.ByteBuffer
import java.nio.ByteOrder

class OpusEncoder {

    // Default-initialize so the class works without an explicit init() call
    private var encoder: KopusEncoder = createEncoder(16000, 1, 24000)

    fun init(sampleRate: Int = 16000, channels: Int = 1, bitrate: Int = 24000) {
        encoder.close()
        encoder = createEncoder(sampleRate, channels, bitrate)
    }

    fun encode(pcmBytes: ByteArray): ByteArray {
        val buf = ByteBuffer.wrap(pcmBytes).order(ByteOrder.LITTLE_ENDIAN)
        val shorts = ShortArray(pcmBytes.size / 2) { buf.short }
        val outData = ByteArray(4000)
        val outLen = encoder.encode(shorts, 0, shorts.size, outData, 0)
        return outData.copyOf(outLen)
    }

    fun release() {
        encoder.close()
    }

    private fun createEncoder(sampleRate: Int, channels: Int, bitrate: Int): KopusEncoder =
        KopusEncoder(
            sampleRate = sampleRate,
            channels = channels,
            application = OpusApplication.Voip
        )
}
