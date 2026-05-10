package com.voicedrop.audio

import io.github.crow_misia.libopus.OpusEncoder as LibOpusEncoder

class OpusEncoder {

    private var encoder: LibOpusEncoder? = null

    fun init(sampleRate: Int = 16000, channels: Int = 1, bitrate: Int = 24000) {
        encoder = LibOpusEncoder.create(sampleRate, channels, LibOpusEncoder.Application.VOIP).apply {
            setBitrate(bitrate)
            setComplexity(5)
        }
    }

    fun encode(pcmBytes: ByteArray): ByteArray {
        val enc = encoder ?: throw IllegalStateException("Encoder not initialized")
        return enc.encode(pcmBytes, pcmBytes.size / 2)
    }

    fun release() {
        encoder?.close()
        encoder = null
    }
}
