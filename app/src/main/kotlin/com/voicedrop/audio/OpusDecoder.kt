package com.voicedrop.audio

import io.github.crow_misia.libopus.OpusDecoder as LibOpusDecoder

class OpusDecoder {

    private var decoder: LibOpusDecoder? = null
    private var sampleRate: Int = 16000
    private var channels: Int = 1

    fun init(sampleRate: Int = 16000, channels: Int = 1) {
        this.sampleRate = sampleRate
        this.channels = channels
        decoder = LibOpusDecoder.create(sampleRate, channels)
    }

    fun decode(opusBytes: ByteArray): ShortArray {
        val dec = decoder ?: throw IllegalStateException("Decoder not initialized")
        val frameSize = sampleRate / 50
        val pcmShorts = ShortArray(frameSize * channels)
        val samplesDecoded = dec.decode(opusBytes, pcmShorts)
        return pcmShorts.copyOf(samplesDecoded * channels)
    }

    fun release() {
        decoder?.close()
        decoder = null
    }
}
