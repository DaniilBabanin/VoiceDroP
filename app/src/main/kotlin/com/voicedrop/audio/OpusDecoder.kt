package com.voicedrop.audio

import eu.buney.kopus.OpusDecoder as KopusDecoder

class OpusDecoder {

    private var sampleRate: Int = 16000
    // Default-initialize so the class works without an explicit init() call
    private var decoder: KopusDecoder = KopusDecoder(sampleRate = 16000, channels = 1)

    fun init(sampleRate: Int = 16000, channels: Int = 1) {
        decoder.close()
        this.sampleRate = sampleRate
        decoder = KopusDecoder(sampleRate = sampleRate, channels = channels)
    }

    fun decode(opusBytes: ByteArray): ShortArray {
        val frameSize = sampleRate / 50  // 20ms at configured sample rate
        val outPcm = ShortArray(frameSize)
        decoder.decode(opusBytes, 0, opusBytes.size, outPcm, frameSize)
        return outPcm
    }

    fun release() {
        decoder.close()
    }
}
