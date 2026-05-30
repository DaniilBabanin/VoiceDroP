package com.voicedrop.audio

import eu.buney.kopus.OpusDecoder as KopusDecoder

class OpusDecoder {

    private var sampleRate: Int = 16000
    private var channels: Int = 1
    // Default-initialize so the class works without an explicit init() call
    private var decoder: KopusDecoder = KopusDecoder(sampleRate = 16000, channels = 1)

    fun init(sampleRate: Int = 16000, channels: Int = 1) {
        decoder.close()
        this.sampleRate = sampleRate
        this.channels = channels
        decoder = KopusDecoder(sampleRate = sampleRate, channels = channels)
    }

    fun decode(opusBytes: ByteArray): ShortArray {
        // Finding #5: size for the maximum Opus frame (120 ms) so a multi-frame
        // or stereo packet from a paired peer cannot overflow the buffer. kopus's
        // frameSize arg and return value are both per-channel (Concentus contract);
        // the output buffer must hold frameSize * channels interleaved shorts.
        val maxPerChannel = maxDecodedSamplesPerChannel(sampleRate)
        val outPcm = ShortArray(maxPerChannel * channels)
        val decodedPerChannel = decoder.decode(opusBytes, 0, opusBytes.size, outPcm, 0, maxPerChannel)
        val total = decodedPerChannel * channels
        return if (total == outPcm.size) outPcm else outPcm.copyOf(total)
    }

    fun release() {
        decoder.close()
    }

    companion object {
        /** Samples per channel in the maximum 120 ms Opus frame at [sampleRate]. */
        internal fun maxDecodedSamplesPerChannel(sampleRate: Int): Int = sampleRate / 1000 * 120
    }
}
