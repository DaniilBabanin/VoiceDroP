package com.voicedrop.audio

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Finding #5 — the decode output buffer was sized for a single 20 ms frame
 * (sampleRate/50); a 40/60/120 ms or stereo packet overflowed it and libopus
 * returned OPUS_BUFFER_TOO_SMALL (garbled/failed decode). The buffer is now
 * sized for the maximum 120 ms Opus frame.
 *
 * Tests the pure sizing helper only — constructing OpusDecoder would load native
 * kopus (UnsatisfiedLinkError under JVM).
 */
class OpusDecoderTest {

    @Test
    fun maxDecodedSamplesPerChannel_120msAtVariousRates() {
        assertEquals(1920, OpusDecoder.maxDecodedSamplesPerChannel(16000)) // 16000/1000*120
        assertEquals(2880, OpusDecoder.maxDecodedSamplesPerChannel(24000))
        assertEquals(5760, OpusDecoder.maxDecodedSamplesPerChannel(48000))
    }

    @Test
    fun maxDecodedSamplesPerChannel_isSixTimesA20msFrame() {
        // The old (buggy) capacity was sampleRate/50 (one 20 ms frame). 120 ms is 6×.
        val twentyMsFrame = 16000 / 50  // 320
        assertEquals(twentyMsFrame * 6, OpusDecoder.maxDecodedSamplesPerChannel(16000))
    }
}
