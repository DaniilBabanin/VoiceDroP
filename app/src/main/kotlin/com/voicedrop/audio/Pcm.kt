package com.voicedrop.audio

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Pack the first [count] samples of a 16-bit PCM [ShortArray] into a
 * little-endian byte array. Shared by [AudioRecorder] (partial capture buffers,
 * explicit [count]) and [AudioPlayer] (whole decoded buffer, default [count]).
 */
internal fun shortsToBytes(shorts: ShortArray, count: Int = shorts.size): ByteArray {
    val buf = ByteBuffer.allocate(count * 2).order(ByteOrder.LITTLE_ENDIAN)
    for (i in 0 until count) buf.putShort(shorts[i])
    return buf.array()
}
