package com.voicedrop.network

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.withContext
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder

class PeerConnection(private val socket: Socket) {

    private val output = socket.getOutputStream()
    private val input = socket.getInputStream()

    @Volatile
    var isAlive: Boolean = true
        private set

    suspend fun send(frame: ByteArray) = withContext(Dispatchers.IO) {
        try {
            val buf = ByteBuffer.allocate(4 + frame.size).order(ByteOrder.BIG_ENDIAN)
            buf.putInt(frame.size)
            buf.put(frame)
            output.write(buf.array())
            output.flush()
        } catch (e: Exception) {
            isAlive = false
            throw e
        }
    }

    suspend fun receive(): ByteArray = withContext(Dispatchers.IO) {
        try {
            val lenBuf = ByteArray(4)
            readFully(lenBuf)
            val length = ByteBuffer.wrap(lenBuf).order(ByteOrder.BIG_ENDIAN).int
            require(length in 1..MAX_FRAME_SIZE) { "Invalid frame length: $length" }
            val frame = ByteArray(length)
            readFully(frame)
            frame
        } catch (e: Exception) {
            isAlive = false
            throw e
        }
    }

    fun receiveFlow(): Flow<ByteArray> = flow {
        while (isAlive && !socket.isClosed) {
            try {
                emit(receive())
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                isAlive = false
                break
            }
        }
    }.flowOn(Dispatchers.IO)

    fun close() {
        isAlive = false
        runCatching { socket.close() }
    }

    private fun readFully(buf: ByteArray) {
        var offset = 0
        while (offset < buf.size) {
            val read = input.read(buf, offset, buf.size - offset)
            if (read == -1) throw java.io.EOFException("Connection closed")
            offset += read
        }
    }

    companion object {
        private const val MAX_FRAME_SIZE = 10 * 1024 * 1024
    }
}
