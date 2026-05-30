package com.voicedrop.network

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

class StunClient {

    suspend fun getPublicAddress(): InetSocketAddress? = withContext(Dispatchers.IO) {
        for ((host, port) in STUN_SERVERS) {
            val result = queryStun(host, port)
            if (result != null) return@withContext result
        }
        Log.w(TAG, "all STUN servers failed")
        null
    }

    private fun queryStun(host: String, port: Int): InetSocketAddress? {
        Log.d(TAG, "querying $host:$port")
        return try {
            val socket = DatagramSocket()
            socket.soTimeout = 3000
            val txId = ByteArray(12).also { java.security.SecureRandom().nextBytes(it) }
            val request = buildStunBindingRequest(txId)
            val addr = InetAddress.getByName(host)
            socket.send(DatagramPacket(request, request.size, addr, port))
            val buf = ByteArray(512)
            val pkt = DatagramPacket(buf, buf.size)
            socket.receive(pkt)
            socket.close()
            parseStunResponse(buf, pkt.length, txId)?.also { Log.i(TAG, "public address via $host: $it") }
        } catch (e: Exception) {
            Log.w(TAG, "STUN query failed ($host:$port): ${e.javaClass.simpleName}: ${e.message}")
            null
        }
    }

    private fun buildStunBindingRequest(txId: ByteArray): ByteArray {
        return ByteBuffer.allocate(20).apply {
            order(ByteOrder.BIG_ENDIAN)
            putShort(0x0001)
            putShort(0)
            putInt(MAGIC_COOKIE)
            put(txId)
        }.array()
    }

    internal fun parseStunResponse(data: ByteArray, length: Int, expectedTxId: ByteArray): InetSocketAddress? {
        val buf = ByteBuffer.wrap(data, 0, length).order(ByteOrder.BIG_ENDIAN)
        val msgType = buf.short
        if (msgType != 0x0101.toShort()) return null

        val msgLength = buf.short.toInt() and 0xFFFF
        val magic = buf.int
        val txId = ByteArray(12).also { buf.get(it) }       // was: buf.position(buf.position() + 12)
        if (!txId.contentEquals(expectedTxId)) return null   // RFC 5389 §6

        var pos = 20
        while (pos < 20 + msgLength) {
            buf.position(pos)
            val attrType = buf.short.toInt() and 0xFFFF
            val attrLen = buf.short.toInt() and 0xFFFF

            when (attrType) {
                ATTR_MAPPED_ADDRESS -> {
                    buf.get()
                    val family = buf.get().toInt() and 0xFF
                    val port = buf.short.toInt() and 0xFFFF
                    val ip = if (family == 0x01) {
                        val addr = ByteArray(4).also { buf.get(it) }
                        InetAddress.getByAddress(addr).hostAddress ?: return null
                    } else return null
                    return InetSocketAddress(ip, port)
                }
                ATTR_XOR_MAPPED_ADDRESS -> {
                    buf.get()
                    val family = buf.get().toInt() and 0xFF
                    val xorPort = (buf.short.toInt() and 0xFFFF) xor (MAGIC_COOKIE ushr 16)
                    val ip = if (family == 0x01) {
                        val xorAddr = ByteArray(4).also { buf.get(it) }
                        val magicBytes = ByteBuffer.allocate(4).putInt(MAGIC_COOKIE).array()
                        val addr = ByteArray(4) { i -> (xorAddr[i].toInt() xor magicBytes[i].toInt()).toByte() }
                        InetAddress.getByAddress(addr).hostAddress ?: return null
                    } else return null
                    return InetSocketAddress(ip, xorPort)
                }
            }

            pos += 4 + attrLen
            if (attrLen % 4 != 0) pos += 4 - attrLen % 4
        }
        return null
    }

    companion object {
        private const val TAG = "VoiceDrop/Stun"
        internal const val MAGIC_COOKIE = 0x2112A442.toInt()
        private const val ATTR_MAPPED_ADDRESS = 0x0001
        private const val ATTR_XOR_MAPPED_ADDRESS = 0x0020

        private val STUN_SERVERS = listOf(
            "stun.cloudflare.com" to 3478,
            "stun.l.google.com" to 19302,
            "stun1.l.google.com" to 19302,
        )

        // Internal for testing
        internal fun parseResponse(data: ByteArray, expectedTxId: ByteArray): InetSocketAddress? =
            StunClient().parseStunResponse(data, data.size, expectedTxId)

        // Back-compat: extract the embedded txId so existing positive tests pass.
        internal fun parseResponse(data: ByteArray): InetSocketAddress? =
            parseResponse(data, data.copyOfRange(8, 20))
    }
}
