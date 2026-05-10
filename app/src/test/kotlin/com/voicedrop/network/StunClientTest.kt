package com.voicedrop.network

import org.junit.Assert.*
import org.junit.Test

class StunClientTest {

    @Test
    fun parseXorMappedAddress() {
        // XOR-MAPPED-ADDRESS attribute (type 0x0020) for 203.0.113.1:12345
        // Constructed per RFC 5389:
        // IP XOR'd with magic cookie 0x2112A442
        // Port XOR'd with high 16 bits of magic cookie (0x2112)
        val magicCookie = 0x2112A442
        val ip = byteArrayOf(203.toByte(), 0, 113.toByte(), 1)
        val ipInt = ((ip[0].toInt() and 0xFF) shl 24) or
                    ((ip[1].toInt() and 0xFF) shl 16) or
                    ((ip[2].toInt() and 0xFF) shl 8) or
                    (ip[3].toInt() and 0xFF)
        val xoredIp = ipInt xor magicCookie
        val port = 12345
        val xoredPort = port xor (magicCookie ushr 16)

        // Build a minimal STUN success response containing only XOR-MAPPED-ADDRESS
        val attrValue = byteArrayOf(
            0x00, 0x01, // family = IPv4
            ((xoredPort ushr 8) and 0xFF).toByte(),
            (xoredPort and 0xFF).toByte(),
            ((xoredIp ushr 24) and 0xFF).toByte(),
            ((xoredIp ushr 16) and 0xFF).toByte(),
            ((xoredIp ushr 8) and 0xFF).toByte(),
            (xoredIp and 0xFF).toByte()
        )

        val attrHeader = byteArrayOf(
            0x00, 0x20, // XOR-MAPPED-ADDRESS
            0x00, attrValue.size.toByte()
        )

        val attrBytes = attrHeader + attrValue
        val transactionId = ByteArray(12)
        val header = byteArrayOf(
            0x01, 0x01, // Success Response
            (attrBytes.size ushr 8).toByte(), (attrBytes.size and 0xFF).toByte(),
            0x21, 0x12, 0xA4.toByte(), 0x42, // Magic cookie
            *transactionId
        )

        val response = header + attrBytes

        val result = StunClient.parseResponse(response)
        assertNotNull(result)
        assertEquals("203.0.113.1", result!!.address.hostAddress)
        assertEquals(12345, result.port)
    }
}
