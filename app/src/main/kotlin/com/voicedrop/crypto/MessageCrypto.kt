package com.voicedrop.crypto

import com.google.crypto.tink.subtle.ChaCha20Poly1305
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import java.util.UUID

object MessageCrypto {

    private const val NONCE_SIZE = 24
    private const val SENDER_FP_SIZE = 32
    private const val RECIPIENT_FP_SIZE = 32
    private const val UUID_SIZE = 16
    private const val TIMESTAMP_SIZE = 8
    private const val FRAME_LENGTH_SIZE = 4

    fun encrypt(sessionKey: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = ChaCha20Poly1305(sessionKey)
        return cipher.encrypt(plaintext, ByteArray(0))
    }

    fun decrypt(sessionKey: ByteArray, ciphertext: ByteArray): ByteArray {
        val cipher = ChaCha20Poly1305(sessionKey)
        return cipher.decrypt(ciphertext, ByteArray(0))
    }

    fun buildFrame(
        senderFp: ByteArray,
        recipientFp: ByteArray,
        uuid: UUID,
        sessionKey: ByteArray,
        plaintextPayload: ByteArray
    ): ByteArray {
        val ciphertext = encrypt(sessionKey, plaintextPayload)
        val timestampMs = System.currentTimeMillis()
        val uuidBytes = uuidToBytes(uuid)

        val framePayload = ByteBuffer.allocate(
            SENDER_FP_SIZE + RECIPIENT_FP_SIZE + UUID_SIZE + TIMESTAMP_SIZE + ciphertext.size
        ).apply {
            order(ByteOrder.BIG_ENDIAN)
            put(senderFp)
            put(recipientFp)
            put(uuidBytes)
            putLong(timestampMs)
            put(ciphertext)
        }.array()

        return ByteBuffer.allocate(FRAME_LENGTH_SIZE + framePayload.size).apply {
            order(ByteOrder.BIG_ENDIAN)
            putInt(framePayload.size)
            put(framePayload)
        }.array()
    }

    fun parseFrame(bytes: ByteArray, sessionKey: ByteArray): ParsedFrame {
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN)
        val frameLength = buf.int
        val senderFp = ByteArray(SENDER_FP_SIZE).also { buf.get(it) }
        val recipientFp = ByteArray(RECIPIENT_FP_SIZE).also { buf.get(it) }
        val uuidBytes = ByteArray(UUID_SIZE).also { buf.get(it) }
        val timestampMs = buf.long
        val ciphertext = ByteArray(frameLength - SENDER_FP_SIZE - RECIPIENT_FP_SIZE - UUID_SIZE - TIMESTAMP_SIZE)
        buf.get(ciphertext)

        val plaintext = decrypt(sessionKey, ciphertext)
        val uuid = bytesToUuid(uuidBytes)

        return ParsedFrame(
            senderFingerprint = senderFp.joinToString("") { "%02x".format(it) },
            recipientFingerprint = recipientFp.joinToString("") { "%02x".format(it) },
            uuid = uuid,
            timestampMs = timestampMs,
            plaintext = plaintext
        )
    }

    fun buildVoicePayload(durationMs: Int, deleteAfterMs: Long, opusBytes: ByteArray): ByteArray {
        return ByteBuffer.allocate(1 + 4 + 4 + 8 + opusBytes.size).apply {
            order(ByteOrder.BIG_ENDIAN)
            put(MessageType.VOICE.value)
            putInt(4 + 8 + opusBytes.size)
            putInt(durationMs)
            putLong(deleteAfterMs)
            put(opusBytes)
        }.array()
    }

    fun buildDeletePayload(targetUuid: UUID): ByteArray {
        return ByteBuffer.allocate(1 + 4 + UUID_SIZE).apply {
            order(ByteOrder.BIG_ENDIAN)
            put(MessageType.DELETE.value)
            putInt(UUID_SIZE)
            put(uuidToBytes(targetUuid))
        }.array()
    }

    fun buildPingPayload(): ByteArray {
        return ByteBuffer.allocate(1 + 4).apply {
            order(ByteOrder.BIG_ENDIAN)
            put(MessageType.PING.value)
            putInt(0)
        }.array()
    }

    fun parsePlaintext(plaintext: ByteArray): ParsedPayload {
        val buf = ByteBuffer.wrap(plaintext).order(ByteOrder.BIG_ENDIAN)
        val type = MessageType.fromValue(buf.get()) ?: throw IllegalArgumentException("Unknown message type")
        val payloadLength = buf.int
        val payload = ByteArray(payloadLength).also { buf.get(it) }
        return ParsedPayload(type, payload)
    }

    private fun uuidToBytes(uuid: UUID): ByteArray {
        return ByteBuffer.allocate(16).apply {
            putLong(uuid.mostSignificantBits)
            putLong(uuid.leastSignificantBits)
        }.array()
    }

    private fun bytesToUuid(bytes: ByteArray): UUID {
        val buf = ByteBuffer.wrap(bytes)
        return UUID(buf.long, buf.long)
    }
}

data class ParsedFrame(
    val senderFingerprint: String,
    val recipientFingerprint: String,
    val uuid: UUID,
    val timestampMs: Long,
    val plaintext: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ParsedFrame) return false
        return uuid == other.uuid
    }

    override fun hashCode(): Int = uuid.hashCode()
}

data class ParsedPayload(
    val type: MessageType,
    val payload: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ParsedPayload) return false
        return type == other.type
    }

    override fun hashCode(): Int = type.hashCode()
}

enum class MessageType(val value: Byte) {
    VOICE(1),
    DELETE(2),
    PING(3),
    ACK(4);

    companion object {
        fun fromValue(b: Byte) = entries.find { it.value == b }
    }
}
