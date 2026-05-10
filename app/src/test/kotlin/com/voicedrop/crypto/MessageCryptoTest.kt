package com.voicedrop.crypto

import com.google.crypto.tink.config.TinkConfig
import com.google.crypto.tink.subtle.X25519
import org.junit.Assert.*
import org.junit.BeforeClass
import org.junit.Test
import java.nio.ByteBuffer
import java.util.UUID

class MessageCryptoTest {

    companion object {
        private lateinit var alicePrivate: ByteArray
        private lateinit var alicePublic: ByteArray
        private lateinit var bobPrivate: ByteArray
        private lateinit var bobPublic: ByteArray
        private lateinit var aliceFp: String
        private lateinit var bobFp: String
        private lateinit var sessionKeyAlice: ByteArray
        private lateinit var sessionKeyBob: ByteArray

        @BeforeClass
        @JvmStatic
        fun setUpClass() {
            TinkConfig.register()
            alicePrivate = X25519.generatePrivateKey()
            alicePublic = X25519.publicFromPrivate(alicePrivate)
            bobPrivate = X25519.generatePrivateKey()
            bobPublic = X25519.publicFromPrivate(bobPrivate)

            aliceFp = ContactKey.fingerprint(alicePublic)
            bobFp = ContactKey.fingerprint(bobPublic)

            // deriveSessionKey(myPrivate, theirPublic) — symmetric because it sorts fingerprints
            sessionKeyAlice = ContactKey.deriveSessionKey(alicePrivate, bobPublic)
            sessionKeyBob = ContactKey.deriveSessionKey(bobPrivate, alicePublic)
        }
    }

    @Test
    fun sessionKeysMatch() {
        assertArrayEquals(sessionKeyAlice, sessionKeyBob)
    }

    @Test
    fun encryptDecryptRoundTrip() {
        val plaintext = "Hello, VoiceDrop!".toByteArray()
        val encrypted = MessageCrypto.encrypt(sessionKeyAlice, plaintext)
        val decrypted = MessageCrypto.decrypt(sessionKeyBob, encrypted)
        assertArrayEquals(plaintext, decrypted)
    }

    @Test
    fun encryptProducesUniqueNonces() {
        val plaintext = ByteArray(16)
        val enc1 = MessageCrypto.encrypt(sessionKeyAlice, plaintext)
        val enc2 = MessageCrypto.encrypt(sessionKeyAlice, plaintext)
        assertFalse(enc1.contentEquals(enc2))
    }

    @Test
    fun tamperedCiphertextFails() {
        val plaintext = ByteArray(64) { it.toByte() }
        val encrypted = MessageCrypto.encrypt(sessionKeyAlice, plaintext).toMutableList()
        encrypted[encrypted.size / 2] = (encrypted[encrypted.size / 2].toInt() xor 0xFF).toByte()
        assertThrows(Exception::class.java) {
            MessageCrypto.decrypt(sessionKeyBob, encrypted.toByteArray())
        }
    }

    @Test
    fun buildParseFrameRoundTrip() {
        val uuid = UUID.randomUUID()
        val senderFpBytes = aliceFp.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val recipientFpBytes = bobFp.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val plaintextPayload = "test payload".toByteArray()

        // buildFrame encrypts internally
        val frame = MessageCrypto.buildFrame(senderFpBytes, recipientFpBytes, uuid, sessionKeyAlice, plaintextPayload)
        // parseFrame decrypts internally — returns plaintext
        val parsed = MessageCrypto.parseFrame(frame, sessionKeyBob)

        assertEquals(aliceFp, parsed.senderFingerprint)
        assertEquals(bobFp, parsed.recipientFingerprint)
        assertEquals(uuid, parsed.uuid)
        assertArrayEquals(plaintextPayload, parsed.plaintext)
    }

    @Test
    fun voicePayloadBuildParse() {
        val opusData = ByteArray(256) { it.toByte() }
        val durationMs = 2500
        val deleteAfterMs = 0L
        val payload = MessageCrypto.buildVoicePayload(durationMs, deleteAfterMs, opusData)
        val parsed = MessageCrypto.parsePlaintext(payload)

        assertEquals(MessageType.VOICE, parsed.type)
        // payload contains: durationMs(4) + deleteAfterMs(8) + opusData
        val buf = ByteBuffer.wrap(parsed.payload)
        assertEquals(durationMs, buf.int)
        assertEquals(deleteAfterMs, buf.long)
        val extractedOpus = ByteArray(opusData.size).also { buf.get(it) }
        assertArrayEquals(opusData, extractedOpus)
    }

    @Test
    fun deletePayloadBuildParse() {
        val uuid = UUID.randomUUID()
        val payload = MessageCrypto.buildDeletePayload(uuid)
        val parsed = MessageCrypto.parsePlaintext(payload)

        assertEquals(MessageType.DELETE, parsed.type)
        // payload is the 16 raw UUID bytes
        val buf = ByteBuffer.wrap(parsed.payload)
        val parsedUuid = UUID(buf.long, buf.long)
        assertEquals(uuid, parsedUuid)
    }

    @Test
    fun pingPayloadBuildParse() {
        val payload = MessageCrypto.buildPingPayload()
        val parsed = MessageCrypto.parsePlaintext(payload)
        assertEquals(MessageType.PING, parsed.type)
    }

    @Test
    fun verificationCodeIsDeterministic() {
        val code1 = ContactKey.computeVerificationCode(sessionKeyAlice, aliceFp, bobFp)
        val code2 = ContactKey.computeVerificationCode(sessionKeyAlice, aliceFp, bobFp)
        assertArrayEquals(code1, code2)
    }

    @Test
    fun verificationCodeIsSymmetric() {
        val fromAlice = ContactKey.computeVerificationCode(sessionKeyAlice, aliceFp, bobFp)
        val fromBob = ContactKey.computeVerificationCode(sessionKeyBob, bobFp, aliceFp)
        assertArrayEquals(fromAlice, fromBob)
    }
}
