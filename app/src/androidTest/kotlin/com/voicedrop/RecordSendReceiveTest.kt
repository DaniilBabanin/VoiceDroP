package com.voicedrop

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.crypto.tink.config.TinkConfig
import com.google.crypto.tink.subtle.X25519
import com.voicedrop.crypto.ContactKey
import com.voicedrop.crypto.MessageCrypto
import com.voicedrop.crypto.MessageType
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.nio.ByteBuffer
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class RecordSendReceiveTest {

    private lateinit var alicePriv: ByteArray
    private lateinit var alicePub: ByteArray
    private lateinit var bobPriv: ByteArray
    private lateinit var bobPub: ByteArray
    private lateinit var aliceFp: String
    private lateinit var bobFp: String
    private lateinit var sessionKey: ByteArray

    @Before
    fun setUp() {
        TinkConfig.register()
        alicePriv = X25519.generatePrivateKey()
        alicePub = X25519.publicFromPrivate(alicePriv)
        bobPriv = X25519.generatePrivateKey()
        bobPub = X25519.publicFromPrivate(bobPriv)
        aliceFp = ContactKey.fingerprint(alicePub)
        bobFp = ContactKey.fingerprint(bobPub)
        sessionKey = ContactKey.deriveSessionKey(alicePriv, bobPub)
    }

    @Test
    fun voicePayloadEncryptDecryptRoundTrip() {
        val fakeOpusBytes = ByteArray(128) { it.toByte() }
        val durationMs = 3000

        val payload = MessageCrypto.buildVoicePayload(durationMs, 0L, fakeOpusBytes)
        val encrypted = MessageCrypto.encrypt(sessionKey, payload)
        val decrypted = MessageCrypto.decrypt(sessionKey, encrypted)
        val parsed = MessageCrypto.parsePlaintext(decrypted)

        assertEquals(MessageType.VOICE, parsed.type)

        // Verify structure: durationMs(4) + deleteAfterMs(8) + opus
        val buf = ByteBuffer.wrap(parsed.payload)
        assertEquals(durationMs, buf.int)
        assertEquals(0L, buf.long)
        val extractedOpus = ByteArray(fakeOpusBytes.size).also { buf.get(it) }
        assertArrayEquals(fakeOpusBytes, extractedOpus)
    }

    @Test
    fun deletePayloadEncryptDecryptRoundTrip() {
        val uuid = UUID.randomUUID()
        val payload = MessageCrypto.buildDeletePayload(uuid)
        val encrypted = MessageCrypto.encrypt(sessionKey, payload)
        val decrypted = MessageCrypto.decrypt(sessionKey, encrypted)
        val parsed = MessageCrypto.parsePlaintext(decrypted)

        assertEquals(MessageType.DELETE, parsed.type)
        val buf = ByteBuffer.wrap(parsed.payload)
        val parsedUuid = UUID(buf.long, buf.long)
        assertEquals(uuid, parsedUuid)
    }

    @Test
    fun frameWireFormatRoundTrip() {
        val uuid = UUID.randomUUID()
        val fakeOpusBytes = ByteArray(64) { it.toByte() }
        val plaintextPayload = MessageCrypto.buildVoicePayload(1000, 0L, fakeOpusBytes)

        val senderFpBytes = aliceFp.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val recipientFpBytes = bobFp.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

        // buildFrame encrypts internally
        val frame = MessageCrypto.buildFrame(senderFpBytes, recipientFpBytes, uuid, sessionKey, plaintextPayload)
        // parseFrame decrypts internally
        val bobSessionKey = ContactKey.deriveSessionKey(bobPriv, alicePub)
        val parsed = MessageCrypto.parseFrame(frame, bobSessionKey)

        assertEquals(aliceFp, parsed.senderFingerprint)
        assertEquals(bobFp, parsed.recipientFingerprint)
        assertEquals(uuid, parsed.uuid)
        assertArrayEquals(plaintextPayload, parsed.plaintext)
    }

    @Test
    fun encryptionIsNonDeterministic() {
        val data = ByteArray(32) { 0x42 }
        val c1 = MessageCrypto.encrypt(sessionKey, data)
        val c2 = MessageCrypto.encrypt(sessionKey, data)
        assertFalse("Each encryption must use a fresh nonce", c1.contentEquals(c2))
    }
}
