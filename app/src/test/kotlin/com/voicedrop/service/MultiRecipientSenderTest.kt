package com.voicedrop.service

import com.voicedrop.crypto.AwaitingFirstReceive
import com.voicedrop.crypto.SentFrame
import com.voicedrop.storage.MessageEntity
import com.voicedrop.storage.TransportType
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.util.UUID

class MultiRecipientSenderTest {

    private lateinit var tmpDir: File

    @Before
    fun setUp() {
        tmpDir = File(System.getProperty("java.io.tmpdir"), "multi-send-${UUID.randomUUID()}").apply { mkdirs() }
    }

    @After
    fun tearDown() {
        tmpDir.deleteRecursively()
    }

    /** Stub `encryptAndSend` that records calls and returns a deterministic SentFrame. */
    private class FakeRatchetSend {
        data class Call(val contactId: String, val plaintext: ByteArray, val savedRow: MessageEntity?)

        val calls = mutableListOf<Call>()
        var throwForContactId: String? = null

        suspend fun invoke(
            contactId: String,
            plaintext: ByteArray,
            buildMessage: (frameUuidHex: String, frameUuidBytes: ByteArray, now: Long) -> MessageEntity?
        ): SentFrame {
            if (contactId == throwForContactId) throw AwaitingFirstReceive()
            val frameUuid = ByteArray(16).also { it[0] = (calls.size + 1).toByte() }
            val now = 1_000L + calls.size
            val row = buildMessage(frameUuid.joinToString("") { "%02x".format(it) }, frameUuid, now)
            calls.add(Call(contactId, plaintext, row))
            return SentFrame(
                frameUuid = frameUuid,
                frameUuidHex = frameUuid.joinToString("") { "%02x".format(it) },
                wireBytes = ByteArray(0),
                dhPub = ByteArray(32),
                pn = 0,
                n = 0
            )
        }
    }

    @Test
    fun fanOutToThreeRecipientsWritesOneFileAndBuildsThreeRowsSharingPath() = runBlocking {
        val fake = FakeRatchetSend()
        val sender = MultiRecipientSender(
            messagesDir = tmpDir,
            encryptAndSend = fake::invoke,
        )

        val opus = byteArrayOf(0x4f, 0x70, 0x75, 0x73)
        val result = sender.sendVoice(
            recipientIds = listOf("c1", "c2", "c3"),
            opusBytes = opus,
            durationMs = 1500,
            deleteAfterMsByContact = mapOf("c1" to 10_000L, "c2" to 20_000L, "c3" to 30_000L),
            waveformPeaks = ByteArray(80),
        )

        assertEquals(3, fake.calls.size)
        assertEquals(setOf("c1", "c2", "c3"), fake.calls.map { it.contactId }.toSet())
        // The opus bytes (the largest component of each plaintext) come from the same
        // source; the deleteAfterMs header field is per-contact, so plaintexts only
        // differ in that one field. Smoke-check that the opus tail is identical:
        val opusTailLen = opus.size
        for (c in fake.calls) {
            val tail = c.plaintext.copyOfRange(c.plaintext.size - opusTailLen, c.plaintext.size)
            assertTrue(tail.contentEquals(opus))
        }
        // All three MessageEntity rows share the same encryptedFilePath.
        val paths = fake.calls.mapNotNull { it.savedRow?.encryptedFilePath }
        assertEquals(3, paths.size)
        assertEquals(1, paths.toSet().size)
        // The shared file exists and contains the opus bytes.
        val sharedPath = paths.first()
        assertTrue(File(sharedPath).exists())
        assertTrue(File(sharedPath).readBytes().contentEquals(opus))
        // Per-contact deleteAfterMs is plumbed through.
        val byContact = fake.calls.associate { it.contactId to it.savedRow!!.deleteAfterMs }
        assertEquals(10_000L, byContact["c1"])
        assertEquals(20_000L, byContact["c2"])
        assertEquals(30_000L, byContact["c3"])
        // The result reports 3 successful sends.
        assertEquals(3, result.successfulRecipientIds.size)
        assertTrue(result.failedRecipientIds.isEmpty())
    }

    @Test
    fun perRecipientFailureSkipsThatRecipientAndContinues() = runBlocking {
        val fake = FakeRatchetSend()
        fake.throwForContactId = "c2"
        val sender = MultiRecipientSender(
            messagesDir = tmpDir,
            encryptAndSend = fake::invoke,
        )

        val result = sender.sendVoice(
            recipientIds = listOf("c1", "c2", "c3"),
            opusBytes = byteArrayOf(1, 2, 3),
            durationMs = 500,
            deleteAfterMsByContact = mapOf("c1" to 0L, "c2" to 0L, "c3" to 0L),
            waveformPeaks = ByteArray(80),
        )

        // c2 was attempted but threw — we still attempt c3.
        assertEquals(listOf("c1", "c3"), result.successfulRecipientIds)
        assertEquals(listOf("c2"), result.failedRecipientIds)
        // The shared file remains because c1 and c3 succeeded.
        val sharedPath = fake.calls.first { it.contactId == "c1" }.savedRow!!.encryptedFilePath
        assertTrue(File(sharedPath!!).exists())
    }

    @Test
    fun allRecipientsFailingDeletesOrphanOpusFile() = runBlocking {
        val fake = FakeRatchetSend()
        // Force every contact id to throw.
        val sender = MultiRecipientSender(
            messagesDir = tmpDir,
            encryptAndSend = { contactId, _, _ ->
                throw AwaitingFirstReceive()
            },
        )

        val result = sender.sendVoice(
            recipientIds = listOf("c1", "c2"),
            opusBytes = byteArrayOf(9, 9, 9),
            durationMs = 100,
            deleteAfterMsByContact = mapOf("c1" to 0L, "c2" to 0L),
            waveformPeaks = ByteArray(80),
        )

        assertTrue(result.successfulRecipientIds.isEmpty())
        assertEquals(listOf("c1", "c2"), result.failedRecipientIds)
        // No opus files left under tmpDir.
        assertEquals(emptyList<String>(), tmpDir.listFiles()?.map { it.name } ?: emptyList<String>())
    }

    @Test
    fun emptyRecipientListReturnsEmptyResultAndWritesNoFile() = runBlocking {
        val fake = FakeRatchetSend()
        val sender = MultiRecipientSender(
            messagesDir = tmpDir,
            encryptAndSend = fake::invoke,
        )

        val result = sender.sendVoice(
            recipientIds = emptyList(),
            opusBytes = byteArrayOf(1),
            durationMs = 1,
            deleteAfterMsByContact = emptyMap(),
            waveformPeaks = ByteArray(80),
        )

        assertTrue(result.successfulRecipientIds.isEmpty())
        assertTrue(result.failedRecipientIds.isEmpty())
        assertEquals(0, fake.calls.size)
        assertFalse("no opus file should be written for an empty fan-out", tmpDir.listFiles()!!.any { it.extension == "opus" })
    }
}
