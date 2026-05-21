package com.voicedrop.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.UUID

/**
 * DR17.5 §"Inner-plaintext schema" — codec coverage. The dispatcher in
 * `ConnectionManager.processFrame` routes on [MessagePayload.Parsed]; the
 * round-trip + forward-compat contract is enforced here so regressions in the
 * inner schema don't leak into the wire path silently.
 */
class MessagePayloadTest {

    @Test
    fun voice_roundTrip_preservesAllFields() {
        val opus = ByteArray(173) { (it xor 0x55).toByte() }
        val encoded = MessagePayload.encodeVoice(durationMs = 3120, deleteAfterMs = 86_400_000L, opusBytes = opus)
        assertEquals(MessagePayload.KIND_VOICE, encoded[0])
        // Layout invariant: 1 + 4 + 8 + opus.size
        assertEquals(1 + 4 + 8 + opus.size, encoded.size)

        val parsed = MessagePayload.parse(encoded)
        assertTrue("expected Voice, got $parsed", parsed is MessagePayload.Parsed.Voice)
        parsed as MessagePayload.Parsed.Voice
        assertEquals(3120, parsed.durationMs)
        assertEquals(86_400_000L, parsed.deleteAfterMs)
        assertArrayEquals(opus, parsed.opusBytes)
    }

    @Test
    fun voice_roundTrip_zeroLengthOpus() {
        val encoded = MessagePayload.encodeVoice(0, 0L, ByteArray(0))
        val parsed = MessagePayload.parse(encoded) as MessagePayload.Parsed.Voice
        assertEquals(0, parsed.durationMs)
        assertEquals(0L, parsed.deleteAfterMs)
        assertEquals(0, parsed.opusBytes.size)
    }

    @Test
    fun hello_roundTrip_isSingleByte() {
        val encoded = MessagePayload.encodeHello()
        assertEquals(1, encoded.size)
        assertEquals(MessagePayload.KIND_HELLO, encoded[0])
        val parsed = MessagePayload.parse(encoded)
        assertTrue(parsed is MessagePayload.Parsed.Hello)
    }

    @Test
    fun delete_roundTrip_preservesUuid() {
        val uuid = UUID.fromString("01234567-89ab-cdef-1011-121314151617")
        val encoded = MessagePayload.encodeDelete(uuid)
        assertEquals(1 + 16, encoded.size)
        assertEquals(MessagePayload.KIND_DELETE, encoded[0])
        val parsed = MessagePayload.parse(encoded) as MessagePayload.Parsed.Delete
        assertEquals(uuid, parsed.targetUuid)
    }

    @Test
    fun unknown_kind_returnsUnknownVariant_doesNotThrow() {
        // Forward-compat contract: a v1.2 device receiving an unknown kind MUST
        // surface it as Parsed.Unknown so the dispatcher can RECEIPT-ack and
        // drop silently. Throwing here would cause the txn to roll back, the
        // RECEIPT would never enqueue, and the sender's outbox would jam.
        // 0x03 is now KIND_PLAYED and has strict size semantics; start from 0x04.
        for (kind in intArrayOf(0x04, 0x10, 0x7F, 0x80, 0xFF)) {
            val body = ByteArray(7) { 0xAA.toByte() }
            val bytes = ByteArray(1 + body.size).also {
                it[0] = kind.toByte()
                body.copyInto(it, 1)
            }
            val parsed = MessagePayload.parse(bytes)
            assertTrue("kind=$kind: expected Unknown, got $parsed", parsed is MessagePayload.Parsed.Unknown)
            parsed as MessagePayload.Parsed.Unknown
            assertEquals(kind, parsed.kind)
            assertEquals(body.size, parsed.bodyLen)
        }
    }

    @Test
    fun unknown_zeroBody_alsoReturnsUnknownVariant() {
        // Minimal future-kind frame (1-byte kind, empty body) must still parse.
        val bytes = byteArrayOf(0x42)
        val parsed = MessagePayload.parse(bytes)
        assertTrue(parsed is MessagePayload.Parsed.Unknown)
        parsed as MessagePayload.Parsed.Unknown
        assertEquals(0x42, parsed.kind)
        assertEquals(0, parsed.bodyLen)
    }

    @Test
    fun empty_throwsInvalidPayload() {
        try {
            MessagePayload.parse(ByteArray(0))
            fail("expected InvalidPayload for empty input")
        } catch (e: InvalidPayload) {
            assertTrue(e.message?.contains("empty") == true)
        }
    }

    @Test
    fun voice_truncatedHeader_throwsInvalidPayload() {
        // Need 1 (kind) + 4 (duration) + 8 (deleteAfter) = 13 bytes minimum.
        for (size in 1..12) {
            val bytes = ByteArray(size).also { it[0] = MessagePayload.KIND_VOICE }
            try {
                MessagePayload.parse(bytes)
                fail("expected InvalidPayload for VOICE size=$size")
            } catch (e: InvalidPayload) {
                assertTrue(e.message?.contains("VOICE") == true)
            }
        }
    }

    @Test
    fun hello_oversize_throwsInvalidPayload() {
        // HELLO is exactly 1 byte. A peer who appended trailing bytes is malformed
        // even if the kind byte matches — strict size check prevents quiet drift.
        val bytes = byteArrayOf(MessagePayload.KIND_HELLO, 0x01, 0x02)
        try {
            MessagePayload.parse(bytes)
            fail("expected InvalidPayload for HELLO with trailing bytes")
        } catch (e: InvalidPayload) {
            assertTrue(e.message?.contains("HELLO") == true)
        }
    }

    @Test
    fun delete_wrongSize_throwsInvalidPayload() {
        for (size in intArrayOf(1, 8, 16, 18)) {
            val bytes = ByteArray(size).also { it[0] = MessagePayload.KIND_DELETE }
            try {
                MessagePayload.parse(bytes)
                fail("expected InvalidPayload for DELETE size=$size")
            } catch (e: InvalidPayload) {
                assertTrue(e.message?.contains("DELETE") == true)
            }
        }
    }

    @Test
    fun kindBytes_arePinned() {
        // Flipping these values silently breaks interop with any prior v1.2.0.0
        // build in the field. The forward-compat contract relies on 0x00-0x03
        // staying locked in; new kinds add at 0x04 and up.
        assertEquals(0x00.toByte(), MessagePayload.KIND_VOICE)
        assertEquals(0x01.toByte(), MessagePayload.KIND_HELLO)
        assertEquals(0x02.toByte(), MessagePayload.KIND_DELETE)
        assertEquals(0x03.toByte(), MessagePayload.KIND_PLAYED)
    }

    @Test
    fun played_roundTrip_preservesTargetUuid() {
        val target = UUID.fromString("01020304-0506-0708-090a-0b0c0d0e0f10")
        val encoded = MessagePayload.encodePlayed(target)
        assertEquals(17, encoded.size)
        assertEquals(MessagePayload.KIND_PLAYED, encoded[0])

        val parsed = MessagePayload.parse(encoded)
        assertTrue("expected Played, got $parsed", parsed is MessagePayload.Parsed.Played)
        parsed as MessagePayload.Parsed.Played
        assertEquals(target, parsed.targetUuid)
    }

    @Test
    fun played_truncatedBody_throwsInvalidPayload() {
        val truncated = ByteArray(10).apply { this[0] = MessagePayload.KIND_PLAYED }
        try {
            MessagePayload.parse(truncated)
            fail("expected InvalidPayload")
        } catch (e: InvalidPayload) {
            assertTrue("message mentions PLAYED size, was: ${e.message}", e.message?.contains("PLAYED size") == true)
        }
    }

    @Test
    fun unknownKind_0x04_stillReturnsUnknown_forwardCompatLeverIntact() {
        // Regression: confirm the forward-compat lever still works for the NEXT
        // extension after KIND_PLAYED (e.g. KIND_REACTION = 0x04 in the future).
        val bytes = byteArrayOf(0x04, 0x00, 0x01, 0x02, 0x03)
        val parsed = MessagePayload.parse(bytes)
        assertTrue("expected Unknown for kind=0x04, got $parsed", parsed is MessagePayload.Parsed.Unknown)
        parsed as MessagePayload.Parsed.Unknown
        assertEquals(0x04, parsed.kind)
        assertEquals(4, parsed.bodyLen)
    }
}
