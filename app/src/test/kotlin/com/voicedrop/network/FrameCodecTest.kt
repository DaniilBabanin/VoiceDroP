package com.voicedrop.network

import com.google.crypto.tink.config.TinkConfig
import com.voicedrop.network.FrameCodec.AAD_LEN
import com.voicedrop.network.FrameCodec.AEAD_TAG_BYTES
import com.voicedrop.network.FrameCodec.DH_PUB_BYTES
import com.voicedrop.network.FrameCodec.FP_BYTES
import com.voicedrop.network.FrameCodec.FRAME_KIND_DATA
import com.voicedrop.network.FrameCodec.FRAME_KIND_RECEIPT
import com.voicedrop.network.FrameCodec.FRAME_KIND_RESET
import com.voicedrop.network.FrameCodec.FRAME_LEN_BYTES
import com.voicedrop.network.FrameCodec.UUID_BYTES
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.GeneralSecurityException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.BeforeClass
import org.junit.Test

class FrameCodecTest {

    companion object {
        @BeforeClass
        @JvmStatic
        fun setUpClass() {
            TinkConfig.register()
        }
    }

    // Per-test fixture inputs — small but representative.
    private val key = ByteArray(32) { (0x10 + it).toByte() }
    private val senderFp = ByteArray(FP_BYTES) { 0x11.toByte() }
    private val recipFp = ByteArray(FP_BYTES) { 0x22.toByte() }
    // A pseudo-random-looking 32-byte dhPub. Not a real X25519 point — the codec
    // only screens for all-zero and low-order, not curve membership. (Membership
    // is irrelevant: a bogus point causes AEAD failure at the ratchet layer.)
    private val dhPub = ByteArray(DH_PUB_BYTES) { (0x33 + it).toByte() }
    private val uuid = ByteArray(UUID_BYTES) { (0x44 + it).toByte() }
    private val pn = 3
    private val n = 7
    private val timestampMs = 1_700_000_000_000L
    private val plaintext = "hello double ratchet".toByteArray(Charsets.UTF_8)

    private fun encodeData() = FrameCodec.encode(
        kind = FRAME_KIND_DATA,
        senderFp = senderFp, recipFp = recipFp, dhPub = dhPub,
        pn = pn, n = n, uuid = uuid, timestampMs = timestampMs,
        key = key, plaintext = plaintext
    )

    @Test
    fun roundTrip_data() {
        val wire = encodeData()
        val ok = FrameCodec.decode(wire) as FrameCodec.DecodeResult.Ok
        val f = ok.frame
        assertEquals(FRAME_KIND_DATA, f.kind)
        assertArrayEquals(senderFp, f.senderFp)
        assertArrayEquals(recipFp, f.recipFp)
        assertArrayEquals(dhPub, f.dhPub)
        assertEquals(pn, f.pn)
        assertEquals(n, f.n)
        assertArrayEquals(uuid, f.uuid)
        assertEquals(timestampMs, f.timestampMs)
        assertEquals(AAD_LEN, f.aad.size)

        val opened = FrameCodec.decrypt(f, key)
        assertArrayEquals(plaintext, opened)
    }

    @Test
    fun roundTrip_receipt() {
        val wire = FrameCodec.encode(
            kind = FRAME_KIND_RECEIPT,
            senderFp = senderFp, recipFp = recipFp, dhPub = dhPub,
            pn = pn, n = n, uuid = uuid, timestampMs = timestampMs,
            key = key, plaintext = plaintext
        )
        val ok = FrameCodec.decode(wire) as FrameCodec.DecodeResult.Ok
        assertEquals(FRAME_KIND_RECEIPT, ok.frame.kind)
        assertArrayEquals(plaintext, FrameCodec.decrypt(ok.frame, key))
    }

    @Test
    fun roundTrip_reset_dhPubSlotMayBeNonStandard() {
        // RESET path repurposes the dhPub slot (resetNonce||zeros). Codec must
        // accept whatever's in the slot — no low-order rejection on this path.
        val resetSlot = ByteArray(DH_PUB_BYTES).also {
            // resetNonce bytes 0..15 random-looking; bytes 16..31 zero per spec.
            for (i in 0 until 16) it[i] = (0xa0 + i).toByte()
        }
        val wire = FrameCodec.encode(
            kind = FRAME_KIND_RESET,
            senderFp = senderFp, recipFp = recipFp, dhPub = resetSlot,
            pn = 0, n = 0, uuid = uuid, timestampMs = timestampMs,
            key = key, plaintext = ByteArray(33)
        )
        val ok = FrameCodec.decode(wire) as FrameCodec.DecodeResult.Ok
        assertEquals(FRAME_KIND_RESET, ok.frame.kind)
    }

    @Test
    fun frameLenMismatch_rejectedBeforeAead() {
        val wire = encodeData()
        // Truncate one byte. The on-wire frameLen still claims the old length,
        // but the buffer is short → deframer rejects without any AEAD attempt.
        val truncated = wire.copyOf(wire.size - 1)
        val drop = FrameCodec.decode(truncated)
        assertEquals(
            FrameCodec.DecodeResult.Drop(FrameCodec.DropReason.FRAME_LEN_MISMATCH),
            drop
        )

        // Now append one byte → same situation, opposite direction.
        val padded = wire + 0x00.toByte()
        val drop2 = FrameCodec.decode(padded)
        assertEquals(
            FrameCodec.DecodeResult.Drop(FrameCodec.DropReason.FRAME_LEN_MISMATCH),
            drop2
        )
    }

    @Test
    fun frameLenTamperedButLengthConsistent_failsAead() {
        // Forge a frame whose on-wire frameLen is wrong but whose buffer length
        // matches that forged value. The deframer's length check passes (it has
        // no second source of truth). AAD includes frameLen, so the only
        // remaining defense is AEAD verification — confirm it fires.
        val original = encodeData()
        val realFrameLen = ByteBuffer.wrap(original, 0, FRAME_LEN_BYTES)
            .order(ByteOrder.BIG_ENDIAN).int

        // Build forgery: keep original bytes, append 4 junk bytes (extending
        // ciphertext), and rewrite frameLen so the buffer size matches.
        val forged = ByteArray(original.size + 4)
        System.arraycopy(original, 0, forged, 0, original.size)
        forged.fill(0x5a.toByte(), original.size, forged.size)
        val forgedFrameLen = realFrameLen + 4
        ByteBuffer.wrap(forged, 0, FRAME_LEN_BYTES).order(ByteOrder.BIG_ENDIAN).putInt(forgedFrameLen)

        val ok = FrameCodec.decode(forged) as FrameCodec.DecodeResult.Ok
        try {
            FrameCodec.decrypt(ok.frame, key)
            fail("expected AEAD failure for tampered-but-consistent frameLen")
        } catch (_: GeneralSecurityException) {
            // expected
        }
    }

    @Test
    fun aadTampering_detectedByAead() {
        // For each AAD-covered field, flip one byte. Decode may either drop
        // structurally (frameLen / frameKind / dhPub paths) OR succeed-then-fail
        // at AEAD. Both are acceptable; the only failure mode is silent accept.
        data class Field(val offset: Int, val structuralDropAllowed: Boolean)
        val fields = listOf(
            Field(offset = 0, structuralDropAllowed = true),            // frameLen
            Field(offset = 4, structuralDropAllowed = true),            // frameKind
            Field(offset = 5, structuralDropAllowed = false),           // senderFp[0]
            Field(offset = 5 + FP_BYTES, structuralDropAllowed = false),// recipFp[0]
            Field(offset = 5 + 2 * FP_BYTES, structuralDropAllowed = true), // dhPub[0]
            Field(offset = 5 + 2 * FP_BYTES + DH_PUB_BYTES, structuralDropAllowed = false),     // pn[0]
            Field(offset = 5 + 2 * FP_BYTES + DH_PUB_BYTES + 4, structuralDropAllowed = false), // n[0]
            Field(offset = 5 + 2 * FP_BYTES + DH_PUB_BYTES + 8, structuralDropAllowed = false), // uuid[0]
            Field(offset = 5 + 2 * FP_BYTES + DH_PUB_BYTES + 8 + UUID_BYTES,
                structuralDropAllowed = false)                                                  // timestampMs[0]
        )
        val original = encodeData()
        for (field in fields) {
            val tampered = original.copyOf()
            tampered[field.offset] = (tampered[field.offset].toInt() xor 0x01).toByte()
            when (val r = FrameCodec.decode(tampered)) {
                is FrameCodec.DecodeResult.Drop -> {
                    assertTrue(
                        "structural drop at offset ${field.offset} not allowed: ${r.reason}",
                        field.structuralDropAllowed
                    )
                }
                is FrameCodec.DecodeResult.Ok -> {
                    try {
                        FrameCodec.decrypt(r.frame, key)
                        fail("AEAD silently accepted tampered byte at offset ${field.offset}")
                    } catch (_: GeneralSecurityException) {
                        // expected — AAD mismatch surfaces here
                    }
                }
            }
        }
    }

    @Test
    fun ciphertextTampering_failsAead() {
        // Sanity — covers the body, not the AAD. The AEAD tag must still fire.
        val wire = encodeData()
        wire[wire.size - 1] = (wire[wire.size - 1].toInt() xor 0x01).toByte()
        val ok = FrameCodec.decode(wire) as FrameCodec.DecodeResult.Ok
        try {
            FrameCodec.decrypt(ok.frame, key)
            fail("expected AEAD failure for tampered ciphertext")
        } catch (_: GeneralSecurityException) {
            // expected
        }
    }

    @Test
    fun ciphertextTruncation_detectedByAead() {
        // Truncate one ciphertext byte AND adjust frameLen so the deframer's
        // length check passes. The deframer hands a now-short ciphertext to
        // AEAD; the truncated tag fails verification. Tests the AEAD layer's
        // length defense once frameLen-mismatch is no longer surfacing it.
        val original = encodeData()
        val truncated = original.copyOf(original.size - 1)
        val realFrameLen = ByteBuffer.wrap(original, 0, FRAME_LEN_BYTES)
            .order(ByteOrder.BIG_ENDIAN).int
        ByteBuffer.wrap(truncated, 0, FRAME_LEN_BYTES).order(ByteOrder.BIG_ENDIAN)
            .putInt(realFrameLen - 1)

        val ok = FrameCodec.decode(truncated) as FrameCodec.DecodeResult.Ok
        try {
            FrameCodec.decrypt(ok.frame, key)
            fail("AEAD silently accepted truncated ciphertext")
        } catch (_: GeneralSecurityException) {
            // expected — tag short
        }
    }

    @Test
    fun ciphertextTrailingBytes_detectedByAead() {
        // Single-byte trailing-junk analog of frameLenTamperedButLengthConsistent_failsAead
        // (which appends 4 bytes). Kept as a named anchor for the DR16 §10.1 catalog.
        val original = encodeData()
        val padded = ByteArray(original.size + 1)
        System.arraycopy(original, 0, padded, 0, original.size)
        padded[padded.size - 1] = 0x5a
        val realFrameLen = ByteBuffer.wrap(original, 0, FRAME_LEN_BYTES)
            .order(ByteOrder.BIG_ENDIAN).int
        ByteBuffer.wrap(padded, 0, FRAME_LEN_BYTES).order(ByteOrder.BIG_ENDIAN)
            .putInt(realFrameLen + 1)

        val ok = FrameCodec.decode(padded) as FrameCodec.DecodeResult.Ok
        try {
            FrameCodec.decrypt(ok.frame, key)
            fail("AEAD silently accepted trailing-byte ciphertext")
        } catch (_: GeneralSecurityException) {
            // expected — appended byte invalidates AEAD tag
        }
    }

    @Test
    fun receipt_aeadTampering_rejected() {
        // RECEIPT frames share the AEAD path with DATA. Locked in here
        // explicitly per DR16 §10.1 so future codec splits can't silently
        // skip RECEIPT in tamper coverage.
        val receiptPlaintext = ByteArray(17).also { it[0] = 0x01 }
        val wire = FrameCodec.encode(
            kind = FRAME_KIND_RECEIPT,
            senderFp = senderFp, recipFp = recipFp, dhPub = dhPub,
            pn = pn, n = n, uuid = uuid, timestampMs = timestampMs,
            key = key, plaintext = receiptPlaintext
        )
        wire[wire.size - 1] = (wire[wire.size - 1].toInt() xor 0x01).toByte()
        val ok = FrameCodec.decode(wire) as FrameCodec.DecodeResult.Ok
        assertEquals(FRAME_KIND_RECEIPT, ok.frame.kind)
        try {
            FrameCodec.decrypt(ok.frame, key)
            fail("AEAD silently accepted tampered RECEIPT ciphertext")
        } catch (_: GeneralSecurityException) {
            // expected
        }
    }

    @Test
    fun unknownFrameKind_dropped() {
        val wire = encodeData()
        // frameKind is at offset 4 (right after the 4-byte frameLen).
        for (kind in 0x03..0xff) {
            val tampered = wire.copyOf()
            tampered[FRAME_LEN_BYTES] = kind.toByte()
            assertEquals(
                "kind 0x${"%02x".format(kind)} should be dropped",
                FrameCodec.DecodeResult.Drop(FrameCodec.DropReason.UNKNOWN_FRAME_KIND),
                FrameCodec.decode(tampered)
            )
        }
    }

    @Test
    fun zeroDhPub_onDataPath_rejected() {
        val wire = FrameCodec.encode(
            kind = FRAME_KIND_DATA,
            senderFp = senderFp, recipFp = recipFp,
            dhPub = ByteArray(DH_PUB_BYTES),
            pn = pn, n = n, uuid = uuid, timestampMs = timestampMs,
            key = key, plaintext = plaintext
        )
        assertEquals(
            FrameCodec.DecodeResult.Drop(FrameCodec.DropReason.ZERO_DH_PUB),
            FrameCodec.decode(wire)
        )
    }

    @Test
    fun zeroDhPub_onReceiptPath_rejected() {
        val wire = FrameCodec.encode(
            kind = FRAME_KIND_RECEIPT,
            senderFp = senderFp, recipFp = recipFp,
            dhPub = ByteArray(DH_PUB_BYTES),
            pn = pn, n = n, uuid = uuid, timestampMs = timestampMs,
            key = key, plaintext = plaintext
        )
        assertEquals(
            FrameCodec.DecodeResult.Drop(FrameCodec.DropReason.ZERO_DH_PUB),
            FrameCodec.decode(wire)
        )
    }

    @Test
    fun lowOrderDhPub_rejected_dataAndReceipt() {
        // Two representative points from the standard libsodium blacklist:
        //  - the order-4 point (just the byte 0x01 followed by zeros)
        //  - p-1 (the "high" representative)
        val orderFour = ByteArray(DH_PUB_BYTES).also { it[0] = 0x01 }
        val pMinus1 = ByteArray(DH_PUB_BYTES) { 0xff.toByte() }
            .also { it[0] = 0xec.toByte(); it[31] = 0x7f.toByte() }
        val pointsToTry = listOf(orderFour, pMinus1)

        for (dh in pointsToTry) {
            for (kind in listOf(FRAME_KIND_DATA, FRAME_KIND_RECEIPT)) {
                val wire = FrameCodec.encode(
                    kind = kind,
                    senderFp = senderFp, recipFp = recipFp, dhPub = dh,
                    pn = pn, n = n, uuid = uuid, timestampMs = timestampMs,
                    key = key, plaintext = plaintext
                )
                val result = FrameCodec.decode(wire)
                assertTrue(
                    "kind=$kind dh[0]=0x${"%02x".format(dh[0].toInt() and 0xff)} must drop",
                    result is FrameCodec.DecodeResult.Drop
                )
                val drop = result as FrameCodec.DecodeResult.Drop
                // Order-4 point has byte[0]==1 with zeros after — that's both
                // technically "all zero except byte 0" AND "low order". We accept
                // either reason as long as it's a drop and not silent accept.
                assertTrue(
                    "expected ZERO/LOW_ORDER drop, got ${drop.reason}",
                    drop.reason == FrameCodec.DropReason.LOW_ORDER_DH_PUB ||
                        drop.reason == FrameCodec.DropReason.ZERO_DH_PUB
                )
            }
        }
    }

    @Test
    fun lowOrderDhPub_highBitFlippedStillRejected() {
        // Attacker flips the masked high bit of byte[31]. Curve25519 ignores
        // this bit, so the underlying point is unchanged — we must still reject.
        val orderFourHighBit = ByteArray(DH_PUB_BYTES).also {
            it[0] = 0x01; it[31] = 0x80.toByte()
        }
        val wire = FrameCodec.encode(
            kind = FRAME_KIND_DATA,
            senderFp = senderFp, recipFp = recipFp, dhPub = orderFourHighBit,
            pn = pn, n = n, uuid = uuid, timestampMs = timestampMs,
            key = key, plaintext = plaintext
        )
        val drop = FrameCodec.decode(wire) as FrameCodec.DecodeResult.Drop
        assertEquals(FrameCodec.DropReason.LOW_ORDER_DH_PUB, drop.reason)
    }

    @Test
    fun layout_golden() {
        val wire = encodeData()
        assertEquals(AAD_LEN + plaintext.size + AEAD_TAG_BYTES, wire.size)

        val buf = ByteBuffer.wrap(wire).order(ByteOrder.BIG_ENDIAN)
        assertEquals(wire.size - FRAME_LEN_BYTES, buf.int)
        assertEquals(FRAME_KIND_DATA, buf.get())
        val sFp = ByteArray(FP_BYTES); buf.get(sFp); assertArrayEquals(senderFp, sFp)
        val rFp = ByteArray(FP_BYTES); buf.get(rFp); assertArrayEquals(recipFp, rFp)
        val dh = ByteArray(DH_PUB_BYTES); buf.get(dh); assertArrayEquals(dhPub, dh)
        assertEquals(pn, buf.int)
        assertEquals(n, buf.int)
        val u = ByteArray(UUID_BYTES); buf.get(u); assertArrayEquals(uuid, u)
        assertEquals(timestampMs, buf.long)
        // Remaining bytes are ciphertext+tag — nonce is NOT on the wire (per spec).
        assertEquals(plaintext.size + AEAD_TAG_BYTES, wire.size - buf.position())
    }

    @Test
    fun bufferShorterThanHeader_dropped() {
        val tooShort = ByteArray(AAD_LEN - 1)
        // Set frameLen so the field parse doesn't blow up before the length check.
        ByteBuffer.wrap(tooShort, 0, FRAME_LEN_BYTES).order(ByteOrder.BIG_ENDIAN)
            .putInt(tooShort.size - FRAME_LEN_BYTES)
        val drop = FrameCodec.decode(tooShort) as FrameCodec.DecodeResult.Drop
        // Either layout or frameLen-mismatch is fine — both are silent rejects.
        assertNotEquals(FrameCodec.DropReason.UNKNOWN_FRAME_KIND, drop.reason)
    }
}
