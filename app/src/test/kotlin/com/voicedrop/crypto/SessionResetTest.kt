package com.voicedrop.crypto

import com.google.crypto.tink.config.TinkConfig
import com.voicedrop.network.FrameCodec
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.BeforeClass
import org.junit.Test

/**
 * DR12 §6.1 / §6.2 encoder/decoder cases. Receive-side state effects,
 * jump-ahead caps, and trigger/rate logic live in [dr13]/[dr14] and have their
 * own test classes (SessionResetReceiveTest etc.) once those phases land.
 */
class SessionResetTest {

    companion object {
        @BeforeClass
        @JvmStatic
        fun setUpClass() {
            TinkConfig.register()
        }

        // Golden vector fixture. The K_reset hex below was computed offline
        // via a reference HKDF-SHA256 — see `kReset_matchesGolden`.
        private val GOLDEN_ID_SHARED = ByteArray(32) { (0xa0 + it).toByte() }
        private val GOLDEN_SENDER_FP = ByteArray(FrameCodec.FP_BYTES) { 0x11.toByte() }
        private val GOLDEN_RECIP_FP = ByteArray(FrameCodec.FP_BYTES) { 0x22.toByte() }
        private val GOLDEN_RESET_NONCE = ByteArray(ResetCrypto.RESET_NONCE_BYTES) { (0x30 + it).toByte() }
        private const val GOLDEN_R = 7
        private const val GOLDEN_K_RESET_HEX =
            "3cad35eba508cbf400adfa7ef5d72009f242b818695cc948faeb044777964391"
    }

    private val senderFp = ByteArray(FrameCodec.FP_BYTES) { 0x11.toByte() }
    private val recipFp = ByteArray(FrameCodec.FP_BYTES) { 0x22.toByte() }
    private val idShared = ByteArray(32) { (0x40 + it).toByte() }
    private val uuid = ByteArray(FrameCodec.UUID_BYTES) { (0x55 + it).toByte() }
    private val timestampMs = 1_700_000_000_000L
    private val postResetEphPub = ByteArray(ResetCrypto.POST_RESET_EPH_PUB_BYTES) { (0x60 + it).toByte() }

    private fun freshResetNonce(): ByteArray =
        ByteArray(ResetCrypto.RESET_NONCE_BYTES) { (0xa0 + it).toByte() }

    private fun roundTripFixture(R: Int = 3): Pair<ByteArray, ByteArray> {
        // Returns (wireBytes, K_reset).
        val resetNonce = freshResetNonce()
        val kReset = ResetCrypto.deriveKReset(idShared, senderFp, recipFp, resetNonce, R)
        val wire = ResetCrypto.encode(
            senderFp = senderFp, recipFp = recipFp,
            resetNonce = resetNonce, R = R,
            uuid = uuid, timestampMs = timestampMs,
            plaintext = ResetCrypto.Plaintext(
                ack = ResetCrypto.ACK_INITIATOR,
                postResetEphPub = postResetEphPub
            ),
            kReset = kReset
        )
        return wire to kReset
    }

    @Test
    fun kReset_matchesGolden() {
        val kReset = ResetCrypto.deriveKReset(
            idSharedSecret = GOLDEN_ID_SHARED,
            senderFp = GOLDEN_SENDER_FP,
            recipFp = GOLDEN_RECIP_FP,
            resetNonce = GOLDEN_RESET_NONCE,
            R = GOLDEN_R
        )
        assertEquals(GOLDEN_K_RESET_HEX, kReset.toHexLower())
    }

    @Test
    fun roundTrip_emitsValidFrame() {
        val (wire, kReset) = roundTripFixture(R = 5)
        val ok = FrameCodec.decode(wire) as FrameCodec.DecodeResult.Ok
        assertEquals(FrameCodec.FRAME_KIND_RESET, ok.frame.kind)
        assertEquals(5, ok.frame.n)        // R rides in the n slot
        assertEquals(0, ok.frame.pn)       // pn slot unused
        // dhPub slot = resetNonce || zeros[16]; tail half must be all-zero.
        for (i in 16 until FrameCodec.DH_PUB_BYTES) {
            assertEquals("dhPub[$i] must be zero", 0, ok.frame.dhPub[i].toInt())
        }

        val decoded = ResetCrypto.decrypt(ok.frame, kReset) as ResetCrypto.DecodeOutcome.Ok
        assertEquals(ResetCrypto.ACK_INITIATOR, decoded.plaintext.ack)
        assertArrayEquals(postResetEphPub, decoded.plaintext.postResetEphPub)
    }

    @Test
    fun reset_frameAeadTampering_rejected() {
        val (wire, kReset) = roundTripFixture()
        // Flip last byte (in the AEAD tag).
        wire[wire.size - 1] = (wire[wire.size - 1].toInt() xor 0x01).toByte()
        val ok = FrameCodec.decode(wire) as FrameCodec.DecodeResult.Ok
        assertSame(
            ResetCrypto.DecodeOutcome.AeadFailure,
            ResetCrypto.decrypt(ok.frame, kReset)
        )
    }

    @Test
    fun reset_directionBinding_bouncebackRejected() {
        // Sender A constructs A→B. Attacker rewrites header to claim B→A and
        // replays back to A. A's `K_reset` derivation uses (sender=B, recip=A)
        // — that's swapped from the original (sender=A, recip=B), so the key
        // is different and AEAD fails.
        val resetNonce = freshResetNonce()
        val R = 2

        val kSendABtoB = ResetCrypto.deriveKReset(idShared, senderFp, recipFp, resetNonce, R)
        val wireAtoB = ResetCrypto.encode(
            senderFp = senderFp, recipFp = recipFp,
            resetNonce = resetNonce, R = R, uuid = uuid, timestampMs = timestampMs,
            plaintext = ResetCrypto.Plaintext(ResetCrypto.ACK_INITIATOR, postResetEphPub),
            kReset = kSendABtoB
        )

        // Build a bounce-back: same body, but header rewritten so sender=recipFp, recip=senderFp.
        // We do this by re-encoding the AAD region — the ciphertext is bound to AAD so this
        // surfaces as AEAD failure (different K_reset would, on its own, also surface as AEAD
        // failure; we exercise BOTH paths to make the test deterministic regardless of order).
        val bounced = wireAtoB.copyOf()
        // senderFp offset = FRAME_LEN_BYTES + FRAME_KIND_BYTES = 5
        val senderOff = FrameCodec.FRAME_LEN_BYTES + FrameCodec.FRAME_KIND_BYTES
        val recipOff = senderOff + FrameCodec.FP_BYTES
        System.arraycopy(recipFp, 0, bounced, senderOff, FrameCodec.FP_BYTES)
        System.arraycopy(senderFp, 0, bounced, recipOff, FrameCodec.FP_BYTES)

        val ok = FrameCodec.decode(bounced) as FrameCodec.DecodeResult.Ok
        // Receiver (A) sees header sender=B, recip=A and derives its K_reset accordingly:
        val kBounce = ResetCrypto.deriveKReset(idShared, recipFp, senderFp, resetNonce, R)
        assertFalse("bounce-back K_reset must differ from outbound", kBounce.contentEquals(kSendABtoB))
        assertSame(
            "bounce-back must fail AEAD",
            ResetCrypto.DecodeOutcome.AeadFailure,
            ResetCrypto.decrypt(ok.frame, kBounce)
        )
    }

    @Test
    fun reset_sameRNonceVariation_keysDiffer() {
        // Two RESETs at the same R but different resetNonce → distinct K_reset.
        val nonceA = ByteArray(ResetCrypto.RESET_NONCE_BYTES) { 0x01.toByte() }
        val nonceB = ByteArray(ResetCrypto.RESET_NONCE_BYTES) { 0x02.toByte() }
        val R = 4

        val kA = ResetCrypto.deriveKReset(idShared, senderFp, recipFp, nonceA, R)
        val kB = ResetCrypto.deriveKReset(idShared, senderFp, recipFp, nonceB, R)
        assertFalse("distinct resetNonce must yield distinct K_reset", kA.contentEquals(kB))
    }

    @Test
    fun reset_pnSlotMustBeZero() {
        // Build a normal RESET frame, then patch the on-wire pn slot to non-zero.
        val (wire, _) = roundTripFixture()
        val pnOff = FrameCodec.FRAME_LEN_BYTES + FrameCodec.FRAME_KIND_BYTES +
            2 * FrameCodec.FP_BYTES + FrameCodec.DH_PUB_BYTES
        ByteBuffer.wrap(wire, pnOff, 4).order(ByteOrder.BIG_ENDIAN).putInt(1)

        val drop = FrameCodec.decode(wire) as FrameCodec.DecodeResult.Drop
        assertEquals(FrameCodec.DropReason.RESET_PN_NONZERO, drop.reason)
    }

    @Test
    fun reset_dhPubSlotTailMustBeZero() {
        // Build a normal RESET frame, then poke a non-zero byte into dhPub[20].
        val (wire, _) = roundTripFixture()
        val dhPubOff = FrameCodec.FRAME_LEN_BYTES + FrameCodec.FRAME_KIND_BYTES + 2 * FrameCodec.FP_BYTES
        wire[dhPubOff + 20] = 0x42

        val drop = FrameCodec.decode(wire) as FrameCodec.DecodeResult.Drop
        assertEquals(FrameCodec.DropReason.RESET_DH_PUB_TAIL_NONZERO, drop.reason)
    }

    @Test
    fun reset_dhPubSlotTailMustBeZero_acceptsValidShape() {
        // Sanity-check the structural validator doesn't false-positive: the
        // bytes 0..15 may be anything (resetNonce), only 16..31 must be zero.
        val resetNonce = ByteArray(ResetCrypto.RESET_NONCE_BYTES) { 0xff.toByte() }
        val R = 11
        val kReset = ResetCrypto.deriveKReset(idShared, senderFp, recipFp, resetNonce, R)
        val wire = ResetCrypto.encode(
            senderFp = senderFp, recipFp = recipFp, resetNonce = resetNonce, R = R,
            uuid = uuid, timestampMs = timestampMs,
            plaintext = ResetCrypto.Plaintext(ResetCrypto.ACK_INITIATOR, postResetEphPub),
            kReset = kReset
        )
        val ok = FrameCodec.decode(wire) as FrameCodec.DecodeResult.Ok
        assertEquals(FrameCodec.FRAME_KIND_RESET, ok.frame.kind)
    }

    @Test
    fun reset_plaintextSizeMustBe33() {
        // Construct a frame whose AEAD succeeds but inner plaintext is the
        // wrong size — encode through FrameCodec.encode with a 32-byte payload.
        val resetNonce = freshResetNonce()
        val R = 6
        val kReset = ResetCrypto.deriveKReset(idShared, senderFp, recipFp, resetNonce, R)
        val dhPubSlot = ByteArray(FrameCodec.DH_PUB_BYTES).also {
            System.arraycopy(resetNonce, 0, it, 0, ResetCrypto.RESET_NONCE_BYTES)
        }
        val wire = FrameCodec.encode(
            kind = FrameCodec.FRAME_KIND_RESET,
            senderFp = senderFp, recipFp = recipFp, dhPub = dhPubSlot,
            pn = 0, n = R, uuid = uuid, timestampMs = timestampMs,
            key = kReset,
            plaintext = ByteArray(32) // wrong size — should be 33
        )

        val ok = FrameCodec.decode(wire) as FrameCodec.DecodeResult.Ok
        assertSame(
            ResetCrypto.DecodeOutcome.InvalidPlaintextSize,
            ResetCrypto.decrypt(ok.frame, kReset)
        )
    }

    @Test
    fun ackByte_invalidValuesRejectedAtConstruction() {
        // Defense-in-depth: Plaintext constructor refuses ack bytes other than 0x00/0x01.
        // (A bytewire frame with ack=0x02 would AEAD-succeed but caller should be
        // unable to construct one through the official API.)
        try {
            ResetCrypto.Plaintext(0x02, postResetEphPub)
            fail("expected IllegalArgumentException for invalid ack")
        } catch (_: IllegalArgumentException) {
            // expected
        }
    }

    @Test
    fun extractors_returnSlotContents() {
        val resetNonce = ByteArray(ResetCrypto.RESET_NONCE_BYTES) { (0xc0 + it).toByte() }
        val R = 13
        val kReset = ResetCrypto.deriveKReset(idShared, senderFp, recipFp, resetNonce, R)
        val wire = ResetCrypto.encode(
            senderFp = senderFp, recipFp = recipFp, resetNonce = resetNonce, R = R,
            uuid = uuid, timestampMs = timestampMs,
            plaintext = ResetCrypto.Plaintext(ResetCrypto.ACK_ACKNOWLEDGER, postResetEphPub),
            kReset = kReset
        )
        val ok = FrameCodec.decode(wire) as FrameCodec.DecodeResult.Ok

        assertArrayEquals(resetNonce, ResetCrypto.extractResetNonce(ok.frame))
        assertEquals(R, ResetCrypto.extractR(ok.frame))
    }

    @Test
    fun resetNonce_generatorIsRandom() {
        val a = ResetCrypto.newResetNonce()
        val b = ResetCrypto.newResetNonce()
        assertEquals(ResetCrypto.RESET_NONCE_BYTES, a.size)
        assertNotEquals(
            "two CSPRNG-generated resetNonces must not collide",
            a.toHexLower(), b.toHexLower()
        )
        // Sanity: not all zero.
        assertTrue("resetNonce must not be all-zero", a.any { it.toInt() != 0 })
    }

    private fun ByteArray.toHexLower(): String =
        joinToString("") { "%02x".format(it) }
}
