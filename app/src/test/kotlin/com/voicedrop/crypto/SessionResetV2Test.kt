package com.voicedrop.crypto

import com.voicedrop.network.FrameCodec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * §3.2 §7.5 — wire-format regression tests for v2 RESET plaintext.
 * Extends dr12 / dr16 patterns. Pure unit tests: build a plaintext,
 * encode under a synthetic K_reset, verify decoder behavior on size/
 * version mutations.
 *
 * Note: §7.5's `reset_v2_aeadFailFallbackToPrevious` and
 * `reset_v2_outboundReAckUsesSamePrekeyAsInbound` belong in
 * PrekeyEpochsLifecycleTest (Task 8) — they require a DB roundtrip.
 */
class SessionResetV2Test {

    private val kReset = ByteArray(32) { 0x77 }
    private val resetNonce = ByteArray(16) { it.toByte() }
    private val senderFp = ByteArray(32) { (0x10 + it).toByte() }
    private val recipFp = ByteArray(32) { (0x40 + it).toByte() }
    private val uuid = ByteArray(16) { (0x80 + it).toByte() }
    private val now = 1_700_000_000_000L

    @Test
    fun reset_v2_plaintextSize66() {
        val pt = ResetCrypto.Plaintext(
            ack = ResetCrypto.ACK_INITIATOR,
            postResetEphPub = ByteArray(32),
            stagedPrekeyPub = ByteArray(32) { 0xAB.toByte() }
        )
        assertEquals(66, pt.toBytes().size)
        assertEquals(ResetCrypto.PLAINTEXT_VERSION_V2, pt.toBytes()[0])
    }

    @Test
    fun reset_v2_decodeRoundtrip() {
        val pt = ResetCrypto.Plaintext(
            ack = ResetCrypto.ACK_ACKNOWLEDGER,
            postResetEphPub = ByteArray(32) { 0xCC.toByte() },
            stagedPrekeyPub = ByteArray(32) { 0xDD.toByte() }
        )
        val wire = ResetCrypto.encode(senderFp, recipFp, resetNonce, R = 5, uuid, now, pt, kReset)
        val decoded = FrameCodec.decode(wire) as FrameCodec.DecodeResult.Ok
        val out = ResetCrypto.decrypt(decoded.frame, kReset)
        assertTrue(out is ResetCrypto.DecodeOutcome.Ok)
        val recovered = (out as ResetCrypto.DecodeOutcome.Ok).plaintext
        assertEquals(ResetCrypto.ACK_ACKNOWLEDGER, recovered.ack)
        assertTrue(recovered.postResetEphPub.contentEquals(pt.postResetEphPub))
        assertTrue(recovered.stagedPrekeyPub.contentEquals(pt.stagedPrekeyPub))
    }

    @Test
    fun reset_v2_versionByteNonZero_rejectedPostAead() {
        // Construct a frame whose plaintext bytes after AEAD decrypt have version=0x03.
        // AEAD succeeds (we encrypt under the same kReset we then decrypt under), so
        // ResetCrypto.decrypt exercises its version-byte check on the recovered plaintext.
        val badPlaintextBytes = ByteArray(66).apply {
            this[0] = 0x03  // wrong version
            this[1] = ResetCrypto.ACK_INITIATOR
        }
        val wire = FrameCodec.encode(
            kind = FrameCodec.FRAME_KIND_RESET,
            senderFp = senderFp, recipFp = recipFp,
            dhPub = ByteArray(32).also { resetNonce.copyInto(it, 0) },
            pn = 0, n = 5, uuid = uuid, timestampMs = now,
            key = kReset, plaintext = badPlaintextBytes
        )
        val decoded = (FrameCodec.decode(wire) as FrameCodec.DecodeResult.Ok).frame
        assertTrue(ResetCrypto.decrypt(decoded, kReset) is ResetCrypto.DecodeOutcome.InvalidPlaintext)
    }

    @Test
    fun reset_v2_plaintextSize65or67_rejected() {
        val short = ByteArray(65)
        val longer = ByteArray(67)
        for (mutated in listOf(short, longer)) {
            val wire = FrameCodec.encode(
                kind = FrameCodec.FRAME_KIND_RESET,
                senderFp = senderFp, recipFp = recipFp,
                dhPub = ByteArray(32).also { resetNonce.copyInto(it, 0) },
                pn = 0, n = 5, uuid = uuid, timestampMs = now,
                key = kReset, plaintext = mutated
            )
            val decoded = (FrameCodec.decode(wire) as FrameCodec.DecodeResult.Ok).frame
            assertTrue(ResetCrypto.decrypt(decoded, kReset) is ResetCrypto.DecodeOutcome.InvalidPlaintext)
        }
    }

    @Test
    fun reset_v2_stagedPrekeyPubAllZeroAccepted_atDecodeLayer() {
        // The decode layer accepts size+version+ack only; the all-zero / low-order
        // value check lives post-decrypt in processInsideTxn (covered by Pcs_E2eTest
        // in Task 10). This test pins that the decoder itself does not impose
        // value-level checks.
        val pt = ResetCrypto.Plaintext(
            ack = ResetCrypto.ACK_INITIATOR,
            postResetEphPub = ByteArray(32),
            stagedPrekeyPub = ByteArray(32)
        )
        val wire = ResetCrypto.encode(senderFp, recipFp, resetNonce, R = 5, uuid, now, pt, kReset)
        val decoded = (FrameCodec.decode(wire) as FrameCodec.DecodeResult.Ok).frame
        assertTrue(ResetCrypto.decrypt(decoded, kReset) is ResetCrypto.DecodeOutcome.Ok)
    }
}
