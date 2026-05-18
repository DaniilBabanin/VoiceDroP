package com.voicedrop.crypto

import com.google.crypto.tink.subtle.X25519
import com.voicedrop.network.FrameCodec
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * DR6 — Double Ratchet core unit tests (pure JVM).
 *
 * Round-trip tests use [FrameCodec] for AAD/sealing so the test path matches
 * what [dr8-decrypt-path.md] will use in production. Skipped-key map is the
 * in-memory implementation in [SkippedKeyMap] — [dr9] will swap for the
 * Room-backed store but the API is identical.
 */
class DoubleRatchetTest {

    // ---------------------------------------------------------------------
    // KDF golden / spec-constant tests
    // ---------------------------------------------------------------------

    @Test
    fun kdfCk_constants_matchSignalSpec() {
        // Signal spec §5.2: chain-key advance with 0x01, message-key with 0x02.
        // Independent recomputation by raw HMAC must match. Flipping these
        // constants is a wire-incompat change — caught here, not in prod.
        val ck = ByteArray(32) { it.toByte() }
        val expectedNewCk = hmacSha256(ck, byteArrayOf(0x01))
        val expectedMk = hmacSha256(ck, byteArrayOf(0x02))
        assertEquals(0x01.toByte(), RatchetKdf.CK_NEXT_BYTE)
        assertEquals(0x02.toByte(), RatchetKdf.CK_MK_BYTE)
        val (newCk, mk) = RatchetKdf.kdfCk(ck)
        assertArrayEquals(expectedNewCk, newCk)
        assertArrayEquals(expectedMk, mk)
    }

    @Test
    fun kdfCk_matchesGolden() {
        // Defense against silent crypto-lib upgrades. Computed offline in Python
        // using `hmac.new(ck, b"\x01"|b"\x02", hashlib.sha256).digest()`.
        val ck = ByteArray(32) { it.toByte() }
        val (newCk, mk) = RatchetKdf.kdfCk(ck)
        assertEquals(
            "9b4c8120a4823a95f47cde17a244f4507244ee6e3957d1fab9fa29b44d3829b7",
            newCk.toHex()
        )
        assertEquals(
            "4304c22c84a53755ab08ead8d97a8d429be5efa480682d7ad1da27f73e1fbe1d",
            mk.toHex()
        )
    }

    @Test
    fun kdfRk_matchesGolden() {
        // HKDF-SHA256, salt=rk (0x00..0x1f), ikm=dhOut (0x20..0x3f),
        // info="voicedrop/rk/v1", L=64. Computed offline.
        val rk = ByteArray(32) { it.toByte() }
        val dhOut = ByteArray(32) { (it + 32).toByte() }
        val (newRk, newCk) = RatchetKdf.kdfRk(rk, dhOut)
        assertEquals(
            "331230bda73dc88e124ccd68f75229cac3ccb8601bcff36c6af754fc1fb0cbdd",
            newRk.toHex()
        )
        assertEquals(
            "4ef0025c543038608146210a54fca3d01a2d3894ad2855f52e4fbb3998fff798",
            newCk.toHex()
        )
    }

    @Test
    fun kdfCk_rejectsWrongSizes() {
        try { RatchetKdf.kdfCk(ByteArray(31)); fail("expected") } catch (_: IllegalArgumentException) {}
        try { RatchetKdf.kdfCk(ByteArray(33)); fail("expected") } catch (_: IllegalArgumentException) {}
    }

    @Test
    fun kdfRk_rejectsWrongSizes() {
        try { RatchetKdf.kdfRk(ByteArray(31), ByteArray(32)); fail("expected") } catch (_: IllegalArgumentException) {}
        try { RatchetKdf.kdfRk(ByteArray(32), ByteArray(33)); fail("expected") } catch (_: IllegalArgumentException) {}
    }

    // ---------------------------------------------------------------------
    // Round trips
    // ---------------------------------------------------------------------

    @Test
    fun roundTrip_AliceToBob_singleMessage() {
        val p = pair()
        val plaintext = "hello bob".toByteArray()
        val wire = sendFrame(p.aliceState, p.aliceFp, p.bobFp, plaintext)
        val out = receiveFrame(p.bobState, p.bobSkipped, wire)
        assertArrayEquals(plaintext, out)
    }

    @Test
    fun roundTrip_BobToAlice_afterFirstReceive() {
        val p = pair()
        // Bob needs Alice's first frame before he can send.
        val a1 = sendFrame(p.aliceState, p.aliceFp, p.bobFp, "hi".toByteArray())
        receiveFrame(p.bobState, p.bobSkipped, a1)

        val plaintext = "hello alice".toByteArray()
        val b1 = sendFrame(p.bobState, p.bobFp, p.aliceFp, plaintext)
        val out = receiveFrame(p.aliceState, p.aliceSkipped, b1)
        assertArrayEquals(plaintext, out)
    }

    @Test
    fun roundTrip_longChain_100MessagesEachDirection() {
        val p = pair()

        // Prime: Alice → Bob first so Bob can derive his sending chain.
        receiveFrame(
            p.bobState, p.bobSkipped,
            sendFrame(p.aliceState, p.aliceFp, p.bobFp, "prime".toByteArray())
        )

        // 100 alternating ping-pongs.
        for (i in 0 until 100) {
            val aMsg = "a$i".toByteArray()
            val aWire = sendFrame(p.aliceState, p.aliceFp, p.bobFp, aMsg)
            assertArrayEquals(aMsg, receiveFrame(p.bobState, p.bobSkipped, aWire))

            val bMsg = "b$i".toByteArray()
            val bWire = sendFrame(p.bobState, p.bobFp, p.aliceFp, bMsg)
            assertArrayEquals(bMsg, receiveFrame(p.aliceState, p.aliceSkipped, bWire))
        }
    }

    @Test
    fun bobCannotSendBeforeFirstReceive() {
        val p = pair()
        try {
            Ratchet.advanceSend(p.bobState)
            fail("expected AwaitingFirstReceive")
        } catch (_: AwaitingFirstReceive) {
            // expected
        }
    }

    @Test
    fun aliceSendsFirst_lazyCKsDerivation() {
        // Alice's state right after bootstrap: CKs is null, DHs is null, DHr is bobBootEphPub.
        // First advanceSend triggers dhRatchetSend, which generates DHs and derives CKs.
        val p = pair()
        assertNull("Alice's CKs nil before first send", p.aliceState.cks)
        assertNull("Alice's DHs.priv nil before first send", p.aliceState.dhsPriv)
        assertNotNull("Alice's DHr is bobBootEphPub", p.aliceState.dhrPub)

        val send = Ratchet.advanceSend(p.aliceState)

        assertNotNull("CKs populated after first send", p.aliceState.cks)
        assertNotNull("DHs.priv populated", p.aliceState.dhsPriv)
        assertNotNull("DHs.pub matches send.dhPub", p.aliceState.dhsPub)
        assertArrayEquals(p.aliceState.dhsPub, send.dhPub)
        assertEquals(0, send.n)   // first message on first chain
        assertEquals(0, send.pn)  // no prior sending chain
        assertEquals(1, p.aliceState.ns)
    }

    // ---------------------------------------------------------------------
    // Out-of-order arrivals
    // ---------------------------------------------------------------------

    @Test
    fun outOfOrder_arrivalsWithinChain() {
        val p = pair()
        // Alice sends three frames on the same chain.
        val wires = (0 until 3).map { i ->
            sendFrame(p.aliceState, p.aliceFp, p.bobFp, "a$i".toByteArray())
        }
        // Bob receives them out of order: 2, 0, 1.
        assertArrayEquals("a2".toByteArray(), receiveFrame(p.bobState, p.bobSkipped, wires[2]))
        // After receiving n=2 first, mk for n=0 and n=1 should be stashed.
        assertEquals(2, p.bobSkipped.size())
        assertArrayEquals("a0".toByteArray(), receiveFrame(p.bobState, p.bobSkipped, wires[0]))
        assertEquals(1, p.bobSkipped.size())
        assertArrayEquals("a1".toByteArray(), receiveFrame(p.bobState, p.bobSkipped, wires[1]))
        assertTrue(p.bobSkipped.isEmpty())
    }

    @Test
    fun outOfOrder_acrossDhRatchetStep() {
        // Scenario: Alice sends three on A1, Bob consumes the first only, Alice
        // ratchets and sends one on A2. Bob's A2-frame receive must stash the
        // unconsumed A1 keys (mk1, mk2) via header.pn=3.
        val p = pair()
        val a1 = sendFrame(p.aliceState, p.aliceFp, p.bobFp, "a1".toByteArray())
        val a2 = sendFrame(p.aliceState, p.aliceFp, p.bobFp, "a2".toByteArray())
        val a3 = sendFrame(p.aliceState, p.aliceFp, p.bobFp, "a3".toByteArray())
        assertArrayEquals("a1".toByteArray(), receiveFrame(p.bobState, p.bobSkipped, a1))

        // Bob replies; Alice receives → Alice's DH ratchets to A2.
        val b1 = sendFrame(p.bobState, p.bobFp, p.aliceFp, "b1".toByteArray())
        receiveFrame(p.aliceState, p.aliceSkipped, b1)

        // Alice sends on the new chain (A2). header.pn should be 3 (a1, a2, a3 on A1).
        val a4 = sendFrame(p.aliceState, p.aliceFp, p.bobFp, "a4".toByteArray())
        // Bob receives a4: dhRatchet, stash A1 keys (1, 2), consume A2/n=0.
        assertArrayEquals("a4".toByteArray(), receiveFrame(p.bobState, p.bobSkipped, a4))
        assertEquals("two unconsumed A1 keys stashed", 2, p.bobSkipped.size())

        // Late a2, a3 arrive: served from skipped store.
        assertArrayEquals("a2".toByteArray(), receiveFrame(p.bobState, p.bobSkipped, a2))
        assertArrayEquals("a3".toByteArray(), receiveFrame(p.bobState, p.bobSkipped, a3))
        assertTrue("skipped store fully drained", p.bobSkipped.isEmpty())
    }

    @Test
    fun oldChainSkippedKey_persistsAcrossDhRatchet_decryptsLateFrame() {
        // Stronger assertion than `outOfOrder_acrossDhRatchetStep`: after consuming
        // the late frame, state.DHr and state.CKr must be byte-equal to their pre-
        // receive values (no chain advance for skipped-key hits — Signal §3.4 invariant).
        val p = pair()
        val a1 = sendFrame(p.aliceState, p.aliceFp, p.bobFp, "a1".toByteArray())
        val a2 = sendFrame(p.aliceState, p.aliceFp, p.bobFp, "a2".toByteArray())  // delayed
        receiveFrame(p.bobState, p.bobSkipped, a1)

        val b1 = sendFrame(p.bobState, p.bobFp, p.aliceFp, "b1".toByteArray())
        receiveFrame(p.aliceState, p.aliceSkipped, b1)

        val a3 = sendFrame(p.aliceState, p.aliceFp, p.bobFp, "a3".toByteArray())  // on new A2 chain
        receiveFrame(p.bobState, p.bobSkipped, a3)

        // Snapshot Bob's chain after consuming a3.
        val dhrBefore = p.bobState.dhrPub!!.copyOf()
        val ckrBefore = p.bobState.ckr!!.copyOf()
        val nrBefore = p.bobState.nr

        // Late a2 arrives; should hit skipped store, NOT touch state.
        val out = receiveFrame(p.bobState, p.bobSkipped, a2)
        assertArrayEquals("a2".toByteArray(), out)

        assertArrayEquals("DHr unchanged after skipped hit", dhrBefore, p.bobState.dhrPub)
        assertArrayEquals("CKr unchanged after skipped hit", ckrBefore, p.bobState.ckr)
        assertEquals("Nr unchanged after skipped hit", nrBefore, p.bobState.nr)
    }

    @Test
    fun dhRatchetStep_firstMessageLost_secondMessageRecovers() {
        // a1 is dropped; bob still recovers a2 (which derives mk for n=1 after
        // stashing the mk for n=0 in the skipped store).
        val p = pair()
        /* val a1 = */ sendFrame(p.aliceState, p.aliceFp, p.bobFp, "lost".toByteArray())
        val a2 = sendFrame(p.aliceState, p.aliceFp, p.bobFp, "a2".toByteArray())
        assertArrayEquals("a2".toByteArray(), receiveFrame(p.bobState, p.bobSkipped, a2))
        assertEquals("mk for lost a1 stashed", 1, p.bobSkipped.size())
    }

    // ---------------------------------------------------------------------
    // Skip-limit
    // ---------------------------------------------------------------------

    @Test
    fun skipLimit_gapExactlyMaxSkip_succeeds() {
        val p = pair()
        // Alice produces MAX_SKIP + 1 frames (indices 0..MAX_SKIP). Bob only sees the last.
        // gap = MAX_SKIP - 0 = MAX_SKIP → succeeds.
        var lastWire: ByteArray? = null
        for (i in 0..RatchetKdf.MAX_SKIP) {
            val w = sendFrame(p.aliceState, p.aliceFp, p.bobFp, "n=$i".toByteArray())
            if (i == RatchetKdf.MAX_SKIP) lastWire = w
        }
        val out = receiveFrame(p.bobState, p.bobSkipped, lastWire!!)
        assertArrayEquals("n=${RatchetKdf.MAX_SKIP}".toByteArray(), out)
        assertEquals(RatchetKdf.MAX_SKIP, p.bobSkipped.size())
    }

    @Test
    fun skipLimit_gapBeyondMaxSkip_rejected() {
        val p = pair()
        // gap = MAX_SKIP + 1 → throws SkipLimitExceeded.
        var lastWire: ByteArray? = null
        for (i in 0..(RatchetKdf.MAX_SKIP + 1)) {
            val w = sendFrame(p.aliceState, p.aliceFp, p.bobFp, "n=$i".toByteArray())
            if (i == RatchetKdf.MAX_SKIP + 1) lastWire = w
        }
        try {
            receiveFrame(p.bobState, p.bobSkipped, lastWire!!)
            fail("expected SkipLimitExceeded")
        } catch (e: SkipLimitExceeded) {
            assertEquals(RatchetKdf.MAX_SKIP + 1, e.gap)
        }
    }

    @Test
    fun skipLimit_aeadFailureLeavesStateUntouched() {
        // Forward-pointing frame that fails AEAD (we corrupt the ciphertext)
        // must NOT advance state.Nr and must NOT leave skipped entries behind.
        val p = pair()
        val a1 = sendFrame(p.aliceState, p.aliceFp, p.bobFp, "a1".toByteArray())
        val a2 = sendFrame(p.aliceState, p.aliceFp, p.bobFp, "a2".toByteArray())
        val a3Wire = sendFrame(p.aliceState, p.aliceFp, p.bobFp, "a3".toByteArray())

        // Corrupt the ciphertext byte of a3.
        a3Wire[a3Wire.size - 1] = (a3Wire[a3Wire.size - 1].toInt() xor 0xff).toByte()

        // Consume a1 to set up the receiving chain.
        receiveFrame(p.bobState, p.bobSkipped, a1)
        val nrBefore = p.bobState.nr
        val ckrBefore = p.bobState.ckr!!.copyOf()
        val skippedSizeBefore = p.bobSkipped.size()

        // Corrupted a3 must fail and leave state pristine.
        try {
            receiveFrame(p.bobState, p.bobSkipped, a3Wire)
            fail("expected AEAD failure")
        } catch (_: RatchetCryptoFailure) {
            // expected
        }
        assertEquals(nrBefore, p.bobState.nr)
        assertArrayEquals(ckrBefore, p.bobState.ckr)
        assertEquals(skippedSizeBefore, p.bobSkipped.size())

        // Clean a2 still decrypts fine afterwards (state was preserved).
        assertArrayEquals("a2".toByteArray(), receiveFrame(p.bobState, p.bobSkipped, a2))
    }

    // ---------------------------------------------------------------------
    // DH ratchet — keypair freshness
    // ---------------------------------------------------------------------

    @Test
    fun dhRatchet_freshKeypairEveryStep() {
        val p = pair()
        // Prime so Bob has a sending chain.
        receiveFrame(
            p.bobState, p.bobSkipped,
            sendFrame(p.aliceState, p.aliceFp, p.bobFp, "prime".toByteArray())
        )

        val alicePrivs = mutableListOf<ByteArray>()
        val bobPrivs = mutableListOf<ByteArray>()

        // Alice's first DHs (from her first send) was generated by dhRatchetSend,
        // then her receive of Bob's first reply regenerated it inside dhRatchetReceive.
        // From here, 10 ping-pongs each rotate both sides.
        for (i in 0 until 10) {
            val aWire = sendFrame(p.aliceState, p.aliceFp, p.bobFp, "a$i".toByteArray())
            alicePrivs.add(p.aliceState.dhsPriv!!.copyOf())
            receiveFrame(p.bobState, p.bobSkipped, aWire)
            bobPrivs.add(p.bobState.dhsPriv!!.copyOf())

            val bWire = sendFrame(p.bobState, p.bobFp, p.aliceFp, "b$i".toByteArray())
            receiveFrame(p.aliceState, p.aliceSkipped, bWire)
        }

        // All 10 of Alice's recorded DHs.priv values must be pairwise distinct.
        for (i in alicePrivs.indices) for (j in i + 1 until alicePrivs.size) {
            assertFalse(
                "Alice DHs.priv repeated at steps $i and $j",
                alicePrivs[i].contentEquals(alicePrivs[j])
            )
        }
        for (i in bobPrivs.indices) for (j in i + 1 until bobPrivs.size) {
            assertFalse(
                "Bob DHs.priv repeated at steps $i and $j",
                bobPrivs[i].contentEquals(bobPrivs[j])
            )
        }
    }

    // ---------------------------------------------------------------------
    // Input validation
    // ---------------------------------------------------------------------

    @Test
    fun decrypt_rejectsAllZeroDhPub() {
        val p = pair()
        // Drive Alice forward so Bob has a real receive chain.
        receiveFrame(
            p.bobState, p.bobSkipped,
            sendFrame(p.aliceState, p.aliceFp, p.bobFp, "x".toByteArray())
        )
        try {
            Ratchet.decrypt(
                state = p.bobState,
                skipped = p.bobSkipped,
                headerDhPub = ByteArray(32),
                headerPn = 0, headerN = 0,
                ciphertext = ByteArray(16),  // anything; we'll throw before AEAD
                aad = ByteArray(133)
            )
            fail("expected InvalidFrame")
        } catch (_: InvalidFrame) {
            // expected
        }
    }

    @Test
    fun decrypt_rejectsLowOrderDhPub() {
        val p = pair()
        receiveFrame(
            p.bobState, p.bobSkipped,
            sendFrame(p.aliceState, p.aliceFp, p.bobFp, "x".toByteArray())
        )
        // X25519 low-order point: 0x01 in byte 0, zeros elsewhere (order 4).
        val lowOrder = ByteArray(32).also { it[0] = 0x01 }
        try {
            Ratchet.decrypt(
                state = p.bobState,
                skipped = p.bobSkipped,
                headerDhPub = lowOrder,
                headerPn = 0, headerN = 0,
                ciphertext = ByteArray(16),
                aad = ByteArray(133)
            )
            fail("expected InvalidFrame")
        } catch (_: InvalidFrame) {
            // expected
        }
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    private class Pairing(
        val aliceState: RatchetState,
        val bobState: RatchetState,
        val aliceFp: ByteArray,
        val bobFp: ByteArray,
        val aliceSkipped: SkippedKeyMap = SkippedKeyMap(),
        val bobSkipped: SkippedKeyMap = SkippedKeyMap()
    )

    private fun pair(): Pairing {
        val aIdPriv = X25519.generatePrivateKey()
        val bIdPriv = X25519.generatePrivateKey()
        val aEphPriv = X25519.generatePrivateKey()
        val bEphPriv = X25519.generatePrivateKey()
        val aIdPub = X25519.publicFromPrivate(aIdPriv)
        val bIdPub = X25519.publicFromPrivate(bIdPriv)
        val aEphPub = X25519.publicFromPrivate(aEphPriv)
        val bEphPub = X25519.publicFromPrivate(bEphPriv)

        val aBoot = Bootstrap.computeInitialBootstrap(
            myIdPriv = aIdPriv, myIdPub = aIdPub, peerIdPub = bIdPub,
            myBootstrapEphPriv = aEphPriv, myBootstrapEphPub = aEphPub,
            peerBootstrapEphPub = bEphPub
        )
        val bBoot = Bootstrap.computeInitialBootstrap(
            myIdPriv = bIdPriv, myIdPub = bIdPub, peerIdPub = aIdPub,
            myBootstrapEphPriv = bEphPriv, myBootstrapEphPub = bEphPub,
            peerBootstrapEphPub = aEphPub
        )
        // Sanity: both sides must converge on the same root key.
        assertArrayEquals(
            "RK_0 must converge across the pairing",
            aBoot.rootKey, bBoot.rootKey
        )
        val aState = RatchetState.fromBootstrap(aBoot)
        val bState = RatchetState.fromBootstrap(bBoot)
        val aFp = Bootstrap.fingerprintBytes(aIdPub)
        val bFp = Bootstrap.fingerprintBytes(bIdPub)
        return when (aBoot.role) {
            Bootstrap.Role.ALICE -> Pairing(aState, bState, aFp, bFp)
            Bootstrap.Role.BOB -> Pairing(bState, aState, bFp, aFp)
        }
    }

    private val rng = SecureRandom()

    private fun sendFrame(
        senderState: RatchetState,
        senderFp: ByteArray,
        recipFp: ByteArray,
        plaintext: ByteArray
    ): ByteArray {
        val send = Ratchet.advanceSend(senderState)
        val uuid = ByteArray(16).also { rng.nextBytes(it) }
        return FrameCodec.encode(
            kind = FrameCodec.FRAME_KIND_DATA,
            senderFp = senderFp, recipFp = recipFp,
            dhPub = send.dhPub, pn = send.pn, n = send.n,
            uuid = uuid, timestampMs = 0L,
            key = send.mk, plaintext = plaintext
        )
    }

    private fun receiveFrame(
        receiverState: RatchetState,
        skipped: SkippedKeyMap,
        wire: ByteArray
    ): ByteArray {
        val decoded = (FrameCodec.decode(wire) as FrameCodec.DecodeResult.Ok).frame
        return Ratchet.decrypt(
            state = receiverState,
            skipped = skipped,
            headerDhPub = decoded.dhPub,
            headerPn = decoded.pn,
            headerN = decoded.n,
            ciphertext = decoded.ciphertext,
            aad = decoded.aad
        )
    }

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
