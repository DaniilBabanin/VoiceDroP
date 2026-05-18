package com.voicedrop.crypto

import com.google.crypto.tink.subtle.X25519
import java.security.MessageDigest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * DR5 — Bootstrap unit tests. Pure JVM (no Android dependencies).
 *
 * Covers:
 *   - decideRole + symmetry
 *   - bootstrap_RK0_dependsOnBobEphemeral (FS gate vs. identity-key-only attacker)
 *   - bootstrap_RK0_sameValueOnBothSides (Alice and Bob converge)
 *   - bootstrap_resetRK0_includesResetNonce
 *   - golden vector (regression catch on HKDF info layout / endianness)
 */
class BootstrapTest {

    @Test
    fun decideRole_smallerFingerprintIsAlice() {
        // Search for a pair where fingerprint order is known both ways; X25519 keypairs are
        // uniformly random so we just generate two and verify the comparison matches the
        // raw 32-byte SHA-256 ordering.
        val aPriv = X25519.generatePrivateKey()
        val bPriv = X25519.generatePrivateKey()
        val aPub = X25519.publicFromPrivate(aPriv)
        val bPub = X25519.publicFromPrivate(bPriv)
        val aFp = MessageDigest.getInstance("SHA-256").digest(aPub)
        val bFp = MessageDigest.getInstance("SHA-256").digest(bPub)

        val expected: Bootstrap.Role = run {
            var cmp = 0
            for (i in aFp.indices) {
                val av = aFp[i].toInt() and 0xff
                val bv = bFp[i].toInt() and 0xff
                if (av != bv) { cmp = av - bv; break }
            }
            if (cmp < 0) Bootstrap.Role.ALICE else Bootstrap.Role.BOB
        }
        assertEquals(expected, Bootstrap.decideRole(aPub, bPub))
    }

    @Test
    fun decideRole_symmetric_alwaysOneAliceOneBob() {
        repeat(20) {
            val aPriv = X25519.generatePrivateKey()
            val bPriv = X25519.generatePrivateKey()
            val aPub = X25519.publicFromPrivate(aPriv)
            val bPub = X25519.publicFromPrivate(bPriv)
            val aRole = Bootstrap.decideRole(aPub, bPub)
            val bRole = Bootstrap.decideRole(bPub, aPub)
            assertNotEquals("collision: same fingerprint pair", aRole, bRole)
        }
    }

    @Test
    fun bootstrap_RK0_sameValueOnBothSides() {
        // Mint two identities + two bootstrap ephemerals, run both halves of
        // computeInitialBootstrap, assert the rootKey matches.
        val pair = freshPairing()
        val a = Bootstrap.computeInitialBootstrap(
            myIdPriv = pair.aIdPriv, myIdPub = pair.aIdPub, peerIdPub = pair.bIdPub,
            myBootstrapEphPriv = pair.aEphPriv, myBootstrapEphPub = pair.aEphPub,
            peerBootstrapEphPub = pair.bEphPub
        )
        val b = Bootstrap.computeInitialBootstrap(
            myIdPriv = pair.bIdPriv, myIdPub = pair.bIdPub, peerIdPub = pair.aIdPub,
            myBootstrapEphPriv = pair.bEphPriv, myBootstrapEphPub = pair.bEphPub,
            peerBootstrapEphPub = pair.aEphPub
        )
        assertArrayEquals("RK_0 must match across peers", a.rootKey, b.rootKey)
        assertNotEquals("one peer must be ALICE, the other BOB", a.role, b.role)
    }

    @Test
    fun bootstrap_RK0_dependsOnBobEphemeral() {
        // Same identities, different bootstrap ephemerals → different RK_0.
        // This proves identity-key-only exfil is insufficient.
        val aIdPriv = X25519.generatePrivateKey()
        val bIdPriv = X25519.generatePrivateKey()
        val aIdPub = X25519.publicFromPrivate(aIdPriv)
        val bIdPub = X25519.publicFromPrivate(bIdPriv)

        val rk0Trials = (0 until 4).map {
            val aEphPriv = X25519.generatePrivateKey()
            val bEphPriv = X25519.generatePrivateKey()
            Bootstrap.computeInitialBootstrap(
                myIdPriv = aIdPriv, myIdPub = aIdPub, peerIdPub = bIdPub,
                myBootstrapEphPriv = aEphPriv,
                myBootstrapEphPub = X25519.publicFromPrivate(aEphPriv),
                peerBootstrapEphPub = X25519.publicFromPrivate(bEphPriv)
            ).rootKey.toList()
        }
        val distinct = rk0Trials.toSet().size
        assertEquals("RK_0 must vary with the bootstrap ephemeral", rk0Trials.size, distinct)
    }

    @Test
    fun bootstrap_RK0_dependsOnIdentityKeys() {
        // Sanity: even with the same bootstrap eph, different identities yield different RK_0.
        val bEphPriv = X25519.generatePrivateKey()
        val bEphPub = X25519.publicFromPrivate(bEphPriv)

        val first = freshBootstrap(bEphPriv, bEphPub)
        val second = freshBootstrap(bEphPriv, bEphPub)
        assertFalse("identical identities not expected", first.aIdPub.contentEquals(second.aIdPub))

        val rk1 = Bootstrap.computeInitialBootstrap(
            myIdPriv = first.aIdPriv, myIdPub = first.aIdPub, peerIdPub = first.bIdPub,
            myBootstrapEphPriv = first.aEphPriv, myBootstrapEphPub = first.aEphPub,
            peerBootstrapEphPub = bEphPub
        ).rootKey
        val rk2 = Bootstrap.computeInitialBootstrap(
            myIdPriv = second.aIdPriv, myIdPub = second.aIdPub, peerIdPub = second.bIdPub,
            myBootstrapEphPriv = second.aEphPriv, myBootstrapEphPub = second.aEphPub,
            peerBootstrapEphPub = bEphPub
        ).rootKey
        assertFalse(rk1.contentEquals(rk2))
    }

    @Test
    fun bootstrap_resetRK0_includesResetNonce() {
        val idShared = ByteArray(32) { (it + 7).toByte() }
        val a = Bootstrap.deriveResetRootKey(idShared, R = 3, resetNonce = ByteArray(16) { 0x11 })
        val b = Bootstrap.deriveResetRootKey(idShared, R = 3, resetNonce = ByteArray(16) { 0x22 })
        assertFalse("different resetNonce must produce different RK_0", a.contentEquals(b))
    }

    @Test
    fun bootstrap_resetRK0_includesEpochR() {
        val idShared = ByteArray(32) { (it + 7).toByte() }
        val nonce = ByteArray(16) { 0x33 }
        val a = Bootstrap.deriveResetRootKey(idShared, R = 1, resetNonce = nonce)
        val b = Bootstrap.deriveResetRootKey(idShared, R = 2, resetNonce = nonce)
        assertFalse("different epoch R must produce different RK_0", a.contentEquals(b))
    }

    @Test(expected = IllegalArgumentException::class)
    fun bootstrap_resetRK0_rejectsR0() {
        // R=0 is the first-pairing case — must go through deriveInitialRootKey, which mixes the
        // bootstrap ephemeral. Letting R=0 through deriveResetRootKey would degrade the FS boundary
        // by silently swapping in a formula that ignores the bootstrap ephemeral.
        Bootstrap.deriveResetRootKey(ByteArray(32), R = 0, resetNonce = ByteArray(16))
    }

    @Test
    fun bootstrap_initialAndResetFormulas_doNotCollide() {
        // Even with R=0 nominally matching and a zero resetNonce, the two formulas differ
        // (initial mixes bootstrapDH into ikm; reset includes resetNonce in info).
        val idShared = ByteArray(32) { (it + 7).toByte() }
        val bootstrapDH = ByteArray(32) { (it + 17).toByte() }
        val initial = Bootstrap.deriveInitialRootKey(idShared, bootstrapDH)
        val resetWithEpoch1 = Bootstrap.deriveResetRootKey(idShared, R = 1, resetNonce = ByteArray(16))
        assertFalse(initial.contentEquals(resetWithEpoch1))
    }

    @Test
    fun bootstrap_aliceShape() {
        // Force ALICE: try until we get the smaller-fp side.
        val state = forceRole(Bootstrap.Role.ALICE)
        assertEquals(Bootstrap.Role.ALICE, state.role)
        assertNull(state.dhsPriv)
        assertNull(state.dhsPub)
        assertNotNull(state.dhrPub)
        assertEquals(32, state.dhrPub!!.size)
        assertEquals(32, state.rootKey.size)
    }

    @Test
    fun bootstrap_bobShape() {
        val state = forceRole(Bootstrap.Role.BOB)
        assertEquals(Bootstrap.Role.BOB, state.role)
        assertNotNull(state.dhsPriv)
        assertNotNull(state.dhsPub)
        assertNull(state.dhrPub)
        assertEquals(32, state.dhsPriv!!.size)
        assertEquals(32, state.dhsPub!!.size)
        assertEquals(32, state.rootKey.size)
    }

    @Test
    fun bootstrap_RK0_goldenVector_initial() {
        // Pinned-input regression — protects against HKDF info-string drift (label change,
        // endianness flip, missing 0x00 separator).
        val idShared = ByteArray(32) { it.toByte() }            // 0x00..0x1f
        val bootstrapDH = ByteArray(32) { (it + 0x20).toByte() } // 0x20..0x3f
        val rk = Bootstrap.deriveInitialRootKey(idShared, bootstrapDH)
        // Computed offline from RFC 5869 HKDF-SHA256 with:
        //   salt = zeros[32]
        //   ikm  = idShared || bootstrapDH (64 bytes)
        //   info = "voicedrop/rk-bootstrap/v1" || 0x00 || be32(0) = 30 bytes
        //   L    = 32
        val expectedHex = "f121023191fa9f652cce5bb7eb17a5217cbbd5d858dd888f59e23ed05753b743"
        assertEquals(expectedHex, rk.joinToString("") { "%02x".format(it) })
    }

    @Test
    fun bootstrap_RK0_goldenVector_reset() {
        val idShared = ByteArray(32) { it.toByte() }
        val resetNonce = ByteArray(16) { (it + 0x40).toByte() }  // 0x40..0x4f
        val rk = Bootstrap.deriveResetRootKey(idShared, R = 1, resetNonce = resetNonce)
        // HKDF-SHA256:
        //   salt = zeros[32]
        //   ikm  = idShared (32 bytes)
        //   info = "voicedrop/rk-bootstrap/v1" || 0x00 || be32(1) || resetNonce (46 bytes)
        //   L    = 32
        val expectedHex = "10e53cce3957859c9040e86402edb640c37c2433979c7674d5885607ed390154"
        assertEquals(expectedHex, rk.joinToString("") { "%02x".format(it) })
    }

    @Test
    fun deriveInitialRootKey_rejectsWrongSizes() {
        assertThrows { Bootstrap.deriveInitialRootKey(ByteArray(31), ByteArray(32)) }
        assertThrows { Bootstrap.deriveInitialRootKey(ByteArray(32), ByteArray(33)) }
    }

    @Test
    fun deriveResetRootKey_rejectsWrongSizes() {
        assertThrows { Bootstrap.deriveResetRootKey(ByteArray(31), 1, ByteArray(16)) }
        assertThrows { Bootstrap.deriveResetRootKey(ByteArray(32), 1, ByteArray(15)) }
    }

    // --- helpers ---

    private data class FreshPairing(
        val aIdPriv: ByteArray, val aIdPub: ByteArray,
        val bIdPriv: ByteArray, val bIdPub: ByteArray,
        val aEphPriv: ByteArray, val aEphPub: ByteArray,
        val bEphPriv: ByteArray, val bEphPub: ByteArray
    )

    private fun freshPairing(): FreshPairing {
        val aIdPriv = X25519.generatePrivateKey()
        val bIdPriv = X25519.generatePrivateKey()
        val aEphPriv = X25519.generatePrivateKey()
        val bEphPriv = X25519.generatePrivateKey()
        return FreshPairing(
            aIdPriv, X25519.publicFromPrivate(aIdPriv),
            bIdPriv, X25519.publicFromPrivate(bIdPriv),
            aEphPriv, X25519.publicFromPrivate(aEphPriv),
            bEphPriv, X25519.publicFromPrivate(bEphPriv)
        )
    }

    private data class HalfPairing(
        val aIdPriv: ByteArray, val aIdPub: ByteArray,
        val bIdPub: ByteArray,
        val aEphPriv: ByteArray, val aEphPub: ByteArray
    )

    private fun freshBootstrap(bEphPriv: ByteArray, bEphPub: ByteArray): HalfPairing {
        val aIdPriv = X25519.generatePrivateKey()
        val bIdPriv = X25519.generatePrivateKey()
        val aEphPriv = X25519.generatePrivateKey()
        return HalfPairing(
            aIdPriv, X25519.publicFromPrivate(aIdPriv),
            X25519.publicFromPrivate(bIdPriv),
            aEphPriv, X25519.publicFromPrivate(aEphPriv)
        )
    }

    /**
     * Generate identity + bootstrap material until `decideRole(myIdPub, peerIdPub)`
     * returns the requested role, then run `computeInitialBootstrap`.
     */
    private fun forceRole(target: Bootstrap.Role): Bootstrap.InitialState {
        repeat(200) {
            val myIdPriv = X25519.generatePrivateKey()
            val peerIdPriv = X25519.generatePrivateKey()
            val myIdPub = X25519.publicFromPrivate(myIdPriv)
            val peerIdPub = X25519.publicFromPrivate(peerIdPriv)
            if (Bootstrap.decideRole(myIdPub, peerIdPub) != target) return@repeat

            val myEphPriv = X25519.generatePrivateKey()
            val peerEphPriv = X25519.generatePrivateKey()
            return Bootstrap.computeInitialBootstrap(
                myIdPriv = myIdPriv, myIdPub = myIdPub, peerIdPub = peerIdPub,
                myBootstrapEphPriv = myEphPriv,
                myBootstrapEphPub = X25519.publicFromPrivate(myEphPriv),
                peerBootstrapEphPub = X25519.publicFromPrivate(peerEphPriv)
            )
        }
        error("could not generate identity pair landing on role=$target in 200 tries")
    }

    private fun assertThrows(block: () -> Unit) {
        try {
            block()
            throw AssertionError("expected exception")
        } catch (_: IllegalArgumentException) {
            // expected
        }
    }
}
