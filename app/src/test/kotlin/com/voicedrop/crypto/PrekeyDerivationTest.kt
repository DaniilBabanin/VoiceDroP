package com.voicedrop.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

/**
 * §3.2 §7.1 — Prekey + /v2 derivation unit tests. Golden vectors pin the
 * /v2 outputs so an unintentional info-string drift (e.g. /v2 → /v3) is
 * caught by a failing assertion rather than silently producing different
 * keys on the wire.
 */
class PrekeyDerivationTest {

    private val zero32 = ByteArray(32)
    private val resetNonce16 = ByteArray(16) { it.toByte() }
    private val senderFp = ByteArray(32) { (0x10 + it).toByte() }
    private val recipFp = ByteArray(32) { (0x40 + it).toByte() }

    @Test
    fun prekeySS_isSymmetric() {
        val a = Prekey.generate()
        val b = Prekey.generate()
        val abShared = Prekey.sharedSecret(a.priv, b.pub)
        val baShared = Prekey.sharedSecret(b.priv, a.pub)
        assertArrayEquals(abShared, baShared)
    }

    @Test
    fun kReset_v2_dependsOnPrekeySS() {
        val idSS = ByteArray(32) { 0x11 }
        val pre1 = ByteArray(32) { 0x22 }
        val pre2 = ByteArray(32) { 0x33 }
        val k1 = ResetCrypto.deriveKReset(idSS, pre1, senderFp, recipFp, resetNonce16, R = 1)
        val k2 = ResetCrypto.deriveKReset(idSS, pre2, senderFp, recipFp, resetNonce16, R = 1)
        assertFalse("K_reset must change when prekeySS changes", k1.contentEquals(k2))
    }

    @Test
    fun rk0_v2_dependsOnPrekeySS() {
        val idSS = ByteArray(32) { 0x11 }
        val pre1 = ByteArray(32) { 0x22 }
        val pre2 = ByteArray(32) { 0x33 }
        val rk1 = Bootstrap.deriveResetRootKey(idSS, pre1, R = 1, resetNonce = resetNonce16)
        val rk2 = Bootstrap.deriveResetRootKey(idSS, pre2, R = 1, resetNonce = resetNonce16)
        assertFalse("RK_0 must change when prekeySS changes", rk1.contentEquals(rk2))
    }

    @Test(expected = IllegalArgumentException::class)
    fun sharedSecret_rejectsWrongSize() {
        Prekey.sharedSecret(ByteArray(31), ByteArray(32))
    }

    @Test
    fun kReset_v2_goldenVector() {
        val idSS = ByteArray(32) { 0xAA.toByte() }
        val prekeySS = ByteArray(32) { 0xBB.toByte() }
        val out = ResetCrypto.deriveKReset(idSS, prekeySS, senderFp, recipFp, resetNonce16, R = 7)
        assertArrayEquals(K_RESET_V2_GOLDEN, out)
    }

    @Test
    fun rk0_v2_goldenVector() {
        val idSS = ByteArray(32) { 0xAA.toByte() }
        val prekeySS = ByteArray(32) { 0xBB.toByte() }
        val out = Bootstrap.deriveResetRootKey(idSS, prekeySS, R = 7, resetNonce = resetNonce16)
        assertArrayEquals(RK0_V2_GOLDEN, out)
    }

    @Test
    fun initialBootstrap_v2_goldenVector() {
        // R=0 path: still mixes idSS || bootstrapDH per dr5; only the info-string tag
        // bumped to /v2. Confirms the structural shape didn't drift in the rename.
        val idSS = ByteArray(32) { 0xAA.toByte() }
        val bootstrapDH = ByteArray(32) { 0xCC.toByte() }
        val out = Bootstrap.deriveInitialRootKey(idSS, bootstrapDH)
        assertArrayEquals(RK0_INITIAL_V2_GOLDEN, out)
    }

    companion object {
        // Pinned after first run. Replacing these intentionally is the only way
        // a future /v3 bump can land without this test catching the drift.
        private val K_RESET_V2_GOLDEN = ByteArray(32) // TODO replace after Step 5
        private val RK0_V2_GOLDEN = ByteArray(32) // TODO replace after Step 5
        private val RK0_INITIAL_V2_GOLDEN = ByteArray(32) // TODO replace after Step 5
    }
}
