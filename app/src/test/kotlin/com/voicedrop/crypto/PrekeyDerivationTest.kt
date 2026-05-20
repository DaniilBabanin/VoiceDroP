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
        // Pinned via Python HKDF-SHA256 (RFC 5869, cross-checked against RFC TC1).
        // Replacing these intentionally is the only way a future /v3 bump can
        // land without this test catching the drift.

        // hex: 30f01995f5ea9f36013411f49656f53c9eeb57b0dea015a36a7b478aeca354de
        private val K_RESET_V2_GOLDEN = byteArrayOf(
            0x30, 0xF0.toByte(), 0x19, 0x95.toByte(), 0xF5.toByte(), 0xEA.toByte(), 0x9F.toByte(), 0x36,
            0x01, 0x34, 0x11, 0xF4.toByte(), 0x96.toByte(), 0x56, 0xF5.toByte(), 0x3C,
            0x9E.toByte(), 0xEB.toByte(), 0x57, 0xB0.toByte(), 0xDE.toByte(), 0xA0.toByte(), 0x15, 0xA3.toByte(),
            0x6A, 0x7B, 0x47, 0x8A.toByte(), 0xEC.toByte(), 0xA3.toByte(), 0x54, 0xDE.toByte()
        )

        // hex: 69f84f506bbfb4c1c874c912af3b48a5da4425b802f7f677bea921b6e0629a4b
        private val RK0_V2_GOLDEN = byteArrayOf(
            0x69, 0xF8.toByte(), 0x4F, 0x50, 0x6B, 0xBF.toByte(), 0xB4.toByte(), 0xC1.toByte(),
            0xC8.toByte(), 0x74, 0xC9.toByte(), 0x12, 0xAF.toByte(), 0x3B, 0x48, 0xA5.toByte(),
            0xDA.toByte(), 0x44, 0x25, 0xB8.toByte(), 0x02, 0xF7.toByte(), 0xF6.toByte(), 0x77,
            0xBE.toByte(), 0xA9.toByte(), 0x21, 0xB6.toByte(), 0xE0.toByte(), 0x62, 0x9A.toByte(), 0x4B
        )

        // hex: f785a1840760f249a80fa83445b906e3dc719f7b0b6ff37903204ba1b14333c0
        private val RK0_INITIAL_V2_GOLDEN = byteArrayOf(
            0xF7.toByte(), 0x85.toByte(), 0xA1.toByte(), 0x84.toByte(), 0x07, 0x60, 0xF2.toByte(), 0x49,
            0xA8.toByte(), 0x0F, 0xA8.toByte(), 0x34, 0x45, 0xB9.toByte(), 0x06, 0xE3.toByte(),
            0xDC.toByte(), 0x71, 0x9F.toByte(), 0x7B, 0x0B, 0x6F, 0xF3.toByte(), 0x79,
            0x03, 0x20, 0x4B, 0xA1.toByte(), 0xB1.toByte(), 0x43, 0x33, 0xC0.toByte()
        )
    }
}
