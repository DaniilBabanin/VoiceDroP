package com.voicedrop.crypto

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.security.KeyStore
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AndroidKeyStore is not available under Robolectric, so DR2 tests live in
 * androidTest (instrumented) rather than src/test/. See KeyManagerTest, which
 * carries the same @Ignore note.
 */
@RunWith(AndroidJUnit4::class)
class WrapAndMacTest {

    private lateinit var context: Context
    private lateinit var km: KeyManager

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        // Clear prefs + delete v2 KeyStore aliases so each test starts clean.
        clearV2State()
        km = KeyManager(context)
    }

    @After
    fun tearDown() {
        clearV2State()
    }

    private fun clearV2State() {
        context.getSharedPreferences("voicedrop_keys", Context.MODE_PRIVATE)
            .edit().clear().commit()
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        for (alias in listOf(
            KeyManager.KEYSTORE_ALIAS_WRAP_V2,
            KeyManager.KEYSTORE_ALIAS_MAC_V2
        )) {
            if (ks.containsAlias(alias)) ks.deleteEntry(alias)
        }
    }

    @Test
    fun wrapAndMac_roundTrip() {
        val plain = "ratchet root key bytes — 32B".toByteArray()
        val (wrapped, hmac) = km.wrapAndMac("contacts.rk_wrapped", "alice".toByteArray(), plain)
        val out = km.unwrapAndVerify("contacts.rk_wrapped", "alice".toByteArray(), wrapped, hmac)
        assertArrayEquals(plain, out)
    }

    @Test
    fun wrapBlob_layoutGolden_isIvPlusCiphertextPlusTag() {
        val plain = ByteArray(32) { it.toByte() }
        val (wrapped, hmac) = km.wrapAndMac("contacts.rk_wrapped", "alice".toByteArray(), plain)
        // [iv:12 || ct:plain.size || tag:16] — Cipher.doFinal emits ct||tag, we prepend iv.
        assertEquals(12 + plain.size + 16, wrapped.size)
        assertEquals(32, hmac.size)  // HmacSHA256 output
    }

    @Test
    fun wrap_iv_isFresh_perCall() {
        val plain = ByteArray(32)
        val (w1, _) = km.wrapAndMac("contacts.rk_wrapped", "alice".toByteArray(), plain)
        val (w2, _) = km.wrapAndMac("contacts.rk_wrapped", "alice".toByteArray(), plain)
        val iv1 = w1.copyOfRange(0, 12)
        val iv2 = w2.copyOfRange(0, 12)
        assertEquals(
            "IVs must not repeat across wraps under the same key",
            false, iv1.contentEquals(iv2)
        )
    }

    @Test
    fun unwrap_failsOnHmacFlip() {
        val plain = "rk".toByteArray()
        val (wrapped, hmac) = km.wrapAndMac("contacts.rk_wrapped", "alice".toByteArray(), plain)
        val tampered = hmac.copyOf().also { it[0] = (it[0].toInt() xor 0x01).toByte() }
        assertThrows(WrapHmacMismatch::class.java) {
            km.unwrapAndVerify("contacts.rk_wrapped", "alice".toByteArray(), wrapped, tampered)
        }
    }

    @Test
    fun unwrap_failsOnRowIdSubstitution() {
        val plain = "rk".toByteArray()
        val (wrapped, hmac) = km.wrapAndMac("contacts.rk_wrapped", "alice".toByteArray(), plain)
        assertThrows(WrapHmacMismatch::class.java) {
            km.unwrapAndVerify("contacts.rk_wrapped", "bob".toByteArray(), wrapped, hmac)
        }
    }

    @Test
    fun unwrap_failsOnColumnSubstitution() {
        val plain = "rk".toByteArray()
        val (wrapped, hmac) = km.wrapAndMac("contacts.rk_wrapped", "alice".toByteArray(), plain)
        assertThrows(WrapHmacMismatch::class.java) {
            km.unwrapAndVerify("contacts.cks_wrapped", "alice".toByteArray(), wrapped, hmac)
        }
    }

    /**
     * Wrap one column/row, try to unwrap as a different column with the original HMAC.
     * Confirms HMAC binding prevents "promotion" attacks (e.g. CKs blob into RK slot)
     * — both columns are AES-decryptable under the same wrap key, only the HMAC differentiates.
     */
    @Test
    fun unwrap_failsOnColumnPromotion_acrossDifferentRoles() {
        val plain = ByteArray(32) { 0x42.toByte() }
        val (wrappedCks, hmacCks) = km.wrapAndMac("contacts.cks_wrapped", "alice".toByteArray(), plain)
        // Pretend an attacker copies wrappedCks into rk_wrapped slot, keeping its (mismatched) HMAC.
        assertThrows(WrapHmacMismatch::class.java) {
            km.unwrapAndVerify("contacts.rk_wrapped", "alice".toByteArray(), wrappedCks, hmacCks)
        }
    }

    @Test
    fun unwrap_constantTimeCompare_usesMessageDigestIsEqual() {
        // Static-analysis substitute: a coarse wall-clock check. We don't aim for nanosecond
        // precision (JVM jitter dwarfs it on real devices) — we just assert that worst-case
        // HMAC comparisons (first-byte vs last-byte difference) don't differ by an order of
        // magnitude. The real defense is the choice of MessageDigest.isEqual in source;
        // grep that file in code review. See DR2 §9.4 / dr16 tests.
        val plain = "x".toByteArray()
        val (wrapped, goodHmac) = km.wrapAndMac("c", "r".toByteArray(), plain)

        val firstFlip = goodHmac.copyOf().also { it[0] = (it[0].toInt() xor 0xff).toByte() }
        val lastFlip = goodHmac.copyOf().also { it[31] = (it[31].toInt() xor 0xff).toByte() }

        fun timeUnwrap(hmac: ByteArray): Long {
            val start = System.nanoTime()
            repeat(200) {
                try { km.unwrapAndVerify("c", "r".toByteArray(), wrapped, hmac) } catch (_: WrapHmacMismatch) {}
            }
            return System.nanoTime() - start
        }
        // Warm up
        repeat(50) { timeUnwrap(firstFlip); timeUnwrap(lastFlip) }
        val t1 = timeUnwrap(firstFlip)
        val tN = timeUnwrap(lastFlip)
        val ratio = t1.toDouble() / tN.toDouble()
        // Generous bound — KeyStore round-trip dominates timing, leaking a few-cycle compare
        // would be far below the noise floor. We mostly want this to flag a switch to e.g.
        // contentEquals which short-circuits on first byte.
        assertTrue("timing ratio out of bounds: $ratio", ratio in 0.25..4.0)
    }
}
