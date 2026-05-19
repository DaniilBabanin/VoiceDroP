package com.voicedrop.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

class SasTest {

    private fun randPub(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

    @Test
    fun codeFor_isSymmetricAcrossArgumentOrder() {
        val a = randPub()
        val b = randPub()
        assertEquals(Sas.codeFor(a, b), Sas.codeFor(b, a))
    }

    @Test
    fun codeFor_isDeterministic() {
        val a = randPub()
        val b = randPub()
        val first = Sas.codeFor(a, b)
        repeat(4) {
            assertEquals(first, Sas.codeFor(a, b))
        }
    }

    @Test
    fun codeFor_returnsSixEmojis() {
        val code = Sas.codeFor(randPub(), randPub())
        assertEquals(6, code.size)
        assertTrue("each entry must be a non-empty emoji string", code.all { it.isNotEmpty() })
    }

    @Test
    fun codeFor_isDistinctUnderSingleBitFlip() {
        // 1000 random pairs; each pair, flip 1 bit of one input, expect the code differs.
        // Probabilistic: a 48-bit code has 2^-48 collision probability per draw — zero
        // collisions across 1000 trials is the expectation.
        val rng = SecureRandom()
        var collisions = 0
        repeat(1000) {
            val a = ByteArray(32).also { rng.nextBytes(it) }
            val b = ByteArray(32).also { rng.nextBytes(it) }
            val original = Sas.codeFor(a, b)
            val mutated = a.copyOf().also { it[0] = (it[0].toInt() xor 0x01).toByte() }
            if (original == Sas.codeFor(mutated, b)) collisions++
        }
        assertEquals("48-bit code should not collide on bit-flip across 1000 trials", 0, collisions)
    }

    @Test
    fun codeFor_vectorPin() {
        // Regression guard. Bumping the derivation tag (v1 → v2) requires updating this vector.
        // Inputs are two synthetic X25519 public keys (NOT real keys — just deterministic byte
        // sequences) chosen so the test is reproducible without RNG.
        val idPubA = ByteArray(32) { it.toByte() }                          // 0x00..0x1F
        val idPubB = ByteArray(32) { (it + 32).toByte() }                   // 0x20..0x3F
        val code = Sas.codeFor(idPubA, idPubB)
        val expected = listOf("🚁", "🐝", "🏎", "🦃", "🐈", "🐉")
        assertEquals(expected, code)
    }

    @Test
    fun fpPairBinding_isSixteenBytesSymmetricAndDeterministic() {
        val a = randPub()
        val b = randPub()
        val ab = Sas.fpPairBinding(a, b)
        val ba = Sas.fpPairBinding(b, a)
        assertEquals(16, ab.size)
        assertArrayEquals(ab, ba)
        assertArrayEquals(ab, Sas.fpPairBinding(a, b))
    }

    @Test
    fun fpPairBinding_isDistinctForDistinctKeys() {
        val a = randPub()
        val b = randPub()
        val c = randPub()
        assertNotEquals(Sas.fpPairBinding(a, b).toList(), Sas.fpPairBinding(a, c).toList())
    }
}
