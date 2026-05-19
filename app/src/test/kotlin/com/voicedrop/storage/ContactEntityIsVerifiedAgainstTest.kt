package com.voicedrop.storage

import com.voicedrop.crypto.Sas
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

class ContactEntityIsVerifiedAgainstTest {

    private val rng = SecureRandom()

    private fun pub(): ByteArray = ByteArray(32).also { rng.nextBytes(it) }

    private fun row(verifiedAt: Long? = null, hash: ByteArray? = null) = ContactEntity(
        id = "x",
        name = "x",
        publicKeyBase64 = "x",
        addedAt = 0L,
        verified_at = verifiedAt,
        verified_fp_pair_hash = hash,
    )

    @Test
    fun nullTimestamp_returnsFalse() {
        val my = pub(); val their = pub()
        assertFalse(row(verifiedAt = null, hash = Sas.fpPairBinding(my, their)).isVerifiedAgainst(my, their))
    }

    @Test
    fun nullHash_returnsFalse() {
        val my = pub(); val their = pub()
        assertFalse(row(verifiedAt = 1L, hash = null).isVerifiedAgainst(my, their))
    }

    @Test
    fun matchingBinding_returnsTrue() {
        val my = pub(); val their = pub()
        assertTrue(row(verifiedAt = 1L, hash = Sas.fpPairBinding(my, their)).isVerifiedAgainst(my, their))
    }

    @Test
    fun mismatchedBinding_returnsFalse() {
        val my = pub(); val their = pub(); val rotated = pub()
        val storedBinding = Sas.fpPairBinding(my, their)
        assertFalse(row(verifiedAt = 1L, hash = storedBinding).isVerifiedAgainst(my, rotated))
    }
}
