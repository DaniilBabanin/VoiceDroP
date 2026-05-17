package com.voicedrop.crypto

import com.google.crypto.tink.subtle.X25519
import com.voicedrop.storage.ContactEntity
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Regression for v1.2.0.7: `QrPairActivity.confirmPairing` used to inline
 * `wrapAndMac("rk", …)` / `wrapAndMac("dhs_priv", …)` while
 * [RatchetStatePersistence] read with `"contacts.rk_wrapped"` /
 * `"contacts.dhs_priv_wrapped"`. The binding HMAC covers the column name, so
 * every first send threw [WrapHmacMismatch] and both Alice's auto-HELLO and any
 * subsequent message died silently. Fix routes the first-pairing write through
 * [RatchetStatePersistence.saveRatchetState] so the column-name strings live in
 * one place.
 *
 * This test pins the round-trip: build a [Bootstrap.InitialState] from both
 * sides of a fresh pair, persist via `saveRatchetState`, reload via
 * `loadRatchetState`, and assert every populated field comes back byte-equal.
 * If anyone reintroduces a hardcoded column literal at either end, this fails.
 */
class BootstrapInsertPersistenceTest {

    @Test
    fun bootstrap_saveThenLoad_recoversRootKeyAndDhState() {
        val aPriv = X25519.generatePrivateKey()
        val aPub = X25519.publicFromPrivate(aPriv)
        val bPriv = X25519.generatePrivateKey()
        val bPub = X25519.publicFromPrivate(bPriv)
        val aEphPriv = X25519.generatePrivateKey()
        val aEphPub = X25519.publicFromPrivate(aEphPriv)
        val bEphPriv = X25519.generatePrivateKey()
        val bEphPub = X25519.publicFromPrivate(bEphPriv)

        val wrapMac = TestWrapMac()

        val sideA = Bootstrap.computeInitialBootstrap(
            myIdPriv = aPriv, myIdPub = aPub, peerIdPub = bPub,
            myBootstrapEphPriv = aEphPriv, myBootstrapEphPub = aEphPub,
            peerBootstrapEphPub = bEphPub
        )
        val sideB = Bootstrap.computeInitialBootstrap(
            myIdPriv = bPriv, myIdPub = bPub, peerIdPub = aPub,
            myBootstrapEphPriv = bEphPriv, myBootstrapEphPub = bEphPub,
            peerBootstrapEphPub = aEphPub
        )

        // Sanity: both peers derived the same RK_0, and the role flip is consistent.
        assertArrayEquals("RK_0 must agree across the pair", sideA.rootKey, sideB.rootKey)
        assertEquals(
            "exactly one side is Alice, the other Bob",
            setOf(Bootstrap.Role.ALICE, Bootstrap.Role.BOB),
            setOf(sideA.role, sideB.role)
        )

        assertRoundTripsCleanly(sideA, fingerprintHex(bPub), name = "Bob-as-seen-by-${sideA.role}", wrapMac = wrapMac)
        assertRoundTripsCleanly(sideB, fingerprintHex(aPub), name = "Alice-as-seen-by-${sideB.role}", wrapMac = wrapMac)
    }

    /**
     * Mirror of the QrPairActivity.confirmPairing insert path: build a base contact,
     * wrap via `saveRatchetState`, then load and assert every non-null field
     * survives byte-for-byte.
     */
    private fun assertRoundTripsCleanly(
        initial: Bootstrap.InitialState,
        peerFingerprint: String,
        name: String,
        wrapMac: WrapMac
    ) {
        val rkBefore = initial.rootKey.copyOf()
        val dhsPrivBefore = initial.dhsPriv?.copyOf()
        val dhsPubBefore = initial.dhsPub?.copyOf()
        val dhrPubBefore = initial.dhrPub?.copyOf()

        val base = ContactEntity(
            id = peerFingerprint,
            name = name,
            publicKeyBase64 = "",
            addedAt = 0L
        )
        val state = RatchetState(
            dhsPriv = initial.dhsPriv,
            dhsPub = initial.dhsPub,
            dhrPub = initial.dhrPub,
            rk = initial.rootKey
        )
        val saved = RatchetStatePersistence.saveRatchetState(base, state, wrapMac)

        val loaded = RatchetStatePersistence.loadRatchetState(saved, wrapMac)
        assertArrayEquals("$name: RK_0 must survive save→load", rkBefore, loaded.rk)
        if (dhsPrivBefore == null) {
            assertNull("$name: dhsPriv stays null", loaded.dhsPriv)
        } else {
            assertNotNull("$name: dhsPriv survives", loaded.dhsPriv)
            assertArrayEquals("$name: dhsPriv bytes", dhsPrivBefore, loaded.dhsPriv)
        }
        if (dhsPubBefore == null) {
            assertNull("$name: dhsPub stays null", loaded.dhsPub)
        } else {
            assertArrayEquals("$name: dhsPub bytes", dhsPubBefore, loaded.dhsPub)
        }
        if (dhrPubBefore == null) {
            assertNull("$name: dhrPub stays null", loaded.dhrPub)
        } else {
            assertArrayEquals("$name: dhrPub bytes", dhrPubBefore, loaded.dhrPub)
        }
    }

    private fun fingerprintHex(pub: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(pub).joinToString("") { "%02x".format(it) }

    /** Pure-JVM WrapMac mirroring KeyManager's binding-HMAC contract from DR2 §9. */
    private class TestWrapMac : WrapMac {
        private val wrapKey: SecretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        private val macKey: SecretKey = SecretKeySpec(ByteArray(32).also { SecureRandom().nextBytes(it) }, "HmacSHA256")

        override fun wrapAndMac(columnName: String, rowId: ByteArray, plain: ByteArray): Pair<ByteArray, ByteArray> {
            val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, wrapKey, GCMParameterSpec(128, iv))
            val ctAndTag = cipher.doFinal(plain)
            val wrapped = iv + ctAndTag
            val hmac = bindingHmac(columnName, rowId, wrapped)
            return wrapped to hmac
        }

        override fun unwrapAndVerify(columnName: String, rowId: ByteArray, wrapped: ByteArray, hmac: ByteArray): ByteArray {
            val expected = bindingHmac(columnName, rowId, wrapped)
            if (!MessageDigest.isEqual(expected, hmac)) throw WrapHmacMismatch()
            val iv = wrapped.copyOfRange(0, 12)
            val ctAndTag = wrapped.copyOfRange(12, wrapped.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, wrapKey, GCMParameterSpec(128, iv))
            return cipher.doFinal(ctAndTag)
        }

        private fun bindingHmac(column: String, rowId: ByteArray, wrapped: ByteArray): ByteArray =
            Mac.getInstance("HmacSHA256").run {
                init(macKey)
                update(column.toByteArray(Charsets.UTF_8))
                update(0x00.toByte())
                update(rowId)
                update(0x00.toByte())
                update(wrapped)
                doFinal()
            }
    }
}
