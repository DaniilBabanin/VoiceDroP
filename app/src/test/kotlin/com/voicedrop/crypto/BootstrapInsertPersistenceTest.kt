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
import org.junit.Assert.assertNotNull
import org.junit.Test
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Regression for v1.2.0.7: `QrPairActivity.confirmPairing` used to inline
 * `wrapAndMac("rk", …)` / `wrapAndMac("dhs_priv", …)` while
 * [RatchetStatePersistence] read with `"contacts.rk_wrapped"` /
 * `"contacts.dhs_priv_wrapped"`. The binding HMAC includes the column name, so
 * every first send threw [WrapHmacMismatch] and both Alice's auto-HELLO and any
 * subsequent message died silently. Fix routes the first-pairing write through
 * [RatchetStatePersistence.saveRatchetState] so the column-name strings live in
 * one place.
 *
 * This test pins the round-trip: build a [Bootstrap.InitialState] the way the
 * pairing flow does, persist via `saveRatchetState`, reload via
 * `loadRatchetState`, and assert the root key matches. If anyone reintroduces
 * a hardcoded column literal at either end, this fails.
 */
class BootstrapInsertPersistenceTest {

    @Test
    fun bootstrap_saveThenLoad_recoversRootKeyAndDhState() {
        val alicePriv = X25519.generatePrivateKey()
        val alicePub = X25519.publicFromPrivate(alicePriv)
        val bobPriv = X25519.generatePrivateKey()
        val bobPub = X25519.publicFromPrivate(bobPriv)
        val aliceEphPriv = X25519.generatePrivateKey()
        val aliceEphPub = X25519.publicFromPrivate(aliceEphPriv)
        val bobEphPriv = X25519.generatePrivateKey()
        val bobEphPub = X25519.publicFromPrivate(bobEphPriv)

        val wrapMac = TestWrapMac()

        // ALICE side — dhsPriv is null, dhrPub is bobEphPub.
        run {
            val initial = Bootstrap.computeInitialBootstrap(
                myIdPriv = alicePriv, myIdPub = alicePub, peerIdPub = bobPub,
                myBootstrapEphPriv = aliceEphPriv, myBootstrapEphPub = aliceEphPub,
                peerBootstrapEphPub = bobEphPub
            )
            val rkBefore = initial.rootKey.copyOf()
            val fingerprint = fingerprintHex(bobPub)
            val base = ContactEntity(id = fingerprint, name = "Bob", publicKeyBase64 = "", addedAt = 0L)
            val state = RatchetState(
                dhsPriv = initial.dhsPriv,
                dhsPub = initial.dhsPub,
                dhrPub = initial.dhrPub,
                rk = initial.rootKey
            )
            val saved = RatchetStatePersistence.saveRatchetState(base, state, wrapMac)

            val loaded = RatchetStatePersistence.loadRatchetState(saved, wrapMac)
            assertArrayEquals("RK_0 must survive save→load round trip (Alice)", rkBefore, loaded.rk)
            assertNotNull("Alice keeps peer DH pub", loaded.dhrPub)
            assertArrayEquals(bobEphPub, loaded.dhrPub)
        }

        // BOB side — dhsPriv is bobEphPriv, dhrPub is null.
        run {
            val initial = Bootstrap.computeInitialBootstrap(
                myIdPriv = bobPriv, myIdPub = bobPub, peerIdPub = alicePub,
                myBootstrapEphPriv = bobEphPriv, myBootstrapEphPub = bobEphPub,
                peerBootstrapEphPub = aliceEphPub
            )
            val rkBefore = initial.rootKey.copyOf()
            val dhsPrivBefore = initial.dhsPriv!!.copyOf()
            val fingerprint = fingerprintHex(alicePub)
            val base = ContactEntity(id = fingerprint, name = "Alice", publicKeyBase64 = "", addedAt = 0L)
            val state = RatchetState(
                dhsPriv = initial.dhsPriv,
                dhsPub = initial.dhsPub,
                dhrPub = initial.dhrPub,
                rk = initial.rootKey
            )
            val saved = RatchetStatePersistence.saveRatchetState(base, state, wrapMac)

            val loaded = RatchetStatePersistence.loadRatchetState(saved, wrapMac)
            assertArrayEquals("RK_0 must survive save→load round trip (Bob)", rkBefore, loaded.rk)
            assertNotNull("Bob keeps DH priv", loaded.dhsPriv)
            assertArrayEquals(dhsPrivBefore, loaded.dhsPriv)
            assertArrayEquals(bobEphPub, loaded.dhsPub)
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
