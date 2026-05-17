package com.voicedrop.crypto

import com.google.crypto.tink.subtle.X25519
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Test

/**
 * DR17.6 — protocol-level invariant the activity's "don't regenerate the bootstrap
 * ephemeral mid-pairing" rule protects.
 *
 * Pure JVM (no Android, no KeyManager) so it runs under the project's existing
 * unit-test config. The activity-level state-machine assertions live in the manual
 * two-device sequence in dr18-manual-tests.md because KeyManager can't run under
 * Robolectric (AndroidKeyStore is not available — see KeyManagerTest.@Ignore).
 */
class BootstrapStableEphRk0Test {

    @Test
    fun sameEphPair_yieldsSameRk0_acrossRepeatedCalls() {
        // Bob keeps the same bootstrap eph across two `computeInitialBootstrap`
        // calls for the same Alice identity pair → RK_0 must be byte-for-byte
        // identical. The bug DR17.6 fixes was the activity re-minting Bob's eph
        // between the two halves of the dance, producing a different RK_0.
        val aIdPriv = X25519.generatePrivateKey()
        val bIdPriv = X25519.generatePrivateKey()
        val aIdPub = X25519.publicFromPrivate(aIdPriv)
        val bIdPub = X25519.publicFromPrivate(bIdPriv)

        val aEphPriv = X25519.generatePrivateKey()
        val aEphPub = X25519.publicFromPrivate(aEphPriv)
        val bEphPriv = X25519.generatePrivateKey()
        val bEphPub = X25519.publicFromPrivate(bEphPriv)

        val first = Bootstrap.computeInitialBootstrap(
            myIdPriv = aIdPriv, myIdPub = aIdPub, peerIdPub = bIdPub,
            myBootstrapEphPriv = aEphPriv, myBootstrapEphPub = aEphPub,
            peerBootstrapEphPub = bEphPub
        )
        val second = Bootstrap.computeInitialBootstrap(
            myIdPriv = aIdPriv, myIdPub = aIdPub, peerIdPub = bIdPub,
            myBootstrapEphPriv = aEphPriv, myBootstrapEphPub = aEphPub,
            peerBootstrapEphPub = bEphPub
        )
        assertArrayEquals(
            "RK_0 must be stable for fixed (identities × eph pair)",
            first.rootKey, second.rootKey
        )
    }

    @Test
    fun differentBobEph_yieldsDifferentRk0_forSameIdentityPair() {
        // Same Alice identity pair, two different Bob ephs → two distinct RK_0s.
        // This is the regression the bug exhibited: the UI re-minted Bob's eph on
        // the second `onCreate`, so Alice's second-half scan saw a different bep
        // and computed a non-matching RK_0.
        val aIdPriv = X25519.generatePrivateKey()
        val bIdPriv = X25519.generatePrivateKey()
        val aIdPub = X25519.publicFromPrivate(aIdPriv)
        val bIdPub = X25519.publicFromPrivate(bIdPriv)

        val aEphPriv = X25519.generatePrivateKey()
        val aEphPub = X25519.publicFromPrivate(aEphPriv)

        val bEphPriv1 = X25519.generatePrivateKey()
        val bEphPub1 = X25519.publicFromPrivate(bEphPriv1)
        val bEphPriv2 = X25519.generatePrivateKey()
        val bEphPub2 = X25519.publicFromPrivate(bEphPriv2)
        assertFalse("test setup: bep1 and bep2 must differ", bEphPub1.contentEquals(bEphPub2))

        val withBep1 = Bootstrap.computeInitialBootstrap(
            myIdPriv = aIdPriv, myIdPub = aIdPub, peerIdPub = bIdPub,
            myBootstrapEphPriv = aEphPriv, myBootstrapEphPub = aEphPub,
            peerBootstrapEphPub = bEphPub1
        )
        val withBep2 = Bootstrap.computeInitialBootstrap(
            myIdPriv = aIdPriv, myIdPub = aIdPub, peerIdPub = bIdPub,
            myBootstrapEphPriv = aEphPriv, myBootstrapEphPub = aEphPub,
            peerBootstrapEphPub = bEphPub2
        )
        assertFalse(
            "RK_0 must differ across Bob ephs — this is the bug DR17.6 fixes at the UI layer",
            withBep1.rootKey.contentEquals(withBep2.rootKey)
        )
    }
}
