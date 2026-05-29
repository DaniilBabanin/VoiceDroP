package com.voicedrop.network

import com.google.crypto.tink.subtle.X25519
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class PullAuthTest {

    private fun hex(s: String): ByteArray =
        s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun hex(b: ByteArray): String =
        b.joinToString("") { "%02x".format(it) }

    private val identityPriv = hex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
    private val serverPriv   = hex("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40")
    private val nonce        = hex("000102030405060708090a0b0c0d0e0f")

    // Property 1: client mac (identityPriv, serverPub) == server mac (serverPriv, identityPub)
    @Test fun proof_is_symmetric_across_dh_sides() {
        val identityPub = X25519.publicFromPrivate(identityPriv)
        val serverPub = X25519.publicFromPrivate(serverPriv)
        val fp = PullAuth.fingerprintBytes(identityPub)

        val clientMac = PullAuth.computeProofMac(identityPriv, serverPub, nonce, fp)
        // Recompute as the server would: ss = X25519(serverPriv, identityPub)
        val ssServer = X25519.computeSharedSecret(serverPriv, identityPub)
        val serverMac = PullAuth.macWithKey(ssServer, nonce, fp)

        assertArrayEquals(clientMac, serverMac)
    }

    // Property 2: a different nonce yields a different mac
    @Test fun mac_changes_with_nonce() {
        val serverPub = X25519.publicFromPrivate(serverPriv)
        val identityPub = X25519.publicFromPrivate(identityPriv)
        val fp = PullAuth.fingerprintBytes(identityPub)
        val m1 = PullAuth.computeProofMac(identityPriv, serverPub, nonce, fp)
        val m2 = PullAuth.computeProofMac(identityPriv, serverPub, hex("0f0e0d0c0b0a09080706050403020100"), fp)
        assertFalse(m1.contentEquals(m2))
    }

    // Golden cross-language vector — frozen in BOTH this test and worker test/auth.spec.ts.
    // Un-skip after Task A1 Step 6 prints the values into Part 0.
    @org.junit.Ignore("fill GOLDEN_MAC from Task A1 Step 6, then remove @Ignore")
    @Test fun golden_vector() {
        val serverPub = X25519.publicFromPrivate(serverPriv)
        val identityPub = X25519.publicFromPrivate(identityPriv)
        val fp = PullAuth.fingerprintBytes(identityPub)
        val mac = PullAuth.computeProofMac(identityPriv, serverPub, nonce, fp)
        assertEquals("FILL_GOLDEN_MAC_HEX", hex(mac))
    }
}
