package com.voicedrop.crypto

import android.content.Context
import android.content.SharedPreferences
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.*
import org.junit.Before
import org.junit.Ignore
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@Ignore("AndroidKeyStore provider not available in Robolectric — move these to androidTest")
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class KeyManagerTest {

    private lateinit var keyManager: KeyManager

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        // Clear prefs for each test to force fresh key generation
        context.getSharedPreferences("voicedrop_keys", Context.MODE_PRIVATE)
            .edit().clear().commit()
        keyManager = KeyManager(context)
    }

    @Test
    fun publicKeyIsNonNull() {
        assertNotNull(keyManager.getPublicKeyBytes())
        assertEquals(32, keyManager.getPublicKeyBytes().size)
    }

    @Test
    fun fingerprintIs64HexChars() {
        val fp = keyManager.getFingerprint()
        assertEquals(64, fp.length)
        assertTrue(fp.all { it.isDigit() || it in 'a'..'f' })
    }

    @Test
    fun fingerprintIsDeterministic() {
        val fp1 = keyManager.getFingerprint()
        val fp2 = keyManager.getFingerprint()
        assertEquals(fp1, fp2)
    }

    @Test
    fun publicKeyBase64RoundTrip() {
        val b64 = keyManager.getPublicKeyBase64()
        val decoded = android.util.Base64.decode(b64, android.util.Base64.NO_WRAP)
        assertArrayEquals(keyManager.getPublicKeyBytes(), decoded)
    }

    @Test
    fun keyPersistsAcrossInstances() {
        val fp1 = keyManager.getFingerprint()
        val context = ApplicationProvider.getApplicationContext<Context>()
        val keyManager2 = KeyManager(context)
        assertEquals(fp1, keyManager2.getFingerprint())
    }
}
