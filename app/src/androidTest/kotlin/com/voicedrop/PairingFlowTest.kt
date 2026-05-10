package com.voicedrop

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.crypto.tink.config.TinkConfig
import com.google.crypto.tink.subtle.X25519
import com.voicedrop.crypto.ContactKey
import com.voicedrop.crypto.KeyManager
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.ContactEntity
import com.voicedrop.storage.MessageRepository
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class PairingFlowTest {

    private lateinit var context: Context
    private lateinit var aliceKeyManager: KeyManager
    private lateinit var db: AppDatabase
    private lateinit var repository: MessageRepository

    @Before
    fun setUp() {
        TinkConfig.register()
        context = ApplicationProvider.getApplicationContext()
        context.getSharedPreferences("voicedrop_keys", Context.MODE_PRIVATE)
            .edit().clear().commit()
        aliceKeyManager = KeyManager(context)
        db = androidx.room.Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        repository = MessageRepository(db.contactDao(), db.messageDao(), db.pendingActionDao())
    }

    @After
    fun tearDown() {
        db.close()
    }

    @Test
    fun sessionKeyDerivationIsSymmetric() {
        val alicePriv = aliceKeyManager.getPrivateKeyBytes()
        val alicePub = aliceKeyManager.getPublicKeyBytes()
        val bobPriv = X25519.generatePrivateKey()
        val bobPub = X25519.publicFromPrivate(bobPriv)

        // Both sides call deriveSessionKey(myPrivate, theirPublic) — HKDF sorts fingerprints so results match
        val keyFromAlice = ContactKey.deriveSessionKey(alicePriv, bobPub)
        val keyFromBob = ContactKey.deriveSessionKey(bobPriv, alicePub)

        assertArrayEquals(keyFromAlice, keyFromBob)
    }

    @Test
    fun verificationCodeIsSymmetricAndFourBytes() {
        val alicePriv = aliceKeyManager.getPrivateKeyBytes()
        val alicePub = aliceKeyManager.getPublicKeyBytes()
        val aliceFp = ContactKey.fingerprint(alicePub)
        val bobPriv = X25519.generatePrivateKey()
        val bobPub = X25519.publicFromPrivate(bobPriv)
        val bobFp = ContactKey.fingerprint(bobPub)

        val sessionKey = ContactKey.deriveSessionKey(alicePriv, bobPub)

        // Both sides compute verification code from session key + fingerprints in any order
        val codeFromAlice = ContactKey.computeVerificationCode(sessionKey, aliceFp, bobFp)
        val codeFromBob = ContactKey.computeVerificationCode(sessionKey, bobFp, aliceFp)

        assertArrayEquals(codeFromAlice, codeFromBob)
        assertEquals(4, codeFromAlice.size)
    }

    @Test
    fun pairingStoresContactInDb() = runBlocking {
        val alicePub = aliceKeyManager.getPublicKeyBytes()
        val aliceFp = aliceKeyManager.getFingerprint()

        val contact = ContactEntity(
            id = aliceFp,
            name = "Alice",
            publicKeyBase64 = android.util.Base64.encodeToString(alicePub, android.util.Base64.NO_WRAP),
            sharedSecretWrapped = ByteArray(32),
            addedAt = System.currentTimeMillis()
        )
        repository.upsertContact(contact)

        val contacts = repository.getAllContacts().first()
        assertEquals(1, contacts.size)
        assertEquals(aliceFp, contacts[0].id)
    }

    @Test
    fun fingerprintIs64HexChars() {
        val fp = aliceKeyManager.getFingerprint()
        assertEquals(64, fp.length)
        assertTrue(fp.all { it.isDigit() || it in 'a'..'f' })
    }
}
