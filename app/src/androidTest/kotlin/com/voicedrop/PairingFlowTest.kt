package com.voicedrop

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.crypto.tink.config.TinkConfig
import com.google.crypto.tink.subtle.X25519
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

/**
 * Post-§3.1 pairing-flow coverage. SAS derivation is identity-keyed via [Sas.codeFor]
 * and tested independently by [com.voicedrop.crypto.SasTest]; this file covers the
 * surrounding Room/contact persistence side of pairing.
 */
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
    fun sasCodeIsSymmetricAndSixEmojisIdentityKeyed() {
        // §3.1 — SAS is keyed off identity public keys, not RK_0. Both sides arrive at
        // identical emojis regardless of role and regardless of the ratchet state.
        // Pure-derivation test — no bootstrap call needed; SasTest covers the full
        // property matrix, this guards the integration shape.
        val alicePub = aliceKeyManager.getPublicKeyBytes()
        val bobPriv = X25519.generatePrivateKey()
        val bobPub = X25519.publicFromPrivate(bobPriv)

        val codeFromAlice = com.voicedrop.crypto.Sas.codeFor(alicePub, bobPub)
        val codeFromBob = com.voicedrop.crypto.Sas.codeFor(bobPub, alicePub)
        assertEquals(codeFromAlice, codeFromBob)
        assertEquals(6, codeFromAlice.size)
        assertTrue(codeFromAlice.all { it.isNotEmpty() })
    }

    @Test
    fun pairingStoresContactInDb() = runBlocking {
        val alicePub = aliceKeyManager.getPublicKeyBytes()
        val aliceFp = aliceKeyManager.getFingerprint()

        val contact = ContactEntity(
            id = aliceFp,
            name = "Alice",
            publicKeyBase64 = android.util.Base64.encodeToString(alicePub, android.util.Base64.NO_WRAP),
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
