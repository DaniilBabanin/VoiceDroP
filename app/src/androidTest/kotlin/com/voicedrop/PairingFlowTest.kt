package com.voicedrop

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.crypto.tink.config.TinkConfig
import com.google.crypto.tink.subtle.X25519
import com.voicedrop.crypto.Bootstrap
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

/**
 * Post-DR17.5 pairing-flow coverage. The v1 ECDH session-key tests live in the
 * removed `RecordSendReceiveTest`; verification-emoji derivation now feeds off
 * `RK_0` from [Bootstrap.computeInitialBootstrap] — covered by [BootstrapTest]
 * in the unit-test tree.
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
    fun verificationCodeIsSymmetricAndFourBytes() {
        // DR17.5: SAS is now driven by RK_0 instead of the v1 ECDH session key.
        // Both sides arrive at the same RK_0 from Bootstrap.computeInitialBootstrap;
        // the symmetric-fingerprint sort inside computeVerificationCode keeps the
        // 4-byte SAS identical regardless of which side computes it.
        val alicePriv = aliceKeyManager.getPrivateKeyBytes()
        val alicePub = aliceKeyManager.getPublicKeyBytes()
        val aliceFp = ContactKey.fingerprint(alicePub)
        val bobPriv = X25519.generatePrivateKey()
        val bobPub = X25519.publicFromPrivate(bobPriv)
        val bobFp = ContactKey.fingerprint(bobPub)
        val bobEphPriv = X25519.generatePrivateKey()
        val bobEphPub = X25519.publicFromPrivate(bobEphPriv)
        val aliceEphPriv = X25519.generatePrivateKey()
        val aliceEphPub = X25519.publicFromPrivate(aliceEphPriv)

        val aliceInitial = Bootstrap.computeInitialBootstrap(
            myIdPriv = alicePriv, myIdPub = alicePub, peerIdPub = bobPub,
            myBootstrapEphPriv = aliceEphPriv, myBootstrapEphPub = aliceEphPub,
            peerBootstrapEphPub = bobEphPub
        )
        val bobInitial = Bootstrap.computeInitialBootstrap(
            myIdPriv = bobPriv, myIdPub = bobPub, peerIdPub = alicePub,
            myBootstrapEphPriv = bobEphPriv, myBootstrapEphPub = bobEphPub,
            peerBootstrapEphPub = aliceEphPub
        )
        assertArrayEquals("RK_0 must converge", aliceInitial.rootKey, bobInitial.rootKey)

        val codeFromAlice = ContactKey.computeVerificationCode(aliceInitial.rootKey, aliceFp, bobFp)
        val codeFromBob = ContactKey.computeVerificationCode(bobInitial.rootKey, bobFp, aliceFp)
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
