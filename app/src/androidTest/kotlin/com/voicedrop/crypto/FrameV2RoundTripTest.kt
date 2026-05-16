package com.voicedrop.crypto

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.crypto.tink.subtle.X25519
import com.voicedrop.network.FrameCodec
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.ContactEntity
import com.voicedrop.storage.MessageEntity
import com.voicedrop.storage.PendingOutboundFrameEntity
import com.voicedrop.storage.TransportType
import java.security.KeyStore
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * DR17 §10.2 — `FrameV2RoundTripTest`.
 *
 * Drives the wire-v2 DATA + RECEIPT round-trip end-to-end with real
 * AndroidKeyStore-backed [KeyManager] and on-device Room. Mirrors
 * `PersistenceInvariantsTest`, which runs the same plumbing under Robolectric
 * with a synthetic [WrapMac]. Running here catches seams the JVM path stubs
 * out: KeyStore wrap budget, AES-GCM IV uniqueness from hardware RNG, real
 * coroutine ↔ Room transaction interleaving on Android.
 *
 *  Flow:
 *   1. Pair Alice + Bob via [Bootstrap].
 *   2. Alice [RatchetEncryptAndSend.encryptAndSend] one DATA frame.
 *   3. Bob [RatchetDecryptAndPersist.receive]s the wire bytes — ratchet advances,
 *      inbound message lands, RECEIPT is enqueued in Bob's outbox.
 *   4. Bob's RECEIPT wire bytes ride back; Alice decrypts → hand off to
 *      [ReceiptInboundHandler].
 *   5. Assert plaintext, ratchet convergence (alice.ns == bob.nr, bob.ns ==
 *      alice.nr), Alice's outbox empty, Alice's message DELIVERED.
 *
 * Uses two separate [AppDatabase] instances — one per party — so
 * `messages.uuid` (PRIMARY KEY) does not collide when the same wire UUID
 * lands as outbound on Alice and inbound on Bob. The shared [KeyManager] is
 * fine: KeyStore aliases are process-scoped and wraps are bound to
 * `(column, rowId)`, with Alice's `rowId = bobIdPubHex` distinct from Bob's
 * `rowId = aliceIdPubHex`.
 */
@RunWith(AndroidJUnit4::class)
class FrameV2RoundTripTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    private lateinit var aliceDb: AppDatabase
    private lateinit var bobDb: AppDatabase
    private lateinit var keyManager: KeyManager

    @Before
    fun setUp() {
        clearKeyStoreV2State()
        aliceDb = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        bobDb = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        keyManager = KeyManager(context)
        ContactMutexRegistry.clear()
    }

    @After
    fun tearDown() {
        aliceDb.close()
        bobDb.close()
        ContactMutexRegistry.clear()
        clearKeyStoreV2State()
    }

    /**
     * Drives the full DATA + RECEIPT cycle. End state must satisfy:
     *  - Bob's `messages` row has Alice's plaintext.
     *  - Bob's ratchet advanced (nr = 1) and emitted exactly one RECEIPT (ns = 1).
     *  - Alice's ratchet advanced on the RECEIPT (nr = 1).
     *  - Alice's outbox is empty (RECEIPT cleared the DATA row).
     *  - Alice's `messages` row state == DELIVERED.
     */
    @Test
    fun dataPlusReceipt_roundTrip_clearsOutbox_andMarksDelivered() = runBlocking {
        val pair = pairAliceAndBob()
        seedContact(aliceDb, pair.aliceRow)
        seedContact(bobDb, pair.bobRow)

        // ---- Alice → Bob: DATA ----
        val aliceTransmitted = mutableListOf<ByteArray>()
        val aliceSender = RatchetEncryptAndSend(
            aliceDb, keyManager, pair.aliceFingerprint
        ) { _, bytes -> aliceTransmitted += bytes }

        val payload = "voice-drop-2026".toByteArray()
        val sent = aliceSender.encryptAndSend(pair.aliceContactId, payload) { hex, _, now ->
            outboundMessage(hex, pair.aliceContactId, now)
        }
        assertEquals(0, sent.n)
        assertEquals(0, sent.pn)
        assertEquals("outbox carries the DATA row", 1,
            aliceDb.pendingOutboundFrameDao().countForContact(pair.aliceContactId))
        val aliceMsgAfterSend = aliceDb.messageDao().getByUuid(sent.frameUuidHex)
        assertNotNull(aliceMsgAfterSend)
        assertEquals(MessageEntity.DELIVERY_PENDING, aliceMsgAfterSend!!.delivery_state)
        val dataWire = aliceTransmitted.single()
        assertArrayEquals(sent.wireBytes, dataWire)

        // ---- Bob receives Alice's DATA ----
        val bobReceiver = RatchetDecryptAndPersist(bobDb, keyManager, pair.bobFingerprint)
        val dataDecoded = (FrameCodec.decode(dataWire) as FrameCodec.DecodeResult.Ok).frame
        val received = bobReceiver.receive(pair.bobContactId, dataDecoded) { pt, hex, _, ts ->
            inboundMessage(hex, pair.bobContactId, pt, ts)
        }
        assertTrue(received is RatchetDecryptAndPersist.Result.Delivered)
        val delivered = received as RatchetDecryptAndPersist.Result.Delivered
        assertArrayEquals("Bob recovers Alice's plaintext exactly", payload, delivered.plaintext)

        val bobContactAfter = bobDb.contactDao().getById(pair.bobContactId)!!
        assertEquals("Bob.nr advanced once on DATA", 1, bobContactAfter.nr)
        assertEquals("Bob.ns advanced once on the auto-enqueued RECEIPT", 1, bobContactAfter.ns)
        assertEquals("Bob's outbox holds the RECEIPT", 1,
            bobDb.pendingOutboundFrameDao().countForContact(pair.bobContactId))
        assertEquals(1, bobDb.messageDao().getByContactList(pair.bobContactId).size)

        // ---- Bob → Alice: RECEIPT ----
        val receiptRows = bobDb.pendingOutboundFrameDao().getByContact(pair.bobContactId)
        assertEquals(1, receiptRows.size)
        val receiptRow = receiptRows.single()
        assertEquals(PendingOutboundFrameEntity.FRAME_KIND_RECEIPT, receiptRow.frame_kind)
        val receiptWire = keyManager.unwrapAndVerify(
            "pending_outbound_frames.wrapped_frame",
            receiptRow.uuid,
            receiptRow.wrapped_frame,
            receiptRow.frame_hmac
        )

        // ---- Alice receives Bob's RECEIPT ----
        val aliceReceiver = RatchetDecryptAndPersist(aliceDb, keyManager, pair.aliceFingerprint)
        val receiptDecoded = (FrameCodec.decode(receiptWire) as FrameCodec.DecodeResult.Ok).frame
        val receiptResult = aliceReceiver.receive(pair.aliceContactId, receiptDecoded) { _, _, _, _ ->
            error("RECEIPT path must not invoke buildInboundMessage")
        }
        assertTrue(receiptResult is RatchetDecryptAndPersist.Result.ReceiptDecrypted)
        val ackedUuid = (receiptResult as RatchetDecryptAndPersist.Result.ReceiptDecrypted).ackedUuid
        assertArrayEquals(
            "RECEIPT payload references Alice's original frame UUID",
            sent.frameUuid, ackedUuid
        )

        // ---- Outbox closure ----
        val handler = ReceiptInboundHandler(aliceDb)
        val outcome = handler.onReceiptDecrypted(pair.aliceContactId, ackedUuid)
        assertEquals(ReceiptInboundHandler.Outcome.Delivered, outcome)

        // ---- Final assertions ----
        val aliceFinal = aliceDb.contactDao().getById(pair.aliceContactId)!!
        val bobFinal = bobDb.contactDao().getById(pair.bobContactId)!!

        assertEquals("Alice.nr advanced once on the RECEIPT", 1, aliceFinal.nr)
        assertEquals("Alice.ns still at 1 (one DATA sent, RECEIPT is a passive receive)",
            1, aliceFinal.ns)
        // Ratchet convergence: send-counter of one party matches receive-counter of the other.
        assertEquals("Alice.ns == Bob.nr", aliceFinal.ns, bobFinal.nr)
        assertEquals("Bob.ns == Alice.nr", bobFinal.ns, aliceFinal.nr)

        assertEquals("Alice's outbox is empty after RECEIPT", 0,
            aliceDb.pendingOutboundFrameDao().countForContact(pair.aliceContactId))
        val aliceMsgFinal = aliceDb.messageDao().getByUuid(sent.frameUuidHex)!!
        assertEquals("Alice's message marked DELIVERED",
            MessageEntity.DELIVERY_DELIVERED, aliceMsgFinal.delivery_state)
        assertTrue("Alice's deliveredAt stamped", aliceMsgFinal.deliveredAt > 0L)
    }

    // ---------------------------------------------------------------------
    // Fixtures
    // ---------------------------------------------------------------------

    private class Pair(
        val aliceContactId: String,
        val bobContactId: String,
        val aliceFingerprint: ByteArray,
        val bobFingerprint: ByteArray,
        val aliceRow: SeedRow,
        val bobRow: SeedRow
    )

    private class SeedRow(
        val contactId: String,
        val displayName: String,
        val peerIdPub: ByteArray,
        val initial: Bootstrap.InitialState
    )

    /** Loop until the local Alice role is decided in our favor — sender goes first. */
    private fun pairAliceAndBob(): Pair {
        lateinit var aPriv: ByteArray
        lateinit var aPub: ByteArray
        lateinit var bPriv: ByteArray
        lateinit var bPub: ByteArray
        while (true) {
            aPriv = X25519.generatePrivateKey()
            aPub = X25519.publicFromPrivate(aPriv)
            bPriv = X25519.generatePrivateKey()
            bPub = X25519.publicFromPrivate(bPriv)
            if (Bootstrap.decideRole(aPub, bPub) == Bootstrap.Role.ALICE) break
        }
        val aEphPriv = X25519.generatePrivateKey()
        val aEphPub = X25519.publicFromPrivate(aEphPriv)
        val bEphPriv = X25519.generatePrivateKey()
        val bEphPub = X25519.publicFromPrivate(bEphPriv)

        val aBoot = Bootstrap.computeInitialBootstrap(aPriv, aPub, bPub, aEphPriv, aEphPub, bEphPub)
        val bBoot = Bootstrap.computeInitialBootstrap(bPriv, bPub, aPub, bEphPriv, bEphPub, aEphPub)

        val aliceContactId = bPub.joinToString("") { "%02x".format(it) }
        val bobContactId = aPub.joinToString("") { "%02x".format(it) }
        return Pair(
            aliceContactId = aliceContactId,
            bobContactId = bobContactId,
            aliceFingerprint = Bootstrap.fingerprintBytes(aPub),
            bobFingerprint = Bootstrap.fingerprintBytes(bPub),
            aliceRow = SeedRow(aliceContactId, "Bob", bPub, aBoot),
            bobRow = SeedRow(bobContactId, "Alice", aPub, bBoot)
        )
    }

    private fun seedContact(db: AppDatabase, row: SeedRow) = runBlocking {
        val initial = ContactEntity(
            id = row.contactId,
            name = row.displayName,
            publicKeyBase64 = android.util.Base64.encodeToString(
                row.peerIdPub, android.util.Base64.NO_WRAP
            ),
            addedAt = 0L
        )
        val state = RatchetState.fromBootstrap(row.initial)
        val withState = RatchetStatePersistence.saveRatchetState(initial, state, keyManager)
        db.contactDao().upsert(withState)
    }

    private fun outboundMessage(uuidHex: String, contactId: String, now: Long): MessageEntity =
        MessageEntity(
            uuid = uuidHex,
            contactId = contactId,
            direction = MessageEntity.DIRECTION_OUTBOUND,
            state = MessageEntity.STATE_OUTBOX,
            transport = TransportType.UNKNOWN,
            encryptedFilePath = null,
            durationMs = 0,
            deleteAfterMs = 0L,
            scheduledDeleteAt = 0L,
            transcription = null,
            createdAt = now,
            sentAt = 0L,
            deliveredAt = 0L
        )

    private fun inboundMessage(
        uuidHex: String,
        contactId: String,
        plaintext: ByteArray,
        wireTimestampMs: Long
    ): MessageEntity =
        MessageEntity(
            uuid = uuidHex,
            contactId = contactId,
            direction = MessageEntity.DIRECTION_INBOUND,
            state = MessageEntity.STATE_DELIVERED,
            transport = TransportType.UNKNOWN,
            encryptedFilePath = null,
            durationMs = plaintext.size,
            deleteAfterMs = 0L,
            scheduledDeleteAt = 0L,
            transcription = null,
            createdAt = wireTimestampMs,
            sentAt = 0L,
            deliveredAt = wireTimestampMs
        )

    /** Erase the v2 wrap/MAC KeyStore aliases so each test starts from a clean slate. */
    private fun clearKeyStoreV2State() {
        context.getSharedPreferences("voicedrop_keys", Context.MODE_PRIVATE)
            .edit().clear().commit()
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        for (alias in listOf(
            KeyManager.KEYSTORE_ALIAS_WRAP_V2,
            KeyManager.KEYSTORE_ALIAS_MAC_V2
        )) {
            if (ks.containsAlias(alias)) ks.deleteEntry(alias)
        }
    }
}
