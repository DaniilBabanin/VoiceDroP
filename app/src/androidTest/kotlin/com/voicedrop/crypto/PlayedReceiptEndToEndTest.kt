package com.voicedrop.crypto

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.crypto.tink.config.TinkConfig
import com.google.crypto.tink.subtle.X25519
import com.voicedrop.network.FrameCodec
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.ContactEntity
import com.voicedrop.storage.MessageEntity
import com.voicedrop.storage.PrekeyEpochEntity
import com.voicedrop.storage.TransportType
import java.nio.ByteBuffer
import java.security.KeyStore
import java.util.UUID
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Spec `16-played-receipt.md` §2 — end-to-end coverage for the KIND_PLAYED wire
 * path: codec → ratchet AEAD → [PlayedInboundHandler] → SQL state flip.
 *
 * **Scope:** wire format + ratchet pipe + handler SQL invariants. Not covered:
 * [ConnectionManager] wiring (exercised by `dr18-manual-tests.md`). This
 * deliberate scope reduction keeps the harness minimal and avoids coupling the
 * test to the full service stack.
 *
 * **Harness design:** mirrors [Pcs_E2eTest] exactly — two [Side] objects, each
 * with an independent in-memory Room database, a shared [KeyManager], and
 * X25519 identity keypairs generated directly. Bootstrap pairing uses the same
 * [Bootstrap.computeInitialBootstrap] dance. The [PlayedInboundHandler] is
 * invoked manually after [RatchetDecryptAndPersist.receive] yields the
 * plaintext, simulating the `postDeliveredSideEffects` call that production
 * code makes after the mutex is released.
 *
 * **Test 2 / idempotency:** [PlayedInboundHandlerTest] already exercises
 * `played→played noop` exhaustively at the unit level. Rather than duplicate
 * that test here with a heavier wire harness, we retain only the two tests
 * that require real ratchet crypto: the primary wire path and the
 * DELETED-state guard.
 */
@RunWith(AndroidJUnit4::class)
class PlayedReceiptEndToEndTest {

    companion object {
        @BeforeClass
        @JvmStatic
        fun setUpClass() {
            TinkConfig.register()
        }
    }

    /**
     * One side of the two-party fixture. Mirrors [Pcs_E2eTest.Side].
     *
     * [contactId] is the peer's fingerprint hex (how this side labels the
     * contact row in its own DB). [peerPub] is the peer's identity public key.
     */
    private data class Side(
        val db: AppDatabase,
        val km: KeyManager,
        val idPriv: ByteArray,
        val idPub: ByteArray,
        /** fingerprintHex(peerPub) — key used to address the peer in our DB. */
        val contactId: String,
        val peerPub: ByteArray
    )

    private lateinit var ctx: Context
    private lateinit var km: KeyManager
    private lateinit var alice: Side
    private lateinit var bob: Side

    @Before
    fun setUp() {
        ctx = ApplicationProvider.getApplicationContext()
        clearKeyStoreV2State()
        km = KeyManager(ctx)
        ContactMutexRegistry.clear()
    }

    @After
    fun tearDown() {
        if (::alice.isInitialized) alice.db.close()
        if (::bob.isInitialized) bob.db.close()
        ContactMutexRegistry.clear()
        clearKeyStoreV2State()
    }

    // =========================================================================
    // 1. voice_then_played_flips_outbound_state_to_played  (primary path)
    // =========================================================================

    /**
     * Primary wire-path regression guard:
     *
     *   1. Bootstrap Alice and Bob.
     *   2. Seed an outbound row in Alice's DB at STATE_DELIVERED with a known UUID.
     *   3. Bob encodes a KIND_PLAYED frame referencing the same UUID and encrypts
     *      it via [RatchetEncryptAndSend.encryptAndSend].
     *   4. Alice decrypts via [RatchetDecryptAndPersist.receive]; the callback
     *      parses the inner plaintext and invokes [PlayedInboundHandler].
     *   5. Assert Alice's row is now STATE_PLAYED.
     *
     * Wire bytes are taken directly from [SentFrame.wireBytes] — no DB extraction
     * needed since [RatchetEncryptAndSend] returns them synchronously.
     */
    @Test
    fun voice_then_played_flips_outbound_state_to_played() = runBlocking {
        pairAliceAndBob()

        // Shared UUID: outbound row on Alice's side uses the 32-char hex form;
        // Bob constructs the KIND_PLAYED payload using the same 16 bytes as UUID.
        val (hex32, targetUuid) = uuidPair(0xAB.toByte())

        // Seed Alice's outbound row in STATE_DELIVERED.
        seedOutboundMessage(alice.db, hex32, alice.contactId, MessageEntity.STATE_DELIVERED, 1500L)

        // Bob builds a KIND_PLAYED frame and encrypts it for Alice.
        val bobEnc = makeEncryptor(bob)
        val playedPayload = MessagePayload.encodePlayed(targetUuid)
        val sent = bobEnc.encryptAndSend(bob.contactId, playedPayload) { _, _, _ -> null }

        // Alice decrypts; callback drives the handler.
        val aliceDec = makeDecryptor(alice)
        val handlerRef = PlayedInboundHandler(alice.db)
        val aliceContactId = alice.contactId   // Bob's fp as seen from Alice = alice.contactId

        var capturedTargetUuid: UUID? = null
        val result = aliceDec.receive(
            alice.contactId,
            (FrameCodec.decode(sent.wireBytes) as FrameCodec.DecodeResult.Ok).frame
        ) { plaintext, _, _, _ ->
            val parsed = MessagePayload.parse(plaintext)
            assertTrue("inner plaintext must be Parsed.Played", parsed is MessagePayload.Parsed.Played)
            capturedTargetUuid = (parsed as MessagePayload.Parsed.Played).targetUuid
            // KIND_PLAYED frames do not create an inbound message row.
            null
        }

        assertTrue("receive must deliver the frame", result is RatchetDecryptAndPersist.Result.Delivered)
        // Mutex is now released — safe to call handler (mirrors postDeliveredSideEffects).
        val handlerOutcome = handlerRef.onPlayedDecrypted(aliceContactId, capturedTargetUuid!!)
        assertSame("handler must return Played", PlayedInboundHandler.Outcome.Played, handlerOutcome)

        val row = alice.db.messageDao().getByUuid(hex32)
        assertEquals("outbound row must be STATE_PLAYED", MessageEntity.STATE_PLAYED, row!!.state)
    }

    // =========================================================================
    // 2. played_does_not_resurrect_deleted_row  (DELETED race / SQL guard)
    // =========================================================================

    /**
     * SQL guard: the `markPlayedBlocking` UPDATE predicate includes
     * `state IN (STATE_SENT, STATE_DELIVERED)`, so a DELETED row is not
     * resurrected. This mirrors the full wire round-trip shape of test 1 to
     * exercise the same SQL path with a different seed state.
     *
     * The idempotency case (played→played noop) is intentionally skipped here
     * because [PlayedInboundHandlerTest.played_to_played_is_noop_returns_NoChange]
     * covers it at the unit level; adding an E2E wire round-trip for it would
     * only duplicate that coverage without adding signal.
     */
    @Test
    fun played_does_not_resurrect_deleted_row() = runBlocking {
        pairAliceAndBob()

        val (hex32, targetUuid) = uuidPair(0xCD.toByte())

        // Alice's row is already in STATE_DELETED (e.g. the user deleted before PLAYED arrived).
        seedOutboundMessage(alice.db, hex32, alice.contactId, MessageEntity.STATE_DELETED, 1500L)

        // Bob still sends a KIND_PLAYED frame.
        val bobEnc = makeEncryptor(bob)
        val playedPayload = MessagePayload.encodePlayed(targetUuid)
        val sent = bobEnc.encryptAndSend(bob.contactId, playedPayload) { _, _, _ -> null }

        // Alice decrypts and invokes the handler.
        val aliceDec = makeDecryptor(alice)
        val handlerRef = PlayedInboundHandler(alice.db)
        val aliceContactId = alice.contactId

        var capturedTargetUuid: UUID? = null
        val result = aliceDec.receive(
            alice.contactId,
            (FrameCodec.decode(sent.wireBytes) as FrameCodec.DecodeResult.Ok).frame
        ) { plaintext, _, _, _ ->
            val parsed = MessagePayload.parse(plaintext)
            assertTrue("inner plaintext must be Parsed.Played", parsed is MessagePayload.Parsed.Played)
            capturedTargetUuid = (parsed as MessagePayload.Parsed.Played).targetUuid
            null
        }

        assertTrue("receive must deliver the frame", result is RatchetDecryptAndPersist.Result.Delivered)
        // Mutex is now released — safe to call handler (mirrors postDeliveredSideEffects).
        val handlerOutcome = handlerRef.onPlayedDecrypted(aliceContactId, capturedTargetUuid!!)
        assertSame("handler must return NoChange for DELETED row", PlayedInboundHandler.Outcome.NoChange, handlerOutcome)

        val row = alice.db.messageDao().getByUuid(hex32)
        assertEquals("DELETED row must remain STATE_DELETED", MessageEntity.STATE_DELETED, row!!.state)
    }

    // =========================================================================
    // Fixtures and helpers
    // =========================================================================

    /** Clear AndroidKeyStore wrap/MAC aliases between tests to avoid key collisions. */
    private fun clearKeyStoreV2State() {
        ctx.getSharedPreferences("voicedrop_keys", Context.MODE_PRIVATE)
            .edit().clear().commit()
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        for (alias in listOf(
            KeyManager.KEYSTORE_ALIAS_WRAP_V2,
            KeyManager.KEYSTORE_ALIAS_MAC_V2
        )) {
            if (ks.containsAlias(alias)) ks.deleteEntry(alias)
        }
    }

    /**
     * Bootstrap Alice and Bob in-process. Mirrors [Pcs_E2eTest.pairAliceAndBob].
     * Each side gets an independent in-memory Room DB; both share [km] for
     * wrap-and-MAC (row bindings are differentiated by contactId-derived rowIds).
     */
    private fun pairAliceAndBob() {
        // Generate identity keypairs; ensure Bootstrap.decideRole(aPub, bPub) == ALICE.
        var aPriv: ByteArray; var aPub: ByteArray
        var bPriv: ByteArray; var bPub: ByteArray
        while (true) {
            aPriv = X25519.generatePrivateKey()
            aPub = X25519.publicFromPrivate(aPriv)
            bPriv = X25519.generatePrivateKey()
            bPub = X25519.publicFromPrivate(bPriv)
            if (Bootstrap.decideRole(aPub, bPub) == Bootstrap.Role.ALICE) break
        }

        // Bob-role generates the bootstrap ephemeral.
        val bobBootstrapEphPriv = X25519.generatePrivateKey()
        val bobBootstrapEphPub = X25519.publicFromPrivate(bobBootstrapEphPriv)

        val aliceState = Bootstrap.computeInitialBootstrap(
            myIdPriv = aPriv,
            myIdPub = aPub,
            peerIdPub = bPub,
            myBootstrapEphPriv = ByteArray(32),
            myBootstrapEphPub = ByteArray(32),
            peerBootstrapEphPub = bobBootstrapEphPub
        )
        val bobState = Bootstrap.computeInitialBootstrap(
            myIdPriv = bPriv,
            myIdPub = bPub,
            peerIdPub = aPub,
            myBootstrapEphPriv = bobBootstrapEphPriv,
            myBootstrapEphPub = bobBootstrapEphPub,
            peerBootstrapEphPub = ByteArray(32)
        )

        check(aliceState.rootKey.contentEquals(bobState.rootKey)) {
            "RK_0 mismatch after bootstrap — fixture bug"
        }

        val aFpHex = Bootstrap.fingerprintBytes(aPub).joinToString("") { "%02x".format(it) }
        val bFpHex = Bootstrap.fingerprintBytes(bPub).joinToString("") { "%02x".format(it) }

        val alicePrekey = Prekey.generate()
        val bobPrekey = Prekey.generate()

        // Alice's DB: she addresses Bob by bFpHex.
        val aliceDb = Room.inMemoryDatabaseBuilder(ctx, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        insertBootstrappedContactRow(aliceDb, bFpHex, bPub, aliceState)
        insertActiveEpoch0(aliceDb, bFpHex, alicePrekey, bobPrekey.pub)

        // Bob's DB: he addresses Alice by aFpHex.
        val bobDb = Room.inMemoryDatabaseBuilder(ctx, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        insertBootstrappedContactRow(bobDb, aFpHex, aPub, bobState)
        insertActiveEpoch0(bobDb, aFpHex, bobPrekey, alicePrekey.pub)

        alice = Side(
            db = aliceDb, km = km,
            idPriv = aPriv, idPub = aPub,
            contactId = bFpHex, peerPub = bPub
        )
        bob = Side(
            db = bobDb, km = km,
            idPriv = bPriv, idPub = bPub,
            contactId = aFpHex, peerPub = aPub
        )

        alicePrekey.priv.fill(0)
        bobPrekey.priv.fill(0)
        bobBootstrapEphPriv.fill(0)
    }

    /** Construct a [RatchetEncryptAndSend] for [side]. transmit is a no-op; wire bytes live in [SentFrame.wireBytes]. */
    private fun makeEncryptor(side: Side): RatchetEncryptAndSend {
        val ownFp = Bootstrap.fingerprintBytes(side.idPub)
        return RatchetEncryptAndSend(
            db = side.db,
            wrapMac = km,
            ownFingerprint32 = ownFp,
            transmit = { _, _ -> }
        )
    }

    /** Construct a [RatchetDecryptAndPersist] for [side]. */
    private fun makeDecryptor(side: Side): RatchetDecryptAndPersist {
        val ownFp = Bootstrap.fingerprintBytes(side.idPub)
        return RatchetDecryptAndPersist(
            db = side.db,
            wrapMac = km,
            ownFingerprint32 = ownFp
        )
    }

    /**
     * Insert a contact row with a real bootstrapped [Bootstrap.InitialState].
     * Mirrors [Pcs_E2eTest.insertBootstrappedContactRow].
     */
    private fun insertBootstrappedContactRow(
        db: AppDatabase,
        contactId: String,
        peerIdPub: ByteArray,
        state: Bootstrap.InitialState
    ) = runBlocking {
        val rowId = contactId.toByteArray(Charsets.UTF_8)
        val (rkW, rkH) = km.wrapAndMac("contacts.rk_wrapped", rowId, state.rootKey)

        val (dhsPrivW, dhsPrivH) = state.dhsPriv?.let {
            km.wrapAndMac("contacts.dhs_priv_wrapped", rowId, it)
        } ?: (null to null)

        db.contactDao().upsert(
            ContactEntity(
                id = contactId,
                name = "peer",
                publicKeyBase64 = android.util.Base64.encodeToString(peerIdPub, android.util.Base64.NO_WRAP),
                addedAt = 0L,
                rk_wrapped = rkW,
                rk_hmac = rkH,
                dhs_priv_wrapped = dhsPrivW,
                dhs_priv_hmac = dhsPrivH,
                dhs_pub = state.dhsPub?.copyOf(),
                dhr_pub = state.dhrPub?.copyOf(),
                ns = 0,
                nr = 0,
                pn = 0,
                reset_epoch = 0,
                expecting_ack = 0
            )
        )
    }

    /**
     * Insert an `active(0)` prekey row. Mirrors [Pcs_E2eTest.insertActiveEpoch0].
     */
    private fun insertActiveEpoch0(
        db: AppDatabase,
        contactId: String,
        kp: Prekey.KeyPair,
        peerPrekeyPub: ByteArray
    ) = runBlocking {
        val rowId = PrekeyEpochEntity.rowIdFor(contactId, 0)
        val (privW, privH) = km.wrapAndMac(PrekeyEpochEntity.COL_MY_PRIV, rowId, kp.priv)
        db.prekeyEpochDao().insert(
            PrekeyEpochEntity(
                contact_id = contactId,
                epoch = 0,
                status = PrekeyEpochEntity.STATUS_ACTIVE,
                my_priv_wrapped = privW,
                my_priv_hmac = privH,
                my_pub = kp.pub.copyOf(),
                peer_pub = peerPrekeyPub.copyOf(),
                expires_at = null
            )
        )
    }

    /**
     * Seed an outbound [MessageEntity] in [db] addressed to [contactId].
     * The [uuid] is the 32-char hex PK form used by outbound rows.
     */
    private fun seedOutboundMessage(
        db: AppDatabase,
        uuid: String,
        contactId: String,
        state: Int,
        deliveredAt: Long
    ) = runBlocking {
        db.messageDao().insert(MessageEntity(
            uuid = uuid,
            contactId = contactId,
            direction = MessageEntity.DIRECTION_OUTBOUND,
            state = state,
            transport = TransportType.UNKNOWN,
            encryptedFilePath = null,
            durationMs = 0,
            deleteAfterMs = 0L,
            scheduledDeleteAt = 0L,
            transcription = null,
            createdAt = 1000L,
            sentAt = 1000L,
            deliveredAt = deliveredAt
        ))
    }

    /**
     * Generate a matched (32-char hex, java.util.UUID) pair from a single filler byte.
     * Mirrors [PlayedInboundHandlerTest.uuidPair]: both forms derive from the same 16
     * bytes so the outbound row's hex PK matches the UUID the sender encodes in the
     * KIND_PLAYED payload.
     */
    private fun uuidPair(filler: Byte): Pair<String, UUID> {
        val bytes = ByteArray(16) { filler }
        val hex32 = bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }
        val bb = ByteBuffer.wrap(bytes)
        val uuid = UUID(bb.long, bb.long)
        return hex32 to uuid
    }
}
