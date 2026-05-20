package com.voicedrop.storage

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.crypto.tink.config.TinkConfig
import com.google.crypto.tink.subtle.X25519
import com.voicedrop.crypto.Bootstrap
import com.voicedrop.crypto.ContactMutexRegistry
import com.voicedrop.crypto.KeyManager
import com.voicedrop.crypto.Prekey
import com.voicedrop.crypto.RePairWipe
import com.voicedrop.crypto.ResetCrypto
import com.voicedrop.crypto.ResetReceive
import com.voicedrop.network.FrameCodec
import java.security.KeyStore
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith

/**
 * §3.2 §7.3 — State-machine regression tests for the `prekey_epochs` table.
 *
 * Covers the 10 lifecycle invariants listed in the spec: pair-time row, pending
 * insertion, atomic promotions (Bob fresh-receive, Alice convergence-ack),
 * retransmit-after-promotion fallback, expiry sweep, hard-delete on wipe,
 * two-cycle previous cleanup, concurrent-init orphan handling, and re-pair wipe.
 *
 * Uses in-memory Room + real AndroidKeyStore-backed [KeyManager]. Cross-side
 * tests (tests 3-5, 8-9) construct two separate [AppDatabase] instances and two
 * [ResetReceive] instances; the single [KeyManager] is shared because its
 * wrap-and-MAC bindings are differentiated by `(contactId, epoch)` rowId, which
 * differs between Alice's and Bob's contacts.
 */
@RunWith(AndroidJUnit4::class)
class PrekeyEpochsLifecycleTest {

    companion object {
        @BeforeClass
        @JvmStatic
        fun setUpClass() {
            TinkConfig.register()
        }
    }

    private lateinit var ctx: Context
    private lateinit var km: KeyManager
    private lateinit var db: AppDatabase
    private lateinit var dao: PrekeyEpochDao

    @Before
    fun setUp() {
        ctx = ApplicationProvider.getApplicationContext()
        clearKeyStoreV2State()
        km = KeyManager(ctx)
        db = Room.inMemoryDatabaseBuilder(ctx, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        dao = db.prekeyEpochDao()
        ContactMutexRegistry.clear()
    }

    @After
    fun tearDown() {
        db.close()
        ContactMutexRegistry.clear()
        clearKeyStoreV2State()
    }

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

    // =========================================================================
    // 1. pairTime_insertsActiveEpoch0
    // =========================================================================

    /**
     * Mirrors the [QrPairActivity.confirmPairing] prekey-epoch row construction
     * at §6.1. After the INSERT, DAO must return an `active(0)` row with non-null
     * `peer_pub`, null `expires_at`, and a verifiable wrap-and-MAC binding.
     */
    @Test
    fun pairTime_insertsActiveEpoch0() = runBlocking {
        val pair = makeContactPair()
        insertContactRow(db, pair.aliceContactId, pair.bobPub)
        insertActiveEpoch0(db, km, pair.aliceContactId, pair.alicePrekey, pair.bobPrekey.pub)

        // byStatus must return exactly the active(0) row.
        val row = dao.byStatus(pair.aliceContactId, PrekeyEpochEntity.STATUS_ACTIVE)
        assertNotNull("active(0) row must exist after confirmPairing", row)
        assertEquals(0, row!!.epoch)
        assertEquals(PrekeyEpochEntity.STATUS_ACTIVE, row.status)
        assertNotNull("peer_pub must be non-null on active row", row.peer_pub)
        assertNull("expires_at must be null on active(0)", row.expires_at)

        // Verify the wrap-and-MAC binding round-trips cleanly (dr2 column/row binding).
        val rowId = PrekeyEpochEntity.rowIdFor(pair.aliceContactId, 0)
        val unwrapped = km.unwrapAndVerify(
            PrekeyEpochEntity.COL_MY_PRIV, rowId, row.my_priv_wrapped, row.my_priv_hmac
        )
        assertEquals(Prekey.PRIV_BYTES, unwrapped.size)

        // dao.all must show exactly one row.
        val all = dao.all(pair.aliceContactId)
        assertEquals(1, all.size)
    }

    // =========================================================================
    // 2. aliceInitiate_insertsPendingNewEpoch
    // =========================================================================

    /**
     * After [ResetReceive.manualResetInitiate]:
     *  - active(0) still present, unchanged.
     *  - pending(1) inserted with peer_pub=null, expires_at=null, valid wrap binding.
     *  - Contact.reset_epoch advanced to 1, expecting_ack=1.
     */
    @Test
    fun aliceInitiate_insertsPendingNewEpoch() = runBlocking {
        val pair = makeContactPair()
        insertContactRow(db, pair.aliceContactId, pair.bobPub)
        insertActiveEpoch0(db, km, pair.aliceContactId, pair.alicePrekey, pair.bobPrekey.pub)

        val aliceReceive = makeResetReceive(db, km, pair.alicePub, pair.alicePriv, pair.bobPub)
        val outcome = aliceReceive.manualResetInitiate(pair.aliceContactId)
        assertEquals(ResetReceive.Outcome.InitiatedReset, outcome)

        // active(0) must still be present.
        val active = dao.byStatus(pair.aliceContactId, PrekeyEpochEntity.STATUS_ACTIVE)
        assertNotNull("active(0) still present after initiate", active)
        assertEquals(0, active!!.epoch)

        // pending(1) must be present with peer_pub=null.
        val pending = dao.byStatus(pair.aliceContactId, PrekeyEpochEntity.STATUS_PENDING)
        assertNotNull("pending(1) inserted by manualResetInitiate", pending)
        assertEquals(1, pending!!.epoch)
        assertNull("pending.peer_pub must be null until ack=1 arrives", pending.peer_pub)
        assertNull("pending.expires_at must be null", pending.expires_at)

        // Wrap binding must verify for the pending row.
        val rowId = PrekeyEpochEntity.rowIdFor(pair.aliceContactId, 1)
        val unwrapped = km.unwrapAndVerify(
            PrekeyEpochEntity.COL_MY_PRIV, rowId, pending.my_priv_wrapped, pending.my_priv_hmac
        )
        assertEquals(Prekey.PRIV_BYTES, unwrapped.size)

        // Two rows total: active(0) + pending(1).
        val all = dao.all(pair.aliceContactId)
        assertEquals(2, all.size)

        // Contact state updated.
        val contact = db.contactDao().getById(pair.aliceContactId)!!
        assertEquals(1, contact.reset_epoch)
        assertEquals(1, contact.expecting_ack)
    }

    // =========================================================================
    // 3. bobFreshReceive_promotesAtomic
    // =========================================================================

    /**
     * Bob processes Alice's ack=0 RESET. His active(0) → previous(0) with
     * expires_at set; a new active(1) row is inserted with peer_pub = Alice's
     * stagedPrekeyPub from the wire frame. Transition is atomic (one txn).
     */
    @Test
    fun bobFreshReceive_promotesAtomic() = runBlocking {
        val pair = makeContactPair()

        // Alice side: set up active(0), initiate reset → produces pending(1) + outbox.
        val aliceDb = db  // reuse setUp db as Alice's DB
        insertContactRow(aliceDb, pair.aliceContactId, pair.bobPub)
        insertActiveEpoch0(aliceDb, km, pair.aliceContactId, pair.alicePrekey, pair.bobPrekey.pub)
        val aliceReceive = makeResetReceive(aliceDb, km, pair.alicePub, pair.alicePriv, pair.bobPub)
        aliceReceive.manualResetInitiate(pair.aliceContactId)

        // Bob side: separate DB.
        val bobDb = Room.inMemoryDatabaseBuilder(ctx, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        try {
            insertContactRow(bobDb, pair.bobContactId, pair.alicePub)
            insertActiveEpoch0(bobDb, km, pair.bobContactId, pair.bobPrekey, pair.alicePrekey.pub)
            val bobReceive = makeResetReceive(bobDb, km, pair.bobPub, pair.bobPriv, pair.alicePub)

            // Extract Alice's outbox RESET wire bytes and feed to Bob.
            val wireFrame = extractResetWireFromOutbox(aliceDb, pair.aliceContactId, km)
            val decoded = (FrameCodec.decode(wireFrame) as FrameCodec.DecodeResult.Ok).frame

            val outcome = bobReceive.onResetFrame(pair.bobContactId, decoded)
            assertEquals(ResetReceive.Outcome.FreshReset, outcome)

            // Bob's old active(0) must be demoted to previous(0) with expires_at set.
            val prev = bobDb.prekeyEpochDao().byStatus(pair.bobContactId, PrekeyEpochEntity.STATUS_PREVIOUS)
            assertNotNull("Bob's previous(0) must exist after fresh-receive", prev)
            assertEquals(0, prev!!.epoch)
            assertNotNull("previous.expires_at must be set", prev.expires_at)
            assertTrue("previous.expires_at must be in the future", prev.expires_at!! > 0L)

            // Bob's new active(1) must exist with peer_pub set.
            val active = bobDb.prekeyEpochDao().byStatus(pair.bobContactId, PrekeyEpochEntity.STATUS_ACTIVE)
            assertNotNull("Bob's active(1) must exist after fresh-receive", active)
            assertEquals(1, active!!.epoch)
            assertNotNull("active.peer_pub must be set to Alice's stagedPrekeyPub", active.peer_pub)

            // Exactly two rows (previous(0) + active(1)); no pending.
            val all = bobDb.prekeyEpochDao().all(pair.bobContactId)
            assertEquals(2, all.size)
            assertNull("No pending row on Bob after fresh-receive",
                bobDb.prekeyEpochDao().byStatus(pair.bobContactId, PrekeyEpochEntity.STATUS_PENDING))
        } finally {
            bobDb.close()
        }
    }

    // =========================================================================
    // 4. aliceConvergenceAck_promotesAtomic
    // =========================================================================

    /**
     * Alice receives Bob's ack=1. Her pending(1) → active(1) with peer_pub bound
     * to Bob's stagedPrekeyPub; her active(0) → previous(0). Exactly two rows.
     */
    @Test
    fun aliceConvergenceAck_promotesAtomic() = runBlocking {
        val pair = makeContactPair()

        // --- Alice initiates ---
        val aliceDb = db
        insertContactRow(aliceDb, pair.aliceContactId, pair.bobPub)
        insertActiveEpoch0(aliceDb, km, pair.aliceContactId, pair.alicePrekey, pair.bobPrekey.pub)
        val aliceReceive = makeResetReceive(aliceDb, km, pair.alicePub, pair.alicePriv, pair.bobPub)
        aliceReceive.manualResetInitiate(pair.aliceContactId)

        // --- Bob processes Alice's initiation ---
        val bobDb = Room.inMemoryDatabaseBuilder(ctx, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        try {
            insertContactRow(bobDb, pair.bobContactId, pair.alicePub)
            insertActiveEpoch0(bobDb, km, pair.bobContactId, pair.bobPrekey, pair.alicePrekey.pub)
            val bobReceive = makeResetReceive(bobDb, km, pair.bobPub, pair.bobPriv, pair.alicePub)

            val aliceWire = extractResetWireFromOutbox(aliceDb, pair.aliceContactId, km)
            val aliceDecoded = (FrameCodec.decode(aliceWire) as FrameCodec.DecodeResult.Ok).frame
            val bobOutcome = bobReceive.onResetFrame(pair.bobContactId, aliceDecoded)
            assertEquals(ResetReceive.Outcome.FreshReset, bobOutcome)

            // --- Alice processes Bob's ack=1 ---
            val bobWire = extractResetWireFromOutbox(bobDb, pair.bobContactId, km)
            val bobDecoded = (FrameCodec.decode(bobWire) as FrameCodec.DecodeResult.Ok).frame
            val aliceOutcome = aliceReceive.onResetFrame(pair.aliceContactId, bobDecoded)
            assertEquals(ResetReceive.Outcome.Acknowledged, aliceOutcome)

            // Alice's pending(1) → active(1).
            val active = dao.byStatus(pair.aliceContactId, PrekeyEpochEntity.STATUS_ACTIVE)
            assertNotNull("Alice's active(1) must exist after convergence ack", active)
            assertEquals(1, active!!.epoch)
            assertNotNull("active(1).peer_pub must be bound to Bob's stagedPrekeyPub", active.peer_pub)

            // Alice's active(0) → previous(0).
            val prev = dao.byStatus(pair.aliceContactId, PrekeyEpochEntity.STATUS_PREVIOUS)
            assertNotNull("Alice's previous(0) must exist", prev)
            assertEquals(0, prev!!.epoch)
            assertNotNull("previous.expires_at must be set", prev.expires_at)

            // No pending row remains.
            assertNull("No pending row on Alice after ack promotion",
                dao.byStatus(pair.aliceContactId, PrekeyEpochEntity.STATUS_PENDING))

            // Exactly two rows.
            val all = dao.all(pair.aliceContactId)
            assertEquals(2, all.size)

            // Contact state: expecting_ack cleared.
            val contact = db.contactDao().getById(pair.aliceContactId)!!
            assertEquals(0, contact.expecting_ack)
        } finally {
            bobDb.close()
        }
    }

    // =========================================================================
    // 5. retransmitAfterPromotion_fallsBackToPrevious
    // =========================================================================

    /**
     * After Alice's convergence ack (test 4 state: Alice has active(1)+previous(0)),
     * replay Alice's original ack=0 RESET frame through Bob again. The production
     * code's active→previous AEAD fallback must handle the retransmit without
     * changing row state (idempotent) and return Reacked (the else branch of
     * applyConvergence — re-ack with the persisted nonce, keyed under previous.prekeySS).
     *
     * We verify idempotency by asserting Bob's row shapes are unchanged from the
     * post-test-3 state.
     */
    @Test
    fun retransmitAfterPromotion_fallsBackToPrevious() = runBlocking {
        val pair = makeContactPair()

        // Set up Alice + Bob through the full round-trip (same as test 4).
        val aliceDb = db
        insertContactRow(aliceDb, pair.aliceContactId, pair.bobPub)
        insertActiveEpoch0(aliceDb, km, pair.aliceContactId, pair.alicePrekey, pair.bobPrekey.pub)
        val aliceReceive = makeResetReceive(aliceDb, km, pair.alicePub, pair.alicePriv, pair.bobPub)
        aliceReceive.manualResetInitiate(pair.aliceContactId)

        // Capture Alice's ack=0 wire bytes BEFORE Bob processes them (since Bob may
        // delete the outbox row on his side after processing — Alice's outbox is in aliceDb).
        val aliceAck0Wire = extractResetWireFromOutbox(aliceDb, pair.aliceContactId, km)
        val aliceAck0Decoded = (FrameCodec.decode(aliceAck0Wire) as FrameCodec.DecodeResult.Ok).frame

        val bobDb = Room.inMemoryDatabaseBuilder(ctx, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        try {
            insertContactRow(bobDb, pair.bobContactId, pair.alicePub)
            insertActiveEpoch0(bobDb, km, pair.bobContactId, pair.bobPrekey, pair.alicePrekey.pub)
            val bobReceive = makeResetReceive(bobDb, km, pair.bobPub, pair.bobPriv, pair.alicePub)

            // First: Bob processes Alice's ack=0 — promotes to active(1)+previous(0).
            val firstOutcome = bobReceive.onResetFrame(pair.bobContactId, aliceAck0Decoded)
            assertEquals(ResetReceive.Outcome.FreshReset, firstOutcome)

            // Capture row shapes after first processing.
            val prevAfterFirst = bobDb.prekeyEpochDao()
                .byStatus(pair.bobContactId, PrekeyEpochEntity.STATUS_PREVIOUS)
            val activeAfterFirst = bobDb.prekeyEpochDao()
                .byStatus(pair.bobContactId, PrekeyEpochEntity.STATUS_ACTIVE)
            assertNotNull(prevAfterFirst)
            assertNotNull(activeAfterFirst)
            val prevEpochAfterFirst = prevAfterFirst!!.epoch
            val activeEpochAfterFirst = activeAfterFirst!!.epoch

            // Second: replay Alice's same ack=0 — retransmit-after-promotion scenario.
            // Bob is now on active(1); active-slot AEAD will fail (different prekeySS
            // epoch); previous(0) fallback must succeed.
            val retransmitOutcome = bobReceive.onResetFrame(pair.bobContactId, aliceAck0Decoded)
            // The retransmit hits applyConvergence's else branch (re-ack) — Reacked.
            assertEquals(ResetReceive.Outcome.Reacked, retransmitOutcome)

            // Row shapes must be identical to post-first-processing state: no new promotions.
            val prevAfterRetransmit = bobDb.prekeyEpochDao()
                .byStatus(pair.bobContactId, PrekeyEpochEntity.STATUS_PREVIOUS)
            val activeAfterRetransmit = bobDb.prekeyEpochDao()
                .byStatus(pair.bobContactId, PrekeyEpochEntity.STATUS_ACTIVE)
            assertNotNull("previous row must still exist after retransmit", prevAfterRetransmit)
            assertNotNull("active row must still exist after retransmit", activeAfterRetransmit)
            assertEquals("previous epoch unchanged", prevEpochAfterFirst, prevAfterRetransmit!!.epoch)
            assertEquals("active epoch unchanged", activeEpochAfterFirst, activeAfterRetransmit!!.epoch)

            // Still exactly two rows.
            val all = bobDb.prekeyEpochDao().all(pair.bobContactId)
            assertEquals(2, all.size)

            // §7.3 — the re-ack enqueued by the Reacked path must be keyed under
            // previous.prekeySS, NOT active.prekeySS.
            //
            // applyFreshReset (first call) enqueues an ack=1 then deleteResetOutboxRows
            // is NOT called by applyConvergence's else branch (retransmit path) — it just
            // appends a second row. So after the retransmit there are >= 2 RESET rows;
            // the last one (ordered by created_at ASC) is the re-ack.
            val allOutboxRows = bobDb.pendingOutboundFrameDao().getByContact(pair.bobContactId)
            val resetOutboxRows = allOutboxRows
                .filter { it.frame_kind == PendingOutboundFrameEntity.FRAME_KIND_RESET }
            assertTrue(
                "Re-enqueued ack=1 outbox row must exist after retransmit (expected >= 2 RESET rows)",
                resetOutboxRows.size >= 2
            )
            // The last row in created_at-ASC order is the re-ack inserted by the retransmit.
            val reAckOutboxRow = resetOutboxRows.last()
            val reAckWire = km.unwrapAndVerify(
                "pending_outbound_frames.wrapped_frame",
                reAckOutboxRow.uuid,
                reAckOutboxRow.wrapped_frame,
                reAckOutboxRow.frame_hmac
            )
            val reAckDecoded = (FrameCodec.decode(reAckWire) as FrameCodec.DecodeResult.Ok).frame

            // Derive prekeySS_previous from Bob's previous(0) row.
            val prevRow = bobDb.prekeyEpochDao()
                .byStatus(pair.bobContactId, PrekeyEpochEntity.STATUS_PREVIOUS)!!
            val prevRowId = PrekeyEpochEntity.rowIdFor(pair.bobContactId, prevRow.epoch)
            val prevMyPriv = km.unwrapAndVerify(
                PrekeyEpochEntity.COL_MY_PRIV, prevRowId, prevRow.my_priv_wrapped, prevRow.my_priv_hmac
            )
            val prekeySS_previous = try {
                Prekey.sharedSecret(prevMyPriv, prevRow.peer_pub!!)
            } finally {
                prevMyPriv.fill(0)
            }

            // Derive prekeySS_active from Bob's active(1) row.
            val activeRow = bobDb.prekeyEpochDao()
                .byStatus(pair.bobContactId, PrekeyEpochEntity.STATUS_ACTIVE)!!
            val activeRowId = PrekeyEpochEntity.rowIdFor(pair.bobContactId, activeRow.epoch)
            val activeMyPriv = km.unwrapAndVerify(
                PrekeyEpochEntity.COL_MY_PRIV, activeRowId, activeRow.my_priv_wrapped, activeRow.my_priv_hmac
            )
            val prekeySS_active = try {
                Prekey.sharedSecret(activeMyPriv, activeRow.peer_pub!!)
            } finally {
                activeMyPriv.fill(0)
            }

            // Bob's idSharedSecret = X25519(bobPriv, alicePub).
            val bobIdShared = X25519.computeSharedSecret(pair.bobPriv, pair.alicePub)
            val reAckNonce = ResetCrypto.extractResetNonce(reAckDecoded)
            val reAckR = ResetCrypto.extractR(reAckDecoded)

            // Decrypt with previous prekeySS — must succeed with ack = ACK_ACKNOWLEDGER.
            val kResetPrev = ResetCrypto.deriveKReset(
                bobIdShared, prekeySS_previous,
                reAckDecoded.senderFp, reAckDecoded.recipFp,
                reAckNonce, reAckR
            )
            val decryptPrev = try {
                ResetCrypto.decrypt(reAckDecoded, kResetPrev)
            } finally {
                kResetPrev.fill(0)
            }
            assertTrue(
                "Re-ack must decrypt under previous prekeySS",
                decryptPrev is ResetCrypto.DecodeOutcome.Ok
            )
            assertEquals(
                "Re-ack plaintext ack byte must be ACK_ACKNOWLEDGER",
                ResetCrypto.ACK_ACKNOWLEDGER,
                (decryptPrev as ResetCrypto.DecodeOutcome.Ok).plaintext.ack
            )

            // Decrypt with active prekeySS — must FAIL (sanity-check that the frame is NOT
            // keyed under the active prekey).
            val kResetActive = ResetCrypto.deriveKReset(
                bobIdShared, prekeySS_active,
                reAckDecoded.senderFp, reAckDecoded.recipFp,
                reAckNonce, reAckR
            )
            val decryptActive = try {
                ResetCrypto.decrypt(reAckDecoded, kResetActive)
            } finally {
                kResetActive.fill(0)
                prekeySS_previous.fill(0)
                prekeySS_active.fill(0)
                bobIdShared.fill(0)
            }
            assertFalse(
                "Re-ack must NOT decrypt under active prekeySS",
                decryptActive is ResetCrypto.DecodeOutcome.Ok
            )
        } finally {
            bobDb.close()
        }
    }

    // =========================================================================
    // 6. previousExpiry_swept
    // =========================================================================

    /**
     * `sweepExpiredPrevious(now)` deletes a `previous` row whose `expires_at < now`
     * and preserves one whose `expires_at >= now`.
     */
    @Test
    fun previousExpiry_swept() = runBlocking {
        val contactId = "contact-sweep"
        insertContactRow(db, contactId, ByteArray(32) { 0x01 })

        val kp = Prekey.generate()
        val peerPub = ByteArray(32) { 0x02 }
        insertPrekeyRow(db, km, contactId, epoch = 0,
            status = PrekeyEpochEntity.STATUS_PREVIOUS,
            kp = kp, peerPub = peerPub, expiresAt = 100L)
        kp.priv.fill(0)

        // Sweep at now=200 → row expires_at=100 is stale, must be deleted.
        val deleted = dao.sweepExpiredPrevious(now = 200L)
        assertEquals("One expired previous row must be deleted", 1, deleted)
        assertNull("Expired previous row must be gone",
            dao.byStatus(contactId, PrekeyEpochEntity.STATUS_PREVIOUS))

        // Insert a fresh previous row with expires_at=300.
        val kp2 = Prekey.generate()
        insertPrekeyRow(db, km, contactId, epoch = 1,
            status = PrekeyEpochEntity.STATUS_PREVIOUS,
            kp = kp2, peerPub = peerPub, expiresAt = 300L)
        kp2.priv.fill(0)

        // Sweep at now=200 → expires_at=300 is in the future, must NOT be deleted.
        val deleted2 = dao.sweepExpiredPrevious(now = 200L)
        assertEquals("Non-expired previous row must be preserved", 0, deleted2)
        val surviving = dao.byStatus(contactId, PrekeyEpochEntity.STATUS_PREVIOUS)
        assertNotNull("Non-expired previous(1) must still exist", surviving)
        assertEquals(1, surviving!!.epoch)
    }

    // =========================================================================
    // 7. previousWipe_dropsWrappedPrivRow
    // =========================================================================

    /**
     * After `deleteEpoch`, `byEpoch` returns null — the entire row including its
     * wrapped priv bytes is gone (hard-delete, not tombstone).
     */
    @Test
    fun previousWipe_dropsWrappedPrivRow() = runBlocking {
        val contactId = "contact-wipe"
        insertContactRow(db, contactId, ByteArray(32) { 0x03 })

        val kp = Prekey.generate()
        insertPrekeyRow(db, km, contactId, epoch = 0,
            status = PrekeyEpochEntity.STATUS_PREVIOUS,
            kp = kp, peerPub = ByteArray(32) { 0x04 }, expiresAt = 99999L)
        kp.priv.fill(0)

        // Verify row exists before deletion.
        assertNotNull("previous(0) must exist before wipe",
            dao.byEpoch(contactId, 0))

        // Hard-delete via deleteEpoch.
        dao.deleteEpoch(contactId, 0)

        // byEpoch must return null — row is gone.
        assertNull("byEpoch(0) must return null after deleteEpoch",
            dao.byEpoch(contactId, 0))

        // all() must return empty list.
        assertTrue("all() must be empty after deleteEpoch",
            dao.all(contactId).isEmpty())
    }

    // =========================================================================
    // 8. twoCyclePath_previousWipedOnRBump
    // =========================================================================

    /**
     * Two full reset cycles. After cycle R→R+1: active(0)→previous(0), active(1).
     * When R+1→R+2 starts (manualResetInitiate): §6.6 unconditional wipe removes
     * previous(0) BEFORE inserting pending(2). Result: active(1) + pending(2) only.
     * The §6.6 wipe is unconditional regardless of expires_at.
     */
    @Test
    fun twoCyclePath_previousWipedOnRBump() = runBlocking {
        val pair = makeContactPair()

        val aliceDb = db
        insertContactRow(aliceDb, pair.aliceContactId, pair.bobPub)
        insertActiveEpoch0(aliceDb, km, pair.aliceContactId, pair.alicePrekey, pair.bobPrekey.pub)
        val aliceReceive = makeResetReceive(aliceDb, km, pair.alicePub, pair.alicePriv, pair.bobPub)

        val bobDb = Room.inMemoryDatabaseBuilder(ctx, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        try {
            insertContactRow(bobDb, pair.bobContactId, pair.alicePub)
            insertActiveEpoch0(bobDb, km, pair.bobContactId, pair.bobPrekey, pair.alicePrekey.pub)
            val bobReceive = makeResetReceive(bobDb, km, pair.bobPub, pair.bobPriv, pair.alicePub)

            // --- Cycle 1: R=0 → R=1 ---
            aliceReceive.manualResetInitiate(pair.aliceContactId)
            val aliceWire1 = extractResetWireFromOutbox(aliceDb, pair.aliceContactId, km)
            bobReceive.onResetFrame(pair.bobContactId,
                (FrameCodec.decode(aliceWire1) as FrameCodec.DecodeResult.Ok).frame)
            val bobWire1 = extractResetWireFromOutbox(bobDb, pair.bobContactId, km)
            aliceReceive.onResetFrame(pair.aliceContactId,
                (FrameCodec.decode(bobWire1) as FrameCodec.DecodeResult.Ok).frame)

            // After cycle 1: Alice has active(1) + previous(0).
            val prevAfterCycle1 = dao.byStatus(pair.aliceContactId, PrekeyEpochEntity.STATUS_PREVIOUS)
            val activeAfterCycle1 = dao.byStatus(pair.aliceContactId, PrekeyEpochEntity.STATUS_ACTIVE)
            assertNotNull("previous(0) after cycle 1", prevAfterCycle1)
            assertEquals(0, prevAfterCycle1!!.epoch)
            assertNotNull("active(1) after cycle 1", activeAfterCycle1)
            assertEquals(1, activeAfterCycle1!!.epoch)

            // --- Cycle 2: Alice initiates R=1 → R=2 ---
            // §6.6 wipe fires inside manualResetInitiate before inserting pending(2).
            val cycle2Outcome = aliceReceive.manualResetInitiate(pair.aliceContactId)
            assertEquals(ResetReceive.Outcome.InitiatedReset, cycle2Outcome)

            // previous(0) must be gone — wiped unconditionally by §6.6.
            assertNull("previous(0) must be wiped by §6.6 on R bump",
                dao.byEpoch(pair.aliceContactId, 0))
            assertNull("previous status must be null after wipe",
                dao.byStatus(pair.aliceContactId, PrekeyEpochEntity.STATUS_PREVIOUS))

            // active(1) must still be there.
            val activeAfterCycle2Init = dao.byStatus(pair.aliceContactId, PrekeyEpochEntity.STATUS_ACTIVE)
            assertNotNull("active(1) preserved through §6.6 wipe", activeAfterCycle2Init)
            assertEquals(1, activeAfterCycle2Init!!.epoch)

            // pending(2) must be present.
            val pendingCycle2 = dao.byStatus(pair.aliceContactId, PrekeyEpochEntity.STATUS_PENDING)
            assertNotNull("pending(2) inserted for cycle 2", pendingCycle2)
            assertEquals(2, pendingCycle2!!.epoch)

            // Exactly two rows: active(1) + pending(2).
            val allAfterCycle2Init = dao.all(pair.aliceContactId)
            assertEquals("Exactly two rows: active(1) + pending(2)", 2, allAfterCycle2Init.size)

            // §7.3 — "R+1 → R+2 (previous(R) wiped unconditionally regardless of expires_at,
            // previous(R+1) inserted)."
            //
            // Continue cycle 2 to completion.

            // Extract Alice's cycle-2 RESET wire from her outbox.
            val aliceWire2 = extractResetWireFromOutbox(aliceDb, pair.aliceContactId, km)

            // Feed Alice's cycle-2 RESET into Bob. Bob currently has active(1); his
            // applyFreshReset promotes active(1)→previous(1) and inserts active(2).
            // §6.6 also wipes Bob's previous(0) (if present) — but Bob's previous(0)
            // was already gone because applyFreshReset for cycle 1 wiped it at that time.
            val bobCycle2Outcome = bobReceive.onResetFrame(
                pair.bobContactId,
                (FrameCodec.decode(aliceWire2) as FrameCodec.DecodeResult.Ok).frame
            )
            assertEquals(ResetReceive.Outcome.FreshReset, bobCycle2Outcome)

            // Bob: previous(1) inserted, active(2) inserted, previous(0) already absent.
            assertNull(
                "Bob's previous(0) must be absent after cycle-2 (wiped unconditionally by §6.6)",
                bobDb.prekeyEpochDao().byEpoch(pair.bobContactId, 0)
            )
            val bobPrev1 = bobDb.prekeyEpochDao()
                .byStatus(pair.bobContactId, PrekeyEpochEntity.STATUS_PREVIOUS)
            assertNotNull("Bob's previous(1) must exist after cycle-2 FreshReset", bobPrev1)
            assertEquals(1, bobPrev1!!.epoch)

            val bobActive2 = bobDb.prekeyEpochDao()
                .byStatus(pair.bobContactId, PrekeyEpochEntity.STATUS_ACTIVE)
            assertNotNull("Bob's active(2) must exist after cycle-2 FreshReset", bobActive2)
            assertEquals(2, bobActive2!!.epoch)

            // Feed Bob's cycle-2 ACK into Alice. Alice's applyConvergence Acknowledged
            // branch: active(1)→previous(1), pending(2)→active(2).
            val bobWire2 = extractResetWireFromOutbox(bobDb, pair.bobContactId, km)
            val aliceCycle2Outcome = aliceReceive.onResetFrame(
                pair.aliceContactId,
                (FrameCodec.decode(bobWire2) as FrameCodec.DecodeResult.Ok).frame
            )
            assertEquals(ResetReceive.Outcome.Acknowledged, aliceCycle2Outcome)

            // Alice final state: exactly 2 rows — active(2) + previous(1); previous(0) gone.
            val aliceFinalAll = dao.all(pair.aliceContactId)
            assertEquals("Alice: exactly 2 rows after cycle-2 completion", 2, aliceFinalAll.size)

            val aliceFinalActive = dao.byStatus(pair.aliceContactId, PrekeyEpochEntity.STATUS_ACTIVE)
            assertNotNull("Alice: active(2) must exist", aliceFinalActive)
            assertEquals(2, aliceFinalActive!!.epoch)

            val aliceFinalPrev = dao.byStatus(pair.aliceContactId, PrekeyEpochEntity.STATUS_PREVIOUS)
            assertNotNull("Alice: previous(1) must exist", aliceFinalPrev)
            assertEquals("Alice: previous row is epoch 1 (previous(R+1) inserted)", 1, aliceFinalPrev!!.epoch)

            assertNull(
                "Alice: previous(0) must be gone after cycle-2 (wiped unconditionally by §6.6)",
                dao.byEpoch(pair.aliceContactId, 0)
            )
        } finally {
            bobDb.close()
        }
    }

    // =========================================================================
    // 9. concurrentInit_leavesOrphanedPending_wipedOnNextRBump
    // =========================================================================

    /**
     * Both sides call manualResetInitiate before either receives the other's frame.
     * Per §6.4a, concurrent-init routes to applyConvergence's else branch (ack=0,
     * same R, expecting_ack=1) — no promotion on either side. Both retain
     * active(R) + pending(R+1, peer_pub=NULL). When either side then initiates again
     * (R+2), §6.6 wipes the orphaned pending(R+1) and inserts pending(R+2).
     */
    @Test
    fun concurrentInit_leavesOrphanedPending_wipedOnNextRBump() = runBlocking {
        val pair = makeContactPair()

        val aliceDb = db
        insertContactRow(aliceDb, pair.aliceContactId, pair.bobPub)
        insertActiveEpoch0(aliceDb, km, pair.aliceContactId, pair.alicePrekey, pair.bobPrekey.pub)
        val aliceReceive = makeResetReceive(aliceDb, km, pair.alicePub, pair.alicePriv, pair.bobPub)

        val bobDb = Room.inMemoryDatabaseBuilder(ctx, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        try {
            insertContactRow(bobDb, pair.bobContactId, pair.alicePub)
            insertActiveEpoch0(bobDb, km, pair.bobContactId, pair.bobPrekey, pair.alicePrekey.pub)
            val bobReceive = makeResetReceive(bobDb, km, pair.bobPub, pair.bobPriv, pair.alicePub)

            // Both initiate concurrently — neither has seen the other's frame yet.
            aliceReceive.manualResetInitiate(pair.aliceContactId)
            bobReceive.manualResetInitiate(pair.bobContactId)

            // Capture both ack=0 frames before cross-feeding.
            val aliceWire = extractResetWireFromOutbox(aliceDb, pair.aliceContactId, km)
            val bobWire = extractResetWireFromOutbox(bobDb, pair.bobContactId, km)

            // Feed Alice's ack=0 into Bob. Bob is already at R=1 with expecting_ack=1
            // → routes to applyConvergence else branch → Reacked, no promotion.
            val bobOutcome = bobReceive.onResetFrame(pair.bobContactId,
                (FrameCodec.decode(aliceWire) as FrameCodec.DecodeResult.Ok).frame)
            assertEquals("Concurrent-init must Reack, not FreshReset", ResetReceive.Outcome.Reacked, bobOutcome)

            // Feed Bob's ack=0 into Alice — same symmetric result.
            val aliceOutcome = aliceReceive.onResetFrame(pair.aliceContactId,
                (FrameCodec.decode(bobWire) as FrameCodec.DecodeResult.Ok).frame)
            assertEquals("Concurrent-init must Reack on Alice too", ResetReceive.Outcome.Reacked, aliceOutcome)

            // After concurrent-init: each side has active(0) + pending(1, peer_pub=NULL).
            val aliceActive = dao.byStatus(pair.aliceContactId, PrekeyEpochEntity.STATUS_ACTIVE)
            val alicePending = dao.byStatus(pair.aliceContactId, PrekeyEpochEntity.STATUS_PENDING)
            assertNotNull("Alice: active(0) preserved", aliceActive)
            assertEquals(0, aliceActive!!.epoch)
            assertNotNull("Alice: pending(1) preserved (orphaned)", alicePending)
            assertEquals(1, alicePending!!.epoch)
            assertNull("Alice: pending(1).peer_pub still null (no promotion)", alicePending.peer_pub)

            val bobActive = bobDb.prekeyEpochDao().byStatus(pair.bobContactId, PrekeyEpochEntity.STATUS_ACTIVE)
            val bobPending = bobDb.prekeyEpochDao().byStatus(pair.bobContactId, PrekeyEpochEntity.STATUS_PENDING)
            assertNotNull("Bob: active(0) preserved", bobActive)
            assertEquals(0, bobActive!!.epoch)
            assertNotNull("Bob: pending(1) preserved (orphaned)", bobPending)
            assertEquals(1, bobPending!!.epoch)
            assertNull("Bob: pending(1).peer_pub still null (no promotion)", bobPending.peer_pub)

            // Now Alice initiates again at R=2. §6.6 must wipe orphaned pending(1).
            val cycle2 = aliceReceive.manualResetInitiate(pair.aliceContactId)
            assertEquals(ResetReceive.Outcome.InitiatedReset, cycle2)

            // pending(1) must be gone — wiped by §6.6.
            assertNull("Alice: orphaned pending(1) wiped on R+2 initiation",
                dao.byEpoch(pair.aliceContactId, 1))

            // pending(2) must exist (the fresh initiation).
            val pending2 = dao.byStatus(pair.aliceContactId, PrekeyEpochEntity.STATUS_PENDING)
            assertNotNull("Alice: pending(2) inserted for R+2 cycle", pending2)
            assertEquals(2, pending2!!.epoch)
            assertNull("pending(2).peer_pub must be null", pending2.peer_pub)

            // active(0) still present — no promotion yet.
            val activeStill = dao.byStatus(pair.aliceContactId, PrekeyEpochEntity.STATUS_ACTIVE)
            assertNotNull("Alice: active(0) still present", activeStill)
            assertEquals(0, activeStill!!.epoch)
        } finally {
            bobDb.close()
        }
    }

    // =========================================================================
    // 10. rePair_wipesAllEpochs
    // =========================================================================

    /**
     * [RePairWipe.wipe] (Task 6) includes `DELETE FROM prekey_epochs WHERE contact_id = ?`.
     * After wipe, dao.all must be empty. Exercises three rows: active(0), pending(1),
     * previous(2) — verifying that all statuses are deleted.
     */
    @Test
    fun rePair_wipesAllEpochs() = runBlocking {
        val contactId = "contact-repairwipe"
        insertContactRow(db, contactId, ByteArray(32) { 0x05 })

        // Insert three rows with distinct statuses to prove all are wiped.
        val kp0 = Prekey.generate()
        insertPrekeyRow(db, km, contactId, epoch = 0,
            status = PrekeyEpochEntity.STATUS_ACTIVE,
            kp = kp0, peerPub = ByteArray(32) { 0x06 }, expiresAt = null)
        kp0.priv.fill(0)

        val kp1 = Prekey.generate()
        insertPrekeyRow(db, km, contactId, epoch = 1,
            status = PrekeyEpochEntity.STATUS_PENDING,
            kp = kp1, peerPub = null, expiresAt = null)
        kp1.priv.fill(0)

        val kp2 = Prekey.generate()
        insertPrekeyRow(db, km, contactId, epoch = 2,
            status = PrekeyEpochEntity.STATUS_PREVIOUS,
            kp = kp2, peerPub = ByteArray(32) { 0x07 }, expiresAt = 99999L)
        kp2.priv.fill(0)

        // Verify three rows pre-wipe.
        assertEquals("Three rows pre-wipe", 3, dao.all(contactId).size)

        // Wipe.
        RePairWipe(db).wipe(contactId)

        // All rows must be gone.
        val remaining = dao.all(contactId)
        assertTrue("dao.all must be empty after RePairWipe.wipe", remaining.isEmpty())
        assertNull("byStatus(ACTIVE) null after wipe",
            dao.byStatus(contactId, PrekeyEpochEntity.STATUS_ACTIVE))
        assertNull("byStatus(PENDING) null after wipe",
            dao.byStatus(contactId, PrekeyEpochEntity.STATUS_PENDING))
        assertNull("byStatus(PREVIOUS) null after wipe",
            dao.byStatus(contactId, PrekeyEpochEntity.STATUS_PREVIOUS))

        // §7.3 — "RePairWipe.wipe(contactId) followed by confirmPairing leaves exactly
        // one row: active(0) with fresh keys."
        //
        // Capture the original active(0) my_pub before the wipe so we can assert the
        // re-paired row has a DIFFERENT (fresh) keypair.
        // Note: kp0.priv was zeroed above but kp0.pub is still valid.
        val originalActivePub = kp0.pub.copyOf()

        // Simulate the post-wipe confirmPairing: insert a fresh active(0) row with
        // a newly-generated keypair whose my_pub DIFFERS from the original active(0).
        val freshKp = Prekey.generate()
        val freshPeerPub = ByteArray(32) { 0x08 }   // deliberately different from original 0x06
        insertPrekeyRow(
            db, km, contactId, epoch = 0,
            status = PrekeyEpochEntity.STATUS_ACTIVE,
            kp = freshKp, peerPub = freshPeerPub, expiresAt = null
        )
        freshKp.priv.fill(0)

        // Exactly one row remains after re-pair.
        val afterRePair = dao.all(contactId)
        assertEquals("Exactly one row after RePairWipe + confirmPairing", 1, afterRePair.size)

        val rePairedActive = dao.byStatus(contactId, PrekeyEpochEntity.STATUS_ACTIVE)
        assertNotNull("Active(0) row must exist after re-pair", rePairedActive)
        assertEquals("Active row epoch must be 0", 0, rePairedActive!!.epoch)

        // Verify the new my_pub differs from the original — proves "fresh keys" invariant.
        assertFalse(
            "Re-paired active(0).my_pub must differ from original (fresh keys)",
            rePairedActive.my_pub.contentEquals(originalActivePub)
        )
    }

    // =========================================================================
    // Fixtures and helpers
    // =========================================================================

    /**
     * Stable two-sided key pair for cross-side tests. [alicePub] < [bobPub] by
     * fingerprint (unsigned) so Alice is always Alice-role per Bootstrap's rule.
     */
    private data class ContactPair(
        val alicePriv: ByteArray,
        val alicePub: ByteArray,
        val alicePrekey: Prekey.KeyPair,
        val aliceContactId: String,   // = fingerprint(bobPub) hex, used as contactId in Alice's DB
        val bobPriv: ByteArray,
        val bobPub: ByteArray,
        val bobPrekey: Prekey.KeyPair,
        val bobContactId: String      // = fingerprint(alicePub) hex, used as contactId in Bob's DB
    )

    private fun makeContactPair(): ContactPair {
        var aPriv: ByteArray; var aPub: ByteArray
        var bPriv: ByteArray; var bPub: ByteArray
        // Ensure Bootstrap.decideRole(aPub, bPub) == ALICE so fingerprint-ordering is stable.
        while (true) {
            aPriv = X25519.generatePrivateKey()
            aPub = X25519.publicFromPrivate(aPriv)
            bPriv = X25519.generatePrivateKey()
            bPub = X25519.publicFromPrivate(bPriv)
            if (Bootstrap.decideRole(aPub, bPub) == Bootstrap.Role.ALICE) break
        }
        val aFpHex = Bootstrap.fingerprintBytes(aPub).joinToString("") { "%02x".format(it) }
        val bFpHex = Bootstrap.fingerprintBytes(bPub).joinToString("") { "%02x".format(it) }
        return ContactPair(
            alicePriv = aPriv, alicePub = aPub,
            alicePrekey = Prekey.generate(),
            aliceContactId = bFpHex,   // Alice's DB contact ID is Bob's fingerprint
            bobPriv = bPriv, bobPub = bPub,
            bobPrekey = Prekey.generate(),
            bobContactId = aFpHex      // Bob's DB contact ID is Alice's fingerprint
        )
    }

    /** Insert a minimal contact row; rk_wrapped is a dummy sentinel so RESET paths don't fail. */
    private fun insertContactRow(db: AppDatabase, contactId: String, peerIdPub: ByteArray) = runBlocking {
        val sentinelRk = ByteArray(32) { 0x11 }
        val rowId = contactId.toByteArray(Charsets.UTF_8)
        val (rkW, rkH) = km.wrapAndMac("contacts.rk_wrapped", rowId, sentinelRk)
        db.contactDao().upsert(
            ContactEntity(
                id = contactId,
                name = "peer",
                publicKeyBase64 = android.util.Base64.encodeToString(peerIdPub, android.util.Base64.NO_WRAP),
                addedAt = 0L,
                rk_wrapped = rkW,
                rk_hmac = rkH
            )
        )
    }

    /**
     * Insert an `active(0)` prekey row mirroring [QrPairActivity.confirmPairing].
     * `kp.priv` is wrapped under [KeyManager.wrapAndMac] bound to
     * `(COL_MY_PRIV, rowIdFor(contactId, 0))`.
     */
    private fun insertActiveEpoch0(
        db: AppDatabase,
        km: KeyManager,
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

    /** Insert an arbitrary prekey row for direct DAO tests (tests 6, 7, 10). */
    private fun insertPrekeyRow(
        db: AppDatabase,
        km: KeyManager,
        contactId: String,
        epoch: Int,
        status: String,
        kp: Prekey.KeyPair,
        peerPub: ByteArray?,
        expiresAt: Long?
    ) = runBlocking {
        val rowId = PrekeyEpochEntity.rowIdFor(contactId, epoch)
        val (privW, privH) = km.wrapAndMac(PrekeyEpochEntity.COL_MY_PRIV, rowId, kp.priv)
        db.prekeyEpochDao().insert(
            PrekeyEpochEntity(
                contact_id = contactId,
                epoch = epoch,
                status = status,
                my_priv_wrapped = privW,
                my_priv_hmac = privH,
                my_pub = kp.pub.copyOf(),
                peer_pub = peerPub?.copyOf(),
                expires_at = expiresAt
            )
        )
    }

    /**
     * Construct a [ResetReceive] for one side. [ownPub] and [ownPriv] are the raw
     * X25519 identity keys for this side; [peerPub] is the peer's identity pub
     * (used to derive idSharedSecret via `X25519(ownPriv, peerPub)`).
     *
     * [KeyManager] is shared (single set of wrap/MAC KeyStore aliases); the wrap
     * bindings are differentiated by contactId-derived rowIds, which are distinct
     * across Alice's and Bob's contacts.
     */
    private fun makeResetReceive(
        db: AppDatabase,
        km: KeyManager,
        ownPub: ByteArray,
        ownPriv: ByteArray,
        peerPub: ByteArray
    ): ResetReceive {
        val ownFp = Bootstrap.fingerprintBytes(ownPub)
        val idSS = X25519.computeSharedSecret(ownPriv, peerPub)
        return ResetReceive(
            db = db,
            wrapMac = km,
            ownFingerprint32 = ownFp,
            idSharedSecretFor = { idSS.copyOf() }
        )
    }

    /**
     * Unwrap and return the wire bytes of the most-recently-enqueued RESET outbox row for
     * [contactId]. Rows are returned in created_at ASC order by the DAO, so `.last()` is the
     * newest. Using `.last()` instead of `.single()` tolerates states where multiple RESET rows
     * are present (e.g. Reacked, where applyConvergence re-enqueues without pruning first).
     */
    private suspend fun extractResetWireFromOutbox(
        db: AppDatabase,
        contactId: String,
        km: KeyManager
    ): ByteArray {
        val rows = db.pendingOutboundFrameDao().getByContact(contactId)
        val resetRows = rows.filter { it.frame_kind == PendingOutboundFrameEntity.FRAME_KIND_RESET }
        check(resetRows.isNotEmpty()) { "No RESET row in outbox for $contactId" }
        val resetRow = resetRows.last()
        return km.unwrapAndVerify(
            "pending_outbound_frames.wrapped_frame",
            resetRow.uuid,
            resetRow.wrapped_frame,
            resetRow.frame_hmac
        )
    }
}
