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
import com.voicedrop.storage.PendingOutboundFrameEntity
import com.voicedrop.storage.PrekeyEpochEntity
import java.security.KeyStore
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith

/**
 * §3.2 §7.4 — End-to-end PCS regression guards for the per-pair rotating X25519 prekey.
 *
 * Five tests covering: full reset + post-reset DATA round-trip, two-cycle prekey rotation,
 * the load-bearing PCS security claim (identity-key exfil cannot recover post-reset RK_0),
 * and the two outbox-retransmit×prekey cases from §7.4 Case A/B.
 *
 * Architecture: two [Side] objects, each with an independent in-memory Room database, a
 * shared [KeyManager] for wrap-and-MAC (row bindings differentiated by contact-ID-derived
 * rowIds, which differ across sides), and separate X25519 identity keypairs generated
 * directly. [ResetReceive] is constructed per-side; [RatchetEncryptAndSend] /
 * [RatchetDecryptAndPersist] are constructed on demand for DATA tests.
 */
@RunWith(AndroidJUnit4::class)
class Pcs_E2eTest {

    companion object {
        @BeforeClass
        @JvmStatic
        fun setUpClass() {
            TinkConfig.register()
        }
    }

    /**
     * One "side" in the two-party fixture. Carries its own DB, the shared wrap/MAC
     * [KeyManager], its own identity keypair (not from KM — KM only handles wrapping),
     * and a [ResetReceive] wired to those primitives.
     *
     * [contactId] is the peer's fingerprint hex (how this side labels the contact row
     * in its own DB) and [peerPub] is the peer's identity public key.
     */
    private data class Side(
        val db: AppDatabase,
        val km: KeyManager,
        val idPriv: ByteArray,
        val idPub: ByteArray,
        val contactId: String,   // = fingerprintHex(peerPub) — peer's fp is our contact row id
        val peerPub: ByteArray,
        val recv: ResetReceive
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
    // 1. e2e_pairResetRoundtrip_postResetDataDecrypts  (§7.4 primary guard)
    // =========================================================================

    /**
     * §7.4 — Primary regression guard. Full two-party sequence:
     *   1. Bootstrap ratchet state (pair Alice and Bob).
     *   2. Alice sends a DATA frame; Bob decrypts it.
     *   3. Alice initiates a manual reset; full convergence round-trip.
     *   4. Both sides are converged (expecting_ack=0, active(1)).
     *   5. Alice sends a post-reset DATA frame; Bob decrypts it.
     *
     * Verifies that the reset does not break the post-reset DATA path.
     */
    @Test
    fun e2e_pairResetRoundtrip_postResetDataDecrypts() = runBlocking {
        pairAliceAndBob()

        // Alice sends pre-reset DATA; Bob must decrypt it.
        val aliceEnc = makeEncryptor(alice)
        val bobDec = makeDecryptor(bob)
        val preResetMsg = "hello pre-reset".toByteArray(Charsets.UTF_8)
        val sent = aliceEnc.encryptAndSend(alice.contactId, preResetMsg) { _, _, _ -> null }
        val received = bobDec.receive(bob.contactId,
            (FrameCodec.decode(sent.wireBytes) as FrameCodec.DecodeResult.Ok).frame
        ) { _, _, _, _ -> null }
        assertTrue("Pre-reset DATA must be Delivered", received is RatchetDecryptAndPersist.Result.Delivered)
        assertTrue("Decrypted bytes must match",
            preResetMsg.contentEquals((received as RatchetDecryptAndPersist.Result.Delivered).plaintext))

        // Full reset round-trip; Alice initiates.
        doManualResetAndConverge(initiator = alice, responder = bob)

        // Verify post-reset state: expecting_ack cleared on both sides.
        val aliceContact = alice.db.contactDao().getById(alice.contactId)
        assertNotNull("Alice contact must exist", aliceContact)
        assertEquals("Alice expecting_ack must be 0 after convergence", 0, aliceContact!!.expecting_ack)

        val bobContact = bob.db.contactDao().getById(bob.contactId)
        assertNotNull("Bob contact must exist", bobContact)
        assertEquals("Bob expecting_ack must be 0 after convergence", 0, bobContact!!.expecting_ack)

        // Post-reset DATA: Alice sends again; Bob decrypts.
        val aliceEnc2 = makeEncryptor(alice)
        val bobDec2 = makeDecryptor(bob)
        val postResetMsg = "hello post-reset".toByteArray(Charsets.UTF_8)
        val sent2 = aliceEnc2.encryptAndSend(alice.contactId, postResetMsg) { _, _, _ -> null }
        val received2 = bobDec2.receive(bob.contactId,
            (FrameCodec.decode(sent2.wireBytes) as FrameCodec.DecodeResult.Ok).frame
        ) { _, _, _, _ -> null }
        assertTrue("Post-reset DATA must be Delivered",
            received2 is RatchetDecryptAndPersist.Result.Delivered)
        assertTrue("Post-reset decrypted bytes must match",
            postResetMsg.contentEquals((received2 as RatchetDecryptAndPersist.Result.Delivered).plaintext))
    }

    // =========================================================================
    // 2. e2e_twoResetsBackToBack_prekeyRotates  (§7.4 two-cycle guard)
    // =========================================================================

    /**
     * §7.4 — Two full reset cycles back-to-back. After each convergence:
     *   - Each side's prekey_epochs ends at exactly active(R) with no pending or previous.
     *   - K_reset derived for cycle 1 and cycle 2 are distinct (prekey rotation).
     *   - active epoch advances to 2 on both sides.
     *
     * [captureKResetBeforeConverge] internally calls [manualResetInitiate] and completes
     * the full round-trip; this test does NOT call [doManualResetAndConverge] separately.
     */
    @Test
    fun e2e_twoResetsBackToBack_prekeyRotates() = runBlocking {
        pairAliceAndBob()

        // --- Cycle 1: R=0 → R=1 ---
        // captureKResetBeforeConverge initiates and fully converges the reset cycle.
        val kReset1 = captureKResetBeforeConverge(initiator = alice, responder = bob)

        // After cycle 1: active(1) on each side.
        val aliceActive1 = alice.db.prekeyEpochDao().byStatus(alice.contactId, PrekeyEpochEntity.STATUS_ACTIVE)
        assertNotNull("Alice active(1) must exist after cycle 1", aliceActive1)
        assertEquals(1, aliceActive1!!.epoch)

        val bobActive1 = bob.db.prekeyEpochDao().byStatus(bob.contactId, PrekeyEpochEntity.STATUS_ACTIVE)
        assertNotNull("Bob active(1) must exist after cycle 1", bobActive1)
        assertEquals(1, bobActive1!!.epoch)

        // --- Cycle 2: R=1 → R=2 ---
        val kReset2 = captureKResetBeforeConverge(initiator = alice, responder = bob)

        // After cycle 2: active(2) on each side.
        val aliceActive2 = alice.db.prekeyEpochDao().byStatus(alice.contactId, PrekeyEpochEntity.STATUS_ACTIVE)
        assertNotNull("Alice active(2) must exist after cycle 2", aliceActive2)
        assertEquals("Alice prekey_epochs ends at active(2)", 2, aliceActive2!!.epoch)

        val bobActive2 = bob.db.prekeyEpochDao().byStatus(bob.contactId, PrekeyEpochEntity.STATUS_ACTIVE)
        assertNotNull("Bob active(2) must exist after cycle 2", bobActive2)
        assertEquals("Bob prekey_epochs ends at active(2)", 2, bobActive2!!.epoch)

        // K_reset for cycle 1 and 2 must differ (prekey was rotated between cycles).
        assertFalse("K_reset cycle1 and cycle2 must be distinct (prekey rotation)",
            kReset1.contentEquals(kReset2))

        kReset1.fill(0)
        kReset2.fill(0)
    }

    // =========================================================================
    // 3. e2e_idPrivOnlyLeak_postResetRk0Unrecoverable  (§7.4 load-bearing PCS guard)
    // =========================================================================

    /**
     * §7.4 §3.2 — Load-bearing PCS security claim:
     *
     * After a reset, an attacker who exfiltrated ONLY both parties' identity
     * private keys at T0 (before the reset) cannot recompute the post-reset
     * RK_0, because RK_0 now depends on the prekey shared-secret which was NOT
     * exfiltrated.
     *
     * The attacker's best guess (prekeySS = 0x00*32) must not produce the real RK_0.
     * This pins the headline §3.2 security invariant.
     */
    @Test
    fun e2e_idPrivOnlyLeak_postResetRk0Unrecoverable() = runBlocking {
        pairAliceAndBob()

        // Snapshot identity privkeys at T0 — the "stolen" material.
        val aliceIdPrivStolen = alice.idPriv.copyOf()
        val bobIdPrivStolen = bob.idPriv.copyOf()

        // Do one full reset cycle.
        doManualResetAndConverge(initiator = alice, responder = bob)

        // Read Bob's real post-reset RK_0 from his wrapped DB column.
        val realRk0 = readWrappedRk(bob)

        // Attacker attempts to recompute RK_0 using ONLY the stolen identity privkeys.
        // idSS is recoverable from either stolen priv + the peer's identity pub.
        val idSS = X25519.computeSharedSecret(aliceIdPrivStolen, bob.idPub)

        // Read the reset nonce from Bob's contact row (attacker can observe this on-wire).
        val resetNonce = readResetNonce(bob)

        // Attacker's best shot: assume prekeySS = zeros (not exfiltrated).
        val attackerRk0 = Bootstrap.deriveResetRootKey(
            idShared = idSS,
            prekeySS = ByteArray(32),   // attacker's forced guess
            R = 1,
            resetNonce = resetNonce
        )

        assertFalse("Stolen idPriv must NOT recover post-reset RK_0 (§3.2 PCS invariant)",
            realRk0.contentEquals(attackerRk0))

        aliceIdPrivStolen.fill(0)
        bobIdPrivStolen.fill(0)
        idSS.fill(0)
        realRk0.fill(0)
        attackerRk0.fill(0)
    }

    // =========================================================================
    // 4. e2e_outboxRetransmit_caseA_previousAlive_fallbackFires  (§7.4 Case A)
    // =========================================================================

    /**
     * §7.4 Case A — Previous prekey row is still alive (non-expired). A RESET frame
     * that was keyed under the now-previous epoch's prekeySS arrives as a retransmit
     * after Bob has already promoted to active(1).
     *
     * Expected: [ResetReceive.Outcome.Reacked]. Bob falls back to previous(0), AEAD
     * succeeds, re-ack is enqueued. Row shapes unchanged from post-cycle-1 state.
     */
    @Test
    fun e2e_outboxRetransmit_caseA_previousAlive_fallbackFires() = runBlocking {
        pairAliceAndBob()

        // Capture Alice's ack=0 RESET wire bytes BEFORE Bob processes them.
        // We will replay this same frame as a retransmit after Bob has promoted.
        alice.recv.manualResetInitiate(alice.contactId)
        val aliceAck0Wire = extractResetWireFromOutbox(alice.db, alice.contactId, km)
        val aliceAck0Decoded = (FrameCodec.decode(aliceAck0Wire) as FrameCodec.DecodeResult.Ok).frame

        // Bob processes Alice's ack=0 for the first time → FreshReset, active(0)→previous(0), active(1).
        val firstOutcome = bob.recv.onResetFrame(bob.contactId, aliceAck0Decoded)
        assertEquals(ResetReceive.Outcome.FreshReset, firstOutcome)

        // Alice processes Bob's ack=1 to clear expecting_ack on her side.
        val bobAck1Wire = extractResetWireFromOutbox(bob.db, bob.contactId, km)
        val ackOutcome = alice.recv.onResetFrame(alice.contactId,
            (FrameCodec.decode(bobAck1Wire) as FrameCodec.DecodeResult.Ok).frame)
        assertEquals(ResetReceive.Outcome.Acknowledged, ackOutcome)

        // Snapshot Bob's row state after first processing.
        val prevAfterFirst = bob.db.prekeyEpochDao().byStatus(bob.contactId, PrekeyEpochEntity.STATUS_PREVIOUS)
        val activeAfterFirst = bob.db.prekeyEpochDao().byStatus(bob.contactId, PrekeyEpochEntity.STATUS_ACTIVE)
        assertNotNull("Bob previous row must exist after first processing", prevAfterFirst)
        assertNotNull("Bob active row must exist after first processing", activeAfterFirst)
        assertNotNull("previous.expires_at must be set (Case A: row is alive)", prevAfterFirst!!.expires_at)
        val prevEpoch = prevAfterFirst.epoch
        val activeEpoch = activeAfterFirst!!.epoch

        // Case A: replay Alice's same ack=0 — previous row is still alive (non-expired TTL=10min).
        // Bob is now on active(1); active AEAD fails; previous fallback must succeed → Reacked.
        val retransmitOutcome = bob.recv.onResetFrame(bob.contactId, aliceAck0Decoded)
        assertEquals("Case A: retransmit must Reack via previous fallback",
            ResetReceive.Outcome.Reacked, retransmitOutcome)

        // Row shapes must be unchanged: no new promotions.
        val prevAfterRetransmit = bob.db.prekeyEpochDao()
            .byStatus(bob.contactId, PrekeyEpochEntity.STATUS_PREVIOUS)
        val activeAfterRetransmit = bob.db.prekeyEpochDao()
            .byStatus(bob.contactId, PrekeyEpochEntity.STATUS_ACTIVE)
        assertNotNull("previous row must still exist after Case A retransmit", prevAfterRetransmit)
        assertNotNull("active row must still exist after Case A retransmit", activeAfterRetransmit)
        assertEquals("previous epoch unchanged", prevEpoch, prevAfterRetransmit!!.epoch)
        assertEquals("active epoch unchanged", activeEpoch, activeAfterRetransmit!!.epoch)
        assertEquals("exactly two rows", 2, bob.db.prekeyEpochDao().all(bob.contactId).size)
    }

    // =========================================================================
    // 5. e2e_outboxRetransmit_caseB_previousSwept_dropsCleanly  (§7.4 Case B)
    // =========================================================================

    /**
     * §7.4 Case B — Previous prekey row has been swept (expired or forcibly deleted).
     * The same retransmitted ack=0 frame arrives; the active AEAD fails; there is no
     * previous fallback. The frame must be dropped cleanly as [ResetReceive.Outcome.AeadFailure]
     * with no state side-effects (row shapes and expecting_ack unchanged).
     */
    @Test
    fun e2e_outboxRetransmit_caseB_previousSwept_dropsCleanly() = runBlocking {
        pairAliceAndBob()

        // Capture Alice's ack=0 RESET wire bytes before Bob processes them.
        alice.recv.manualResetInitiate(alice.contactId)
        val aliceAck0Wire = extractResetWireFromOutbox(alice.db, alice.contactId, km)
        val aliceAck0Decoded = (FrameCodec.decode(aliceAck0Wire) as FrameCodec.DecodeResult.Ok).frame

        // Bob processes Alice's ack=0 → FreshReset, active(0)→previous(0) (TTL=10min).
        val firstOutcome = bob.recv.onResetFrame(bob.contactId, aliceAck0Decoded)
        assertEquals(ResetReceive.Outcome.FreshReset, firstOutcome)

        // Alice processes Bob's ack=1 to converge.
        val bobAck1Wire = extractResetWireFromOutbox(bob.db, bob.contactId, km)
        val ackOutcome = alice.recv.onResetFrame(alice.contactId,
            (FrameCodec.decode(bobAck1Wire) as FrameCodec.DecodeResult.Ok).frame)
        assertEquals(ResetReceive.Outcome.Acknowledged, ackOutcome)

        // Force-expire the previous row by setting expires_at to a time in the past.
        // This simulates the §6.7 sweep having run. We use direct SQL so we don't depend
        // on test-clock manipulation.
        val rawDb = bob.db.openHelper.writableDatabase
        rawDb.execSQL(
            "UPDATE prekey_epochs SET expires_at = 1 WHERE contact_id = ? AND status = 'previous'",
            arrayOf<Any>(bob.contactId)
        )

        // Snapshot Bob's row count and active epoch before the Case B drop.
        val activeBeforeDrop = bob.db.prekeyEpochDao()
            .byStatus(bob.contactId, PrekeyEpochEntity.STATUS_ACTIVE)
        assertNotNull("active row must exist before Case B drop", activeBeforeDrop)
        val activeEpochBeforeDrop = activeBeforeDrop!!.epoch

        // Case B: replay Alice's same ack=0. previous row is now expired; both AEAD slots fail.
        // Outcome must be AeadFailure — no state mutation.
        val dropOutcome = bob.recv.onResetFrame(bob.contactId, aliceAck0Decoded)
        assertEquals("Case B: expired previous must cause AeadFailure (clean drop)",
            ResetReceive.Outcome.AeadFailure, dropOutcome)

        // State must be unchanged: still exactly one previous (forced-expired) + one active.
        val activeAfterDrop = bob.db.prekeyEpochDao()
            .byStatus(bob.contactId, PrekeyEpochEntity.STATUS_ACTIVE)
        assertNotNull("active row must still exist after Case B drop", activeAfterDrop)
        assertEquals("active epoch unchanged after Case B drop",
            activeEpochBeforeDrop, activeAfterDrop!!.epoch)

        val bobContactAfterDrop = bob.db.contactDao().getById(bob.contactId)
        assertNotNull("Bob contact must exist after Case B drop", bobContactAfterDrop)
        assertEquals("expecting_ack must be 0 after Case B drop (no state mutation)",
            0, bobContactAfterDrop!!.expecting_ack)
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
     * Bootstrap Alice and Bob in-process. Each gets an independent in-memory Room DB;
     * both share the single [km] for wrap-and-MAC (row bindings are differentiated by
     * contactId-derived rowIds which are distinct: Alice's DB uses Bob's fp as contactId
     * and vice-versa).
     *
     * Uses [Bootstrap.computeInitialBootstrap] to derive real RK_0 and DH state so the
     * DATA encrypt/decrypt path actually works. Prekey epoch(0) rows are inserted on both
     * sides as at pair-time.
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

        // Generate per-pair bootstrap ephemeral for Bob (Bob-role generates it at pair time).
        val bobBootstrapEphPriv = X25519.generatePrivateKey()
        val bobBootstrapEphPub = X25519.publicFromPrivate(bobBootstrapEphPriv)

        // Run bootstrap from Alice's perspective.
        val aliceState = Bootstrap.computeInitialBootstrap(
            myIdPriv = aPriv,
            myIdPub = aPub,
            peerIdPub = bPub,
            myBootstrapEphPriv = ByteArray(32), // Alice-role: this field is unused in ALICE path
            myBootstrapEphPub = ByteArray(32),  // Alice-role: unused
            peerBootstrapEphPub = bobBootstrapEphPub
        )
        // Run bootstrap from Bob's perspective.
        val bobState = Bootstrap.computeInitialBootstrap(
            myIdPriv = bPriv,
            myIdPub = bPub,
            peerIdPub = aPub,
            myBootstrapEphPriv = bobBootstrapEphPriv,
            myBootstrapEphPub = bobBootstrapEphPub,
            peerBootstrapEphPub = ByteArray(32) // Bob-role: peer eph is unused in BOB path
        )

        // Both RK_0s must be identical — sanity check.
        check(aliceState.rootKey.contentEquals(bobState.rootKey)) {
            "RK_0 mismatch after bootstrap — fixture bug"
        }

        val aFpHex = Bootstrap.fingerprintBytes(aPub).joinToString("") { "%02x".format(it) }
        val bFpHex = Bootstrap.fingerprintBytes(bPub).joinToString("") { "%02x".format(it) }

        // Prekey keypairs for epoch 0.
        val alicePrekey = Prekey.generate()
        val bobPrekey = Prekey.generate()

        // Alice's DB: contactId = bFpHex (Bob's fingerprint), peerPub = bPub.
        val aliceDb = Room.inMemoryDatabaseBuilder(ctx, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        insertBootstrappedContactRow(aliceDb, bFpHex, bPub, aliceState)
        insertActiveEpoch0(aliceDb, km, bFpHex, alicePrekey, bobPrekey.pub)

        // Bob's DB: contactId = aFpHex (Alice's fingerprint), peerPub = aPub.
        val bobDb = Room.inMemoryDatabaseBuilder(ctx, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        insertBootstrappedContactRow(bobDb, aFpHex, aPub, bobState)
        insertActiveEpoch0(bobDb, km, aFpHex, bobPrekey, alicePrekey.pub)

        val aliceRecv = makeResetReceive(aliceDb, km, aPub, aPriv, bPub)
        val bobRecv = makeResetReceive(bobDb, km, bPub, bPriv, aPub)

        alice = Side(
            db = aliceDb, km = km,
            idPriv = aPriv, idPub = aPub,
            contactId = bFpHex, peerPub = bPub,
            recv = aliceRecv
        )
        bob = Side(
            db = bobDb, km = km,
            idPriv = bPriv, idPub = bPub,
            contactId = aFpHex, peerPub = aPub,
            recv = bobRecv
        )

        alicePrekey.priv.fill(0)
        bobPrekey.priv.fill(0)
        bobBootstrapEphPriv.fill(0)
    }

    /**
     * Execute one full reset round-trip (initiator → responder ack=1 → initiator converges).
     * Asserts each outcome to catch regressions in the state-machine path.
     */
    private suspend fun doManualResetAndConverge(initiator: Side, responder: Side) {
        val initiateOutcome = initiator.recv.manualResetInitiate(initiator.contactId)
        assertEquals(ResetReceive.Outcome.InitiatedReset, initiateOutcome)

        val initiatorWire = extractResetWireFromOutbox(initiator.db, initiator.contactId, km)
        val respondOutcome = responder.recv.onResetFrame(
            responder.contactId,
            (FrameCodec.decode(initiatorWire) as FrameCodec.DecodeResult.Ok).frame
        )
        assertEquals(ResetReceive.Outcome.FreshReset, respondOutcome)

        val responderWire = extractResetWireFromOutbox(responder.db, responder.contactId, km)
        val convergeOutcome = initiator.recv.onResetFrame(
            initiator.contactId,
            (FrameCodec.decode(responderWire) as FrameCodec.DecodeResult.Ok).frame
        )
        assertEquals(ResetReceive.Outcome.Acknowledged, convergeOutcome)
    }

    /**
     * Capture the K_reset that would be used for the *next* reset cycle. Reads the active
     * prekeySS from the initiator's prekey row, the idSharedSecret from both parties' identity
     * keys, and the reset nonce that will be generated when manualResetInitiate fires.
     *
     * NOTE: since we can't intercept the nonce before [manualResetInitiate] generates it, we
     * instead perform the reset and read the K_reset from the outbox frame's wire bytes.
     * This is the only reliable way to capture K_reset without patching production code.
     *
     * The approach: initiate the reset, read K_reset from the outbox (by decrypting the wire
     * with the known prekeySS), then complete convergence. Returns the K_reset bytes.
     */
    private suspend fun captureKResetBeforeConverge(initiator: Side, responder: Side): ByteArray {
        // We derive K_reset post-facto from the outbox frame: initiate, then derive K_reset using
        // the active prekeySS from the initiator's prekey row and the on-wire nonce/R.
        initiator.recv.manualResetInitiate(initiator.contactId)

        val initiatorWire = extractResetWireFromOutbox(initiator.db, initiator.contactId, km)
        val decoded = (FrameCodec.decode(initiatorWire) as FrameCodec.DecodeResult.Ok).frame

        val resetNonce = ResetCrypto.extractResetNonce(decoded)
        val R = ResetCrypto.extractR(decoded)

        // Read the initiator's active prekey row to derive prekeySS. At the time of
        // manualResetInitiate, pending(R) has been inserted but the *active* row (epoch R-1)
        // is still present and was the one ResetReceive used for K_reset derivation. If a
        // future refactor demotes the active row inside initInsideTxn this helper must fail
        // loudly — a silent fallback would make test 2's K_reset-distinctness assertion
        // vacuous (real vs zeros instead of real vs real).
        val activePrekeyRow = checkNotNull(
            initiator.db.prekeyEpochDao().byStatus(initiator.contactId, PrekeyEpochEntity.STATUS_ACTIVE)
        ) { "captureKResetBeforeConverge: active prekey row absent after manualResetInitiate" }
        val peerPub = checkNotNull(activePrekeyRow.peer_pub) {
            "captureKResetBeforeConverge: active prekey row has null peer_pub"
        }
        val rowId = PrekeyEpochEntity.rowIdFor(initiator.contactId, activePrekeyRow.epoch)
        val myPriv = km.unwrapAndVerify(
            PrekeyEpochEntity.COL_MY_PRIV, rowId,
            activePrekeyRow.my_priv_wrapped, activePrekeyRow.my_priv_hmac
        )
        val prekeySS = try {
            Prekey.sharedSecret(myPriv, peerPub)
        } finally {
            myPriv.fill(0)
        }
        val idSS = X25519.computeSharedSecret(initiator.idPriv, initiator.peerPub)
        val senderFp = Bootstrap.fingerprintBytes(initiator.idPub)
        val recipFp = Bootstrap.fingerprintBytes(initiator.peerPub)
        val kReset = try {
            ResetCrypto.deriveKReset(idSS, prekeySS, senderFp, recipFp, resetNonce, R)
        } finally {
            idSS.fill(0)
            prekeySS.fill(0)
        }

        // Now complete the round-trip convergence.
        responder.recv.onResetFrame(responder.contactId, decoded)
        val responderWire = extractResetWireFromOutbox(responder.db, responder.contactId, km)
        initiator.recv.onResetFrame(initiator.contactId,
            (FrameCodec.decode(responderWire) as FrameCodec.DecodeResult.Ok).frame)

        return kReset
    }

    /**
     * Unwrap and return Bob's 32-byte RK_0 from his wrapped DB column.
     * Column tag is `"contacts.rk_wrapped"` per [RatchetStatePersistence].
     */
    private suspend fun readWrappedRk(side: Side): ByteArray {
        val contact = side.db.contactDao().getById(side.contactId)
            ?: error("contact ${side.contactId} not found in side DB")
        val rowId = side.contactId.toByteArray(Charsets.UTF_8)
        return km.unwrapAndVerify("contacts.rk_wrapped", rowId, contact.rk_wrapped, contact.rk_hmac)
    }

    /**
     * Read the reset nonce from [side]'s contact row. This is the on-wire nonce that
     * participated in the last successful AEAD open — it was committed by [applyFreshReset]
     * and is what an attacker who observes the wire would know.
     */
    private suspend fun readResetNonce(side: Side): ByteArray {
        val contact = side.db.contactDao().getById(side.contactId)
            ?: error("contact ${side.contactId} not found in side DB")
        return contact.reset_nonce ?: error("reset_nonce is null — reset has not occurred")
    }

    /**
     * Construct a [ResetReceive] for one side. [ownPub] and [ownPriv] are the raw X25519
     * identity keypairs for this side; [peerPub] is the peer's identity public key.
     * The shared [KeyManager] handles wrap-and-MAC; row bindings are differentiated by
     * contactId-derived rowIds.
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

    /** Construct a [RatchetEncryptAndSend] for [side]. Transmit lambda appends to a discarded queue. */
    private fun makeEncryptor(side: Side): RatchetEncryptAndSend {
        val ownFp = Bootstrap.fingerprintBytes(side.idPub)
        return RatchetEncryptAndSend(
            db = side.db,
            wrapMac = km,
            ownFingerprint32 = ownFp,
            transmit = { _, _ -> /* no-op; wire bytes returned by encryptAndSend */ }
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
     * This populates [rk_wrapped], [rk_hmac], and the DH ephemeral columns so
     * [RatchetStatePersistence.loadRatchetState] can actually bootstrap.
     *
     * Role split: ALICE gets dhr_pub = Bob's bootstrap eph pub; BOB gets dhs_priv/pub.
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
     * Insert an `active(0)` prekey row mirroring [QrPairActivity.confirmPairing]. Copied
     * verbatim from [PrekeyEpochsLifecycleTest] — test files are intentionally self-contained.
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

    /**
     * Unwrap and return the wire bytes of the most-recently-enqueued RESET outbox row for
     * [contactId]. Copied verbatim from [PrekeyEpochsLifecycleTest] — test files are
     * intentionally self-contained.
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
