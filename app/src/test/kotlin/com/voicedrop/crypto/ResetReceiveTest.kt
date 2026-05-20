package com.voicedrop.crypto

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.google.crypto.tink.config.TinkConfig
import com.google.crypto.tink.subtle.X25519
import com.voicedrop.network.FrameCodec
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.ContactEntity
import com.voicedrop.storage.PendingOutboundFrameEntity
import com.voicedrop.storage.PrekeyEpochEntity
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * DR13 §6.3 — receive-side state machine. Pre-AEAD drops, post-AEAD rate limits,
 * the three R_in branches (fresh / convergence / lost-ack), DH-state helpers,
 * and manual initiation.
 *
 * Robolectric + in-memory Room so the per-contact mutex and `runInTransaction`
 * boundary are real. WrapMac is the same AES-GCM + HMAC fake used by
 * `PersistenceInvariantsTest`.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class ResetReceiveTest {

    companion object {
        @BeforeClass
        @JvmStatic
        fun setUpClass() {
            TinkConfig.register()
        }
    }

    private lateinit var db: AppDatabase
    private lateinit var wrapMac: TestWrapMac

    /** Stable fixtures so tests don't depend on RNG. */
    private val idShared = ByteArray(32) { (0x80 + it).toByte() }
    private val initialTime = 1_700_000_000_000L

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        db = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        wrapMac = TestWrapMac()
        ContactMutexRegistry.clear()
    }

    @After
    fun tearDown() {
        db.close()
        ContactMutexRegistry.clear()
    }

    // ----- pre-AEAD drops -----

    @Test
    fun reset_replayedR_droppedAndRatchetUntouched() = runBlocking {
        val fx = freshContact(role = Role.ALICE, reset_epoch = 5)
        val before = currentRk(fx.contactId)

        // Peer sends R_in=3 — below contact.R=5 → strict-less-than drop.
        val frame = buildInboundFrame(fx, rIn = 3, ack = ResetCrypto.ACK_INITIATOR, resetNonce = randomNonce())
        val outcome = fx.receive.onResetFrame(fx.contactId, frame)

        assertSame(ResetReceive.Outcome.Replayed, outcome)
        // Contact unchanged.
        val after = db.contactDao().getById(fx.contactId)!!
        assertEquals(5, after.reset_epoch)
        assertEquals(0, after.expecting_ack)
        assertArrayEquals(before, after.rk_wrapped)
        // No outbox row.
        assertEquals(0, outboxCount(fx.contactId))
    }

    @Test
    fun reset_jumpAhead_capped_atPlus17() = runBlocking {
        val fx = freshContact(role = Role.ALICE, reset_epoch = 0)
        val frame = buildInboundFrame(fx, rIn = 17, ack = ResetCrypto.ACK_INITIATOR, resetNonce = randomNonce())
        val outcome = fx.receive.onResetFrame(fx.contactId, frame)
        assertSame(ResetReceive.Outcome.JumpAheadCapped, outcome)
        val after = db.contactDao().getById(fx.contactId)!!
        assertEquals(0, after.reset_epoch)
    }

    @Test
    fun reset_jumpAhead_acceptsPlus16() = runBlocking {
        val fx = freshContact(role = Role.ALICE, reset_epoch = 0)
        val frame = buildInboundFrame(fx, rIn = 16, ack = ResetCrypto.ACK_INITIATOR, resetNonce = randomNonce())
        val outcome = fx.receive.onResetFrame(fx.contactId, frame)
        assertSame(ResetReceive.Outcome.FreshReset, outcome)
        val after = db.contactDao().getById(fx.contactId)!!
        assertEquals(16, after.reset_epoch)
    }

    @Test
    fun reset_duringBudgetExhausted_refused() = runBlocking {
        val fx = freshContact(role = Role.ALICE, reset_epoch = 0)
        // Pre-set budget window to active.
        db.contactDao().upsert(
            db.contactDao().getById(fx.contactId)!!
                .copy(budget_exhausted_until = initialTime + 1_000_000L)
        )

        val frame = buildInboundFrame(fx, rIn = 1, ack = ResetCrypto.ACK_INITIATOR, resetNonce = randomNonce())
        val outcome = fx.receive.onResetFrame(fx.contactId, frame)

        assertSame(ResetReceive.Outcome.BudgetExhausted, outcome)
        val after = db.contactDao().getById(fx.contactId)!!
        assertEquals(0, after.reset_epoch) // not bumped
    }

    // ----- fresh-R path -----

    @Test
    fun reset_bumpsR_andBootstrapsFreshRK() = runBlocking {
        val fx = freshContact(role = Role.ALICE, reset_epoch = 2)
        val before = currentRk(fx.contactId)

        val resetNonce = randomNonce()
        val frame = buildInboundFrame(fx, rIn = 3, ack = ResetCrypto.ACK_INITIATOR, resetNonce = resetNonce)
        val outcome = fx.receive.onResetFrame(fx.contactId, frame)

        assertSame(ResetReceive.Outcome.FreshReset, outcome)
        val after = db.contactDao().getById(fx.contactId)!!
        assertEquals(3, after.reset_epoch)
        assertArrayEquals("reset_nonce persisted from on-wire", resetNonce, after.reset_nonce)
        // RK rotated.
        assertFalse(
            "rk_wrapped must change after fresh reset",
            after.rk_wrapped.contentEquals(before)
        )
        // We're Alice locally → no dhs_priv generated; peer is Bob → adopt peer's pub.
        assertNull("Alice-role: dhs_priv unset", after.dhs_priv_wrapped)
        assertNull("Alice-role: dhs_pub unset", after.dhs_pub)
        assertNotNull("Bob-peer: dhr_pub adopted", after.dhr_pub)
        // ack=1 enqueued.
        assertEquals(1, outboxCount(fx.contactId))
        // Sending chain wiped.
        assertNull(after.cks_wrapped); assertNull(after.ckr_wrapped)
        assertEquals(0, after.ns); assertEquals(0, after.nr); assertEquals(0, after.pn)
        // Inbound rate counter ticked.
        assertEquals(1, after.inbound_reset_count_24h)
    }

    @Test
    fun reset_fresh_asBobRecipient_generatesOwnEphemeral() = runBlocking {
        val fx = freshContact(role = Role.BOB, reset_epoch = 0)

        val frame = buildInboundFrame(fx, rIn = 1, ack = ResetCrypto.ACK_INITIATOR, resetNonce = randomNonce())
        val outcome = fx.receive.onResetFrame(fx.contactId, frame)

        assertSame(ResetReceive.Outcome.FreshReset, outcome)
        val after = db.contactDao().getById(fx.contactId)!!
        // Local is Bob → dhs filled, dhr null (peer was Alice).
        assertNotNull(after.dhs_priv_wrapped)
        assertNotNull(after.dhs_pub)
        assertNull(after.dhr_pub)
    }

    @Test
    fun reset_fresh_ackZero_enqueuesReplyAckOne() = runBlocking {
        val fx = freshContact(role = Role.ALICE, reset_epoch = 0)

        val frame = buildInboundFrame(fx, rIn = 1, ack = ResetCrypto.ACK_INITIATOR, resetNonce = randomNonce())
        fx.receive.onResetFrame(fx.contactId, frame)

        val row = db.pendingOutboundFrameDao().getByContact(fx.contactId).single()
        assertEquals(PendingOutboundFrameEntity.FRAME_KIND_RESET, row.frame_kind)
        val ack = decodeOutbox(fx, row)
        assertEquals(ResetCrypto.ACK_ACKNOWLEDGER, ack.ackByte)
        assertEquals(1, ack.rOut)
    }

    @Test
    fun reset_fresh_ackOne_doesNotEnqueueReply() = runBlocking {
        // A RESET arriving with ack=1 at fresh-R: peer is acking something we
        // never initiated. State setup happens; no outbox reply enqueued.
        val fx = freshContact(role = Role.ALICE, reset_epoch = 0)
        // Use Bob-peer + a real X25519 pub so the validator accepts.
        val frame = buildInboundFrame(fx, rIn = 1, ack = ResetCrypto.ACK_ACKNOWLEDGER, resetNonce = randomNonce())
        fx.receive.onResetFrame(fx.contactId, frame)
        assertEquals(0, outboxCount(fx.contactId))
        val after = db.contactDao().getById(fx.contactId)!!
        assertEquals(1, after.reset_epoch)
        // Per §6.3 pseudocode: expecting_ack = (ack == 0) = false here.
        assertEquals(0, after.expecting_ack)
    }

    @Test
    fun reset_postResetEphPub_lowOrderRejected() = runBlocking {
        // Build an inbound RESET whose Bob-peer plaintext slot is all-zero (a
        // recognized low-order point). Must be dropped post-AEAD.
        val fx = freshContact(role = Role.ALICE, reset_epoch = 0)
        val resetNonce = randomNonce()
        // Peer is Bob (by fixture). We craft postResetEphPub = zeros[32] → all-zero check trips.
        val frame = buildInboundFrameRaw(
            fx = fx,
            rIn = 1,
            ack = ResetCrypto.ACK_INITIATOR,
            resetNonce = resetNonce,
            postResetEphPub = ByteArray(ResetCrypto.POST_RESET_EPH_PUB_BYTES)
        )
        val outcome = fx.receive.onResetFrame(fx.contactId, frame)
        assertSame(ResetReceive.Outcome.PostResetEphRejected, outcome)
        // State untouched.
        val after = db.contactDao().getById(fx.contactId)!!
        assertEquals(0, after.reset_epoch)
        assertEquals(0, outboxCount(fx.contactId))
    }

    // ----- inbound rate limit -----

    @Test
    fun reset_inboundRateLimit_4FreshRPer24h() = runBlocking {
        // Sequence: 4 fresh-R bumps accepted (count = 1..4). Fifth → InboundRateLimited,
        // budget_exhausted_until set, ratchet NOT bumped.
        val fx = freshContact(role = Role.ALICE, reset_epoch = 0)
        for (i in 1..4) {
            val frame = buildInboundFrame(fx, rIn = i, ack = ResetCrypto.ACK_INITIATOR, resetNonce = randomNonce())
            val outcome = fx.receive.onResetFrame(fx.contactId, frame)
            assertSame("bump $i accepted", ResetReceive.Outcome.FreshReset, outcome)
        }
        val before5 = db.contactDao().getById(fx.contactId)!!
        assertEquals(4, before5.reset_epoch)
        assertEquals(4, before5.inbound_reset_count_24h)
        assertEquals(0L, before5.budget_exhausted_until)

        val frame5 = buildInboundFrame(fx, rIn = 5, ack = ResetCrypto.ACK_INITIATOR, resetNonce = randomNonce())
        val outcome5 = fx.receive.onResetFrame(fx.contactId, frame5)
        assertSame(ResetReceive.Outcome.InboundRateLimited, outcome5)

        val after5 = db.contactDao().getById(fx.contactId)!!
        assertEquals("R not bumped past cap", 4, after5.reset_epoch)
        assertTrue("budget window armed", after5.budget_exhausted_until > initialTime)
        assertEquals(
            "window end is now + 7d",
            initialTime + ResetReceive.BUDGET_EXHAUSTED_MS, after5.budget_exhausted_until
        )
    }

    // ----- convergence / lost-ack -----

    @Test
    fun reset_convergence_ackOneClearsExpectingAck() = runBlocking {
        // Simulate: we initiated (manual). Peer's ack=1 arrives at same R.
        val fx = freshContact(role = Role.ALICE, reset_epoch = 0)
        fx.receive.manualResetInitiate(fx.contactId)
        val mid = db.contactDao().getById(fx.contactId)!!
        assertEquals(1, mid.reset_epoch)
        assertEquals(1, mid.expecting_ack)
        val ourNonce = mid.reset_nonce!!.copyOf()
        // Outbox now has our initiator RESET.
        val initialOutbox = outboxCount(fx.contactId)
        assertEquals(1, initialOutbox)

        // Peer's ack=1 carries OUR persisted resetNonce (in the happy path; lost-ack
        // tests below verify the other case). We just need to deliver a valid AEAD
        // under (peerFp→ourFp, R=1, ourNonce).
        val frame = buildInboundFrame(fx, rIn = 1, ack = ResetCrypto.ACK_ACKNOWLEDGER, resetNonce = ourNonce)
        val outcome = fx.receive.onResetFrame(fx.contactId, frame)

        assertSame(ResetReceive.Outcome.Acknowledged, outcome)
        val after = db.contactDao().getById(fx.contactId)!!
        assertEquals(0, after.expecting_ack)
        // DR15: peer's ack-of-our-init drops our retransmit row so the [dr15]
        // schedule's next tick exits cleanly.
        assertEquals(0, outboxCount(fx.contactId))
        assertTrue("initialOutbox should have been 1 before the ack arrived", initialOutbox == 1)
    }

    @Test
    fun reset_init_deletesStaleOutboxResetRows_beforeNewInsert() = runBlocking {
        // First init lays down RESET row at R=1.
        val fx = freshContact(role = Role.ALICE, reset_epoch = 0)
        fx.receive.manualResetInitiate(fx.contactId)
        assertEquals(1, outboxCount(fx.contactId))

        // Force a second manual init — older row should be deleted before INSERT.
        fx.receive.manualResetInitiate(fx.contactId)

        // Only ONE RESET row remains, for R=2.
        val rows = db.pendingOutboundFrameDao().getByContact(fx.contactId)
        assertEquals(1, rows.size)
        val ack = decodeOutbox(fx, rows.single())
        assertEquals(2, ack.rOut)
    }

    @Test
    fun reset_freshR_deletesStaleOutboxResetRows() = runBlocking {
        // Set up: we initiated at R=1 (row in outbox), then peer initiates at R=2.
        val fx = freshContact(role = Role.ALICE, reset_epoch = 0)
        fx.receive.manualResetInitiate(fx.contactId)
        assertEquals(1, outboxCount(fx.contactId))

        // Peer's R_in=2 frame — supersedes our R=1 init.
        val nonce = randomNonce()
        val frame = buildInboundFrame(fx, rIn = 2, ack = ResetCrypto.ACK_INITIATOR, resetNonce = nonce)
        val outcome = fx.receive.onResetFrame(fx.contactId, frame)
        assertSame(ResetReceive.Outcome.FreshReset, outcome)

        // Our stale R=1 RESET row gone. The applyFreshReset ack=0 branch enqueued a
        // new ack=1 row at R=2 — so outbox count is 1, not 0.
        val rows = db.pendingOutboundFrameDao().getByContact(fx.contactId)
        assertEquals(1, rows.size)
        val ack = decodeOutbox(fx, rows.single())
        assertEquals(2, ack.rOut)
        assertEquals(ResetCrypto.ACK_ACKNOWLEDGER, ack.ackByte)
    }

    @Test
    fun reset_convergence_dupAckZero_reAcks() = runBlocking {
        // Simulate: we initiated. Peer retransmits ack=0 (their initial RESET).
        // We should re-enqueue our ack=1 using OUR persisted nonce.
        val fx = freshContact(role = Role.ALICE, reset_epoch = 0)
        fx.receive.manualResetInitiate(fx.contactId)
        val ourNonce = db.contactDao().getById(fx.contactId)!!.reset_nonce!!.copyOf()
        val initialOutbox = outboxCount(fx.contactId)

        // Peer's retransmit uses THEIR nonce (different from ours). K_reset on
        // the wire is keyed under peer's nonce; we still derive correctly because
        // we read the on-wire nonce from the header.
        val theirNonce = randomNonce()
        assertNotEquals(ourNonce.toHexLower(), theirNonce.toHexLower())
        val frame = buildInboundFrame(fx, rIn = 1, ack = ResetCrypto.ACK_INITIATOR, resetNonce = theirNonce)
        val outcome = fx.receive.onResetFrame(fx.contactId, frame)
        assertSame(ResetReceive.Outcome.Reacked, outcome)

        assertEquals(initialOutbox + 1, outboxCount(fx.contactId))
        val newest = db.pendingOutboundFrameDao().getByContact(fx.contactId).last()
        val ack = decodeOutbox(fx, newest)
        // Our re-ack uses OUR persisted nonce per §6.3, NOT the peer's.
        assertArrayEquals(ourNonce, ack.resetNonce)
        assertEquals(ResetCrypto.ACK_ACKNOWLEDGER, ack.ackByte)
    }

    @Test
    fun reset_lostAck_dupInitiator_recipientReAcks() = runBlocking {
        // Sequence: peer sends fresh ack=0 → we process (no init from our side, so
        // !expecting_ack after fresh-R per literal spec... ACTUALLY spec sets
        // expecting_ack=(ack==0)=true on fresh-R recipient side, so this dup goes
        // through CONVERGENCE branch, not lost-ack. So this test is renamed.)
        //
        // To exercise the literal lost-ack branch (R_in == R, !expecting_ack) we'd
        // need recipient.expecting_ack=false at same R — only reachable by future
        // protocol refinements. For now we test the practical "duplicate initiator
        // re-acks" scenario which lands in CONVERGENCE.
        val fx = freshContact(role = Role.ALICE, reset_epoch = 0)
        val resetNonce = randomNonce()
        val first = buildInboundFrame(fx, rIn = 1, ack = ResetCrypto.ACK_INITIATOR, resetNonce = resetNonce)
        fx.receive.onResetFrame(fx.contactId, first)
        val mid = db.contactDao().getById(fx.contactId)!!
        assertEquals(1, mid.reset_epoch)
        assertEquals(1, mid.expecting_ack) // recipient stays expecting per spec literal
        val initialOutbox = outboxCount(fx.contactId)
        assertEquals(1, initialOutbox)

        // Peer retransmits the SAME RESET (same nonce — bit-identical idempotent).
        val dup = buildInboundFrame(fx, rIn = 1, ack = ResetCrypto.ACK_INITIATOR, resetNonce = resetNonce)
        val outcome = fx.receive.onResetFrame(fx.contactId, dup)

        // R unchanged, but a new ack=1 RESET enqueued (convergence ack==0 branch).
        assertSame(ResetReceive.Outcome.Reacked, outcome)
        val after = db.contactDao().getById(fx.contactId)!!
        assertEquals(1, after.reset_epoch)
        assertEquals(initialOutbox + 1, outboxCount(fx.contactId))
    }

    // ----- AEAD failure / direction binding -----

    @Test
    fun reset_aeadFailure_doesNotMutateState() = runBlocking {
        val fx = freshContact(role = Role.ALICE, reset_epoch = 0)
        val before = currentRk(fx.contactId)
        // Build a frame, then tamper with the AEAD tag.
        val resetNonce = randomNonce()
        val frame = buildInboundFrame(fx, rIn = 1, ack = ResetCrypto.ACK_INITIATOR, resetNonce = resetNonce)
        val tamperedCt = frame.ciphertext.copyOf()
        tamperedCt[tamperedCt.size - 1] = (tamperedCt[tamperedCt.size - 1].toInt() xor 0x01).toByte()
        val tamperedFrame = frame.copy(ciphertext = tamperedCt)

        val outcome = fx.receive.onResetFrame(fx.contactId, tamperedFrame)

        assertSame(ResetReceive.Outcome.AeadFailure, outcome)
        val after = db.contactDao().getById(fx.contactId)!!
        assertEquals(0, after.reset_epoch)
        assertArrayEquals(before, after.rk_wrapped)
    }

    // ----- manual initiation -----

    @Test
    fun reset_manualTriggerRoundTrip() = runBlocking {
        val fx = freshContact(role = Role.ALICE, reset_epoch = 2)
        val before = currentRk(fx.contactId)

        val outcome = fx.receive.manualResetInitiate(fx.contactId)
        assertSame(ResetReceive.Outcome.InitiatedReset, outcome)

        val after = db.contactDao().getById(fx.contactId)!!
        assertEquals(3, after.reset_epoch)
        assertEquals(1, after.expecting_ack)
        assertNotNull(after.reset_nonce)
        assertFalse("rk rotates on init", after.rk_wrapped.contentEquals(before))
        // Alice-role: no dhs generated, but persisted state was wiped.
        assertNull(after.dhs_priv_wrapped)
        assertNull(after.dhs_pub)
        assertNull(after.dhr_pub)
        // RESET row enqueued.
        val row = db.pendingOutboundFrameDao().getByContact(fx.contactId).single()
        assertEquals(PendingOutboundFrameEntity.FRAME_KIND_RESET, row.frame_kind)
        val ack = decodeOutbox(fx, row)
        assertEquals(ResetCrypto.ACK_INITIATOR, ack.ackByte)
        assertEquals(3, ack.rOut)
        assertArrayEquals(after.reset_nonce, ack.resetNonce)
    }

    @Test
    fun reset_manualInit_asBob_generatesEphemeral() = runBlocking {
        val fx = freshContact(role = Role.BOB, reset_epoch = 0)
        fx.receive.manualResetInitiate(fx.contactId)
        val after = db.contactDao().getById(fx.contactId)!!
        assertNotNull(after.dhs_priv_wrapped)
        assertNotNull(after.dhs_pub)
        // Bob's outbound RESET carries his fresh pub in the plaintext slot.
        val row = db.pendingOutboundFrameDao().getByContact(fx.contactId).single()
        val ack = decodeOutbox(fx, row)
        assertArrayEquals(after.dhs_pub, ack.postResetEphPub)
    }

    @Test
    fun reset_manualInit_refusedDuringBudgetExhausted() = runBlocking {
        val fx = freshContact(role = Role.ALICE, reset_epoch = 0)
        db.contactDao().upsert(
            db.contactDao().getById(fx.contactId)!!.copy(budget_exhausted_until = initialTime + 1_000_000L)
        )
        val outcome = fx.receive.manualResetInitiate(fx.contactId)
        assertSame(ResetReceive.Outcome.InitiationRefusedBudget, outcome)
        val after = db.contactDao().getById(fx.contactId)!!
        assertEquals(0, after.reset_epoch)
        assertEquals(0, outboxCount(fx.contactId))
    }

    // =========================================================================
    // Fixtures
    // =========================================================================

    private enum class Role { ALICE, BOB }

    private class Fixture(
        val contactId: String,
        val ownIdPriv: ByteArray,
        val ownIdPub: ByteArray,
        val ownFp: ByteArray,
        val peerIdPriv: ByteArray,
        val peerIdPub: ByteArray,
        val peerFp: ByteArray,
        val role: Role,
        val receive: ResetReceive
    )

    /**
     * Build a paired contact in DR3 schema. Caller picks the local role: ALICE
     * means our fingerprint sorts lower than peer's (we're the post-reset Alice).
     */
    private fun freshContact(role: Role, reset_epoch: Int): Fixture {
        var ownPriv: ByteArray; var ownPub: ByteArray
        var peerPriv: ByteArray; var peerPub: ByteArray
        while (true) {
            ownPriv = X25519.generatePrivateKey()
            ownPub = X25519.publicFromPrivate(ownPriv)
            peerPriv = X25519.generatePrivateKey()
            peerPub = X25519.publicFromPrivate(peerPriv)
            val ownFp = Bootstrap.fingerprintBytes(ownPub)
            val peerFp = Bootstrap.fingerprintBytes(peerPub)
            val cmp = compareUnsignedBytes(ownFp, peerFp)
            val ownIsAlice = cmp < 0
            if (role == Role.ALICE && ownIsAlice) break
            if (role == Role.BOB && !ownIsAlice) break
        }
        val ownFp = Bootstrap.fingerprintBytes(ownPub)
        val peerFp = Bootstrap.fingerprintBytes(peerPub)
        val contactId = peerPub.toHexLower()

        // Seed contact with a wrapped sentinel rk (the value's irrelevant for
        // these tests; the wrap-hmac must just verify).
        val seedRk = ByteArray(32) { (0x10 + it).toByte() }
        val rowId = contactId.toByteArray(Charsets.UTF_8)
        val (rkW, rkH) = wrapMac.wrapAndMac("contacts.rk_wrapped", rowId, seedRk)

        runBlocking {
            db.contactDao().upsert(
                ContactEntity(
                    id = contactId,
                    name = "peer",
                    publicKeyBase64 = android.util.Base64.encodeToString(peerPub, android.util.Base64.NO_WRAP),
                    addedAt = 0L,
                    rk_wrapped = rkW,
                    rk_hmac = rkH,
                    reset_epoch = reset_epoch
                )
            )
        }

        // §3.2 — seed the active(epoch=0) prekey row. After this point,
        // production rotates active on every FreshReset, so any test that
        // constructs synthetic frames in a loop must re-read the current
        // active row each iteration via [activePrekeySS] (not a fixed seed
        // value snapshotted at fixture time).
        seedActivePrekey0(contactId)

        val idShared = this.idShared
        val receive = ResetReceive(
            db = db,
            wrapMac = wrapMac,
            ownFingerprint32 = ownFp,
            idSharedSecretFor = { idShared.copyOf() },
            clock = { initialTime }
        )
        return Fixture(
            contactId = contactId,
            ownIdPriv = ownPriv, ownIdPub = ownPub, ownFp = ownFp,
            peerIdPriv = peerPriv, peerIdPub = peerPub, peerFp = peerFp,
            role = role,
            receive = receive
        )
    }

    /** Insert active(epoch=0) prekey row with freshly-generated keys. */
    private fun seedActivePrekey0(contactId: String) = runBlocking {
        val kp = Prekey.generate()
        val peerPrekeyPub = X25519.publicFromPrivate(X25519.generatePrivateKey())
        val rowId = PrekeyEpochEntity.rowIdFor(contactId, 0)
        val (privW, privH) = wrapMac.wrapAndMac(PrekeyEpochEntity.COL_MY_PRIV, rowId, kp.priv)
        db.prekeyEpochDao().insert(
            PrekeyEpochEntity(
                contact_id = contactId,
                epoch = 0,
                status = PrekeyEpochEntity.STATUS_ACTIVE,
                my_priv_wrapped = privW,
                my_priv_hmac = privH,
                my_pub = kp.pub,
                peer_pub = peerPrekeyPub,
                expires_at = null
            )
        )
    }

    /**
     * Read the current `status='active'` (or 'previous') prekey row and
     * compute `prekeySS = X25519(unwrap(my_priv), peer_pub)`. Mirrors
     * production [ResetReceive.loadActivePrekeySS]. Returns null when no
     * such row exists — caller falls back to the other status as needed.
     *
     * Must be called fresh each time the test synthesizes a K_reset because
     * `applyFreshReset` rotates the active row on every successful inbound:
     * a fixture-time snapshot goes stale after the first reset cycle.
     */
    private fun prekeySSForStatus(contactId: String, status: String): ByteArray? = runBlocking {
        val row = db.prekeyEpochDao().byStatusBlocking(contactId, status) ?: return@runBlocking null
        val peer = row.peer_pub ?: return@runBlocking null
        val rId = PrekeyEpochEntity.rowIdFor(contactId, row.epoch)
        val priv = wrapMac.unwrapAndVerify(
            PrekeyEpochEntity.COL_MY_PRIV, rId, row.my_priv_wrapped, row.my_priv_hmac
        )
        try {
            Prekey.sharedSecret(priv, peer)
        } finally {
            priv.fill(0)
        }
    }

    private fun activePrekeySS(contactId: String): ByteArray =
        prekeySSForStatus(contactId, PrekeyEpochEntity.STATUS_ACTIVE)
            ?: error("no active prekey row for $contactId — fixture not seeded?")

    /**
     * Build an inbound RESET frame as if it came from the peer. Selects a valid
     * postResetEphPub automatically — generates a fresh X25519 pub if peer is
     * Bob, zeros otherwise (Alice-role peer's slot is unused per §6.1).
     */
    private fun buildInboundFrame(
        fx: Fixture,
        rIn: Int,
        ack: Byte,
        resetNonce: ByteArray
    ): FrameCodec.DecodedFrame {
        // peer's role from peer's POV: peer is Bob iff peerFp >= ownFp.
        val peerIsBob = compareUnsignedBytes(fx.peerFp, fx.ownFp) >= 0
        val postResetEphPub = if (peerIsBob) {
            val priv = X25519.generatePrivateKey()
            X25519.publicFromPrivate(priv)
        } else {
            ByteArray(ResetCrypto.POST_RESET_EPH_PUB_BYTES)
        }
        return buildInboundFrameRaw(fx, rIn, ack, resetNonce, postResetEphPub)
    }

    private fun buildInboundFrameRaw(
        fx: Fixture,
        rIn: Int,
        ack: Byte,
        resetNonce: ByteArray,
        postResetEphPub: ByteArray
    ): FrameCodec.DecodedFrame {
        // K_reset from peer's POV: sender=peer, recip=us, R=rIn, nonce=resetNonce.
        // §3.2 — re-read the active prekey row at frame-build time. Tests that
        // build multiple frames in sequence (e.g. [reset_inboundRateLimit_4FreshRPer24h])
        // must use the CURRENT active row because production rotates active on
        // every FreshReset; a snapshot from fixture time goes stale after one cycle.
        val prekeySS = activePrekeySS(fx.contactId)
        val kReset = ResetCrypto.deriveKReset(idShared, prekeySS, fx.peerFp, fx.ownFp, resetNonce, rIn)
        val uuid = ByteArray(FrameCodec.UUID_BYTES).also { SecureRandom().nextBytes(it) }
        val wire = ResetCrypto.encode(
            senderFp = fx.peerFp,
            recipFp = fx.ownFp,
            resetNonce = resetNonce,
            R = rIn,
            uuid = uuid,
            timestampMs = initialTime,
            plaintext = ResetCrypto.Plaintext(
                ack = ack,
                postResetEphPub = postResetEphPub,
                // §3.2 — production validates this via [isValidX25519Public]
                // (rejects all-zero / low-order points). Generate a fresh X25519
                // pub so the validator always passes regardless of the test.
                stagedPrekeyPub = X25519.publicFromPrivate(X25519.generatePrivateKey())
            ),
            kReset = kReset
        )
        return (FrameCodec.decode(wire) as FrameCodec.DecodeResult.Ok).frame
    }

    private fun currentRk(contactId: String): ByteArray =
        runBlocking { db.contactDao().getById(contactId)!!.rk_wrapped.copyOf() }

    private fun outboxCount(contactId: String): Int =
        runBlocking { db.pendingOutboundFrameDao().countForContact(contactId) }

    /** Decode + open one of our outbound RESET rows so we can inspect what we sent. */
    private fun decodeOutbox(fx: Fixture, row: PendingOutboundFrameEntity): DecodedAck {
        val wire = wrapMac.unwrapAndVerify(
            "pending_outbound_frames.wrapped_frame", row.uuid, row.wrapped_frame, row.frame_hmac
        )
        val frame = (FrameCodec.decode(wire) as FrameCodec.DecodeResult.Ok).frame
        val resetNonce = ResetCrypto.extractResetNonce(frame)
        val rOut = ResetCrypto.extractR(frame)
        // §3.2 — outbounds enqueued during processInsideTxn are encoded with the
        // SAME prekeySS that opened the inbound. After applyFreshReset rotates
        // active → previous, decoding the outbound needs the previous row's
        // prekeySS (active was just regenerated and doesn't match). For paths
        // that don't rotate (manualResetInitiate's outbound; applyConvergence's
        // re-ack), active is still right. Mirror production's §6.5 fallback:
        // try active first, then previous.
        val pt = tryDecodeOutbox(fx, frame, resetNonce, rOut, PrekeyEpochEntity.STATUS_ACTIVE)
            ?: tryDecodeOutbox(fx, frame, resetNonce, rOut, PrekeyEpochEntity.STATUS_PREVIOUS)
            ?: error("decodeOutbox: AEAD failed under both active and previous prekeys")
        return DecodedAck(
            rOut = rOut,
            resetNonce = resetNonce,
            ackByte = pt.ack,
            postResetEphPub = pt.postResetEphPub
        )
    }

    private fun tryDecodeOutbox(
        fx: Fixture,
        frame: FrameCodec.DecodedFrame,
        resetNonce: ByteArray,
        rOut: Int,
        status: String
    ): ResetCrypto.Plaintext? {
        val prekeySS = prekeySSForStatus(fx.contactId, status) ?: return null
        val kReset = ResetCrypto.deriveKReset(idShared, prekeySS, fx.ownFp, fx.peerFp, resetNonce, rOut)
        return try {
            (ResetCrypto.decrypt(frame, kReset) as? ResetCrypto.DecodeOutcome.Ok)?.plaintext
        } finally {
            kReset.fill(0)
        }
    }

    private class DecodedAck(
        val rOut: Int,
        val resetNonce: ByteArray,
        val ackByte: Byte,
        val postResetEphPub: ByteArray
    )

    private fun randomNonce(): ByteArray =
        ByteArray(ResetCrypto.RESET_NONCE_BYTES).also { SecureRandom().nextBytes(it) }

    private fun ByteArray.toHexLower(): String = joinToString("") { "%02x".format(it) }

    private fun compareUnsignedBytes(a: ByteArray, b: ByteArray): Int {
        require(a.size == b.size)
        for (i in a.indices) {
            val av = a[i].toInt() and 0xff
            val bv = b[i].toInt() and 0xff
            if (av != bv) return av - bv
        }
        return 0
    }

    /** Same shape as PersistenceInvariantsTest's TestWrapMac — duplicated to keep this file standalone. */
    private class TestWrapMac : WrapMac {
        private val wrapKey: SecretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        private val macKey: SecretKey = SecretKeySpec(ByteArray(32).also { SecureRandom().nextBytes(it) }, "HmacSHA256")

        override fun wrapAndMac(columnName: String, rowId: ByteArray, plain: ByteArray): kotlin.Pair<ByteArray, ByteArray> {
            val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, wrapKey, GCMParameterSpec(128, iv))
            val ctAndTag = cipher.doFinal(plain)
            val wrapped = iv + ctAndTag
            val hmac = bindingHmac(columnName, rowId, wrapped)
            return wrapped to hmac
        }

        override fun unwrapAndVerify(columnName: String, rowId: ByteArray, wrapped: ByteArray, hmac: ByteArray): ByteArray {
            val expected = bindingHmac(columnName, rowId, wrapped)
            if (!MessageDigest.isEqual(expected, hmac)) throw WrapHmacMismatch()
            val iv = wrapped.copyOfRange(0, 12)
            val ctAndTag = wrapped.copyOfRange(12, wrapped.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, wrapKey, GCMParameterSpec(128, iv))
            return cipher.doFinal(ctAndTag)
        }

        private fun bindingHmac(column: String, rowId: ByteArray, wrapped: ByteArray): ByteArray =
            Mac.getInstance("HmacSHA256").run {
                init(macKey)
                update(column.toByteArray(Charsets.UTF_8))
                update(0x00.toByte())
                update(rowId)
                update(0x00.toByte())
                update(wrapped)
                doFinal()
            }
    }
}
