package com.voicedrop.crypto

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.google.crypto.tink.config.TinkConfig
import com.google.crypto.tink.subtle.X25519
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.ContactEntity
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
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
 * DR14 §6.4 — Auto-reset trigger classifier + 4/24h rate gate + 7d budget refuse.
 *
 * Robolectric + in-memory Room so [AutoResetTrigger] can run its real
 * `runInTransaction` gate and the real [ResetReceive.manualResetInitiate] fires.
 *
 * Tests **`reset_autoTrigger_onStructuralCorruption_butNotOnAeadFailure`** and
 * **`reset_autoTriggerRateLimit_4Per24h`** are load-bearing regression guards
 * per dr14-reset-triggers.md — never delete them.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class AutoResetTriggerTest {

    companion object {
        @BeforeClass
        @JvmStatic
        fun setUpClass() {
            TinkConfig.register()
        }
    }

    private lateinit var db: AppDatabase
    private lateinit var wrapMac: TestWrapMac
    private val idShared = ByteArray(32) { (0x40 + it).toByte() }
    private var nowMs = 1_700_000_000_000L

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

    // -------------------------------------------------------------------------
    // Classifier — eligibility
    // -------------------------------------------------------------------------

    @Test
    fun classify_structuralCorrupt_isStructural() {
        val ex = RatchetStatePersistence.RatchetStateCorrupt("c", "cks wrapped/hmac mismatch")
        assertSame(AutoResetTrigger.FailureClass.STRUCTURAL, AutoResetTrigger.classify(ex))
    }

    @Test
    fun classify_wrapHmacMismatch_isCryptoTamper() {
        assertSame(AutoResetTrigger.FailureClass.CRYPTO_TAMPER, AutoResetTrigger.classify(WrapHmacMismatch()))
    }

    @Test
    fun classify_aead_isAead() {
        assertSame(
            AutoResetTrigger.FailureClass.AEAD,
            AutoResetTrigger.classify(RatchetCryptoFailure(RuntimeException("aead")))
        )
    }

    @Test
    fun classify_ratchetNotBootstrapped_isOther() {
        assertSame(
            AutoResetTrigger.FailureClass.OTHER,
            AutoResetTrigger.classify(RatchetStatePersistence.RatchetNotBootstrapped("c"))
        )
    }

    @Test
    fun classify_arbitrary_isOther() {
        assertSame(AutoResetTrigger.FailureClass.OTHER, AutoResetTrigger.classify(IllegalArgumentException()))
    }

    // -------------------------------------------------------------------------
    // Top-level: auto-reset on structural corruption ONLY (LOAD-BEARING)
    // -------------------------------------------------------------------------

    /**
     * Load-bearing per dr14-reset-triggers.md — auto-reset MUST fire on
     * RatchetStateCorrupt and MUST NOT fire on RatchetCryptoFailure.
     */
    @Test
    fun reset_autoTrigger_onStructuralCorruption_butNotOnAeadFailure() = runBlocking {
        val fx = freshContact(role = Role.ALICE, reset_epoch = 0)

        // 10 tampered DATA frames mapped through classify ⇒ all AEAD ⇒ no fire.
        repeat(10) {
            val outcome = fx.trigger.onStructuralCorruption(fx.contactId, RatchetCryptoFailure(RuntimeException()))
            assertSame(AutoResetTrigger.Decision.SkippedNotStructural, outcome)
        }
        assertEquals(0, outboxCount(fx.contactId))
        assertEquals(0, db.contactDao().getById(fx.contactId)!!.auto_reset_count_24h)

        // One synthetic DB-corruption signal → fires.
        val decision = fx.trigger.onStructuralCorruption(
            fx.contactId,
            RatchetStatePersistence.RatchetStateCorrupt(fx.contactId, "ckr wrapped/hmac mismatch")
        )
        assertTrue("expected Triggered, got $decision", decision is AutoResetTrigger.Decision.Triggered)
        assertEquals(1, db.contactDao().getById(fx.contactId)!!.auto_reset_count_24h)
        assertEquals(1, outboxCount(fx.contactId))
        assertEquals(1, db.contactDao().getById(fx.contactId)!!.reset_epoch)
    }

    @Test
    fun reset_autoTrigger_NOT_onWrapHmacMismatch() = runBlocking {
        val fx = freshContact(role = Role.ALICE, reset_epoch = 0)
        val outcome = fx.trigger.onStructuralCorruption(fx.contactId, WrapHmacMismatch())
        assertSame(AutoResetTrigger.Decision.SkippedNotStructural, outcome)
        assertEquals(0, outboxCount(fx.contactId))
        assertEquals(0, db.contactDao().getById(fx.contactId)!!.auto_reset_count_24h)
    }

    // -------------------------------------------------------------------------
    // Rate limit + backoff
    // -------------------------------------------------------------------------

    /**
     * Load-bearing per dr14-reset-triggers.md — 4/24h cap MUST arm 7d budget.
     */
    @Test
    fun reset_autoTriggerRateLimit_4Per24h() = runBlocking {
        val fx = freshContact(role = Role.ALICE, reset_epoch = 0)

        // Attempt 1 — immediate fire.
        assertTrue(fx.trigger.onStructuralCorruption(fx.contactId, structural()) is AutoResetTrigger.Decision.Triggered)

        // Attempt 2 — 30s later.
        nowMs += 30_000L
        assertTrue(fx.trigger.onStructuralCorruption(fx.contactId, structural()) is AutoResetTrigger.Decision.Triggered)

        // Attempt 3 — 5min later.
        nowMs += 5L * 60 * 1000
        assertTrue(fx.trigger.onStructuralCorruption(fx.contactId, structural()) is AutoResetTrigger.Decision.Triggered)

        // Attempt 4 — 30min later.
        nowMs += 30L * 60 * 1000
        assertTrue(fx.trigger.onStructuralCorruption(fx.contactId, structural()) is AutoResetTrigger.Decision.Triggered)

        assertEquals(4, db.contactDao().getById(fx.contactId)!!.auto_reset_count_24h)
        // Only one initiator RESET row exists per contact at a time: each
        // manualResetInitiate calls deleteResetOutboxRowsInsideTxn before
        // inserting (see ResetReceive.initInsideTxn). Counter is the auth.
        assertEquals(1, outboxCount(fx.contactId))

        // Attempt 5 — even after a long wait, cap arms budget refuse window.
        nowMs += 1L * 60 * 60 * 1000
        val capped = fx.trigger.onStructuralCorruption(fx.contactId, structural())
        assertTrue("expected BudgetExhaustedNow, got $capped", capped is AutoResetTrigger.Decision.BudgetExhaustedNow)
        val budgetUntil = (capped as AutoResetTrigger.Decision.BudgetExhaustedNow).until
        assertEquals(nowMs + AutoResetTrigger.BUDGET_EXHAUSTED_MS, budgetUntil)
        assertEquals(1, outboxCount(fx.contactId)) // still the single standing RESET row

        // Subsequent calls during the 7d window → SkippedBudgetExhausted.
        nowMs += 60_000L
        val later = fx.trigger.onStructuralCorruption(fx.contactId, structural())
        assertTrue("expected SkippedBudgetExhausted, got $later", later is AutoResetTrigger.Decision.SkippedBudgetExhausted)
    }

    @Test
    fun reset_budgetExhausted_refusesAutoReset_for7d() = runBlocking {
        val fx = freshContact(role = Role.ALICE, reset_epoch = 0)
        // Pre-arm budget.
        db.contactDao().upsert(
            db.contactDao().getById(fx.contactId)!!.copy(budget_exhausted_until = nowMs + 1_000_000L)
        )
        val outcome = fx.trigger.onStructuralCorruption(fx.contactId, structural())
        assertTrue(outcome is AutoResetTrigger.Decision.SkippedBudgetExhausted)
        assertEquals(0, outboxCount(fx.contactId))
    }

    @Test
    fun autoTrigger_backoff_30s_betweenAttempts1and2() = runBlocking {
        val fx = freshContact(role = Role.ALICE, reset_epoch = 0)
        assertTrue(fx.trigger.onStructuralCorruption(fx.contactId, structural()) is AutoResetTrigger.Decision.Triggered)

        // 29s later — still rate-limited.
        nowMs += 29_000L
        val limited = fx.trigger.onStructuralCorruption(fx.contactId, structural())
        assertTrue("expected SkippedRateLimited at +29s, got $limited", limited is AutoResetTrigger.Decision.SkippedRateLimited)
        assertEquals(1, db.contactDao().getById(fx.contactId)!!.auto_reset_count_24h)
        assertEquals(1, outboxCount(fx.contactId))

        // 30s+ later — fires.
        nowMs += 2_000L
        assertTrue(fx.trigger.onStructuralCorruption(fx.contactId, structural()) is AutoResetTrigger.Decision.Triggered)
        assertEquals(2, db.contactDao().getById(fx.contactId)!!.auto_reset_count_24h)
        // Outbox still 1 — the second fire replaced (not added) the standing RESET row.
        assertEquals(1, outboxCount(fx.contactId))
    }

    @Test
    fun autoTrigger_backoff_5min_betweenAttempts2and3() = runBlocking {
        val fx = freshContact(role = Role.ALICE, reset_epoch = 0)
        // Burn attempts 1+2.
        assertTrue(fx.trigger.onStructuralCorruption(fx.contactId, structural()) is AutoResetTrigger.Decision.Triggered)
        nowMs += 30_000L
        assertTrue(fx.trigger.onStructuralCorruption(fx.contactId, structural()) is AutoResetTrigger.Decision.Triggered)

        // 30s after #2 — must still be rate-limited (need 5min).
        nowMs += 30_000L
        assertTrue(fx.trigger.onStructuralCorruption(fx.contactId, structural()) is AutoResetTrigger.Decision.SkippedRateLimited)

        // 5min after #2 — fires.
        nowMs += (5L * 60 * 1000 - 30_000L)
        assertTrue(fx.trigger.onStructuralCorruption(fx.contactId, structural()) is AutoResetTrigger.Decision.Triggered)
        assertEquals(3, db.contactDao().getById(fx.contactId)!!.auto_reset_count_24h)
    }

    @Test
    fun autoTrigger_windowRollsOver_after24h() = runBlocking {
        val fx = freshContact(role = Role.ALICE, reset_epoch = 0)
        // Burn all 4 within a few hours.
        assertTrue(fx.trigger.onStructuralCorruption(fx.contactId, structural()) is AutoResetTrigger.Decision.Triggered)
        nowMs += AutoResetTrigger.BACKOFF_SCHEDULE_MS[0] + 1
        assertTrue(fx.trigger.onStructuralCorruption(fx.contactId, structural()) is AutoResetTrigger.Decision.Triggered)
        nowMs += AutoResetTrigger.BACKOFF_SCHEDULE_MS[1] + 1
        assertTrue(fx.trigger.onStructuralCorruption(fx.contactId, structural()) is AutoResetTrigger.Decision.Triggered)
        nowMs += AutoResetTrigger.BACKOFF_SCHEDULE_MS[2] + 1
        assertTrue(fx.trigger.onStructuralCorruption(fx.contactId, structural()) is AutoResetTrigger.Decision.Triggered)
        assertEquals(4, db.contactDao().getById(fx.contactId)!!.auto_reset_count_24h)

        // Clear the budget-exhausted arming the 5th attempt would set, then jump >24h
        // past the window-start. The next structural failure should be treated as a
        // fresh window (count=1) — but the test contact still has its
        // budget_exhausted_until set if a 5th fire happened. Drive into the window
        // BEFORE going past the 4th: 23.99h after start, attempt 5 fires budget;
        // 25h after start, fresh window opens.
        nowMs = db.contactDao().getById(fx.contactId)!!.auto_reset_window_start + AutoResetTrigger.WINDOW_24H_MS + 60_000L
        // Clear budget if any so the gate doesn't refuse on that branch.
        db.contactDao().upsert(db.contactDao().getById(fx.contactId)!!.copy(budget_exhausted_until = 0L))

        assertTrue(fx.trigger.onStructuralCorruption(fx.contactId, structural()) is AutoResetTrigger.Decision.Triggered)
        val after = db.contactDao().getById(fx.contactId)!!
        assertEquals(1, after.count24hOf())
        assertEquals(nowMs, after.auto_reset_window_start)
    }

    // -------------------------------------------------------------------------
    // Fixtures
    // -------------------------------------------------------------------------

    private fun structural(): Throwable =
        RatchetStatePersistence.RatchetStateCorrupt("c", "cks wrapped/hmac mismatch")

    private enum class Role { ALICE, BOB }

    private class Fixture(
        val contactId: String,
        val ownIdPriv: ByteArray,
        val ownIdPub: ByteArray,
        val ownFp: ByteArray,
        val peerIdPub: ByteArray,
        val role: Role,
        val receive: ResetReceive,
        val trigger: AutoResetTrigger
    )

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
        val contactId = peerPub.toHexLower()

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

        val idSharedSnapshot = idShared
        val clockFn = { nowMs }
        val receive = ResetReceive(
            db = db,
            wrapMac = wrapMac,
            ownFingerprint32 = ownFp,
            idSharedSecretFor = { idSharedSnapshot.copyOf() },
            clock = clockFn
        )
        val trigger = AutoResetTrigger(
            db = db,
            resetReceive = receive,
            clock = clockFn
        )
        return Fixture(
            contactId = contactId,
            ownIdPriv = ownPriv, ownIdPub = ownPub, ownFp = ownFp,
            peerIdPub = peerPub,
            role = role,
            receive = receive,
            trigger = trigger
        )
    }

    private fun outboxCount(contactId: String): Int =
        runBlocking { db.pendingOutboundFrameDao().countForContact(contactId) }

    private fun ContactEntity.count24hOf(): Int = auto_reset_count_24h

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

    /** Same AES-GCM + HMAC fake used by PersistenceInvariantsTest / ResetReceiveTest. */
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
