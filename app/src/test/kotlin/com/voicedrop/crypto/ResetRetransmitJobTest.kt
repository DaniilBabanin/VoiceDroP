package com.voicedrop.crypto

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.voicedrop.network.PendingOutboxReplay
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.ContactEntity
import com.voicedrop.storage.PendingOutboundFrameEntity
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicInteger

/**
 * DR15 §6.3 retransmit — fixed-offset schedule, expecting_ack/no-row early exit,
 * connectivity-handover trigger, per-contact cancel-on-restart.
 *
 * Avoids real `kotlinx.coroutines.delay` by injecting a synchronous `delayMs`
 * that records the requested offset and invokes an optional per-tick mutation
 * before returning. This lets us simulate "ack arrives between tick #2 and #3"
 * without actually waiting 15 seconds.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class ResetRetransmitJobTest {

    private lateinit var db: AppDatabase
    private lateinit var wrapMac: TestWrapMac
    private lateinit var scope: CoroutineScope
    private var nowMs = 1_700_000_000_000L
    private val contactId = "peer-retx"
    private val resetUuid = ByteArray(16).also { it[0] = 0x01 }

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        db = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        wrapMac = TestWrapMac()
        scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        runBlocking {
            db.contactDao().upsert(
                ContactEntity(
                    id = contactId,
                    name = "peer",
                    publicKeyBase64 = "AA==",
                    addedAt = 0L,
                    rk_wrapped = ByteArray(28),
                    rk_hmac = ByteArray(32),
                    expecting_ack = 1,
                    reset_epoch = 1
                )
            )
        }
    }

    @After
    fun tearDown() {
        scope.cancel()
        db.close()
    }

    // -------------------------------------------------------------------------
    // Schedule fires 5 ticks at the configured offsets
    // -------------------------------------------------------------------------

    @Test
    fun schedule_firesAllFive_atConfiguredOffsets() = runBlocking {
        insertResetRow()
        val fixture = newFixture(transmitReturn = false)

        fixture.job.start(contactId).join()

        assertEquals(
            ResetRetransmitJob.DEFAULT_SCHEDULE_MS.toList(),
            fixture.recordedDelays.toList()
        )
        assertEquals(5, fixture.transmitCount.get())
        // Row still present; attempts bumped to 5 (transmit returned failure each time).
        val row = db.pendingOutboundFrameDao().getByUuid(resetUuid)
        assertNotNull("expected row to remain after 5 failed transmits", row)
        assertEquals(5, row!!.attempts)
    }

    // -------------------------------------------------------------------------
    // Early exit when peer's ack clears expecting_ack mid-schedule
    // -------------------------------------------------------------------------

    @Test
    fun schedule_exitsEarly_whenExpectingAckClears() = runBlocking {
        insertResetRow()
        val fixture = newFixture(transmitReturn = false)
        // Between tick #2 (idx=2) and the replay that follows, simulate the peer's
        // ack arriving via ResetReceive — clears expecting_ack AND deletes the row.
        fixture.onTickStart[2] = {
            db.openHelper.writableDatabase.execSQL(
                "UPDATE contacts SET expecting_ack = 0 WHERE id = ?", arrayOf<Any>(contactId)
            )
            // ResetReceive deletes the row in the same txn; mirror that here.
            db.openHelper.writableDatabase.execSQL(
                "DELETE FROM pending_outbound_frames WHERE contact_id = ?", arrayOf<Any>(contactId)
            )
        }

        fixture.job.start(contactId).join()

        // 2 ticks fired (idx 0 and 1) before the mutation; tick #2's pre-replay
        // check sees no row → exit.
        assertEquals(2, fixture.transmitCount.get())
        assertEquals(
            ResetRetransmitJob.DEFAULT_SCHEDULE_MS.toList().take(3),
            fixture.recordedDelays.toList()
        )
    }

    @Test
    fun schedule_exitsEarly_whenRowDisappears_butAckStillExpected() = runBlocking {
        // Edge: outbox give-up cap fires (delete row) but expecting_ack is still
        // true. Schedule must still exit because there's nothing to retransmit.
        insertResetRow()
        val fixture = newFixture(transmitReturn = false)
        fixture.onTickStart[1] = {
            db.openHelper.writableDatabase.execSQL(
                "DELETE FROM pending_outbound_frames WHERE contact_id = ?", arrayOf<Any>(contactId)
            )
        }

        fixture.job.start(contactId).join()

        assertEquals(1, fixture.transmitCount.get())
        // Two delays recorded: idx 0 (fired) and idx 1 (delay returned but check failed).
        assertEquals(2, fixture.recordedDelays.size)
    }

    // -------------------------------------------------------------------------
    // Connectivity-handover trigger fires replay out-of-schedule
    // -------------------------------------------------------------------------

    @Test
    fun onConnectivityAvailable_callsReplayDirectly() = runBlocking {
        insertResetRow()
        val fixture = newFixture(transmitReturn = false)

        fixture.job.onConnectivityAvailable()

        assertEquals(1, fixture.transmitCount.get())
        // No schedule delays involved.
        assertTrue(fixture.recordedDelays.isEmpty())
        val row = db.pendingOutboundFrameDao().getByUuid(resetUuid)!!
        assertEquals(1, row.attempts)
    }

    // -------------------------------------------------------------------------
    // start() cancels any prior in-flight schedule for same contact
    // -------------------------------------------------------------------------

    @Test
    fun start_cancelsPriorJobForSameContact() = runBlocking {
        insertResetRow()
        val fixture = newFixture(transmitReturn = false)
        // First job: hang on the first delay forever (don't add a tick handler).
        // We hand-tie this by gating the delay through a Channel.
        // Simpler: use a fixture whose delayMs awaits a flag that's never set.
        val hangFixture = newFixture(
            transmitReturn = false,
            customDelay = { kotlinx.coroutines.delay(60_000) }
        )

        val first = hangFixture.job.start(contactId)
        // Start a second job for the same contact.
        val second = hangFixture.job.start(contactId)

        // First should be cancelled.
        Thread.sleep(50)  // give the suspension a moment
        assertTrue("first job should be cancelled", first.isCancelled || first.isCompleted)
        second.cancel()
    }

    @Test
    fun cancelAll_cancelsEveryActiveJob() = runBlocking {
        insertResetRow()
        val fixture = newFixture(
            transmitReturn = false,
            customDelay = { kotlinx.coroutines.delay(60_000) }
        )

        val a = fixture.job.start("contact-a")
        val b = fixture.job.start("contact-b")
        fixture.job.cancelAll()
        Thread.sleep(50)

        assertTrue(a.isCancelled || a.isCompleted)
        assertTrue(b.isCancelled || b.isCompleted)
    }

    // -------------------------------------------------------------------------
    // Restart-recovery semantics (DR11 outbox replay re-fires the persisted row)
    // -------------------------------------------------------------------------

    @Test
    fun replay_resubmits_persistedResetRow_acrossSimulatedRestart() = runBlocking {
        // The job lives in memory; killing the process drops the schedule. A
        // fresh process calls replay.replayAll() from App.onCreate — the persisted
        // row + persisted attempts/created_at survives, and the give-up cap still
        // applies. Simulate by replaying directly without the schedule.
        insertResetRow()
        val fixture = newFixture(transmitReturn = false)
        fixture.replay.replayAll()
        fixture.replay.replayAll()
        fixture.replay.replayAll()
        assertEquals(3, fixture.transmitCount.get())
        val row = db.pendingOutboundFrameDao().getByUuid(resetUuid)!!
        assertEquals(3, row.attempts)
    }

    // =========================================================================
    // Fixtures
    // =========================================================================

    private class Fixture(
        val job: ResetRetransmitJob,
        val replay: PendingOutboxReplay,
        val transmitCount: AtomicInteger,
        val recordedDelays: MutableList<Long>,
        val onTickStart: MutableMap<Int, () -> Unit>
    )

    private fun newFixture(
        transmitReturn: Boolean,
        customDelay: (suspend (Long) -> Unit)? = null
    ): Fixture {
        val transmitCount = AtomicInteger(0)
        val replay = PendingOutboxReplay(
            db = db,
            wrapMac = wrapMac,
            transmit = { _, _, _ ->
                transmitCount.incrementAndGet()
                transmitReturn
            },
            clock = { nowMs },
            eventLog = {}
        )
        val recordedDelays = mutableListOf<Long>()
        val onTickStart = mutableMapOf<Int, () -> Unit>()
        val tickIdx = AtomicInteger(0)
        val delayFn: suspend (Long) -> Unit = customDelay ?: { ms ->
            val idx = tickIdx.getAndIncrement()
            onTickStart[idx]?.invoke()
            recordedDelays.add(ms)
        }
        val job = ResetRetransmitJob(
            db = db,
            replay = replay,
            scope = scope,
            clock = { nowMs },
            delayMs = delayFn,
            eventLog = {}
        )
        return Fixture(job, replay, transmitCount, recordedDelays, onTickStart)
    }

    private fun insertResetRow() {
        runBlocking {
            val (wrapped, hmac) = wrapMac.wrapAndMac(
                "pending_outbound_frames.wrapped_frame", resetUuid, ByteArray(64) { it.toByte() }
            )
            db.pendingOutboundFrameDao().insert(
                PendingOutboundFrameEntity(
                    uuid = resetUuid,
                    contact_id = contactId,
                    frame_kind = PendingOutboundFrameEntity.FRAME_KIND_RESET,
                    wrapped_frame = wrapped,
                    frame_hmac = hmac,
                    created_at = nowMs,
                    attempts = 0
                )
            )
        }
    }

    /** Same AES-GCM + HMAC fake used by other DR test files. */
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
