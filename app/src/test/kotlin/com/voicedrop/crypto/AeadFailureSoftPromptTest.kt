package com.voicedrop.crypto

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.ContactEntity
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * DR14 — Soft-prompt heuristic on consecutive AEAD failures.
 *
 * The underlying counter columns are written by [RatchetDecryptAndPersist] (the
 * DR8 outside-txn bump on AEAD failure; the in-txn zero on AEAD success). This
 * suite simulates those writes via direct UPDATEs since the unit under test
 * only READS them and manages dismissal / stale-window cleanup.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class AeadFailureSoftPromptTest {

    private lateinit var db: AppDatabase
    private var nowMs = 1_700_000_000_000L
    private val contactId = "peer-aaaa"

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        db = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        runBlocking {
            db.contactDao().upsert(
                ContactEntity(
                    id = contactId,
                    name = "peer",
                    publicKeyBase64 = "AA==",
                    addedAt = 0L,
                    rk_wrapped = ByteArray(28),
                    rk_hmac = ByteArray(32)
                )
            )
        }
    }

    @After
    fun tearDown() { db.close() }

    @Test
    fun belowThreshold_isIdle() = runBlocking {
        bumpFailuresTo(failures = 9, windowStart = nowMs - 60_000L)
        val state = sut().evaluate(contactId)
        assertSame(AeadFailureSoftPrompt.State.Idle, state)
    }

    @Test
    fun atThreshold_inWindow_shouldPrompt() = runBlocking {
        bumpFailuresTo(failures = 10, windowStart = nowMs - 30_000L)
        val state = sut().evaluate(contactId)
        assertTrue("expected ShouldPrompt, got $state", state is AeadFailureSoftPrompt.State.ShouldPrompt)
        val sp = state as AeadFailureSoftPrompt.State.ShouldPrompt
        assertEquals(10, sp.failures)
    }

    @Test
    fun atThreshold_butWindowExpired_clearsCounter_andReturnsIdle() = runBlocking {
        bumpFailuresTo(failures = 10, windowStart = nowMs - (AeadFailureSoftPrompt.WINDOW_MS + 60_000L))
        val state = sut().evaluate(contactId)
        assertSame(AeadFailureSoftPrompt.State.Idle, state)
        val after = db.contactDao().getById(contactId)!!
        assertEquals(0, after.consecutive_aead_failures)
        assertEquals(0L, after.consecutive_aead_failures_window_start)
    }

    @Test
    fun atThreshold_butDismissed_returnsSuppressed() = runBlocking {
        bumpFailuresTo(failures = 12, windowStart = nowMs - 60_000L)
        // Pre-arm dismissal.
        db.contactDao().upsert(
            db.contactDao().getById(contactId)!!.copy(soft_prompt_dismissed_until = nowMs + 1_000_000L)
        )
        val state = sut().evaluate(contactId)
        assertTrue("expected Suppressed, got $state", state is AeadFailureSoftPrompt.State.Suppressed)
    }

    @Test
    fun dismiss_setsSuppressionWindow_andClearsCounter() = runBlocking {
        bumpFailuresTo(failures = 11, windowStart = nowMs - 60_000L)
        sut().dismiss(contactId)

        val after = db.contactDao().getById(contactId)!!
        assertEquals(nowMs + AeadFailureSoftPrompt.DISMISS_SUPPRESS_MS, after.soft_prompt_dismissed_until)
        assertEquals(0, after.consecutive_aead_failures)
        assertEquals(0L, after.consecutive_aead_failures_window_start)

        // And subsequent evaluate ⇒ Suppressed.
        val state = sut().evaluate(contactId)
        assertTrue("expected Suppressed after dismiss, got $state", state is AeadFailureSoftPrompt.State.Suppressed)
    }

    @Test
    fun dismissalExpires_andCounterRebuildsToThreshold_thenPromptsAgain() = runBlocking {
        // First prompt + dismiss.
        bumpFailuresTo(failures = 10, windowStart = nowMs - 30_000L)
        sut().dismiss(contactId)

        // 24h+1m later, fresh failure burst rebuilds the counter.
        nowMs += AeadFailureSoftPrompt.DISMISS_SUPPRESS_MS + 60_000L
        bumpFailuresTo(failures = 10, windowStart = nowMs - 30_000L)

        val state = sut().evaluate(contactId)
        assertTrue("expected ShouldPrompt after dismissal expired, got $state", state is AeadFailureSoftPrompt.State.ShouldPrompt)
    }

    @Test
    fun zeroCounter_isIdle() = runBlocking {
        val state = sut().evaluate(contactId)
        assertSame(AeadFailureSoftPrompt.State.Idle, state)
    }

    @Test
    fun unknownContact_isIdle() = runBlocking {
        val state = sut().evaluate("not-a-contact")
        assertSame(AeadFailureSoftPrompt.State.Idle, state)
    }

    // -------------------------------------------------------------------------

    private fun sut() = AeadFailureSoftPrompt(db = db, clock = { nowMs })

    /** Directly write the counter columns the way [RatchetDecryptAndPersist] would. */
    private fun bumpFailuresTo(failures: Int, windowStart: Long) {
        db.openHelper.writableDatabase.execSQL(
            "UPDATE contacts SET consecutive_aead_failures = ?, " +
                "consecutive_aead_failures_window_start = ? WHERE id = ?",
            arrayOf<Any>(failures, windowStart, contactId)
        )
    }
}
