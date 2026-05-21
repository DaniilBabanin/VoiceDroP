package com.voicedrop.ui

import android.app.Activity
import android.app.Application
import android.content.Context
import android.content.Intent
import android.os.SystemClock
import android.view.LayoutInflater
import android.view.View
import android.widget.TextView
import androidx.test.core.app.ApplicationProvider
import com.voicedrop.R
import com.voicedrop.service.ServiceState
import com.voicedrop.service.VoiceDropService
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.ContactEntity
import com.voicedrop.storage.MessageRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/**
 * Spec `18-record-playback-ux.md` §5 — `RecordingBanner` is the view-side wirer
 * that drives `@layout/banner_recording` from [ServiceState.recordingState]. The
 * banner is visible iff `state == RECORDING`, renders single-recipient vs fanout
 * label copy, and dispatches `ACTION_RECORD_CANCEL` / `ACTION_RECORD_STOP` from
 * the two icon buttons.
 *
 * The button click path uses `Context.startForegroundService(...)`, which under
 * Robolectric lands in `ShadowApplication.startedServices` and is observable
 * via `shadowOf(app).peekNextStartedService()` — same primitive used by
 * VoiceDropServiceCancelTest's intent-helper assertion.
 *
 * `ServiceState` is a process-global singleton, so each test resets it back to
 * IDLE in [tearDown] and wipes the on-disk DB the wirer reads contact names from
 * (mirrors VoiceDropServiceCancelTest pattern).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class RecordingBannerTest {

    private lateinit var ctx: Context
    private lateinit var repo: MessageRepository
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)

    @Before
    fun setUp() {
        ctx = ApplicationProvider.getApplicationContext()
        val db = AppDatabase.getInstance(ctx)
        repo = MessageRepository(db.contactDao(), db.messageDao(), db.pendingActionDao())
        ServiceState.updateState(ServiceState.State.IDLE, emptyList())
    }

    @After
    fun tearDown() = runBlocking {
        scope.cancel()
        AppDatabase.getInstance(ctx).clearAllTables()
        ServiceState.updateState(ServiceState.State.IDLE, emptyList())
    }

    /**
     * The wirer needs a host activity to inflate against (themed Context). A
     * bare Robolectric activity carries the app's default theme, which is
     * enough for `?attr/colorErrorContainer` and friends to resolve.
     */
    private fun inflateAndBind(): View {
        val activity = Robolectric.buildActivity(Activity::class.java).create().get()
        val view = LayoutInflater.from(activity).inflate(R.layout.banner_recording, null)
        RecordingBanner(view, repo, scope).bind(ServiceState.recordingState)
        return view
    }

    @Test
    fun bannerHidden_whenIdle() = runBlocking {
        val view = inflateAndBind()
        val root = view.findViewById<View>(R.id.banner_recording_root)
        delay(20)
        assertEquals(View.GONE, root.visibility)
    }

    @Test
    fun bannerShowsSingleRecipientName() = runBlocking {
        val contactId = "a".repeat(64)
        AppDatabase.getInstance(ctx).contactDao().upsert(
            ContactEntity(
                id = contactId,
                name = "Alice",
                publicKeyBase64 = "dGVzdA==",
                addedAt = 0L,
            )
        )
        val view = inflateAndBind()
        ServiceState.updateState(
            ServiceState.State.RECORDING,
            listOf(contactId),
            startedAtElapsedRealtime = SystemClock.elapsedRealtime(),
            startedAtWallClock = System.currentTimeMillis(),
        )
        // collectLatest hops to Dispatchers.IO to read the contact name, so a
        // single yield isn't enough — give the IO dispatcher a slice.
        delay(100)
        val root = view.findViewById<View>(R.id.banner_recording_root)
        val label = view.findViewById<TextView>(R.id.banner_recording_label)
        assertEquals(View.VISIBLE, root.visibility)
        assertEquals("Recording for Alice", label.text.toString())
    }

    @Test
    fun bannerShowsRecipientCount_forFanout() = runBlocking {
        val view = inflateAndBind()
        ServiceState.updateState(
            ServiceState.State.RECORDING,
            listOf("a".repeat(64), "b".repeat(64), "c".repeat(64)),
            startedAtElapsedRealtime = SystemClock.elapsedRealtime(),
            startedAtWallClock = System.currentTimeMillis(),
        )
        delay(50)
        val label = view.findViewById<TextView>(R.id.banner_recording_label)
        assertEquals("Recording for 3 recipients", label.text.toString())
    }

    @Test
    fun cancelButton_dispatchesRecordCancelIntent() = runBlocking {
        val view = inflateAndBind()
        ServiceState.updateState(
            ServiceState.State.RECORDING,
            listOf("a".repeat(64)),
            startedAtElapsedRealtime = SystemClock.elapsedRealtime(),
            startedAtWallClock = System.currentTimeMillis(),
        )
        delay(50)

        val app = shadowOf(ApplicationProvider.getApplicationContext<Application>())
        app.clearStartedServices()

        view.findViewById<View>(R.id.banner_recording_cancel).performClick()

        val started: Intent? = app.peekNextStartedService()
        assertNotNull("cancel click must startForegroundService", started)
        assertEquals(VoiceDropService.ACTION_RECORD_CANCEL, started?.action)
        assertEquals(
            VoiceDropService::class.java.name,
            started?.component?.className,
        )
    }

    @Test
    fun sendButton_dispatchesRecordStopIntent() = runBlocking {
        val view = inflateAndBind()
        ServiceState.updateState(
            ServiceState.State.RECORDING,
            listOf("a".repeat(64)),
            startedAtElapsedRealtime = SystemClock.elapsedRealtime(),
            startedAtWallClock = System.currentTimeMillis(),
        )
        delay(50)

        val app = shadowOf(ApplicationProvider.getApplicationContext<Application>())
        app.clearStartedServices()

        view.findViewById<View>(R.id.banner_recording_send).performClick()

        val started: Intent? = app.peekNextStartedService()
        assertNotNull("send click must startForegroundService", started)
        assertEquals(VoiceDropService.ACTION_RECORD_STOP, started?.action)
        assertEquals(
            VoiceDropService::class.java.name,
            started?.component?.className,
        )
    }
}
