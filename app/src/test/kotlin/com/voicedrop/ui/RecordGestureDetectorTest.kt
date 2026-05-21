package com.voicedrop.ui

import android.app.Activity
import android.view.MotionEvent
import android.view.View
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Spec 18-record-playback-ux.md §4. Pure-UI gesture state machine — these tests
 * synthesise [MotionEvent]s and assert callback ordering without touching a real
 * device. mockito-kotlin is not on the test classpath, so we mirror
 * [RecordingBannerTest]'s pattern: build a Robolectric activity to get a themed
 * Context, then construct a fixed-width [View] subclass to make the cancel /
 * un-latch thresholds deterministic.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], manifest = Config.NONE)
class RecordGestureDetectorTest {

    private var fakeClockMs: Long = 0L
    private val events = mutableListOf<String>()
    private var recording = false

    private lateinit var view: View
    private lateinit var detector: RecordGestureDetector

    @Before
    fun setUp() {
        events.clear()
        recording = false
        fakeClockMs = 0L
        val activity = Robolectric.buildActivity(Activity::class.java).create().get()
        // width = 200 makes cancel threshold = -120, un-latch = -60. getWidth() is final
        // on View, so we lay the view out at (0,0)-(200,50) to give it real dimensions.
        view = View(activity).apply { layout(0, 0, 200, 50) }
        detector = RecordGestureDetector(
            view = view,
            onStart = { events += "start"; recording = true },
            onStop = { events += "stop"; recording = false },
            onCancel = { events += "cancel"; recording = false },
            isRecording = { recording },
            clock = { fakeClockMs },
        )
    }

    private fun motion(action: Int, rawX: Float = 0f, rawY: Float = 0f): MotionEvent =
        MotionEvent.obtain(0L, fakeClockMs, action, rawX, rawY, 0)

    @Test
    fun tapBelowHoldThreshold_togglesRecording_on() {
        detector.onTouch(view, motion(MotionEvent.ACTION_DOWN, 0f))
        fakeClockMs = 50L
        detector.onTouch(view, motion(MotionEvent.ACTION_UP, 0f))
        assertEquals(listOf("start"), events)
    }

    @Test
    fun tapWhileRecording_stops() {
        recording = true
        detector.onTouch(view, motion(MotionEvent.ACTION_DOWN, 0f))
        fakeClockMs = 100L
        detector.onTouch(view, motion(MotionEvent.ACTION_UP, 0f))
        assertEquals(listOf("stop"), events)
    }

    @Test
    fun holdPastThreshold_startsRecordingOnMove() {
        detector.onTouch(view, motion(MotionEvent.ACTION_DOWN, 0f))
        fakeClockMs = 250L
        detector.onTouch(view, motion(MotionEvent.ACTION_MOVE, 0f))
        assertEquals(listOf("start"), events)
    }

    @Test
    fun holdRelease_withoutDrag_sends() {
        detector.onTouch(view, motion(MotionEvent.ACTION_DOWN, 0f))
        fakeClockMs = 250L
        detector.onTouch(view, motion(MotionEvent.ACTION_MOVE, 0f))
        detector.onTouch(view, motion(MotionEvent.ACTION_UP, 0f))
        assertEquals(listOf("start", "stop"), events)
    }

    @Test
    fun holdDragPastCancelThreshold_latches_releaseCancels() {
        detector.onTouch(view, motion(MotionEvent.ACTION_DOWN, 0f))
        fakeClockMs = 250L
        detector.onTouch(view, motion(MotionEvent.ACTION_MOVE, 0f))
        // width = 200, cancel threshold = -120. Drag to -130 latches.
        detector.onTouch(view, motion(MotionEvent.ACTION_MOVE, -130f))
        detector.onTouch(view, motion(MotionEvent.ACTION_UP, -130f))
        assertEquals(listOf("start", "cancel"), events)
    }

    @Test
    fun holdDragPastThenBack_unlatches_releaseStops() {
        detector.onTouch(view, motion(MotionEvent.ACTION_DOWN, 0f))
        fakeClockMs = 250L
        detector.onTouch(view, motion(MotionEvent.ACTION_MOVE, 0f))
        detector.onTouch(view, motion(MotionEvent.ACTION_MOVE, -130f))
        // un-latch threshold = -60. Drag back to -40 un-latches.
        detector.onTouch(view, motion(MotionEvent.ACTION_MOVE, -40f))
        detector.onTouch(view, motion(MotionEvent.ACTION_UP, -40f))
        assertEquals(listOf("start", "stop"), events)
    }

    @Test
    fun actionCancel_inHoldMode_sendsNotCancels() {
        // Spec §10: only a deliberate user UP after cancel-latch counts as cancel.
        // OS-issued ACTION_CANCEL during HOLD_MODE should send.
        detector.onTouch(view, motion(MotionEvent.ACTION_DOWN, 0f))
        fakeClockMs = 250L
        detector.onTouch(view, motion(MotionEvent.ACTION_MOVE, 0f))
        detector.onTouch(view, motion(MotionEvent.ACTION_CANCEL, 0f))
        assertEquals(listOf("start", "stop"), events)
    }
}
