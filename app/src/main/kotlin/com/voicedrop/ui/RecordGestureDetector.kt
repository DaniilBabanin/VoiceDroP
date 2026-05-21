package com.voicedrop.ui

import android.os.SystemClock
import android.view.MotionEvent
import android.view.View

/**
 * Spec 18-record-playback-ux.md §4. Gesture state machine for a record-toggle FAB.
 *
 * - TAP (release before 200ms): toggles record on/off via [onStart] / [onStop] based
 *   on [isRecording].
 * - HOLD (press past 200ms): begins recording (calls [onStart] iff not already
 *   recording); releases on ACTION_UP via [onStop]. Drag-left past
 *   `CANCEL_DRAG_FRACTION * view.width` latches a cancel; releasing while latched
 *   fires [onCancel]. Drag-right past `(1 - UNLATCH_DRAG_FRACTION) * threshold`
 *   un-latches (hysteresis).
 * - During HOLD, [onSlideProgress] is fed with a [0f..1f] fraction of how close the
 *   user is to the cancel threshold — the host can use it to animate the
 *   "← slide to cancel" affordance.
 *
 * Pure UI: no service references; no coroutines; safe to unit-test off-device with
 * synthesised [MotionEvent]s.
 */
class RecordGestureDetector(
    private val view: View,
    private val onStart: () -> Unit,
    private val onStop: () -> Unit,
    private val onCancel: () -> Unit,
    private val isRecording: () -> Boolean,
    private val onSlideProgress: (Float) -> Unit = {},
    private val clock: () -> Long = { SystemClock.uptimeMillis() },
) : View.OnTouchListener {

    private enum class S { IDLE, AMBIGUOUS, HOLD_MODE, CANCEL_LATCHED }

    private var state: S = S.IDLE
    private var downAt: Long = 0L
    private var downX: Float = 0f

    override fun onTouch(v: View, event: MotionEvent): Boolean {
        when (event.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                downAt = clock()
                downX = event.rawX
                state = S.AMBIGUOUS
                return true
            }
            MotionEvent.ACTION_MOVE -> {
                if (state == S.AMBIGUOUS) {
                    if (clock() - downAt >= HOLD_THRESHOLD_MS) {
                        // Promote to HOLD_MODE. If we weren't already recording (because
                        // a separate path started us), call onStart now.
                        if (!isRecording()) onStart()
                        state = S.HOLD_MODE
                    }
                }
                if (state == S.HOLD_MODE || state == S.CANCEL_LATCHED) {
                    val dragX = event.rawX - downX
                    val cancelPx = -view.width * CANCEL_DRAG_FRACTION
                    val unlatchPx = -view.width * UNLATCH_DRAG_FRACTION
                    onSlideProgress(((-dragX) / (view.width * CANCEL_DRAG_FRACTION)).coerceIn(0f, 1f))
                    if (state == S.HOLD_MODE && dragX <= cancelPx) {
                        state = S.CANCEL_LATCHED
                    } else if (state == S.CANCEL_LATCHED && dragX >= unlatchPx) {
                        state = S.HOLD_MODE
                    }
                }
                return true
            }
            MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                val isCancel = event.actionMasked == MotionEvent.ACTION_CANCEL
                val finalState = state
                state = S.IDLE
                onSlideProgress(0f)
                when (finalState) {
                    S.AMBIGUOUS -> {
                        // Quick tap: toggle.
                        if (isRecording()) onStop() else onStart()
                    }
                    S.HOLD_MODE -> {
                        // Released without crossing cancel: send (spec §10 "background
                        // mid-record → send").
                        if (!isCancel || isRecording()) onStop()
                    }
                    S.CANCEL_LATCHED -> {
                        // Confirmed cancel — but only on a deliberate UP. An OS-issued
                        // ACTION_CANCEL is *not* a user cancel; treat as send (spec §10).
                        if (isCancel) onStop() else onCancel()
                    }
                    S.IDLE -> { /* defensive */ }
                }
                return true
            }
        }
        return false
    }

    companion object {
        const val HOLD_THRESHOLD_MS: Long = 200L
        const val CANCEL_DRAG_FRACTION: Float = 0.6f
        const val UNLATCH_DRAG_FRACTION: Float = 0.3f
    }
}
