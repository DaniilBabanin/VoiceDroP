package com.voicedrop.ui

import android.content.Context
import android.os.SystemClock
import android.view.View
import android.widget.Chronometer
import android.widget.ImageButton
import android.widget.TextView
import com.voicedrop.R
import com.voicedrop.service.ServiceState
import com.voicedrop.service.VoiceDropService
import com.voicedrop.storage.MessageRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Spec `18-record-playback-ux.md` §5. Drives the included `@layout/banner_recording`
 * view from [ServiceState.recordingState]. Visible iff `state == RECORDING`.
 *
 *  - Single-recipient: "Recording for Alice".
 *  - Fanout: "Recording for 3 recipients".
 *
 * Cancel dispatches [VoiceDropService.recordCancelIntent]; send dispatches
 * [VoiceDropService.recordStopIntent]. The banner does not need to know who started
 * the recording — observing [ServiceState.recordingState] covers in-chat FAB, QS
 * tile, per-contact widget, and All-widget uniformly.
 *
 * Integration (Task 3) is responsible for inflating `@layout/banner_recording` as
 * an include in the host activity and calling [bind] with the activity's
 * lifecycle scope. This wirer is otherwise self-contained.
 */
class RecordingBanner(
    private val rootView: View,
    private val repository: MessageRepository,
    private val scope: CoroutineScope,
) {
    // The host activity wraps `banner_recording` via <include android:id="@+id/banner_recording" ...>,
    // which overrides the included layout's root id, so `rootView` itself IS the banner root.
    // findViewById(R.id.banner_recording_root) on the override path returns null.
    private val root: View = rootView
    private val label: TextView = rootView.findViewById(R.id.banner_recording_label)
    private val timer: Chronometer = rootView.findViewById(R.id.banner_recording_timer)
    private val cancelBtn: ImageButton = rootView.findViewById(R.id.banner_recording_cancel)
    private val sendBtn: ImageButton = rootView.findViewById(R.id.banner_recording_send)

    init {
        cancelBtn.setOnClickListener {
            val ctx: Context = it.context
            ctx.startForegroundService(VoiceDropService.recordCancelIntent(ctx))
        }
        sendBtn.setOnClickListener {
            val ctx: Context = it.context
            ctx.startForegroundService(VoiceDropService.recordStopIntent(ctx))
        }
    }

    /**
     * Subscribe to [state] and render. Cancellation of the returned launch is the
     * caller's responsibility (e.g. via the activity's lifecycleScope, which is
     * cancelled on STOP).
     */
    fun bind(state: StateFlow<ServiceState.RecordingState>) {
        scope.launch {
            state.collectLatest { snapshot ->
                if (snapshot.state != ServiceState.State.RECORDING) {
                    root.visibility = View.GONE
                    timer.stop()
                    return@collectLatest
                }
                root.visibility = View.VISIBLE
                // Chronometer base uses the SystemClock.elapsedRealtime() origin,
                // which is exactly what ServiceState records at start.
                timer.base = snapshot.startedAtElapsedRealtime.takeIf { it > 0L }
                    ?: SystemClock.elapsedRealtime()
                timer.start()

                val ctx = root.context
                val ids = snapshot.activeContactIds
                val text = if (ids.size == 1) {
                    val name = withContext(Dispatchers.IO) {
                        repository.getContact(ids.first())?.name ?: ""
                    }
                    ctx.getString(R.string.recording_for_one, name)
                } else {
                    ctx.getString(R.string.recording_for_many, ids.size)
                }
                label.text = text
            }
        }
    }
}
