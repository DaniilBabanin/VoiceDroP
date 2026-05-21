package com.voicedrop.ui

import android.view.View
import android.widget.Button
import android.widget.ImageButton
import android.widget.SeekBar
import android.widget.TextView
import com.voicedrop.R
import com.voicedrop.service.ServiceState
import com.voicedrop.service.VoiceDropService
import com.voicedrop.storage.MessageRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Spec 18-record-playback-ux.md §6. Chat-only playback controller — pause/resume,
 * scrub via SeekBar, speed cycle 1× → 1.5× → 2× → 0.5× → 1×, stop.
 *
 * Visible iff [ServiceState.playingUuid] is non-null. Scrub is dispatched on
 * `onStopTrackingTouch`, not on each move, to avoid spamming the foreground service.
 */
class PlaybackBanner(
    private val rootView: View,
    private val repository: MessageRepository,
    private val scope: CoroutineScope,
) {
    // Host activity wraps the banner via <include android:id="@+id/banner_playback" ...>,
    // which overrides the included layout's root id (`banner_playback_root`). `rootView` IS the root.
    private val root: View = rootView
    private val pauseBtn: ImageButton = rootView.findViewById(R.id.banner_playback_pause)
    private val seekBar: SeekBar = rootView.findViewById(R.id.banner_playback_seek)
    private val timeText: TextView = rootView.findViewById(R.id.banner_playback_time)
    private val speedBtn: Button = rootView.findViewById(R.id.banner_playback_speed)
    private val stopBtn: ImageButton = rootView.findViewById(R.id.banner_playback_stop)

    private var isPaused = false
    private var draggingSeek = false
    private var totalMs: Int = 0

    init {
        pauseBtn.setOnClickListener {
            val ctx = it.context
            if (isPaused) {
                ctx.startForegroundService(VoiceDropService.resumeIntent(ctx))
                isPaused = false
                pauseBtn.setImageResource(R.drawable.ic_pause)
                pauseBtn.contentDescription = ctx.getString(R.string.action_pause)
            } else {
                ctx.startForegroundService(VoiceDropService.pauseIntent(ctx))
                isPaused = true
                pauseBtn.setImageResource(R.drawable.ic_play)
                pauseBtn.contentDescription = ctx.getString(R.string.action_resume)
            }
        }
        stopBtn.setOnClickListener {
            val ctx = it.context
            ctx.startForegroundService(VoiceDropService.stopPlayIntent(ctx))
        }
        speedBtn.setOnClickListener {
            val next = nextSpeed(ServiceState.playingSpeed.value)
            val ctx = it.context
            ctx.startForegroundService(VoiceDropService.setSpeedIntent(ctx, next))
        }
        seekBar.setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
            override fun onProgressChanged(bar: SeekBar, p: Int, fromUser: Boolean) {
                if (fromUser) {
                    timeText.text = formatTime((p / 1000f) * totalMs, totalMs)
                }
            }
            override fun onStartTrackingTouch(bar: SeekBar) { draggingSeek = true }
            override fun onStopTrackingTouch(bar: SeekBar) {
                draggingSeek = false
                val frac = bar.progress / 1000f
                val ctx = bar.context
                ctx.startForegroundService(VoiceDropService.seekIntent(ctx, frac))
            }
        })
    }

    fun bind() {
        scope.launch {
            ServiceState.playingUuid.collectLatest { uuid ->
                if (uuid == null) {
                    root.visibility = View.GONE
                    isPaused = false
                    pauseBtn.setImageResource(R.drawable.ic_pause)
                    return@collectLatest
                }
                val duration = withContext(Dispatchers.IO) {
                    repository.getMessage(uuid)?.durationMs ?: 0
                }
                totalMs = duration
                root.visibility = View.VISIBLE
            }
        }
        scope.launch {
            ServiceState.playingProgress.collectLatest { progress ->
                if (draggingSeek) return@collectLatest
                seekBar.progress = (progress * 1000f).toInt()
                timeText.text = formatTime(progress * totalMs, totalMs)
            }
        }
        scope.launch {
            ServiceState.playingSpeed.collectLatest { speed ->
                speedBtn.text = formatSpeed(speed)
            }
        }
    }

    companion object {
        /**
         * Spec §6.3 cycle: 1× → 1.5× → 2× → 0.5× → 1×.
         */
        internal fun nextSpeed(current: Float): Float = when {
            current < 0.75f -> 1f         // 0.5× → 1×
            current < 1.25f -> 1.5f       // 1× → 1.5×
            current < 1.75f -> 2f         // 1.5× → 2×
            else -> 0.5f                  // 2× → 0.5×
        }

        internal fun formatSpeed(speed: Float): String = when (speed) {
            0.5f -> "0.5×"
            1f -> "1×"
            1.5f -> "1.5×"
            2f -> "2×"
            else -> "%.2f×".format(speed)
        }

        private fun formatTime(currentMsF: Float, totalMs: Int): String {
            val cs = (currentMsF / 1000f).toInt()
            val ts = totalMs / 1000
            return "%d:%02d / %d:%02d".format(cs / 60, cs % 60, ts / 60, ts % 60)
        }
    }
}
