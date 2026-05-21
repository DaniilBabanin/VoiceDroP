package com.voicedrop.ui

import android.graphics.Color
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.format.DateUtils
import android.text.style.ForegroundColorSpan
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.ImageButton
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.card.MaterialCardView
import com.google.android.material.color.MaterialColors
import com.google.android.material.shape.CornerFamily
import com.voicedrop.R
import com.voicedrop.service.VoiceDropService
import com.voicedrop.storage.MessageEntity
import com.voicedrop.storage.TransportType
import java.io.File

class MessageAdapter(
    private val onShareRequest: (MessageEntity) -> Unit = {}
) : ListAdapter<MessageEntity, MessageAdapter.ViewHolder>(DIFF_CALLBACK) {

    private var playingUuid: String? = null
    private var playingProgress: Float = 0f
    private var recyclerView: RecyclerView? = null

    fun setPlayingUuid(uuid: String?) {
        if (playingUuid == uuid) return
        val previous = playingUuid
        playingUuid = uuid
        if (uuid == null) playingProgress = 0f
        val list = currentList
        if (previous != null) {
            val idx = list.indexOfFirst { it.uuid == previous }
            if (idx >= 0) notifyItemChanged(idx)
        }
        if (uuid != null) {
            val idx = list.indexOfFirst { it.uuid == uuid }
            if (idx >= 0) notifyItemChanged(idx)
        }
    }

    /**
     * Stream playback progress (0f..1f) to the currently bound ViewHolder for
     * [playingUuid] without going through [notifyItemChanged] — direct view update
     * keeps the ~50Hz emission off the diff/rebind path.
     */
    fun setPlayingProgress(progress: Float) {
        playingProgress = progress.coerceIn(0f, 1f)
        val uuid = playingUuid ?: return
        val idx = currentList.indexOfFirst { it.uuid == uuid }
        if (idx < 0) return
        val holder = recyclerView?.findViewHolderForAdapterPosition(idx) as? ViewHolder ?: return
        holder.setProgress(playingProgress)
    }

    override fun onAttachedToRecyclerView(rv: RecyclerView) {
        super.onAttachedToRecyclerView(rv)
        recyclerView = rv
    }

    override fun onDetachedFromRecyclerView(rv: RecyclerView) {
        super.onDetachedFromRecyclerView(rv)
        recyclerView = null
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_message, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = getItem(position)
        val isPlaying = playingUuid == item.uuid
        holder.bind(item, isPlaying, if (isPlaying) playingProgress else 0f, onShareRequest)
    }

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        private val card: MaterialCardView = view.findViewById(R.id.messageCard)
        private val durationText: TextView = view.findViewById(R.id.durationText)
        private val infoText: TextView = view.findViewById(R.id.infoText)
        private val playButton: ImageButton = view.findViewById(R.id.playButton)
        private val waveformView: WaveformView = view.findViewById(R.id.waveform_view)

        fun setProgress(progress: Float) {
            waveformView.setProgress(progress)
        }

        fun bind(
            message: MessageEntity,
            isPlaying: Boolean,
            progress: Float,
            onShareRequest: (MessageEntity) -> Unit,
        ) {
            val ctx = itemView.context
            val isOutbound = message.direction == MessageEntity.DIRECTION_OUTBOUND

            val lp = card.layoutParams as FrameLayout.LayoutParams
            lp.gravity = if (isOutbound) Gravity.END else Gravity.START
            card.layoutParams = lp

            val cornerLg = ctx.resources.displayMetrics.density * 16f
            val cornerSm = ctx.resources.displayMetrics.density * 4f
            card.shapeAppearanceModel = card.shapeAppearanceModel.toBuilder().apply {
                setAllCorners(CornerFamily.ROUNDED, cornerLg)
                if (isOutbound) {
                    setBottomRightCorner(CornerFamily.ROUNDED, cornerSm)
                } else {
                    setBottomLeftCorner(CornerFamily.ROUNDED, cornerSm)
                }
            }.build()

            card.setCardBackgroundColor(
                MaterialColors.getColor(
                    card,
                    if (isOutbound) com.google.android.material.R.attr.colorPrimaryContainer
                    else com.google.android.material.R.attr.colorSurfaceVariant
                )
            )

            durationText.text = formatDuration(message.durationMs)
            infoText.text = buildInfoSpannable(message)

            waveformView.setPeaks(message.waveformPeaks)
            waveformView.setProgress(progress)

            val canPlay = message.encryptedFilePath != null &&
                message.state != MessageEntity.STATE_DELETED &&
                File(message.encryptedFilePath).exists()
            playButton.visibility = if (canPlay) View.VISIBLE else View.GONE
            if (canPlay) {
                playButton.setImageResource(
                    if (isPlaying) R.drawable.ic_pause else R.drawable.ic_play
                )
                playButton.contentDescription = ctx.getString(
                    if (isPlaying) R.string.action_pause else R.string.action_play
                )
                playButton.setOnClickListener { v ->
                    val intent = if (isPlaying) {
                        VoiceDropService.stopPlayIntent(v.context)
                    } else {
                        VoiceDropService.playIntent(v.context, message.uuid)
                    }
                    v.context.startForegroundService(intent)
                }
            }

            card.setOnLongClickListener {
                if (canPlay) { onShareRequest(message); true } else false
            }
        }

        private fun formatDuration(ms: Int): String {
            val totalSecs = ms / 1000
            return "%d:%02d".format(totalSecs / 60, totalSecs % 60)
        }

        private fun buildInfoSpannable(message: MessageEntity): CharSequence {
            val sb = SpannableStringBuilder()
            sb.append(formatTimestamp(message.createdAt))

            statusGlyph(message.state)?.let { (glyph, colored) ->
                sb.append("  ·  ")
                val start = sb.length
                sb.append(glyph)
                if (colored) {
                    val tertiary = MaterialColors.getColor(
                        itemView,
                        com.google.android.material.R.attr.colorTertiary,
                        Color.CYAN
                    )
                    sb.setSpan(
                        ForegroundColorSpan(tertiary),
                        start, sb.length,
                        Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
                    )
                }
            }

            transportGlyph(message.transport)?.let { glyph ->
                sb.append("  ·  ")
                sb.append(glyph)
            }
            return sb
        }

        private fun statusGlyph(state: Int): Pair<String, Boolean>? = when (state) {
            MessageEntity.STATE_OUTBOX -> "…" to false
            MessageEntity.STATE_SENT -> "✓" to false
            MessageEntity.STATE_DELIVERED -> "✓✓" to false
            MessageEntity.STATE_PLAYED -> "✓✓" to true
            MessageEntity.STATE_DELETED -> "⌫" to false
            MessageEntity.STATE_UNDELIVERABLE -> "!" to false
            else -> null
        }

        private fun transportGlyph(transport: TransportType): String? = when (transport) {
            TransportType.LAN -> "⌁ LAN"
            TransportType.P2P -> "⌁ P2P"
            TransportType.WEBRTC -> "⌁ P2P"
            TransportType.RELAY -> "↻ Relay"
            else -> null
        }

        private fun formatTimestamp(createdAt: Long): String {
            val flags = DateUtils.FORMAT_SHOW_TIME or DateUtils.FORMAT_ABBREV_ALL
            val now = System.currentTimeMillis()
            return if (now - createdAt < DateUtils.DAY_IN_MILLIS) {
                DateUtils.formatDateTime(itemView.context, createdAt, flags)
            } else {
                DateUtils.formatDateTime(
                    itemView.context, createdAt,
                    flags or DateUtils.FORMAT_SHOW_DATE or DateUtils.FORMAT_SHOW_YEAR
                )
            }
        }
    }

    companion object {
        private val DIFF_CALLBACK = object : DiffUtil.ItemCallback<MessageEntity>() {
            override fun areItemsTheSame(a: MessageEntity, b: MessageEntity) = a.uuid == b.uuid

            // MessageEntity.equals is uuid-only (ByteArray fields can't safely use
            // data-class structural equality). Compare the fields that actually drive
            // bind() here so DiffUtil still triggers a rebind when render-relevant
            // state changes. Phase E will start consuming waveformPeaks in bind();
            // include it now (via contentEquals) so the lazy backfill in Phase F
            // produces a rebind.
            override fun areContentsTheSame(a: MessageEntity, b: MessageEntity): Boolean =
                a.direction == b.direction &&
                    a.state == b.state &&
                    a.transport == b.transport &&
                    a.encryptedFilePath == b.encryptedFilePath &&
                    a.durationMs == b.durationMs &&
                    a.createdAt == b.createdAt &&
                    a.transcription == b.transcription &&
                    a.delivery_state == b.delivery_state &&
                    (a.waveformPeaks?.contentEquals(b.waveformPeaks) ?: (b.waveformPeaks == null))
        }
    }
}
