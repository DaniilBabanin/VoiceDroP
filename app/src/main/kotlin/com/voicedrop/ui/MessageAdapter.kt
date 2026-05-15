package com.voicedrop.ui

import android.text.format.DateUtils
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
import com.voicedrop.R
import com.voicedrop.service.VoiceDropService
import com.voicedrop.storage.MessageEntity
import com.voicedrop.storage.TransportType
import java.io.File

class MessageAdapter(
    private val onShareRequest: (MessageEntity) -> Unit = {}
) : ListAdapter<MessageEntity, MessageAdapter.ViewHolder>(DIFF_CALLBACK) {

    private var playingUuid: String? = null

    fun setPlayingUuid(uuid: String?) {
        if (playingUuid == uuid) return
        val previous = playingUuid
        playingUuid = uuid
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

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_message, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        holder.bind(getItem(position), playingUuid == getItem(position).uuid, onShareRequest)
    }

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        private val card: ViewGroup = view.findViewById(R.id.messageCard)
        private val infoText: TextView = view.findViewById(R.id.infoText)
        private val playButton: ImageButton = view.findViewById(R.id.playButton)

        fun bind(message: MessageEntity, isPlaying: Boolean, onShareRequest: (MessageEntity) -> Unit) {
            val isOutbound = message.direction == MessageEntity.DIRECTION_OUTBOUND
            val lp = card.layoutParams as FrameLayout.LayoutParams
            lp.gravity = if (isOutbound) Gravity.END else Gravity.START
            card.layoutParams = lp

            infoText.text = buildInfoLine(message)

            val canPlay = message.encryptedFilePath != null &&
                message.state != MessageEntity.STATE_DELETED &&
                File(message.encryptedFilePath).exists()
            playButton.visibility = if (canPlay) View.VISIBLE else View.GONE
            if (canPlay) {
                playButton.setImageResource(
                    if (isPlaying) R.drawable.ic_pause else R.drawable.ic_play
                )
                playButton.contentDescription = itemView.context.getString(
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
                if (canPlay) {
                    onShareRequest(message)
                    true
                } else {
                    false
                }
            }
        }

        private fun buildInfoLine(message: MessageEntity): String {
            val parts = mutableListOf<String>()
            parts += formatDuration(message.durationMs)
            parts += formatTimestamp(message.createdAt)
            stateLabel(message.state)?.let { parts += it }
            transportLabel(message.transport)?.let { parts += it }
            return parts.joinToString("  ·  ")
        }

        private fun formatDuration(ms: Int): String {
            val totalSecs = ms / 1000
            return "%d:%02d".format(totalSecs / 60, totalSecs % 60)
        }

        private fun stateLabel(state: Int): String? = when (state) {
            MessageEntity.STATE_OUTBOX -> itemView.context.getString(R.string.state_sending)
            MessageEntity.STATE_SENT -> itemView.context.getString(R.string.state_sent)
            MessageEntity.STATE_DELIVERED -> itemView.context.getString(R.string.state_delivered)
            MessageEntity.STATE_PLAYED -> itemView.context.getString(R.string.state_played)
            MessageEntity.STATE_DELETED -> itemView.context.getString(R.string.state_deleted)
            MessageEntity.STATE_UNDELIVERABLE -> itemView.context.getString(R.string.state_failed)
            else -> null
        }

        private fun transportLabel(transport: TransportType): String? = when (transport) {
            TransportType.LAN -> itemView.context.getString(R.string.transport_lan)
            TransportType.P2P -> itemView.context.getString(R.string.transport_p2p)
            TransportType.RELAY -> itemView.context.getString(R.string.transport_relay)
            TransportType.WEBRTC -> itemView.context.getString(R.string.transport_p2p)
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
            override fun areContentsTheSame(a: MessageEntity, b: MessageEntity) = a == b
        }
    }
}
