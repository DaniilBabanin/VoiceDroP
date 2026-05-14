package com.voicedrop.ui

import android.content.Context
import android.text.format.DateUtils
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.FrameLayout
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.voicedrop.R
import com.voicedrop.service.VoiceDropService
import com.voicedrop.storage.MessageEntity
import com.voicedrop.storage.TransportType
import java.io.File

class MessageAdapter : ListAdapter<MessageEntity, MessageAdapter.ViewHolder>(DIFF_CALLBACK) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_message, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        private val card: ViewGroup = view.findViewById(R.id.messageCard)
        private val durationText: TextView = view.findViewById(R.id.durationText)
        private val statusText: TextView = view.findViewById(R.id.statusText)
        private val timestampText: TextView = view.findViewById(R.id.timestampText)
        private val transportText: TextView = view.findViewById(R.id.transportText)
        private val playButton: Button = view.findViewById(R.id.playButton)

        fun bind(message: MessageEntity) {
            val isOutbound = message.direction == MessageEntity.DIRECTION_OUTBOUND
            val lp = card.layoutParams as FrameLayout.LayoutParams
            lp.gravity = if (isOutbound) Gravity.END else Gravity.START
            card.layoutParams = lp

            durationText.text = formatDuration(message.durationMs)
            statusText.text = stateLabel(message.state)
            timestampText.text = formatTimestamp(message.createdAt)

            val transportLabel = transportLabel(message.transport)
            if (transportLabel != null) {
                transportText.text = transportLabel
                transportText.visibility = View.VISIBLE
            } else {
                transportText.visibility = View.GONE
            }

            val canPlay = message.encryptedFilePath != null &&
                message.state != MessageEntity.STATE_DELETED &&
                File(message.encryptedFilePath).exists()
            playButton.visibility = if (canPlay) View.VISIBLE else View.GONE
            if (canPlay) {
                playButton.setOnClickListener { v ->
                    val intent = VoiceDropService.playIntent(v.context, message.uuid)
                    v.context.startForegroundService(intent)
                }
            }
        }

        private fun formatDuration(ms: Int): String {
            val totalSecs = ms / 1000
            return "%d:%02d".format(totalSecs / 60, totalSecs % 60)
        }

        private fun stateLabel(state: Int): String = when (state) {
            MessageEntity.STATE_OUTBOX -> itemView.context.getString(R.string.state_sending)
            MessageEntity.STATE_SENT -> itemView.context.getString(R.string.state_sent)
            MessageEntity.STATE_DELIVERED -> itemView.context.getString(R.string.state_delivered)
            MessageEntity.STATE_PLAYED -> itemView.context.getString(R.string.state_played)
            MessageEntity.STATE_DELETED -> itemView.context.getString(R.string.state_deleted)
            MessageEntity.STATE_UNDELIVERABLE -> itemView.context.getString(R.string.state_failed)
            else -> ""
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
