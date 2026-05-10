package com.voicedrop.notification

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.voicedrop.R
import com.voicedrop.storage.ContactEntity

class NotificationHelper(private val context: Context) {

    private val notificationManager = NotificationManagerCompat.from(context)

    init {
        createChannels()
    }

    private fun createChannels() {
        val systemManager = context.getSystemService(NotificationManager::class.java)

        val messagesChannel = NotificationChannel(
            CHANNEL_MESSAGES,
            "Voice Messages",
            NotificationManager.IMPORTANCE_HIGH
        ).apply {
            description = "Incoming voice message notifications"
            enableVibration(true)
            setSound(null, null)
        }

        val recordingChannel = NotificationChannel(
            CHANNEL_RECORDING,
            "Recording",
            NotificationManager.IMPORTANCE_HIGH
        ).apply {
            description = "Active recording indicator"
            lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            setSound(null, null)
        }

        systemManager.createNotificationChannels(listOf(messagesChannel, recordingChannel))
    }

    fun buildIncomingNotification(
        contact: ContactEntity,
        uuid: String,
        durationMs: Int
    ): Notification {
        val notifId = uuid.hashCode()
        val minutes = durationMs / 60000
        val seconds = (durationMs % 60000) / 1000
        val duration = if (minutes > 0) "${minutes}m ${seconds}s" else "${seconds}s"

        val playIntent = PendingIntent.getBroadcast(
            context,
            notifId,
            Intent(context, NotificationActionReceiver::class.java).apply {
                action = NotificationActionReceiver.ACTION_PLAY
                putExtra("uuid", uuid)
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val deleteIntent = PendingIntent.getBroadcast(
            context,
            notifId + 1,
            Intent(context, NotificationActionReceiver::class.java).apply {
                action = NotificationActionReceiver.ACTION_DELETE
                putExtra("uuid", uuid)
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(context, CHANNEL_MESSAGES)
            .setSmallIcon(R.drawable.ic_tile_idle)
            .setContentTitle(contact.name)
            .setContentText("Voice message ($duration)")
            .addAction(R.drawable.ic_tile_idle, "▶ Play", playIntent)
            .addAction(R.drawable.ic_tile_idle, "🗑 Delete", deleteIntent)
            .setAutoCancel(false)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .build()
    }

    fun buildRecordingNotification(contactName: String): Notification {
        return NotificationCompat.Builder(context, CHANNEL_RECORDING)
            .setSmallIcon(R.drawable.ic_tile_recording)
            .setContentTitle("🔴 Recording — tap to stop")
            .setContentText("To: $contactName")
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .build()
    }

    fun updateRecordingNotification(notifId: Int, text: String) {
        val notification = NotificationCompat.Builder(context, CHANNEL_RECORDING)
            .setSmallIcon(R.drawable.ic_tile_sending)
            .setContentTitle(text)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .build()
        try {
            notificationManager.notify(notifId, notification)
        } catch (_: SecurityException) {}
    }

    fun updatePlaybackProgress(notifId: Int, progressMs: Int, totalMs: Int) {
        val stopIntent = PendingIntent.getBroadcast(
            context,
            notifId + 2,
            Intent(context, NotificationActionReceiver::class.java).apply {
                action = NotificationActionReceiver.ACTION_STOP_PLAY
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val notification = NotificationCompat.Builder(context, CHANNEL_MESSAGES)
            .setSmallIcon(R.drawable.ic_tile_idle)
            .setContentTitle("Playing…")
            .setProgress(totalMs, progressMs, false)
            .addAction(R.drawable.ic_tile_idle, "⏹ Stop", stopIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .build()

        try {
            notificationManager.notify(notifId, notification)
        } catch (_: SecurityException) {}
    }

    fun notifyIncoming(contact: ContactEntity, uuid: String, durationMs: Int) {
        val notification = buildIncomingNotification(contact, uuid, durationMs)
        try {
            notificationManager.notify(uuid.hashCode(), notification)
        } catch (_: SecurityException) {}
    }

    fun cancelNotification(notifId: Int) {
        notificationManager.cancel(notifId)
    }

    companion object {
        const val CHANNEL_MESSAGES = "voicedrop_messages"
        const val CHANNEL_RECORDING = "voicedrop_recording"
    }
}
