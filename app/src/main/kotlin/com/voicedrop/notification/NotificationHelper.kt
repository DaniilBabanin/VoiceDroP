package com.voicedrop.notification

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
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

        // setData makes the Intents filterEquals-distinct per (uuid, action):
        // request codes derive from uuid.hashCode(), so two messages whose hashes
        // land near each other would otherwise share a PendingIntent and
        // FLAG_UPDATE_CURRENT would repoint its uuid extra — Play/Delete/Share
        // acting on the wrong message.
        val playIntent = PendingIntent.getBroadcast(
            context,
            notifId,
            Intent(context, NotificationActionReceiver::class.java).apply {
                action = NotificationActionReceiver.ACTION_PLAY
                data = Uri.parse("voicedrop://msg/$uuid/play")
                putExtra("uuid", uuid)
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val deleteIntent = PendingIntent.getBroadcast(
            context,
            notifId + 1,
            Intent(context, NotificationActionReceiver::class.java).apply {
                action = NotificationActionReceiver.ACTION_DELETE
                data = Uri.parse("voicedrop://msg/$uuid/delete")
                putExtra("uuid", uuid)
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val shareIntent = PendingIntent.getBroadcast(
            context,
            notifId + 3,
            Intent(context, NotificationActionReceiver::class.java).apply {
                action = NotificationActionReceiver.ACTION_SHARE
                data = Uri.parse("voicedrop://msg/$uuid/share")
                putExtra("uuid", uuid)
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(context, CHANNEL_MESSAGES)
            .setSmallIcon(R.drawable.ic_tile_idle)
            .setContentTitle(contact.name)
            .setContentText("Voice message ($duration)")
            .addAction(R.drawable.ic_tile_idle, "▶ Play", playIntent)
            .addAction(R.drawable.ic_tile_idle, "↗ Share", shareIntent)
            .addAction(R.drawable.ic_tile_idle, "🗑 Delete", deleteIntent)
            .setAutoCancel(false)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .build()
    }

    fun buildIdleNotification(): Notification {
        return NotificationCompat.Builder(context, CHANNEL_RECORDING)
            .setSmallIcon(R.drawable.ic_tile_idle)
            .setContentTitle("VoiceDrop")
            .setContentText("Listening for messages")
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .build()
    }

    fun buildRecordingNotification(contactName: String, startTimeMillis: Long): Notification {
        // Lockscreen shows only the redacted public version — the "recording"
        // fact stays glanceable but the recipient name is keyguard-gated.
        val publicVersion = NotificationCompat.Builder(context, CHANNEL_RECORDING)
            .setSmallIcon(R.drawable.ic_tile_recording)
            .setContentTitle("🔴 Recording — tap to stop")
            .setOngoing(true)
            .setWhen(startTimeMillis)
            .setShowWhen(true)
            .setUsesChronometer(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .build()
        return NotificationCompat.Builder(context, CHANNEL_RECORDING)
            .setSmallIcon(R.drawable.ic_tile_recording)
            .setContentTitle("🔴 Recording — tap to stop")
            .setContentText("To: $contactName")
            .setOngoing(true)
            .setWhen(startTimeMillis)
            .setShowWhen(true)
            .setUsesChronometer(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setPublicVersion(publicVersion)
            .build()
    }

    fun updateRecordingNotification(notifId: Int, text: String) {
        // In-app RecordingBanner covers this state when foregrounded; no need to also pop a notification.
        if (ForegroundTracker.isAppInForeground) return
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
        // In-app PlaybackBanner covers this state when foregrounded.
        if (ForegroundTracker.isAppInForeground) return
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
        // When the app is in the foreground the contact-list row updates (unread badge)
        // and the chat bubble appears in-place — no need to also pop a heads-up.
        if (ForegroundTracker.isAppInForeground) return
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
