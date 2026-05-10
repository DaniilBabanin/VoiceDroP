package com.voicedrop.notification

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.voicedrop.service.VoiceDropService
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.MessageEntity
import com.voicedrop.storage.MessageRepository
import com.voicedrop.storage.PendingActionEntity
import com.voicedrop.crypto.MessageCrypto
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.io.File
import java.util.UUID

class NotificationActionReceiver : BroadcastReceiver() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onReceive(context: Context, intent: Intent) {
        val uuid = intent.getStringExtra("uuid")
        val db = AppDatabase.getInstance(context)
        val repository = MessageRepository(db.contactDao(), db.messageDao(), db.pendingActionDao())
        val notificationHelper = NotificationHelper(context)

        when (intent.action) {
            ACTION_PLAY -> {
                if (uuid == null) return
                val serviceIntent = VoiceDropService.playIntent(context, uuid)
                context.startForegroundService(serviceIntent)
            }

            ACTION_DELETE -> {
                if (uuid == null) return
                scope.launch {
                    val message = repository.getMessage(uuid) ?: return@launch

                    message.encryptedFilePath?.let { path ->
                        secureDelete(File(path))
                    }
                    repository.markDeleted(uuid)
                    notificationHelper.cancelNotification(uuid.hashCode())

                    val targetUuidObj = runCatching { UUID.fromString(uuid) }.getOrNull() ?: return@launch
                    val deletePayload = MessageCrypto.buildDeletePayload(targetUuidObj)
                    repository.insertPendingAction(
                        PendingActionEntity(
                            contactId = message.contactId,
                            type = PendingActionEntity.TYPE_SEND_DELETE,
                            payload = deletePayload,
                            createdAt = System.currentTimeMillis()
                        )
                    )
                }
            }

            ACTION_STOP_PLAY -> {
                val serviceIntent = Intent(context, VoiceDropService::class.java).apply {
                    action = VoiceDropService.ACTION_STOP_PLAY
                }
                context.startService(serviceIntent)
                if (uuid != null) notificationHelper.cancelNotification(uuid.hashCode())
            }
        }
    }

    private fun secureDelete(file: File) {
        if (!file.exists()) return
        try {
            val length = file.length()
            if (length > 0) {
                file.outputStream().use { out ->
                    val zeros = ByteArray(minOf(length, 65536).toInt())
                    var remaining = length
                    while (remaining > 0) {
                        val toWrite = minOf(remaining, zeros.size.toLong()).toInt()
                        out.write(zeros, 0, toWrite)
                        remaining -= toWrite
                    }
                }
            }
        } finally {
            file.delete()
        }
    }

    companion object {
        const val ACTION_PLAY = "com.voicedrop.notification.PLAY"
        const val ACTION_DELETE = "com.voicedrop.notification.DELETE"
        const val ACTION_STOP_PLAY = "com.voicedrop.notification.STOP_PLAY"
    }
}
