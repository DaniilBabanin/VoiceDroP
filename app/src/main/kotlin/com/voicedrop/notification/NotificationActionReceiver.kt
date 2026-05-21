package com.voicedrop.notification

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.widget.Toast
import com.voicedrop.R
import com.voicedrop.audio.VoiceMessageShare
import com.voicedrop.crypto.Bootstrap
import com.voicedrop.crypto.KeyManager
import com.voicedrop.crypto.MessagePayload
import com.voicedrop.crypto.RatchetEncryptAndSend
import com.voicedrop.service.VoiceDropService
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.MessageRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
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

                    // Local DELETE — refcount-aware: the audio file is wiped only when
                    // no other recipient's row still references it (fan-out safe).
                    // Sender-side handling is unchanged from v1 per dr17.5 — only the
                    // outbound wire encoding changes.
                    repository.markDeletedWithBlobRefcount(message)
                    notificationHelper.cancelNotification(uuid.hashCode())

                    val targetUuidObj = runCatching { UUID.fromString(uuid) }.getOrNull() ?: return@launch
                    sendRemoteDelete(context, db, message.contactId, targetUuidObj)
                }
            }

            ACTION_STOP_PLAY -> {
                val serviceIntent = Intent(context, VoiceDropService::class.java).apply {
                    action = VoiceDropService.ACTION_STOP_PLAY
                }
                context.startService(serviceIntent)
                if (uuid != null) notificationHelper.cancelNotification(uuid.hashCode())
            }

            ACTION_SHARE -> {
                if (uuid == null) return
                val pendingResult = goAsync()
                scope.launch {
                    try {
                        val file = VoiceMessageShare.prepare(context, uuid)
                        if (file == null) {
                            withContext(Dispatchers.Main) {
                                Toast.makeText(context, R.string.share_unavailable, Toast.LENGTH_SHORT).show()
                            }
                        } else {
                            VoiceMessageShare.share(context, file)
                        }
                    } finally {
                        pendingResult.finish()
                    }
                }
            }
        }
    }

    /**
     * DR17.5 W7 — wire shape changed but the protocol stays: a DELETE on the local
     * side ALSO sends a DELETE-kind inner plaintext through the ratchet so the peer
     * deletes their copy. Transmits no-op'd here — the row lands in the v2 outbox
     * and the running service's `PendingOutboxReplay` picks it up. We send an
     * ACTION_FLUSH_OUTBOX intent to nudge that immediately.
     */
    private suspend fun sendRemoteDelete(
        context: Context,
        db: AppDatabase,
        contactId: String,
        targetUuid: UUID
    ) {
        val keyManager = KeyManager(context)
        val ownFp32 = Bootstrap.fingerprintBytes(keyManager.getPublicKeyBytes())
        val sender = RatchetEncryptAndSend(
            db = db,
            wrapMac = keyManager,
            ownFingerprint32 = ownFp32,
            transmit = { _, _ -> /* deferred to outbox replay */ }
        )
        try {
            sender.encryptAndSend(contactId, MessagePayload.encodeDelete(targetUuid)) { _, _, _ -> null }
        } catch (t: Throwable) {
            android.util.Log.w(
                "VoiceDrop/NotifAction",
                "remote DELETE failed for ${contactId.take(8)} target=${targetUuid.toString().take(8)}: ${t.message}"
            )
            return
        }
        context.startForegroundService(VoiceDropService.flushOutboxIntent(context))
    }

    companion object {
        const val ACTION_PLAY = "com.voicedrop.notification.PLAY"
        const val ACTION_DELETE = "com.voicedrop.notification.DELETE"
        const val ACTION_STOP_PLAY = "com.voicedrop.notification.STOP_PLAY"
        const val ACTION_SHARE = "com.voicedrop.notification.SHARE"
    }
}
