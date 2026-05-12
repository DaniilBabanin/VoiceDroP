package com.voicedrop.service

import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import android.os.PowerManager
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import android.util.Log
import com.voicedrop.audio.AudioPlayer
import com.voicedrop.audio.AudioRecorder
import com.voicedrop.crypto.KeyManager
import com.voicedrop.crypto.MessageCrypto
import com.voicedrop.crypto.ContactKey
import com.voicedrop.network.ConnectionManager
import com.voicedrop.notification.NotificationHelper
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.MessageEntity
import com.voicedrop.storage.MessageRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.io.File
import java.util.UUID

class VoiceDropService : Service() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private lateinit var notificationHelper: NotificationHelper
    private lateinit var keyManager: KeyManager
    private lateinit var repository: MessageRepository
    private lateinit var connectionManager: ConnectionManager  // reassigned on reload

    private val audioRecorder = AudioRecorder()
    private val audioPlayer = AudioPlayer()

    private var recordingContactId: String? = null
    private var recordStartTime: Long = 0L
    private var recordingJob: Deferred<ByteArray>? = null
    private var wakeLock: PowerManager.WakeLock? = null
    private var playbackJob: Job? = null

    override fun onCreate() {
        super.onCreate()
        notificationHelper = NotificationHelper(this)
        keyManager = KeyManager(this)

        val db = AppDatabase.getInstance(this)
        repository = MessageRepository(db.contactDao(), db.messageDao(), db.pendingActionDao())

        val prefs = getSharedPreferences("voicedrop_settings", Context.MODE_PRIVATE)
        val workerUrl = prefs.getString("signaling_url", "") ?: ""
        connectionManager = ConnectionManager(this, repository, keyManager, workerUrl)
        connectionManager.start()

        // Stay alive as a foreground service so the TCP listener is always up for incoming messages
        startForeground(NOTIFICATION_ID_IDLE, notificationHelper.buildIdleNotification())
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_RELOAD_CONFIG -> {
                connectionManager.stop()
                val prefs = getSharedPreferences("voicedrop_settings", Context.MODE_PRIVATE)
                val newUrl = prefs.getString("signaling_url", "") ?: ""
                connectionManager = ConnectionManager(this, repository, keyManager, newUrl)
                connectionManager.start()
            }
            ACTION_RECORD_START -> {
                val contactId = intent.getStringExtra(EXTRA_CONTACT_ID) ?: return START_STICKY
                startRecording(contactId)
            }
            ACTION_RECORD_STOP -> stopRecording()
            ACTION_PLAY -> {
                val uuid = intent.getStringExtra(EXTRA_UUID) ?: return START_STICKY
                play(uuid)
            }
            ACTION_STOP_PLAY -> stopPlay()
        }
        return START_STICKY
    }

    private fun startRecording(contactId: String) {
        recordingContactId = contactId
        recordStartTime = System.currentTimeMillis()

        scope.launch {
            val c = repository.getContact(contactId)
            val contactName = c?.name ?: "Contact"

            val notification = notificationHelper.buildRecordingNotification(contactName)
            startForeground(NOTIFICATION_ID_RECORDING, notification)

            vibrateDouble()
            ServiceState.updateState(ServiceState.State.RECORDING, contactId)

            try {
                audioRecorder.start()
                // Launch the capture loop; await it in stopRecording() to get the opus bytes
                recordingJob = scope.async { audioRecorder.recordLoop { } }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start recording", e)
                startForeground(NOTIFICATION_ID_IDLE, notificationHelper.buildIdleNotification())
                ServiceState.updateState(ServiceState.State.IDLE, null)
            }
        }
    }

    private fun stopRecording() {
        scope.launch {
            val contactId = recordingContactId ?: return@launch
            recordingContactId = null

            vibrateSingle()
            ServiceState.updateState(ServiceState.State.SENDING, contactId)
            notificationHelper.updateRecordingNotification(NOTIFICATION_ID_RECORDING, "Sending…")

            try {
                // Signal the record loop to finish and collect the encoded audio
                audioRecorder.stopRecording()
                val opusBytes = recordingJob?.await() ?: ByteArray(0)
                recordingJob = null
                val durationMs = (System.currentTimeMillis() - recordStartTime).toInt()

                val contact = repository.getContact(contactId) ?: return@launch
                val sessionKey = ContactKey.deriveSessionKey(
                    keyManager.getPrivateKeyBytes(),
                    android.util.Base64.decode(contact.publicKeyBase64, android.util.Base64.NO_WRAP)
                )

                val deleteAfterMs = contact.autoDeleteAfterMs
                val payload = MessageCrypto.buildVoicePayload(durationMs, deleteAfterMs, opusBytes)

                val senderFpHex = keyManager.getFingerprint()
                val senderFpBytes = senderFpHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                val recipFpBytes = contactId.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                val uuid = UUID.randomUUID()

                val wireFrame = MessageCrypto.buildFrame(
                    senderFpBytes, recipFpBytes, uuid, sessionKey, payload
                )

                val encryptedBytes = MessageCrypto.encrypt(sessionKey, opusBytes)
                val messagesDir = File(filesDir, "messages")
                messagesDir.mkdirs()
                val encFile = File(messagesDir, "${uuid}.enc")
                encFile.writeBytes(encryptedBytes)

                acquireWakeLock()

                repository.insertMessage(
                    MessageEntity(
                        uuid = uuid.toString(),
                        contactId = contactId,
                        direction = MessageEntity.DIRECTION_OUTBOUND,
                        state = MessageEntity.STATE_OUTBOX,
                        encryptedFilePath = encFile.absolutePath,
                        durationMs = durationMs,
                        deleteAfterMs = deleteAfterMs,
                        scheduledDeleteAt = 0L,
                        transcription = null,
                        createdAt = System.currentTimeMillis(),
                        sentAt = 0L,
                        deliveredAt = 0L
                    )
                )

                connectionManager.sendToContact(contactId, wireFrame)
                repository.updateMessageStateSent(uuid.toString(), MessageEntity.STATE_SENT, System.currentTimeMillis())

            } catch (e: Exception) {
                Log.e(TAG, "Failed to send message", e)
            } finally {
                releaseWakeLock()
                // Return to idle foreground state — keep service alive for incoming messages
                startForeground(NOTIFICATION_ID_IDLE, notificationHelper.buildIdleNotification())
                ServiceState.updateState(ServiceState.State.IDLE, null)
            }
        }
    }

    fun play(uuid: String) {
        playbackJob?.cancel()
        playbackJob = scope.launch {
            try {
                val message = repository.getMessage(uuid) ?: return@launch
                val contactId = message.contactId
                val contact = repository.getContact(contactId) ?: return@launch
                val sessionKey = ContactKey.deriveSessionKey(
                    keyManager.getPrivateKeyBytes(),
                    android.util.Base64.decode(contact.publicKeyBase64, android.util.Base64.NO_WRAP)
                )

                val encFile = message.encryptedFilePath?.let { File(it) } ?: return@launch
                val encrypted = encFile.readBytes()
                val opusBytes = MessageCrypto.decrypt(sessionKey, encrypted)

                val notifId = uuid.hashCode()
                notificationHelper.updatePlaybackProgress(notifId, 0, message.durationMs)

                audioPlayer.play(opusBytes) { progress ->
                    val elapsed = (progress * message.durationMs).toInt()
                    scope.launch {
                        notificationHelper.updatePlaybackProgress(notifId, elapsed, message.durationMs)
                    }
                }

                repository.updateMessageState(uuid, MessageEntity.STATE_PLAYED)
                notificationHelper.cancelNotification(notifId)

            } catch (e: Exception) {
                Log.e(TAG, "Playback failed", e)
            }
        }
    }

    private fun stopPlay() {
        playbackJob?.cancel()
        playbackJob = null
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        audioRecorder.stopRecording()
        recordingJob?.cancel()
        recordingJob = null
        recordingContactId = null
        releaseWakeLock()
        stopSelf()
    }

    override fun onDestroy() {
        connectionManager.stop()
        scope.cancel()
        releaseWakeLock()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun vibrateDouble() {
        getVibrator()?.vibrate(
            VibrationEffect.createWaveform(longArrayOf(0, 80, 40, 80), -1)
        )
    }

    private fun vibrateSingle() {
        getVibrator()?.vibrate(
            VibrationEffect.createOneShot(120, VibrationEffect.DEFAULT_AMPLITUDE)
        )
    }

    private fun getVibrator(): Vibrator? {
        return if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
            (getSystemService(Context.VIBRATOR_MANAGER_SERVICE) as VibratorManager).defaultVibrator
        } else {
            @Suppress("DEPRECATION")
            getSystemService(Context.VIBRATOR_SERVICE) as Vibrator
        }
    }

    private fun acquireWakeLock() {
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "VoiceDrop:send").apply {
            acquire(30_000L)
        }
    }

    private fun releaseWakeLock() {
        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null
    }

    companion object {
        const val ACTION_RECORD_START = "com.voicedrop.ACTION_RECORD_START"
        const val ACTION_RECORD_STOP = "com.voicedrop.ACTION_RECORD_STOP"
        const val ACTION_PLAY = "com.voicedrop.ACTION_PLAY"
        const val ACTION_STOP_PLAY = "com.voicedrop.ACTION_STOP_PLAY"
        const val ACTION_RELOAD_CONFIG = "com.voicedrop.ACTION_RELOAD_CONFIG"
        const val EXTRA_CONTACT_ID = "contact_id"
        const val EXTRA_UUID = "uuid"
        const val NOTIFICATION_ID_IDLE = 1000
        const val NOTIFICATION_ID_RECORDING = 1001
        private const val TAG = "VoiceDropService"

        fun recordStartIntent(context: Context, contactId: String) =
            Intent(context, VoiceDropService::class.java).apply {
                action = ACTION_RECORD_START
                putExtra(EXTRA_CONTACT_ID, contactId)
            }

        fun recordStopIntent(context: Context) =
            Intent(context, VoiceDropService::class.java).apply {
                action = ACTION_RECORD_STOP
            }

        fun playIntent(context: Context, uuid: String) =
            Intent(context, VoiceDropService::class.java).apply {
                action = ACTION_PLAY
                putExtra(EXTRA_UUID, uuid)
            }
    }
}
