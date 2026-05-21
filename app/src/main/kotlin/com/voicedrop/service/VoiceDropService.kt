package com.voicedrop.service

import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import android.os.PowerManager
import android.os.SystemClock
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import android.util.Log
import com.google.crypto.tink.subtle.X25519
import com.voicedrop.audio.AudioPlayer
import com.voicedrop.audio.AudioRecorder
import com.voicedrop.crypto.AutoResetTrigger
import com.voicedrop.crypto.Bootstrap
import com.voicedrop.crypto.KeyManager
import com.voicedrop.crypto.RatchetDecryptAndPersist
import com.voicedrop.crypto.RatchetEncryptAndSend
import com.voicedrop.crypto.ReceiptInboundHandler
import com.voicedrop.crypto.ResetReceive
import com.voicedrop.crypto.ResetRetransmitJob
import com.voicedrop.network.ConnectionManager
import com.voicedrop.network.IngestRateLimiter
import com.voicedrop.network.PendingOutboxReplay
import com.voicedrop.notification.NotificationHelper
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.MessageEntity
import com.voicedrop.storage.MessageRepository
import com.voicedrop.storage.TransportType
import com.voicedrop.ui.SettingsActivity.Companion.PREF_RELAY_FALLBACK_ENABLED
import com.voicedrop.ui.AllWidgetProvider
import com.voicedrop.ui.VoiceDropWidgetProvider
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import java.io.File
import java.io.IOException

class VoiceDropService : Service() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private lateinit var notificationHelper: NotificationHelper
    private lateinit var keyManager: KeyManager
    private lateinit var db: AppDatabase
    private lateinit var repository: MessageRepository
    private lateinit var connectionManager: ConnectionManager

    // DR17.5 W3 — long-lived ratchet components owned by the service so the
    // ConnectionManager (which routes wire bytes) gets the same instances on
    // both inbound and outbound paths. Reset retransmit job's coroutine scope
    // is the service scope so it survives until the service stops.
    private lateinit var ratchetSender: RatchetEncryptAndSend
    private lateinit var pendingOutboxReplay: PendingOutboxReplay
    private lateinit var resetRetransmitJob: ResetRetransmitJob
    private lateinit var resetReceive: ResetReceive
    private lateinit var ownFingerprint32: ByteArray

    private val audioRecorder = AudioRecorder()
    private val audioPlayer = AudioPlayer()

    private var recordingContactIds: List<String> = emptyList()
    private var recordStartTime: Long = 0L
    private var recordStartElapsedRealtime: Long = 0L
    private var recordingJob: Deferred<AudioRecorder.RecordResult>? = null
    private var wakeLock: PowerManager.WakeLock? = null
    private var playbackJob: Job? = null

    override fun onCreate() {
        super.onCreate()
        notificationHelper = NotificationHelper(this)
        keyManager = KeyManager(this)

        db = AppDatabase.getInstance(this)
        repository = MessageRepository(db.contactDao(), db.messageDao(), db.pendingActionDao())

        ownFingerprint32 = Bootstrap.fingerprintBytes(keyManager.getPublicKeyBytes())

        // The transmit lambda dereferences `connectionManager` at call time, not
        // capture time, so ACTION_RELOAD_CONFIG can swap the connection manager
        // without breaking outbound paths.
        val transmitForRatchet: suspend (String, ByteArray) -> Unit = { id, bytes ->
            val transport = connectionManager.transmit(id, bytes)
            if (transport == TransportType.UNKNOWN) {
                // Active-backoff is already armed by transmit() and the outbox
                // row is in place via the ratchet txn; raise so encryptAndSend's
                // runCatching surfaces the miss for telemetry but does NOT roll
                // back the persisted state.
                throw IOException("transmit: no path for ${id.take(8)} — outbox replay owns retries")
            }
        }
        val transmitForReplay: suspend (Int, String, ByteArray) -> Boolean = { _, id, bytes ->
            connectionManager.transmit(id, bytes) != TransportType.UNKNOWN
        }

        ratchetSender = RatchetEncryptAndSend(
            db = db,
            wrapMac = keyManager,
            ownFingerprint32 = ownFingerprint32,
            transmit = transmitForRatchet
        )
        val ratchetReceiver = RatchetDecryptAndPersist(db, keyManager, ownFingerprint32)
        val receiptInboundHandler = ReceiptInboundHandler(db)
        resetReceive = ResetReceive(
            db = db,
            wrapMac = keyManager,
            ownFingerprint32 = ownFingerprint32,
            idSharedSecretFor = { contactId ->
                val contact = repository.getContact(contactId)
                    ?: error("idSharedSecretFor: contact $contactId not found")
                val peerPub = android.util.Base64.decode(
                    contact.publicKeyBase64, android.util.Base64.NO_WRAP
                )
                val priv = keyManager.getPrivateKeyBytes()
                try {
                    X25519.computeSharedSecret(priv, peerPub)
                } finally {
                    priv.fill(0)
                }
            }
        )
        pendingOutboxReplay = PendingOutboxReplay(
            db = db,
            wrapMac = keyManager,
            transmit = transmitForReplay
        )
        resetRetransmitJob = ResetRetransmitJob(
            db = db,
            replay = pendingOutboxReplay,
            scope = scope
        )
        val autoResetTrigger = AutoResetTrigger(db, resetReceive)
        val ingestRateLimiter = IngestRateLimiter()

        val prefs = getSharedPreferences("voicedrop_settings", Context.MODE_PRIVATE)
        val workerUrl = prefs.getString("signaling_url", "") ?: ""
        val relayFallback = prefs.getBoolean(PREF_RELAY_FALLBACK_ENABLED, true)
        connectionManager = ConnectionManager(
            context = this,
            repository = repository,
            keyManager = keyManager,
            workerUrl = workerUrl,
            db = db,
            ratchetReceiver = ratchetReceiver,
            receiptInboundHandler = receiptInboundHandler,
            resetReceive = resetReceive,
            autoResetTrigger = autoResetTrigger,
            ingestRateLimiter = ingestRateLimiter,
            pendingOutboxReplay = pendingOutboxReplay,
            resetRetransmitJob = resetRetransmitJob,
            relayFallbackEnabled = relayFallback
        )
        connectionManager.start()

        // Stay alive as a foreground service so the TCP listener is always up for incoming messages
        startForeground(NOTIFICATION_ID_IDLE, notificationHelper.buildIdleNotification())

        // DR17.5 W3 startup hooks — replay any outbox accumulated while the
        // process was killed, and resume reset retransmit schedules for any
        // contact whose previous init didn't get acked.
        scope.launch {
            try {
                pendingOutboxReplay.replayAll()
            } catch (t: Throwable) {
                Log.w(TAG, "startup outbox replay failed", t)
            }
            try {
                for (contact in repository.getAllContacts().first()) {
                    if (contact.expecting_ack != 0) {
                        Log.i(TAG, "startup: resuming reset retransmit for ${contact.id.take(8)}")
                        resetRetransmitJob.start(contact.id)
                    }
                }
            } catch (t: Throwable) {
                Log.w(TAG, "startup reset-retransmit resume failed", t)
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_RELOAD_CONFIG -> {
                connectionManager.stop()
                val prefs = getSharedPreferences("voicedrop_settings", Context.MODE_PRIVATE)
                val newUrl = prefs.getString("signaling_url", "") ?: ""
                val relayFallback = prefs.getBoolean(PREF_RELAY_FALLBACK_ENABLED, true)
                val ratchetReceiver = RatchetDecryptAndPersist(db, keyManager, ownFingerprint32)
                val receiptInboundHandler = ReceiptInboundHandler(db)
                val autoResetTrigger = AutoResetTrigger(db, resetReceive)
                val ingestRateLimiter = IngestRateLimiter()
                connectionManager = ConnectionManager(
                    context = this,
                    repository = repository,
                    keyManager = keyManager,
                    workerUrl = newUrl,
                    db = db,
                    ratchetReceiver = ratchetReceiver,
                    receiptInboundHandler = receiptInboundHandler,
                    resetReceive = resetReceive,
                    autoResetTrigger = autoResetTrigger,
                    ingestRateLimiter = ingestRateLimiter,
                    pendingOutboxReplay = pendingOutboxReplay,
                    resetRetransmitJob = resetRetransmitJob,
                    relayFallbackEnabled = relayFallback
                )
                connectionManager.start()
            }
            ACTION_FLUSH_OUTBOX -> {
                // Triggered from QrPairActivity after pairing (auto-HELLO outbox row)
                // and from any UI that wants an immediate replay without waiting for
                // NetworkCallback.onAvailable.
                scope.launch {
                    try {
                        pendingOutboxReplay.replayAll()
                    } catch (t: Throwable) {
                        Log.w(TAG, "ACTION_FLUSH_OUTBOX: replay failed", t)
                    }
                }
            }
            ACTION_RECORD_START -> {
                val ids = intent.getStringArrayExtra(EXTRA_CONTACT_IDS)?.toList()
                    ?: intent.getStringExtra(EXTRA_CONTACT_ID)?.let { listOf(it) }
                    ?: return START_STICKY
                startRecording(ids)
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

    private fun startRecording(contactIds: List<String>) {
        if (contactIds.isEmpty()) return
        recordingContactIds = contactIds
        recordStartTime = System.currentTimeMillis()
        recordStartElapsedRealtime = SystemClock.elapsedRealtime()

        scope.launch {
            val firstContact = repository.getContact(contactIds.first())
            // Notification label: single name if 1 recipient, "N recipients" otherwise.
            val notificationLabel = if (contactIds.size == 1) {
                firstContact?.name ?: "Contact"
            } else {
                "${contactIds.size} recipients"
            }

            val notification = notificationHelper.buildRecordingNotification(
                notificationLabel,
                recordStartTime,
            )
            startForeground(NOTIFICATION_ID_RECORDING, notification)

            vibrateDouble()
            ServiceState.updateState(
                ServiceState.State.RECORDING,
                contactIds,
                recordStartElapsedRealtime,
                recordStartTime,
            )
            VoiceDropWidgetProvider.refreshAll(this@VoiceDropService)
            AllWidgetProvider.refreshAll(this@VoiceDropService)

            try {
                audioRecorder.start()
                recordingJob = scope.async { audioRecorder.recordLoop { } }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start recording", e)
                startForeground(NOTIFICATION_ID_IDLE, notificationHelper.buildIdleNotification())
                ServiceState.updateState(ServiceState.State.IDLE, emptyList())
                VoiceDropWidgetProvider.refreshAll(this@VoiceDropService)
                AllWidgetProvider.refreshAll(this@VoiceDropService)
            }
        }
    }

    private fun stopRecording() {
        scope.launch {
            val contactIds = recordingContactIds.takeIf { it.isNotEmpty() } ?: return@launch
            recordingContactIds = emptyList()

            vibrateSingle()
            ServiceState.updateState(ServiceState.State.SENDING, contactIds)
            VoiceDropWidgetProvider.refreshAll(this@VoiceDropService)
            AllWidgetProvider.refreshAll(this@VoiceDropService)
            notificationHelper.updateRecordingNotification(NOTIFICATION_ID_RECORDING, "Sending…")

            try {
                audioRecorder.stopRecording()
                val recordResult = recordingJob?.await() ?: run {
                    Log.w(TAG, "stopRecording: no recordingJob (start failed?) — nothing to send")
                    return@launch
                }
                recordingJob = null
                val opusBytes = recordResult.opus
                val waveformPeaks = recordResult.peaks
                val durationMs = (System.currentTimeMillis() - recordStartTime).toInt()

                // Per-contact auto-delete window: each recipient's row honors that
                // contact's autoDeleteAfterMs setting.
                val deleteAfterMsByContact = mutableMapOf<String, Long>()
                for (id in contactIds) {
                    val c = repository.getContact(id)
                    if (c != null) deleteAfterMsByContact[id] = c.autoDeleteAfterMs
                }
                val liveRecipients = contactIds.filter { it in deleteAfterMsByContact }
                if (liveRecipients.isEmpty()) {
                    Log.w(TAG, "stopRecording: no live recipients (all deleted mid-record?) — dropping send")
                    return@launch
                }

                acquireWakeLock()

                val sender = MultiRecipientSender(
                    messagesDir = File(filesDir, "messages"),
                    encryptAndSend = ratchetSender::encryptAndSend,
                )
                val result = sender.sendVoice(
                    recipientIds = liveRecipients,
                    opusBytes = opusBytes,
                    durationMs = durationMs,
                    deleteAfterMsByContact = deleteAfterMsByContact,
                    waveformPeaks = waveformPeaks,
                )

                if (result.failedRecipientIds.isNotEmpty() && result.successfulRecipientIds.isEmpty()) {
                    // All recipients failed: surface the same UX as the legacy single-recipient
                    // AwaitingFirstReceive toast. Concrete cause is in the logs.
                    android.os.Handler(android.os.Looper.getMainLooper()).post {
                        android.widget.Toast.makeText(
                            this@VoiceDropService,
                            "Setting up secure channel — try again in a moment",
                            android.widget.Toast.LENGTH_SHORT
                        ).show()
                    }
                }
                Log.i(
                    TAG,
                    "sent voice memo (${durationMs}ms) to ${result.successfulRecipientIds.size}/" +
                        "${liveRecipients.size} recipients — failed: ${result.failedRecipientIds.joinToString { it.take(8) }}"
                )
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "Failed to send message", e)
            } finally {
                releaseWakeLock()
                startForeground(NOTIFICATION_ID_IDLE, notificationHelper.buildIdleNotification())
                ServiceState.updateState(ServiceState.State.IDLE, emptyList())
                VoiceDropWidgetProvider.refreshAll(this@VoiceDropService)
                AllWidgetProvider.refreshAll(this@VoiceDropService)
            }
        }
    }

    fun play(uuid: String) {
        playbackJob?.cancel()
        ServiceState.setPlayingUuid(uuid)
        ServiceState.resetPlayingProgress()
        playbackJob = scope.launch {
            val notifId = uuid.hashCode()
            try {
                val message = repository.getMessage(uuid) ?: return@launch
                val opusFile = message.encryptedFilePath?.let { File(it) } ?: return@launch
                if (!opusFile.exists()) return@launch
                // DR17.5: opus bytes are plaintext at rest (decision 2b); read directly.
                val opusBytes = opusFile.readBytes()

                notificationHelper.updatePlaybackProgress(notifId, 0, message.durationMs)

                audioPlayer.play(opusBytes) { progress ->
                    ServiceState.setPlayingProgress(progress)
                    val elapsed = (progress * message.durationMs).toInt()
                    scope.launch {
                        notificationHelper.updatePlaybackProgress(notifId, elapsed, message.durationMs)
                    }
                }

                repository.updateMessageState(uuid, MessageEntity.STATE_PLAYED)
            } catch (e: Exception) {
                Log.e(TAG, "Playback failed", e)
            } finally {
                notificationHelper.cancelNotification(notifId)
                if (ServiceState.playingUuid.value == uuid) {
                    ServiceState.setPlayingUuid(null)
                    ServiceState.resetPlayingProgress()
                }
            }
        }
    }

    private fun stopPlay() {
        playbackJob?.cancel()
        playbackJob = null
        ServiceState.setPlayingUuid(null)
        ServiceState.resetPlayingProgress()
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        audioRecorder.stopRecording()
        recordingJob?.cancel()
        recordingJob = null
        recordingContactIds = emptyList()
        releaseWakeLock()
        stopSelf()
    }

    override fun onDestroy() {
        connectionManager.stop()
        resetRetransmitJob.cancelAll()
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
        /** DR17.5 W3 — UI hook for "kick the outbox now" (e.g. after pairing auto-HELLO). */
        const val ACTION_FLUSH_OUTBOX = "com.voicedrop.ACTION_FLUSH_OUTBOX"
        const val EXTRA_CONTACT_ID = "contact_id"
        const val EXTRA_CONTACT_IDS = "contact_ids"    // string array, used by tile + All-widget
        const val EXTRA_UUID = "uuid"
        const val NOTIFICATION_ID_IDLE = 1000
        const val NOTIFICATION_ID_RECORDING = 1001
        private const val TAG = "VoiceDropService"

        fun recordStartIntent(context: Context, contactId: String) =
            Intent(context, VoiceDropService::class.java).apply {
                action = ACTION_RECORD_START
                putExtra(EXTRA_CONTACT_ID, contactId)
            }

        fun recordStartAllIntent(context: Context, contactIds: List<String>) =
            Intent(context, VoiceDropService::class.java).apply {
                action = ACTION_RECORD_START
                putExtra(EXTRA_CONTACT_IDS, contactIds.toTypedArray())
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

        fun stopPlayIntent(context: Context) =
            Intent(context, VoiceDropService::class.java).apply {
                action = ACTION_STOP_PLAY
            }

        fun flushOutboxIntent(context: Context) =
            Intent(context, VoiceDropService::class.java).apply {
                action = ACTION_FLUSH_OUTBOX
            }
    }
}
