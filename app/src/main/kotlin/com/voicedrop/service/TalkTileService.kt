package com.voicedrop.service

import android.Manifest
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.drawable.Icon
import android.os.Build
import android.os.SystemClock
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.util.Log
import com.voicedrop.R
import com.voicedrop.storage.ActiveContactsPrefs
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.MessageRepository
import com.voicedrop.ui.ContactPickerDialog
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

class TalkTileService : TileService() {

    private val scope = CoroutineScope(Dispatchers.Main + Job())
    private var stateJob: Job? = null
    private var timerJob: Job? = null
    private lateinit var repository: MessageRepository

    override fun onCreate() {
        super.onCreate()
        val db = AppDatabase.getInstance(this)
        repository = MessageRepository(db.contactDao(), db.messageDao(), db.pendingActionDao())
    }

    override fun onStartListening() {
        stateJob = scope.launch {
            ServiceState.recordingState.collect { state ->
                updateTile(state)
            }
        }
    }

    override fun onStopListening() {
        stateJob?.cancel()
        timerJob?.cancel()
        stateJob = null
        timerJob = null
    }

    override fun onClick() {
        val state = ServiceState.recordingState.value
        Log.d(TAG, "onClick state=${state.state}")

        when (state.state) {
            ServiceState.State.RECORDING -> {
                stopRecording()
            }
            ServiceState.State.IDLE, ServiceState.State.SENDING -> {
                scope.launch {
                    try {
                        val contacts = repository.getAllContacts().first()
                        if (contacts.isEmpty()) {
                            showDialog(ContactPickerDialog(this@TalkTileService, emptyList()) {})
                            return@launch
                        }
                        // Fan-out target: every checked contact whose ratchet has learned dhr_pub.
                        // DR17.5 W4 — skip contacts whose dhr_pub is still null (Bob mid-bootstrap).
                        val eligible = ActiveContactsPrefs.resolveRecipients(
                            this@TalkTileService, contacts
                        ).filter { it.dhr_pub != null }
                        if (eligible.isNotEmpty()) {
                            startRecordingFanOut(eligible.map { it.id })
                            return@launch
                        }
                        // No eligible recipients in the active set — fall back to the picker
                        // so the user can pick a different contact or wait for pairing.
                        if (contacts.any { it.dhr_pub != null }) {
                            Log.i(TAG, "onClick: no eligible checked recipients — showing picker")
                            showDialog(ContactPickerDialog(this@TalkTileService, contacts) { id ->
                                startRecordingFanOut(listOf(id))
                            })
                        } else {
                            Log.i(TAG, "onClick: no contacts bootstrapped yet")
                            showDialog(ContactPickerDialog(this@TalkTileService, contacts) {})
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "onClick coroutine failed", e)
                    }
                }
            }
        }
    }

    private fun startRecordingFanOut(contactIds: List<String>) {
        if (contactIds.isEmpty()) return
        if (checkSelfPermission(Manifest.permission.RECORD_AUDIO) ==
            PackageManager.PERMISSION_GRANTED
        ) {
            startForegroundService(VoiceDropService.recordStartAllIntent(this, contactIds))
        } else {
            val intent = Intent(this, PermissionActivity::class.java).apply {
                action = VoiceDropService.ACTION_RECORD_START
                putExtra(VoiceDropService.EXTRA_CONTACT_IDS, contactIds.toTypedArray())
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            startTileActivity(intent)
        }
    }

    private fun stopRecording() {
        // Recording state implies mic permission is already granted, so go straight to the service.
        startForegroundService(VoiceDropService.recordStopIntent(this))
    }

    private fun startTileActivity(intent: Intent) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val pi = PendingIntent.getActivity(
                this, intent.action.hashCode(), intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            startActivityAndCollapse(pi)
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }

    private fun updateTile(state: ServiceState.RecordingState) {
        val tile = qsTile ?: return
        when (state.state) {
            ServiceState.State.IDLE -> {
                timerJob?.cancel()
                timerJob = null
                tile.state = Tile.STATE_INACTIVE
                tile.icon = Icon.createWithResource(this, R.drawable.ic_tile_idle)
                scope.launch {
                    val contacts = repository.getAllContacts().first()
                    val recipients = ActiveContactsPrefs.resolveRecipients(this@TalkTileService, contacts)
                    tile.label = when {
                        contacts.isEmpty() -> "No contacts"
                        recipients.isEmpty() -> "VoiceDrop"
                        recipients.size == 1 -> recipients.first().name
                        else -> "${recipients.size} recipients"
                    }
                    tile.updateTile()
                }
                return
            }
            ServiceState.State.RECORDING -> {
                tile.state = Tile.STATE_ACTIVE
                tile.icon = Icon.createWithResource(this, R.drawable.ic_tile_recording)
                if (timerJob == null) {
                    val startedAt = state.startedAtElapsedRealtime
                    timerJob = scope.launch {
                        while (true) {
                            val elapsed = if (startedAt > 0L) {
                                (SystemClock.elapsedRealtime() - startedAt) / 1000
                            } else 0L
                            tile.label = "${elapsed / 60}:${"%02d".format(elapsed % 60)} recording…"
                            tile.updateTile()
                            delay(1000)
                        }
                    }
                }
                return
            }
            ServiceState.State.SENDING -> {
                timerJob?.cancel()
                timerJob = null
                tile.state = Tile.STATE_ACTIVE
                tile.icon = Icon.createWithResource(this, R.drawable.ic_tile_sending)
                tile.label = "Sending…"
            }
        }
        tile.updateTile()
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    companion object {
        private const val TAG = "VoiceDrop/Tile"
    }
}
