package com.voicedrop.service

import android.content.Intent
import android.graphics.drawable.Icon
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import com.voicedrop.R
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

        when (state.state) {
            ServiceState.State.RECORDING -> {
                val intent = Intent(this, PermissionActivity::class.java).apply {
                    action = VoiceDropService.ACTION_RECORD_STOP
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                startActivityAndCollapse(intent)
            }
            ServiceState.State.IDLE, ServiceState.State.SENDING -> {
                scope.launch {
                    val contacts = repository.getAllContacts().first()
                    when {
                        contacts.isEmpty() -> {
                            showDialog(ContactPickerDialog(this@TalkTileService, emptyList()) {})
                        }
                        contacts.size == 1 -> {
                            launchRecording(contacts[0].id)
                        }
                        else -> {
                            val prefs = getSharedPreferences("voicedrop_settings", MODE_PRIVATE)
                            val lastContactId = prefs.getString("pref_last_contact_id", null)
                            val target = contacts.find { it.id == lastContactId }
                            if (target != null) {
                                launchRecording(target.id)
                            } else {
                                showDialog(ContactPickerDialog(this@TalkTileService, contacts) { contactId ->
                                    launchRecording(contactId)
                                })
                            }
                        }
                    }
                }
            }
        }
    }

    fun onLongClick() {
        scope.launch {
            val contacts = repository.getAllContacts().first()
            showDialog(ContactPickerDialog(this@TalkTileService, contacts) { contactId ->
                launchRecording(contactId)
            })
        }
    }

    private fun launchRecording(contactId: String) {
        val intent = Intent(this, PermissionActivity::class.java).apply {
            action = VoiceDropService.ACTION_RECORD_START
            putExtra(VoiceDropService.EXTRA_CONTACT_ID, contactId)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        startActivityAndCollapse(intent)
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
                    tile.label = when {
                        contacts.isEmpty() -> "No contacts"
                        contacts.size == 1 -> contacts[0].name
                        else -> "VoiceDrop"
                    }
                    tile.updateTile()
                }
                return
            }
            ServiceState.State.RECORDING -> {
                tile.state = Tile.STATE_ACTIVE
                tile.icon = Icon.createWithResource(this, R.drawable.ic_tile_recording)
                if (timerJob == null) {
                    val startTime = System.currentTimeMillis()
                    timerJob = scope.launch {
                        while (true) {
                            val elapsed = (System.currentTimeMillis() - startTime) / 1000
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
}
