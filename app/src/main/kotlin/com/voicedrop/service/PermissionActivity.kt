package com.voicedrop.service

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity

class PermissionActivity : AppCompatActivity() {

    private val recordPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { results ->
        val audioGranted = results[Manifest.permission.RECORD_AUDIO] == true
        val notifGranted = if (Build.VERSION.SDK_INT >= 33) {
            results[Manifest.permission.POST_NOTIFICATIONS] == true
        } else true

        if (audioGranted) {
            dispatchIntent()
        } else {
            Toast.makeText(
                this,
                "Microphone permission required. Grant it in Settings.",
                Toast.LENGTH_LONG
            ).show()
            startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                data = android.net.Uri.fromParts("package", packageName, null)
            })
        }
        finish()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val action = intent?.action

        if (action == VoiceDropService.ACTION_RECORD_STOP) {
            startForegroundService(VoiceDropService.recordStopIntent(this))
            finish()
            return
        }

        val permissionsNeeded = mutableListOf<String>()
        if (checkSelfPermission(Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
            permissionsNeeded.add(Manifest.permission.RECORD_AUDIO)
        }
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            permissionsNeeded.add(Manifest.permission.POST_NOTIFICATIONS)
        }

        if (permissionsNeeded.isEmpty()) {
            dispatchIntent()
            finish()
        } else {
            recordPermissionLauncher.launch(permissionsNeeded.toTypedArray())
        }
    }

    private fun dispatchIntent() {
        val contactIds = intent?.getStringArrayExtra(VoiceDropService.EXTRA_CONTACT_IDS)?.toList()
        val contactId = intent?.getStringExtra(VoiceDropService.EXTRA_CONTACT_ID)
        val serviceIntent = when {
            !contactIds.isNullOrEmpty() ->
                VoiceDropService.recordStartAllIntent(this, contactIds)
            contactId != null ->
                VoiceDropService.recordStartIntent(this, contactId)
            else ->
                VoiceDropService.recordStopIntent(this)
        }
        startForegroundService(serviceIntent)
    }
}
