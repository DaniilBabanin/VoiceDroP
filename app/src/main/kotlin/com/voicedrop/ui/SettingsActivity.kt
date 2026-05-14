package com.voicedrop.ui

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.view.MenuItem
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import com.mikepenz.aboutlibraries.LibsBuilder
import com.voicedrop.R
import com.voicedrop.crypto.KeyManager
import com.voicedrop.service.VoiceDropService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

class SettingsActivity : AppCompatActivity() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    override fun onCreate(savedInstanceState: Bundle?) {
        Log.d(TAG, "onCreate start")
        super.onCreate(savedInstanceState)
        try {
            setContentView(R.layout.activity_settings)
            Log.d(TAG, "setContentView OK")
        } catch (e: Exception) {
            Log.e(TAG, "setContentView FAILED", e)
            finish(); return
        }

        val toolbar = findViewById<Toolbar>(R.id.toolbar)
        setSupportActionBar(toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)

        val prefs = getSharedPreferences("voicedrop_settings", MODE_PRIVATE)
        val keyManager = KeyManager(this)

        val displayNameEdit = findViewById<EditText>(R.id.edit_display_name)
        displayNameEdit.setText(prefs.getString("display_name", ""))

        val signalingUrlEdit = findViewById<EditText>(R.id.edit_signaling_url)
        signalingUrlEdit.setText(prefs.getString("signaling_url", ""))

        val fingerprintText = findViewById<TextView>(R.id.text_my_fingerprint)
        val fp = keyManager.getFingerprint()
        fingerprintText.text = fp.chunked(8).joinToString(" ")

        val saveUrlButton = findViewById<Button>(R.id.button_save_url)
        saveUrlButton.setOnClickListener {
            val name = displayNameEdit.text.toString().trim()
            val url = signalingUrlEdit.text.toString().trim()
            prefs.edit()
                .putString("display_name", name.ifBlank { "VoiceDrop User" })
                .putString("signaling_url", url)
                .apply()
            Toast.makeText(this, getString(R.string.url_saved), Toast.LENGTH_SHORT).show()
            startService(Intent(this, VoiceDropService::class.java).apply {
                action = VoiceDropService.ACTION_RELOAD_CONFIG
            })
        }

        findViewById<Button>(R.id.button_privacy_policy).setOnClickListener {
            val url = getString(R.string.privacy_policy_url)
            try {
                startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
            } catch (e: ActivityNotFoundException) {
                Toast.makeText(this, url, Toast.LENGTH_LONG).show()
            }
        }

        findViewById<Button>(R.id.button_open_source_licenses).setOnClickListener {
            LibsBuilder()
                .withActivityTitle(getString(R.string.open_source_licenses))
                .withSearchEnabled(true)
                .withLicenseShown(true)
                .withEdgeToEdge(true)
                .start(this)
        }

        val testConnectionButton = findViewById<Button>(R.id.button_test_connection)
        testConnectionButton.setOnClickListener {
            val url = signalingUrlEdit.text.toString().trim()
            if (url.isBlank()) {
                Toast.makeText(this, "No URL configured", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            scope.launch(Dispatchers.IO) {
                try {
                    val testUrl = url.replace("wss://", "https://").replace("ws://", "http://")
                    val connection = java.net.URL(testUrl).openConnection() as java.net.HttpURLConnection
                    connection.connectTimeout = 5000
                    connection.readTimeout = 5000
                    val code = connection.responseCode
                    scope.launch(Dispatchers.Main) {
                        Toast.makeText(
                            this@SettingsActivity,
                            if (code in 100..599) getString(R.string.connection_ok) + " (HTTP $code)" else getString(R.string.connection_failed),
                            Toast.LENGTH_SHORT
                        ).show()
                    }
                } catch (e: Exception) {
                    scope.launch(Dispatchers.Main) {
                        Toast.makeText(this@SettingsActivity, getString(R.string.connection_failed) + ": ${e.message}", Toast.LENGTH_LONG).show()
                    }
                }
            }
        }
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == android.R.id.home) {
            finish()
            return true
        }
        return super.onOptionsItemSelected(item)
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    companion object {
        private const val TAG = "VoiceDrop/Settings"
    }
}
