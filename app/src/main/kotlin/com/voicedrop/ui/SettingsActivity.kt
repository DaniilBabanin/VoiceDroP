package com.voicedrop.ui

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.voicedrop.R
import com.voicedrop.crypto.KeyManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

class SettingsActivity : AppCompatActivity() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

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

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }
}
