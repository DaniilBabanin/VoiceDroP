package com.voicedrop.ui

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.view.MenuItem
import android.view.View
import android.widget.Button
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.core.content.FileProvider
import androidx.viewpager2.widget.ViewPager2
import com.google.android.material.tabs.TabLayout
import com.google.android.material.tabs.TabLayoutMediator
import com.google.zxing.BarcodeFormat
import com.journeyapps.barcodescanner.BarcodeEncoder
import com.journeyapps.barcodescanner.DecoratedBarcodeView
import com.voicedrop.R
import com.voicedrop.crypto.ContactKey
import com.voicedrop.crypto.KeyManager
import com.voicedrop.storage.ActiveContactsPrefs
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.ContactEntity
import com.voicedrop.storage.MessageRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File
import java.security.MessageDigest

@Serializable
data class ContactCard(val v: Int, val id: String, val name: String, val pk: String)

class QrPairActivity : AppCompatActivity() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private lateinit var keyManager: KeyManager
    private lateinit var repository: MessageRepository
    private val json = Json { ignoreUnknownKeys = true }

    private var barcodeView: DecoratedBarcodeView? = null

    private val cameraPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (!granted) {
            Toast.makeText(this, "Camera permission required for QR scanning", Toast.LENGTH_SHORT).show()
        }
    }

    private val filePickerLauncher = registerForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri ->
        uri?.let { importFromUri(it) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_qr_pair)

        val toolbar = findViewById<Toolbar>(R.id.toolbar)
        setSupportActionBar(toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)

        keyManager = KeyManager(this)
        val db = AppDatabase.getInstance(this)
        repository = MessageRepository(db.contactDao(), db.messageDao(), db.pendingActionDao())

        intent?.data?.let { uri ->
            if (intent.action == Intent.ACTION_VIEW) {
                if (uri.scheme == "voicedrop") {
                    val cardJson = uri.getQueryParameter("card")
                    if (cardJson != null) handleScannedCard(cardJson)
                    else showError("Invalid VoiceDrop QR code")
                } else {
                    importFromUri(uri)
                }
                return
            }
        }

        setupTabs()
    }

    private fun setupTabs() {
        val viewPager = findViewById<ViewPager2>(R.id.view_pager)
        val tabLayout = findViewById<TabLayout>(R.id.tab_layout)

        val adapter = QrPairPagerAdapter(this, keyManager, ::handleScannedCard, ::openFilePicker, ::shareAsFile)
        viewPager.adapter = adapter

        TabLayoutMediator(tabLayout, viewPager) { tab, position ->
            tab.text = when (position) {
                0 -> "My QR"
                1 -> "Scan"
                2 -> "Import File"
                else -> ""
            }
        }.attach()

        viewPager.registerOnPageChangeCallback(object : ViewPager2.OnPageChangeCallback() {
            override fun onPageSelected(position: Int) {
                if (position == 1) {
                    if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
                        cameraPermissionLauncher.launch(Manifest.permission.CAMERA)
                    }
                }
            }
        })
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == android.R.id.home) {
            finish()
            return true
        }
        return super.onOptionsItemSelected(item)
    }

    internal fun openFilePicker() {
        filePickerLauncher.launch("application/x-voicedrop")
    }

    internal fun shareAsFile() {
        scope.launch {
            val prefs = getSharedPreferences("voicedrop_settings", MODE_PRIVATE)
            val displayName = prefs.getString("display_name", "VoiceDrop User") ?: "VoiceDrop User"
            val fp = keyManager.getFingerprint()
            val shortId = fp.take(8)
            val card = ContactCard(v = 1, id = shortId, name = displayName, pk = keyManager.getPublicKeyBase64())
            val cardJson = json.encodeToString(card)

            val exportDir = File(filesDir, "export")
            exportDir.mkdirs()
            val exportFile = File(exportDir, "${displayName}.voicedrop")
            exportFile.writeText(cardJson)

            val uri = FileProvider.getUriForFile(
                this@QrPairActivity,
                "${packageName}.fileprovider",
                exportFile
            )

            val shareIntent = Intent(Intent.ACTION_SEND).apply {
                type = "application/x-voicedrop"
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            startActivity(Intent.createChooser(shareIntent, "Share contact card"))
        }
    }

    private fun importFromUri(uri: Uri) {
        scope.launch {
            try {
                val content = withContext(Dispatchers.IO) {
                    contentResolver.openInputStream(uri)?.bufferedReader()?.readText()
                } ?: return@launch

                handleScannedCard(content)
            } catch (e: Exception) {
                android.util.Log.e(TAG, "importFromUri failed", e)
                showError("Could not read contact card file")
            }
        }
    }

    fun handleScannedCard(text: String) {
        android.util.Log.d(TAG, "handleScannedCard: ${text.take(80)}")
        scope.launch {
            try {
                val cardJson = if (text.startsWith("voicedrop://")) {
                    Uri.parse(text).getQueryParameter("card") ?: text
                } else {
                    text
                }
                val card = json.decodeFromString<ContactCard>(cardJson)

                if (card.v != 1) {
                    showError("Incompatible contact card version")
                    return@launch
                }

                val theirPublicKeyBytes = android.util.Base64.decode(card.pk, android.util.Base64.NO_WRAP)
                val theirFingerprint = ContactKey.fingerprint(theirPublicKeyBytes)
                val myPrivateKey = keyManager.getPrivateKeyBytes()
                val sessionKey = ContactKey.deriveSessionKey(myPrivateKey, theirPublicKeyBytes)

                val myFingerprint = keyManager.getFingerprint()
                val verificationBytes = ContactKey.computeVerificationCode(sessionKey, myFingerprint, theirFingerprint)
                val emojis = PairingVerificationEmojiMap.getEmojisForBytes(verificationBytes)

                showVerificationScreen(card, theirFingerprint, theirPublicKeyBytes, sessionKey, emojis)

            } catch (e: Exception) {
                android.util.Log.e(TAG, "handleScannedCard failed", e)
                showError("Invalid QR code — not a VoiceDrop contact card")
            }
        }
    }

    private fun showVerificationScreen(
        card: ContactCard,
        theirFingerprint: String,
        theirPublicKeyBytes: ByteArray,
        sessionKey: ByteArray,
        emojis: List<String>
    ) {
        val emojiStr = emojis.joinToString(" ")
        AlertDialog.Builder(this)
            .setTitle("Verify Pairing")
            .setMessage(
                "Verification code:\n\n$emojiStr\n\n" +
                "Compare this code with your contact.\n\n" +
                "By pairing, both parties agree that voice messages may be recorded and sent between paired devices."
            )
            .setPositiveButton("Codes match — confirm") { _, _ ->
                scope.launch { confirmPairing(card, theirFingerprint, theirPublicKeyBytes, sessionKey) }
            }
            .setNegativeButton("Codes differ — abort") { _, _ -> }
            .setCancelable(false)
            .show()
    }

    private suspend fun confirmPairing(
        card: ContactCard,
        fingerprint: String,
        publicKeyBytes: ByteArray,
        sessionKey: ByteArray
    ) {
        val wrappedKey = sessionKey
        val contact = ContactEntity(
            id = fingerprint,
            name = card.name,
            publicKeyBase64 = card.pk,
            sharedSecretWrapped = wrappedKey,
            addedAt = System.currentTimeMillis()
        )
        repository.upsertContact(contact)
        if (ActiveContactsPrefs.getDefaultId(this) == null) {
            ActiveContactsPrefs.setDefaultId(this, contact.id)
        }
        Toast.makeText(this, "${card.name} added!", Toast.LENGTH_SHORT).show()
        finish()
    }

    private fun showError(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }

    override fun onResume() {
        super.onResume()
        barcodeView?.resume()
    }

    override fun onPause() {
        super.onPause()
        barcodeView?.pause()
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    companion object {
        private const val TAG = "VoiceDrop/QrPair"
    }
}
