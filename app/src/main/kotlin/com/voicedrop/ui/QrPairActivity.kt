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
import com.google.crypto.tink.subtle.X25519
import com.voicedrop.crypto.Bootstrap
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

/**
 * v1 cards used `v=1` and `{id, name, pk}`. v1.2 bumps to `v=2` and adds `bep`
 * (Base64-encoded 32-byte X25519 bootstrap ephemeral public key — see DR5).
 * Hard cutover: v1 cards are rejected on scan with a user-facing prompt to upgrade.
 */
@Serializable
data class ContactCard(
    val v: Int,
    val id: String,
    val name: String,
    val pk: String,
    val bep: String? = null
)

class QrPairActivity : AppCompatActivity() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private lateinit var keyManager: KeyManager
    private lateinit var repository: MessageRepository
    private val json = Json { ignoreUnknownKeys = true }

    // DR5 — per-pairing X25519 bootstrap ephemeral. Generated once when the pairing screen
    // opens; the public half rides in the outgoing QR/file. After a successful pair, the
    // role decision tells us whether to retain (Bob: becomes DHs.priv) or wipe (Alice).
    // Wiped in onDestroy regardless.
    private lateinit var myBootstrapEphPriv: ByteArray
    private lateinit var myBootstrapEphPub: ByteArray
    private var bootstrapEphRetired = false

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

        myBootstrapEphPriv = X25519.generatePrivateKey()
        myBootstrapEphPub = X25519.publicFromPrivate(myBootstrapEphPriv)

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

    /** v2 contact-card JSON with this session's bootstrap ephemeral pub. */
    internal fun getMyContactCardJson(): String {
        val prefs = getSharedPreferences("voicedrop_settings", MODE_PRIVATE)
        val displayName = prefs.getString("display_name", "VoiceDrop User") ?: "VoiceDrop User"
        val fp = keyManager.getFingerprint()
        val shortId = fp.take(8)
        val bep = android.util.Base64.encodeToString(myBootstrapEphPub, android.util.Base64.NO_WRAP)
        val card = ContactCard(
            v = 2,
            id = shortId,
            name = displayName,
            pk = keyManager.getPublicKeyBase64(),
            bep = bep
        )
        return json.encodeToString(card)
    }

    internal fun shareAsFile() {
        scope.launch {
            val prefs = getSharedPreferences("voicedrop_settings", MODE_PRIVATE)
            val displayName = prefs.getString("display_name", "VoiceDrop User") ?: "VoiceDrop User"
            val cardJson = getMyContactCardJson()

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

                if (card.v != 2) {
                    // Hard cutover per plan/08-dr/00-overview.md §8 — v1 cards refused.
                    showError("This QR is from VoiceDrop v1.1 or older. Both devices must be on v1.2+ to pair.")
                    return@launch
                }
                if (card.bep == null) {
                    showError("Invalid v2 contact card — missing bootstrap key")
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
        val view = layoutInflater.inflate(R.layout.dialog_verify_pairing, null)
        view.findViewById<TextView>(R.id.verificationEmojis).text =
            emojis.joinToString(" ")
        AlertDialog.Builder(this)
            .setTitle(R.string.verification_title)
            .setView(view)
            .setPositiveButton(R.string.verification_codes_match) { _, _ ->
                scope.launch { confirmPairing(card, theirFingerprint, theirPublicKeyBytes, sessionKey) }
            }
            .setNegativeButton(R.string.verification_codes_differ) { _, _ -> }
            .setCancelable(false)
            .show()
    }

    private suspend fun confirmPairing(
        card: ContactCard,
        fingerprint: String,
        publicKeyBytes: ByteArray,
        @Suppress("UNUSED_PARAMETER") sessionKey: ByteArray
    ) {
        // DR5: compute the initial double-ratchet root key and persist the wrapped ratchet
        // state alongside the existing identity columns. Until DR7/DR8 land, ConnectionManager
        // still uses the v1 ECDH session key path — the wrapped state lies dormant.
        val peerBep = card.bep
            ?: run { showError("Invalid v2 contact card — missing bootstrap key"); return }
        val peerBootstrapEphPub = try {
            android.util.Base64.decode(peerBep, android.util.Base64.NO_WRAP)
        } catch (_: IllegalArgumentException) {
            showError("Invalid v2 contact card — malformed bootstrap key"); return
        }
        if (peerBootstrapEphPub.size != Bootstrap.X25519_BYTES) {
            showError("Invalid v2 contact card — bootstrap key wrong size"); return
        }

        val myIdPriv = keyManager.getPrivateKeyBytes()
        val myIdPub = keyManager.getPublicKeyBytes()

        val initial = try {
            Bootstrap.computeInitialBootstrap(
                myIdPriv = myIdPriv,
                myIdPub = myIdPub,
                peerIdPub = publicKeyBytes,
                myBootstrapEphPriv = myBootstrapEphPriv,
                myBootstrapEphPub = myBootstrapEphPub,
                peerBootstrapEphPub = peerBootstrapEphPub
            )
        } finally {
            myIdPriv.fill(0)
        }

        val rowId = fingerprint.toByteArray(Charsets.UTF_8)
        val (rkWrapped, rkHmac) = keyManager.wrapAndMac("rk", rowId, initial.rootKey)
        initial.rootKey.fill(0)

        val dhsPrivWrapped: ByteArray?
        val dhsPrivHmac: ByteArray?
        val dhsPrivLocal = initial.dhsPriv
        if (dhsPrivLocal != null) {
            val (w, h) = keyManager.wrapAndMac("dhs_priv", rowId, dhsPrivLocal)
            dhsPrivWrapped = w
            dhsPrivHmac = h
            dhsPrivLocal.fill(0)
        } else {
            dhsPrivWrapped = null
            dhsPrivHmac = null
        }

        // Wipe the activity-held bootstrap eph priv: Bob no longer needs the raw copy
        // (it's now wrapped into DB), Alice never needed it past this point.
        myBootstrapEphPriv.fill(0)
        bootstrapEphRetired = true

        val contact = ContactEntity(
            id = fingerprint,
            name = card.name,
            publicKeyBase64 = card.pk,
            addedAt = System.currentTimeMillis(),
            rk_wrapped = rkWrapped,
            rk_hmac = rkHmac,
            dhs_priv_wrapped = dhsPrivWrapped,
            dhs_priv_hmac = dhsPrivHmac,
            dhs_pub = initial.dhsPub,
            dhr_pub = initial.dhrPub
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
        if (::myBootstrapEphPriv.isInitialized && !bootstrapEphRetired) {
            myBootstrapEphPriv.fill(0)
        }
        super.onDestroy()
    }

    companion object {
        private const val TAG = "VoiceDrop/QrPair"
    }
}
