package com.voicedrop.ui

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.view.MenuItem
import android.view.View
import android.widget.Button
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.core.content.FileProvider
import androidx.viewpager2.widget.ViewPager2
import com.google.android.material.tabs.TabLayout
import com.google.android.material.tabs.TabLayoutMediator
import com.journeyapps.barcodescanner.DecoratedBarcodeView
import com.voicedrop.R
import com.google.crypto.tink.subtle.X25519
import com.voicedrop.crypto.Bootstrap
import com.voicedrop.crypto.ContactKey
import com.voicedrop.crypto.KeyManager
import com.voicedrop.crypto.MessagePayload
import com.voicedrop.crypto.RatchetEncryptAndSend
import com.voicedrop.crypto.RatchetState
import com.voicedrop.crypto.RatchetStatePersistence
import com.voicedrop.crypto.RePairWipe
import com.voicedrop.service.VoiceDropService
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
    private lateinit var db: AppDatabase
    private lateinit var repository: MessageRepository
    private val json = Json { ignoreUnknownKeys = true }

    // DR5 — per-pairing X25519 bootstrap ephemeral. Generated once when the pairing
    // screen opens; the public half rides in the outgoing QR/file. After a successful
    // pair, the role decision determines whether to retain (Bob: becomes DHs.priv,
    // wrapped + stored) or wipe (Alice). Wiped in onDestroy regardless.
    private lateinit var myBootstrapEphPriv: ByteArray
    private lateinit var myBootstrapEphPub: ByteArray
    private var bootstrapEphRetired = false

    /**
     * DR17.5 W5 — when non-null, this is a re-pair flow for an existing contact.
     * Per dr15 §6.5 the contact's ratchet/outbox/skipped-key state is wiped
     * (preserving messages) before the new QR exchange completes. The scanned card's
     * peer identity MUST match the existing contact's identity — refused otherwise.
     */
    private var repairContactId: String? = null

    private var barcodeView: DecoratedBarcodeView? = null

    // DR17.6 — three-state UI controller. The post-scan Verify panel is hosted by
    // this activity (not a dialog, not a fragment in the pager) so it can fully
    // replace the tab UI while the user compares emojis on both devices, without
    // tearing down the activity (which would regenerate `myBootstrapEphPriv` and
    // break the partner's reverse scan).
    private enum class UiState { SHOWING_QR, VERIFY, CONFIRMING }
    private var uiState: UiState = UiState.SHOWING_QR

    /**
     * Holds the post-`computeInitialBootstrap` state across the user's emoji-compare
     * decision. Wiped on Match consumption, Different tap, back-press out of VERIFY,
     * and `onDestroy`. Carries the only in-memory copy of `RK_0` and (Bob's) DHs.priv,
     * so every exit path must `fill(0)` before clearing the reference.
     */
    private var pendingInitialState: Bootstrap.InitialState? = null
    private data class PendingPeer(
        val card: ContactCard,
        val theirFingerprint: String,
        val emojis: List<String>
    )
    private var pendingPeer: PendingPeer? = null

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

    private val backCallback = object : OnBackPressedCallback(true) {
        override fun handleOnBackPressed() {
            if (uiState == UiState.VERIFY) {
                popVerifyToShowingQr()
            } else {
                finish()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val prefs = getSharedPreferences("voicedrop_settings", MODE_PRIVATE)
        if (prefs.getString("signaling_url", "").isNullOrBlank()) {
            androidx.appcompat.app.AlertDialog.Builder(this)
                .setTitle(R.string.pair_blocked_no_url_title)
                .setMessage(R.string.pair_blocked_no_url_message)
                .setPositiveButton(R.string.open_settings) { _, _ ->
                    startActivity(Intent(this, SettingsActivity::class.java))
                }
                .setNegativeButton(android.R.string.cancel, null)
                .setOnDismissListener { finish() }
                .show()
            return
        }

        setContentView(R.layout.activity_qr_pair)

        val toolbar = findViewById<Toolbar>(R.id.toolbar)
        setSupportActionBar(toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)

        keyManager = KeyManager(this)
        db = AppDatabase.getInstance(this)
        repository = MessageRepository(db.contactDao(), db.messageDao(), db.pendingActionDao())

        myBootstrapEphPriv = X25519.generatePrivateKey()
        myBootstrapEphPub = X25519.publicFromPrivate(myBootstrapEphPriv)

        repairContactId = intent?.getStringExtra(EXTRA_REPAIR_CONTACT_ID)
        if (repairContactId != null) {
            Toast.makeText(this, R.string.repair_warning, Toast.LENGTH_LONG).show()
        }

        onBackPressedDispatcher.addCallback(this, backCallback)

        // DR17.6 — always inflate tabs before dispatching deep-link / file-import,
        // so a back-press from VERIFY has a real SHOWING_QR to land on.
        setupTabs()

        intent?.data?.let { uri ->
            if (intent.action == Intent.ACTION_VIEW) {
                if (uri.scheme == "voicedrop") {
                    val cardJson = uri.getQueryParameter("card")
                    if (cardJson != null) handleScannedCard(cardJson)
                    else showError("Invalid VoiceDrop QR code")
                } else {
                    importFromUri(uri)
                }
            }
        }
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
            // DR17.6 — toolbar home mirrors the system back-press: in VERIFY it
            // pops to SHOWING_QR (wiping pendingInitialState); otherwise finish.
            if (uiState == UiState.VERIFY) {
                popVerifyToShowingQr()
            } else {
                finish()
            }
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

    /**
     * §3.1 — SAS emojis are derived from the IDENTITY public keys via [Sas.codeFor],
     * stable for the lifetime of those keys. The bootstrap `initial.rootKey` (RK_0)
     * is no longer used for SAS, but the verify panel still holds it across the
     * VERIFY → CONFIRMING transition so confirmPairing can persist the v2 state.
     * DR17.6 — the re-pair peer-identity check fires here, before the bootstrap
     * derivation, so a wrong-peer scan in re-pair mode is rejected before any key
     * material is created.
     */
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
                    showError("This QR is from VoiceDrop v1.1 or older. Both devices must be on v1.2+ to pair.")
                    return@launch
                }
                if (card.bep == null) {
                    showError("Invalid v2 contact card — missing bootstrap key")
                    return@launch
                }

                val theirPublicKeyBytes = android.util.Base64.decode(card.pk, android.util.Base64.NO_WRAP)
                val theirFingerprint = ContactKey.fingerprint(theirPublicKeyBytes)

                // DR17.6 — re-pair peer-identity gate. Moved from confirmPairing so the
                // user finds out about a wrong-peer scan immediately, with no wasted
                // bootstrap derivation and no temporarily-held RK_0 to wipe.
                val repairId = repairContactId
                if (repairId != null && repairId != theirFingerprint) {
                    showError("This QR is from a different contact. Re-pair scans the SAME peer.")
                    return@launch
                }

                val peerBootstrapEphPub = try {
                    android.util.Base64.decode(card.bep, android.util.Base64.NO_WRAP)
                } catch (_: IllegalArgumentException) {
                    showError("Invalid v2 contact card — malformed bootstrap key"); return@launch
                }
                if (peerBootstrapEphPub.size != Bootstrap.X25519_BYTES) {
                    showError("Invalid v2 contact card — bootstrap key wrong size"); return@launch
                }

                val myIdPriv = keyManager.getPrivateKeyBytes()
                val myIdPub = keyManager.getPublicKeyBytes()
                val initial = try {
                    Bootstrap.computeInitialBootstrap(
                        myIdPriv = myIdPriv,
                        myIdPub = myIdPub,
                        peerIdPub = theirPublicKeyBytes,
                        myBootstrapEphPriv = myBootstrapEphPriv,
                        myBootstrapEphPub = myBootstrapEphPub,
                        peerBootstrapEphPub = peerBootstrapEphPub
                    )
                } finally {
                    myIdPriv.fill(0)
                }

                val emojis = com.voicedrop.crypto.Sas.codeFor(myIdPub, theirPublicKeyBytes)

                transitionToVerify(card, theirFingerprint, initial, emojis)
            } catch (e: Exception) {
                android.util.Log.e(TAG, "handleScannedCard failed", e)
                showError("Invalid QR code — not a VoiceDrop contact card")
            }
        }
    }

    /**
     * DR17.6 — replaces the old AlertDialog with an in-activity VERIFY panel. The
     * tab UI is hidden; the verify_container FrameLayout fills the area below the
     * toolbar. The activity is NOT finished here — only on Match or Different (or
     * the back-press out of VERIFY, which finishes nothing).
     */
    private fun transitionToVerify(
        card: ContactCard,
        theirFingerprint: String,
        initial: Bootstrap.InitialState,
        emojis: List<String>
    ) {
        pendingInitialState = initial
        pendingPeer = PendingPeer(card, theirFingerprint, emojis)
        uiState = UiState.VERIFY

        val tabLayout = findViewById<TabLayout>(R.id.tab_layout)
        val viewPager = findViewById<ViewPager2>(R.id.view_pager)
        val verifyContainer = findViewById<FrameLayout>(R.id.verify_container)

        tabLayout.visibility = View.GONE
        viewPager.visibility = View.GONE
        verifyContainer.visibility = View.VISIBLE
        verifyContainer.removeAllViews()
        layoutInflater.inflate(R.layout.view_verify_pairing, verifyContainer, true)

        verifyContainer.findViewById<TextView>(R.id.verify_title).text =
            getString(R.string.verification_with_peer_title, card.name)
        verifyContainer.findViewById<TextView>(R.id.verify_emojis).apply {
            text = emojis.joinToString(" ")
            contentDescription = getString(R.string.verification_title)
        }

        QrEncoder.encode(
            "voicedrop://pair?card=${Uri.encode(getMyContactCardJson())}",
            VERIFY_QR_PX
        )?.let { bitmap ->
            verifyContainer.findViewById<ImageView>(R.id.verify_qr_thumbnail).setImageBitmap(bitmap)
        }

        val matchButton = verifyContainer.findViewById<Button>(R.id.verify_button_match)
        matchButton.text = getString(R.string.verification_pair_with_peer, card.name)
        matchButton.setOnClickListener { onMatchTapped() }

        verifyContainer.findViewById<Button>(R.id.verify_button_different)
            .setOnClickListener { onDifferentTapped() }
    }

    private fun onMatchTapped() {
        val peer = pendingPeer ?: return
        val initial = pendingInitialState ?: return
        uiState = UiState.CONFIRMING

        val verifyContainer = findViewById<FrameLayout>(R.id.verify_container)
        verifyContainer.findViewById<Button>(R.id.verify_button_match).isEnabled = false
        verifyContainer.findViewById<Button>(R.id.verify_button_different).isEnabled = false

        scope.launch {
            confirmPairing(peer.card, peer.theirFingerprint, initial)
            // confirmPairing zeros initial.rootKey / dhsPriv during wrap and then
            // finishes the activity. Null the field handles to drop the references.
            pendingInitialState = null
            pendingPeer = null
        }
    }

    private fun onDifferentTapped() {
        wipePendingInitialState()
        pendingPeer = null
        finish()
    }

    private fun popVerifyToShowingQr() {
        wipePendingInitialState()
        pendingPeer = null
        uiState = UiState.SHOWING_QR

        val tabLayout = findViewById<TabLayout>(R.id.tab_layout)
        val viewPager = findViewById<ViewPager2>(R.id.view_pager)
        val verifyContainer = findViewById<FrameLayout>(R.id.verify_container)

        verifyContainer.visibility = View.GONE
        verifyContainer.removeAllViews()
        tabLayout.visibility = View.VISIBLE
        viewPager.visibility = View.VISIBLE
    }

    private fun wipePendingInitialState() {
        pendingInitialState?.let {
            it.rootKey.fill(0)
            it.dhsPriv?.fill(0)
        }
        pendingInitialState = null
    }

    private suspend fun confirmPairing(
        card: ContactCard,
        fingerprint: String,
        initial: Bootstrap.InitialState
    ) {
        // DR17.5 W5 — re-pair flow: the peer-identity check moved to handleScannedCard
        // (DR17.6); here we still wipe the contact's v2 state before the upsert. Not
        // strictly one txn — a crash between wipe and upsert leaves pending_repair=1
        // with empty ratchet; user retries from "Pair again" and the upsert restores
        // the contact row.
        val repairId = repairContactId
        if (repairId != null) {
            RePairWipe(db).wipe(repairId)
        }

        // Route the first-pairing write through RatchetStatePersistence so the
        // wrap-binding column names match what loadRatchetState reads. The DR5
        // implementation used to inline `wrapAndMac("rk", …)` / `wrapAndMac("dhs_priv", …)`
        // here while persistence read with `"contacts.rk_wrapped"` / `"contacts.dhs_priv_wrapped"`
        // — every first send then failed with WrapHmacMismatch on the load.
        val myIdPub = keyManager.getPublicKeyBytes()
        val theirIdPub = android.util.Base64.decode(card.pk, android.util.Base64.NO_WRAP)
        val now = System.currentTimeMillis()
        val baseContact = ContactEntity(
            id = fingerprint,
            name = card.name,
            publicKeyBase64 = card.pk,
            addedAt = now,
            verified_at = now,
            verified_fp_pair_hash = com.voicedrop.crypto.Sas.fpPairBinding(myIdPub, theirIdPub),
        )
        val state = RatchetState(
            dhsPriv = initial.dhsPriv,
            dhsPub = initial.dhsPub,
            dhrPub = initial.dhrPub,
            rk = initial.rootKey
        )
        val contact = RatchetStatePersistence.saveRatchetState(baseContact, state, keyManager)
        // saveRatchetState reads but does not zero the input ByteArrays.
        initial.rootKey.fill(0)
        initial.dhsPriv?.fill(0)

        // Wipe the activity-held bootstrap eph priv: Bob no longer needs the raw copy
        // (it's now wrapped into DB), Alice never needed it past this point.
        myBootstrapEphPriv.fill(0)
        bootstrapEphRetired = true

        repository.upsertContact(contact)
        if (ActiveContactsPrefs.getDefaultId(this) == null) {
            ActiveContactsPrefs.setDefaultId(this, contact.id)
        }

        // DR17.5 §"Auto-bootstrap HELLO" — Alice (lexicographically-lower fp) fires
        // one HELLO frame so Bob's ratchet learns Alice's `dhr_pub` from the DATA
        // header and can subsequently send. No-op for Bob.
        if (initial.role == Bootstrap.Role.ALICE) {
            launchAutoHello(contact.id)
        }

        Toast.makeText(this, "${card.name} added!", Toast.LENGTH_SHORT).show()
        finish()
    }

    private suspend fun launchAutoHello(contactId: String) {
        val ownFp32 = Bootstrap.fingerprintBytes(keyManager.getPublicKeyBytes())
        // Transmit is a no-op — the wire frame lands in `pending_outbound_frames`
        // via the ratchet txn, and the running VoiceDropService picks it up on
        // its next replay (triggered explicitly below via ACTION_FLUSH_OUTBOX).
        val sender = RatchetEncryptAndSend(
            db = db,
            wrapMac = keyManager,
            ownFingerprint32 = ownFp32,
            transmit = { _, _ -> /* deferred to outbox replay */ }
        )
        try {
            withContext(Dispatchers.IO) {
                sender.encryptAndSend(contactId, MessagePayload.encodeHello()) { _, _, _ -> null }
            }
            android.util.Log.i(TAG, "auto-HELLO outboxed for ${contactId.take(8)}")
        } catch (t: Throwable) {
            // First HELLO is best-effort; if it fails we still leave the contact
            // paired and rely on the user retrying once Bob comes online.
            android.util.Log.w(TAG, "auto-HELLO failed for ${contactId.take(8)}: ${t.message}")
            return
        }
        // Kick the service to immediately try transmitting the HELLO outbox row.
        startForegroundService(VoiceDropService.flushOutboxIntent(this))
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
        wipePendingInitialState()
        pendingPeer = null
        if (::myBootstrapEphPriv.isInitialized && !bootstrapEphRetired) {
            myBootstrapEphPriv.fill(0)
        }
        super.onDestroy()
    }

    companion object {
        private const val TAG = "VoiceDrop/QrPair"
        private const val VERIFY_QR_PX = 480

        /**
         * Extra: when set, launches the activity in re-pair mode for the given
         * contact id. See [com.voicedrop.crypto.RePairWipe] and dr15 §6.5.
         */
        const val EXTRA_REPAIR_CONTACT_ID = "repair_contact_id"
    }
}
