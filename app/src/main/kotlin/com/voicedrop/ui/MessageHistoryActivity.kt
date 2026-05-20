package com.voicedrop.ui

import android.content.Intent
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.view.View
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import android.widget.Toast
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.crypto.tink.subtle.X25519
import com.voicedrop.R
import com.voicedrop.audio.VoiceMessageShare
import com.voicedrop.crypto.Bootstrap
import com.voicedrop.crypto.KeyManager
import com.voicedrop.crypto.ResetReceive
import com.voicedrop.service.ServiceState
import com.voicedrop.service.VoiceDropService
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.MessageRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MessageHistoryActivity : AppCompatActivity() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private lateinit var adapter: MessageAdapter
    private lateinit var repository: MessageRepository
    private lateinit var contactId: String

    // §3.1 — cache the local identity public key after the first KeyManager read.
    // Read by both the subtitle render and the in-chat Verify panel; cached because
    // KeyManager.getPublicKeyBytes hits SharedPreferences. Only mutated from `scope`,
    // which is Main-confined, so no synchronisation required.
    private var cachedMyIdPub: ByteArray? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_message_history)
        EdgeToEdgeSetup.apply(this)

        contactId = intent.getStringExtra(EXTRA_CONTACT_ID) ?: run { finish(); return }
        val contactName = intent.getStringExtra(EXTRA_CONTACT_NAME) ?: contactId

        val toolbar = findViewById<androidx.appcompat.widget.Toolbar>(R.id.toolbar)
        setSupportActionBar(toolbar)
        supportActionBar?.title = contactName
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        toolbar.setNavigationOnClickListener { finish() }

        adapter = MessageAdapter { message ->
            scope.launch {
                val file = VoiceMessageShare.prepare(this@MessageHistoryActivity, message.uuid)
                if (file == null) {
                    Toast.makeText(
                        this@MessageHistoryActivity,
                        R.string.share_unavailable,
                        Toast.LENGTH_SHORT
                    ).show()
                } else {
                    VoiceMessageShare.share(this@MessageHistoryActivity, file)
                }
            }
        }

        val recyclerView = findViewById<RecyclerView>(R.id.recycler_messages)
        val layoutManager = LinearLayoutManager(this).apply { stackFromEnd = true }
        recyclerView.layoutManager = layoutManager
        recyclerView.adapter = adapter
        EdgeToEdgeSetup.applyBottomInset(recyclerView)

        val emptyState = findViewById<View>(R.id.empty_state_messages)

        val db = AppDatabase.getInstance(this)
        repository = MessageRepository(db.contactDao(), db.messageDao(), db.pendingActionDao())

        scope.launch {
            val (myIdPub, theirIdPub) = loadKeyPair() ?: return@launch
            supportActionBar?.subtitle =
                com.voicedrop.crypto.Sas.codeFor(myIdPub, theirIdPub).joinToString(" ")
        }

        scope.launch {
            repository.getMessages(contactId).collectLatest { messages ->
                if (messages.isEmpty()) {
                    emptyState.visibility = View.VISIBLE
                    recyclerView.visibility = View.GONE
                } else {
                    emptyState.visibility = View.GONE
                    recyclerView.visibility = View.VISIBLE
                    adapter.submitList(messages)
                    recyclerView.scrollToPosition(messages.size - 1)
                }
            }
        }

        scope.launch {
            ServiceState.playingUuid.collectLatest { uuid ->
                adapter.setPlayingUuid(uuid)
            }
        }
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.menu_message_history, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.action_auto_delete -> { showAutoDeletePicker(); true }
            R.id.action_verify_identity -> { showVerifyIdentity(); true }
            R.id.action_reset_session -> { showResetSessionConfirm(); true }
            R.id.action_repair -> { showRepairConfirm(); true }
            else -> super.onOptionsItemSelected(item)
        }
    }

    /**
     * DR17.5 W5 — "Reset secure session" affordance. Atomically wipes the ratchet
     * and enqueues an outbound RESET; [ResetRetransmitJob] (running in the service)
     * resumes the retransmit schedule via the connectivity callback / next replay.
     */
    private fun showResetSessionConfirm() {
        AlertDialog.Builder(this)
            .setTitle(R.string.reset_secure_session)
            .setMessage(R.string.reset_secure_session_description)
            .setPositiveButton(R.string.reset_secure_session) { _, _ -> runManualReset() }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    /**
     * §3.1 — opens the in-chat identity-verification panel. Single-sided: tapping
     * "Mark as verified" writes `verified_at` for this device only. No frame is sent.
     * Sibling write site: `QrPairActivity.confirmPairing` writes verified_at at
     * pair-time when the user taps Match. Both writes are local; no peer round-trip.
     */
    private fun showVerifyIdentity() {
        scope.launch {
            val (myIdPub, theirIdPub) = loadKeyPair() ?: return@launch
            VerifyIdentityDialog(
                context = this@MessageHistoryActivity,
                contactId = contactId,
                myIdPub = myIdPub,
                theirIdPub = theirIdPub,
                scope = scope,
            ).show()
        }
    }

    /**
     * §3.1 — loads `(myIdPub, theirIdPub)` for `Sas.codeFor` / `Sas.fpPairBinding`.
     * `myIdPub` is cached after the first read (KeyManager hits SharedPreferences);
     * the contact's public key is reread each call so a re-pair mid-session reflects.
     * Returns null only if the contact row was deleted between activity-open and call.
     */
    private suspend fun loadKeyPair(): Pair<ByteArray, ByteArray>? {
        val contact = repository.getContact(contactId) ?: return null
        val theirIdPub = android.util.Base64.decode(
            contact.publicKeyBase64, android.util.Base64.NO_WRAP
        )
        val myIdPub = cachedMyIdPub ?: withContext(Dispatchers.IO) {
            KeyManager(this@MessageHistoryActivity).getPublicKeyBytes()
        }.also { cachedMyIdPub = it }
        return myIdPub to theirIdPub
    }

    private fun runManualReset() {
        scope.launch {
            val outcome = withContext(Dispatchers.IO) {
                val db = AppDatabase.getInstance(this@MessageHistoryActivity)
                val keyManager = KeyManager(this@MessageHistoryActivity)
                val ownFp32 = Bootstrap.fingerprintBytes(keyManager.getPublicKeyBytes())
                val resetReceive = ResetReceive(
                    db = db,
                    wrapMac = keyManager,
                    ownFingerprint32 = ownFp32,
                    idSharedSecretFor = { id ->
                        val c = repository.getContact(id)
                            ?: error("contact $id not found")
                        val peerPub = android.util.Base64.decode(
                            c.publicKeyBase64, android.util.Base64.NO_WRAP
                        )
                        val priv = keyManager.getPrivateKeyBytes()
                        try {
                            X25519.computeSharedSecret(priv, peerPub)
                        } finally {
                            priv.fill(0)
                        }
                    }
                )
                resetReceive.manualResetInitiate(contactId)
            }
            val msg = when (outcome) {
                ResetReceive.Outcome.InitiatedReset -> R.string.reset_initiated
                ResetReceive.Outcome.InitiationRefusedBudget -> R.string.reset_refused_budget
                else -> {
                    Toast.makeText(this@MessageHistoryActivity,
                        "Reset outcome: $outcome", Toast.LENGTH_SHORT).show()
                    return@launch
                }
            }
            Toast.makeText(this@MessageHistoryActivity, msg, Toast.LENGTH_LONG).show()
            // Kick the outbox to send the RESET frame immediately.
            startForegroundService(VoiceDropService.flushOutboxIntent(this@MessageHistoryActivity))
        }
    }

    /**
     * DR17.5 W5 — "Identity key compromised? Re-pair" affordance. Per dr15 §6.5,
     * re-pair wipes the contact's ratchet/outbox/skipped-key state before the new
     * QR scan; the actual wipe is owned by [com.voicedrop.crypto.RePairWipe] and
     * runs from QrPairActivity in re-pair mode.
     */
    private fun showRepairConfirm() {
        AlertDialog.Builder(this)
            .setTitle(R.string.repair_contact_title)
            .setMessage(R.string.repair_warning)
            .setPositiveButton(R.string.repair_contact_title) { _, _ ->
                val intent = Intent(this, QrPairActivity::class.java).apply {
                    putExtra(QrPairActivity.EXTRA_REPAIR_CONTACT_ID, contactId)
                }
                startActivity(intent)
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    private fun showAutoDeletePicker() {
        scope.launch {
            val contact = repository.getContact(contactId) ?: return@launch
            val options = AUTO_DELETE_OPTIONS
            val labels = options.map { ms ->
                when (ms) {
                    0L -> getString(R.string.auto_delete_none)
                    else -> formatDuration(ms)
                }
            }.toTypedArray()
            val currentIndex = options.indexOfFirst { it == contact.autoDeleteAfterMs }
                .takeIf { it >= 0 } ?: 0

            AlertDialog.Builder(this@MessageHistoryActivity)
                .setTitle(R.string.auto_delete)
                .setSingleChoiceItems(labels, currentIndex) { dialog, which ->
                    val selected = options[which]
                    scope.launch {
                        repository.upsertContact(contact.copy(autoDeleteAfterMs = selected))
                    }
                    dialog.dismiss()
                }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
        }
    }

    private fun formatDuration(ms: Long): String {
        val hours = ms / (60 * 60 * 1000L)
        return if (hours < 24) {
            resources.getQuantityString(R.plurals.hours, hours.toInt(), hours.toInt())
        } else {
            val days = hours / 24
            resources.getQuantityString(R.plurals.days, days.toInt(), days.toInt())
        }
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    companion object {
        const val EXTRA_CONTACT_ID = "contact_id"
        const val EXTRA_CONTACT_NAME = "contact_name"

        private val AUTO_DELETE_OPTIONS = longArrayOf(
            0L,
            60 * 60 * 1000L,           // 1 hour
            24 * 60 * 60 * 1000L,       // 24 hours
            7 * 24 * 60 * 60 * 1000L    // 7 days
        )
    }
}
