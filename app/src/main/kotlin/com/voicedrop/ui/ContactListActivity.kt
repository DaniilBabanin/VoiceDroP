package com.voicedrop.ui

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.ItemTouchHelper
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.voicedrop.R
import com.voicedrop.crypto.AeadFailureSoftPrompt
import com.voicedrop.service.AutoDeleteWorker
import com.voicedrop.service.VoiceDropService
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.ContactEntity
import com.voicedrop.storage.MessageRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ContactListActivity : AppCompatActivity() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private lateinit var repository: MessageRepository
    private lateinit var adapter: ContactAdapter
    private lateinit var recyclerView: RecyclerView
    private lateinit var aeadSoftPrompt: AeadFailureSoftPrompt
    private var aeadBannerPollJob: Job? = null

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { results ->
        if (results[Manifest.permission.RECORD_AUDIO] == true) {
            startForegroundService(Intent(this, VoiceDropService::class.java))
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_contact_list)
        EdgeToEdgeSetup.apply(this)
        requestMissingPermissions()

        val db = AppDatabase.getInstance(this)
        repository = MessageRepository(db.contactDao(), db.messageDao(), db.pendingActionDao())
        aeadSoftPrompt = AeadFailureSoftPrompt(db)

        AutoDeleteWorker.schedule(this)
        if (checkSelfPermission(Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED) {
            startForegroundService(Intent(this, VoiceDropService::class.java))
        }

        val toolbar = findViewById<androidx.appcompat.widget.Toolbar>(R.id.toolbar)
        setSupportActionBar(toolbar)

        adapter = ContactAdapter { contactId ->
            scope.launch {
                val contact = repository.getContact(contactId) ?: return@launch
                val intent = Intent(this@ContactListActivity, MessageHistoryActivity::class.java).apply {
                    putExtra(MessageHistoryActivity.EXTRA_CONTACT_ID, contactId)
                    putExtra(MessageHistoryActivity.EXTRA_CONTACT_NAME, contact.name)
                }
                startActivity(intent)
            }
        }

        recyclerView = findViewById(R.id.recycler_contacts)
        recyclerView.layoutManager = LinearLayoutManager(this)
        recyclerView.adapter = adapter
        setupSwipeToDelete()

        val emptyState = findViewById<TextView>(R.id.text_empty_state)
        val fab = findViewById<FloatingActionButton>(R.id.fab_add_contact)
        fab.setOnClickListener {
            if (isSignalingUrlConfigured()) {
                startActivity(Intent(this, QrPairActivity::class.java))
            } else {
                showSignalingUrlRequiredDialog()
            }
        }
        EdgeToEdgeSetup.applyBottomInset(fab)

        checkOnboarding()

        scope.launch {
            repository.getAllContacts().collectLatest { contacts ->
                if (contacts.isEmpty()) {
                    emptyState.visibility = View.VISIBLE
                    recyclerView.visibility = View.GONE
                } else {
                    emptyState.visibility = View.GONE
                    recyclerView.visibility = View.VISIBLE
                    adapter.submitList(contacts)
                }
            }
        }
        startAeadBannerPolling()
    }

    /**
     * DR17.5 W6 — poll AeadFailureSoftPrompt for any contact in [State.ShouldPrompt]
     * state. AeadFailureSoftPrompt.evaluate is suspend (one-shot), not a Flow — we
     * tick every 5s to pick up new threshold crossings without a Room observer.
     * Tap on the banner dismisses for 24h (per dr14 §6.4).
     */
    private fun startAeadBannerPolling() {
        val banner = findViewById<TextView>(R.id.banner_aead_soft_prompt)
        aeadBannerPollJob?.cancel()
        aeadBannerPollJob = scope.launch {
            while (true) {
                val contacts = try {
                    repository.getAllContacts().first()
                } catch (_: Exception) { emptyList() }
                val prompts = withContext(Dispatchers.IO) {
                    contacts.mapNotNull { c ->
                        val state = aeadSoftPrompt.evaluate(c.id)
                        if (state is AeadFailureSoftPrompt.State.ShouldPrompt) c else null
                    }
                }
                if (prompts.isEmpty()) {
                    banner.visibility = View.GONE
                    banner.setOnClickListener(null)
                } else {
                    banner.visibility = View.VISIBLE
                    banner.text = if (prompts.size == 1) {
                        getString(R.string.aead_soft_prompt_banner, prompts[0].name)
                    } else {
                        getString(R.string.aead_soft_prompt_banner_multi)
                    }
                    banner.setOnClickListener {
                        scope.launch {
                            withContext(Dispatchers.IO) {
                                prompts.forEach { aeadSoftPrompt.dismiss(it.id) }
                            }
                            banner.visibility = View.GONE
                        }
                    }
                }
                delay(5_000L)
            }
        }
    }

    private fun requestMissingPermissions() {
        val needed = mutableListOf<String>()
        if (checkSelfPermission(Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
            needed.add(Manifest.permission.RECORD_AUDIO)
        }
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            needed.add(Manifest.permission.POST_NOTIFICATIONS)
        }
        if (needed.isNotEmpty()) permissionLauncher.launch(needed.toTypedArray())
    }

    private fun checkOnboarding() {
        val prefs = getSharedPreferences("voicedrop_settings", MODE_PRIVATE)
        if (!prefs.getBoolean("pref_onboarding_done", false)) {
            scope.launch {
                val contacts = repository.getAllContacts()
                contacts.collect { list ->
                    if (list.isEmpty()) {
                        // Show onboarding overlay - handled in layout
                    }
                    prefs.edit().putBoolean("pref_onboarding_done", true).apply()
                    return@collect
                }
            }
        }
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.menu_main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.action_settings -> {
                startActivity(Intent(this, SettingsActivity::class.java))
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun setupSwipeToDelete() {
        val swipeCallback = object : ItemTouchHelper.SimpleCallback(
            0, ItemTouchHelper.LEFT or ItemTouchHelper.RIGHT
        ) {
            override fun onMove(
                rv: RecyclerView, vh: RecyclerView.ViewHolder, target: RecyclerView.ViewHolder
            ) = false

            override fun onSwiped(viewHolder: RecyclerView.ViewHolder, direction: Int) {
                val position = viewHolder.adapterPosition
                if (position == RecyclerView.NO_POSITION) return
                val contact = adapter.currentList[position]
                showDeleteConfirmation(contact, position)
            }
        }
        ItemTouchHelper(swipeCallback).attachToRecyclerView(recyclerView)
    }

    private fun showDeleteConfirmation(contact: ContactEntity, position: Int) {
        AlertDialog.Builder(this)
            .setTitle(R.string.delete_contact_title)
            .setMessage(getString(R.string.delete_contact_message, contact.name))
            .setPositiveButton(R.string.delete) { _, _ ->
                scope.launch { deleteContact(contact) }
            }
            .setNegativeButton(android.R.string.cancel) { _, _ ->
                adapter.notifyItemChanged(position)
            }
            .setOnCancelListener { adapter.notifyItemChanged(position) }
            .show()
    }

    private suspend fun deleteContact(contact: ContactEntity) {
        withContext(Dispatchers.IO) {
            // Refcount-aware: opus files shared with other contacts' rows are preserved.
            repository.deleteAllMessagesForContactWithBlobCleanup(contact.id)
        }
        repository.deleteContact(contact)
        VoiceDropWidgetProvider.refreshAll(this@ContactListActivity)
        AllWidgetProvider.refreshAll(this@ContactListActivity)
    }

    private fun isSignalingUrlConfigured(): Boolean {
        val prefs = getSharedPreferences("voicedrop_settings", MODE_PRIVATE)
        return !prefs.getString("signaling_url", "").isNullOrBlank()
    }

    private fun showSignalingUrlRequiredDialog() {
        AlertDialog.Builder(this)
            .setTitle(R.string.pair_blocked_no_url_title)
            .setMessage(R.string.pair_blocked_no_url_message)
            .setPositiveButton(R.string.open_settings) { _, _ ->
                startActivity(Intent(this, SettingsActivity::class.java))
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }
}
