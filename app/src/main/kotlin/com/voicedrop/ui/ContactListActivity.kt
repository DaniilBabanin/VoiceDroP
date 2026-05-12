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
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.voicedrop.R
import com.voicedrop.service.AutoDeleteWorker
import com.voicedrop.service.VoiceDropService
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.MessageRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

class ContactListActivity : AppCompatActivity() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private lateinit var repository: MessageRepository
    private lateinit var adapter: ContactAdapter

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { /* results ignored — permissions are best-effort at launch */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_contact_list)
        requestMissingPermissions()

        val db = AppDatabase.getInstance(this)
        repository = MessageRepository(db.contactDao(), db.messageDao(), db.pendingActionDao())

        AutoDeleteWorker.schedule(this)
        startForegroundService(Intent(this, VoiceDropService::class.java))

        val toolbar = findViewById<androidx.appcompat.widget.Toolbar>(R.id.toolbar)
        setSupportActionBar(toolbar)

        adapter = ContactAdapter { contactId ->
            // Show messages for selected contact
        }

        val recyclerView = findViewById<RecyclerView>(R.id.recycler_contacts)
        recyclerView.layoutManager = LinearLayoutManager(this)
        recyclerView.adapter = adapter

        val emptyState = findViewById<TextView>(R.id.text_empty_state)
        val fab = findViewById<FloatingActionButton>(R.id.fab_add_contact)
        fab.setOnClickListener {
            startActivity(Intent(this, QrPairActivity::class.java))
        }

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

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }
}
