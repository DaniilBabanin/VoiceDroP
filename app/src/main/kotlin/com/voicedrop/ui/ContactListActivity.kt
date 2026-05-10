package com.voicedrop.ui

import android.content.Intent
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.voicedrop.R
import com.voicedrop.service.AutoDeleteWorker
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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_contact_list)

        val db = AppDatabase.getInstance(this)
        repository = MessageRepository(db.contactDao(), db.messageDao(), db.pendingActionDao())

        AutoDeleteWorker.schedule(this)

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
