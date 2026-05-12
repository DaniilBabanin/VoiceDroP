package com.voicedrop.ui

import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.voicedrop.R
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.MessageRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

class MessageHistoryActivity : AppCompatActivity() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private lateinit var adapter: MessageAdapter
    private lateinit var repository: MessageRepository
    private lateinit var contactId: String

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_message_history)

        contactId = intent.getStringExtra(EXTRA_CONTACT_ID) ?: run { finish(); return }
        val contactName = intent.getStringExtra(EXTRA_CONTACT_NAME) ?: contactId

        val toolbar = findViewById<androidx.appcompat.widget.Toolbar>(R.id.toolbar)
        setSupportActionBar(toolbar)
        supportActionBar?.title = contactName
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        toolbar.setNavigationOnClickListener { finish() }

        adapter = MessageAdapter()

        val recyclerView = findViewById<RecyclerView>(R.id.recycler_messages)
        val layoutManager = LinearLayoutManager(this).apply { stackFromEnd = true }
        recyclerView.layoutManager = layoutManager
        recyclerView.adapter = adapter

        val emptyState = findViewById<TextView>(R.id.text_empty_messages)

        val db = AppDatabase.getInstance(this)
        repository = MessageRepository(db.contactDao(), db.messageDao(), db.pendingActionDao())

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
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.menu_message_history, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == R.id.action_auto_delete) {
            showAutoDeletePicker()
            return true
        }
        return super.onOptionsItemSelected(item)
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
