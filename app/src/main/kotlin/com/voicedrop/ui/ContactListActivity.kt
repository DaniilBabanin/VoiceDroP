package com.voicedrop.ui

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.os.Build
import android.os.Bundle
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.text.style.StyleSpan
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
import com.google.android.material.color.MaterialColors
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.voicedrop.R
import com.voicedrop.crypto.AeadFailureSoftPrompt
import com.voicedrop.service.AutoDeleteWorker
import com.voicedrop.service.VoiceDropService
import com.voicedrop.storage.ActiveContactsPrefs
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.ContactEntity
import com.voicedrop.storage.ContactRowMeta
import com.voicedrop.storage.MessageEntity
import com.voicedrop.storage.MessageRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ContactListActivity : AppCompatActivity() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private lateinit var repository: MessageRepository
    private lateinit var adapter: ContactAdapter
    private lateinit var recyclerView: RecyclerView
    private lateinit var aeadSoftPrompt: AeadFailureSoftPrompt
    private var aeadBannerPollJob: Job? = null

    // Captured on the main thread in onCreate so the Dispatchers.Default
    // preview-builder doesn't touch the View hierarchy / theme from a worker.
    private var tertiaryColor: Int = Color.CYAN

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

        val toolbar = findViewById<com.google.android.material.appbar.MaterialToolbar>(R.id.toolbar)
        setSupportActionBar(toolbar)

        tertiaryColor = MaterialColors.getColor(
            toolbar,
            com.google.android.material.R.attr.colorTertiary,
            Color.CYAN
        )

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

        val emptyState = findViewById<View>(R.id.empty_state_contacts)
        val fab = findViewById<FloatingActionButton>(R.id.fab_add_contact)
        fab.setOnClickListener {
            if (isSignalingUrlConfigured()) {
                startActivity(Intent(this, QrPairActivity::class.java))
            } else {
                showSignalingUrlRequiredDialog()
            }
        }
        emptyState.findViewById<com.google.android.material.button.MaterialButton>(
            R.id.button_empty_state_pair
        ).setOnClickListener { fab.callOnClick() }
        EdgeToEdgeSetup.applyBottomInset(fab)

        checkOnboarding()

        scope.launch {
            repository.getAllContactsWithMeta()
                .map { metas -> metas.map { buildUiState(it) } }
                .flowOn(Dispatchers.Default)
                .collectLatest { uiStates ->
                    if (uiStates.isEmpty()) {
                        emptyState.visibility = View.VISIBLE
                        recyclerView.visibility = View.GONE
                    } else {
                        emptyState.visibility = View.GONE
                        recyclerView.visibility = View.VISIBLE
                        adapter.submitList(uiStates)
                    }
                }
        }
        startAeadBannerPolling()
    }

    /**
     * §A — projects a [ContactRowMeta] DAO row into the [ContactRowUiState] the
     * adapter consumes. Runs on Dispatchers.Default; touches the avatar LRU
     * cache and a few SharedPreferences reads (active-contact set), both
     * thread-safe.
     */
    private fun buildUiState(meta: ContactRowMeta): ContactRowUiState {
        val ctx = this
        val avatar = AvatarFactory.forContact(ctx, meta.contact.id, meta.contact.name)
        val preview = buildPreviewText(meta)
        val timestamp = RelativeTime.format(meta.lastMessageAt, System.currentTimeMillis())
        val isActive = ActiveContactsPrefs.getActiveIds(ctx).contains(meta.contact.id)
        return ContactRowUiState(
            id = meta.contact.id,
            name = meta.contact.name,
            avatarDrawable = avatar,
            previewText = preview,
            timestampText = timestamp,
            badgeCount = meta.unreadCount,
            isActive = isActive,
        )
    }

    /**
     * §A — preview-text builder. Empty-history rows render the localized italic
     * onboarding hint; otherwise a glyph + duration line with weight/colour cues
     * that mirror [MessageAdapter]'s in-bubble glyphs.
     */
    private fun buildPreviewText(meta: ContactRowMeta): CharSequence {
        val ctx = this
        val direction = meta.lastMessageDirection
        val state = meta.lastMessageState
        val durationMs = meta.lastMessageDurationMs
        if (direction == null || state == null || durationMs == null) {
            val empty = ctx.getString(R.string.contact_preview_no_messages)
            val sb = SpannableStringBuilder(empty)
            sb.setSpan(StyleSpan(Typeface.ITALIC), 0, sb.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            return sb
        }
        val sb = SpannableStringBuilder()
        val duration = formatDurationShort(durationMs)
        if (direction == MessageEntity.DIRECTION_OUTBOUND) {
            when (state) {
                MessageEntity.STATE_OUTBOX -> sb.append("…  ")
                MessageEntity.STATE_SENT -> sb.append("✓  ")
                MessageEntity.STATE_DELIVERED -> sb.append("✓✓  ")
                MessageEntity.STATE_PLAYED -> {
                    val start = sb.length
                    sb.append("✓✓")
                    sb.setSpan(
                        ForegroundColorSpan(tertiaryColor),
                        start, sb.length,
                        Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
                    )
                    sb.append("  ")
                }
                MessageEntity.STATE_UNDELIVERABLE -> sb.append("!  ")
                else -> { /* nothing */ }
            }
            sb.append(duration)
        } else {
            val unread = state == MessageEntity.STATE_SENT || state == MessageEntity.STATE_DELIVERED
            if (unread) {
                val start = sb.length
                sb.append("↓ ").append(duration)
                sb.setSpan(
                    StyleSpan(Typeface.BOLD),
                    start, sb.length,
                    Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
                )
            } else {
                sb.append(duration)
            }
        }
        return sb
    }

    private fun formatDurationShort(ms: Int): String {
        val totalSecs = ms / 1000
        return "%d:%02d".format(totalSecs / 60, totalSecs % 60)
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
