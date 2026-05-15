package com.voicedrop.ui

import android.appwidget.AppWidgetManager
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.ArrayAdapter
import android.widget.ListView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.voicedrop.R
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.ContactEntity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class VoiceDropWidgetConfigActivity : AppCompatActivity() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var widgetId = AppWidgetManager.INVALID_APPWIDGET_ID

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        widgetId = intent?.extras?.getInt(
            AppWidgetManager.EXTRA_APPWIDGET_ID,
            AppWidgetManager.INVALID_APPWIDGET_ID
        ) ?: AppWidgetManager.INVALID_APPWIDGET_ID

        // Default to canceled so back-press cleans the placeholder widget up.
        setResult(
            RESULT_CANCELED,
            Intent().putExtra(AppWidgetManager.EXTRA_APPWIDGET_ID, widgetId)
        )

        if (widgetId == AppWidgetManager.INVALID_APPWIDGET_ID) {
            finish()
            return
        }

        setContentView(R.layout.widget_config)

        val list = findViewById<ListView>(R.id.widget_contact_list)
        val emptyHint = findViewById<TextView>(R.id.widget_empty_hint)

        scope.launch {
            val contacts = withContext(Dispatchers.IO) {
                AppDatabase.getInstance(this@VoiceDropWidgetConfigActivity)
                    .contactDao()
                    .getAllList()
            }
            renderList(list, emptyHint, contacts)
        }
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private fun renderList(
        list: ListView,
        emptyHint: TextView,
        contacts: List<ContactEntity>
    ) {
        if (contacts.isEmpty()) {
            list.visibility = View.GONE
            emptyHint.visibility = View.VISIBLE
            return
        }
        list.visibility = View.VISIBLE
        emptyHint.visibility = View.GONE

        val adapter = ArrayAdapter(
            this,
            android.R.layout.simple_list_item_1,
            contacts.map { it.name }
        )
        list.adapter = adapter
        list.setOnItemClickListener { _, _, position, _ ->
            onContactPicked(contacts[position].id)
        }
    }

    private fun onContactPicked(contactId: String) {
        VoiceDropWidgetProvider.saveContactId(this, widgetId, contactId)
        val mgr = AppWidgetManager.getInstance(this)
        VoiceDropWidgetProvider.updateWidget(this, mgr, widgetId)
        setResult(
            RESULT_OK,
            Intent().putExtra(AppWidgetManager.EXTRA_APPWIDGET_ID, widgetId)
        )
        finish()
    }
}
