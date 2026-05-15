package com.voicedrop.ui

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.Context
import android.content.Intent
import android.widget.RemoteViews
import com.voicedrop.R
import com.voicedrop.service.PermissionActivity
import com.voicedrop.service.VoiceDropService
import com.voicedrop.storage.AppDatabase
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class VoiceDropWidgetProvider : AppWidgetProvider() {

    override fun onUpdate(
        context: Context,
        appWidgetManager: AppWidgetManager,
        appWidgetIds: IntArray
    ) {
        for (id in appWidgetIds) {
            updateWidget(context, appWidgetManager, id)
        }
    }

    override fun onDeleted(context: Context, appWidgetIds: IntArray) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit()
        for (id in appWidgetIds) {
            prefs.remove(contactKey(id))
        }
        prefs.apply()
    }

    companion object {
        const val PREFS_NAME = "voicedrop_widget"

        private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

        fun contactKey(widgetId: Int): String = "widget_${widgetId}_contact_id"

        fun saveContactId(context: Context, widgetId: Int, contactId: String) {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .putString(contactKey(widgetId), contactId)
                .apply()
        }

        fun getContactId(context: Context, widgetId: Int): String? =
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getString(contactKey(widgetId), null)

        fun updateWidget(
            context: Context,
            appWidgetManager: AppWidgetManager,
            widgetId: Int
        ) {
            val contactId = getContactId(context, widgetId)
            val views = RemoteViews(context.packageName, R.layout.widget_voicedrop)

            if (contactId == null) {
                views.setTextViewText(R.id.widget_label, context.getString(R.string.widget_unbound))
                views.setOnClickPendingIntent(
                    R.id.widget_root,
                    buildLauncherPendingIntent(context, widgetId)
                )
                appWidgetManager.updateAppWidget(widgetId, views)
                return
            }

            views.setTextViewText(R.id.widget_label, context.getString(R.string.widget_loading))
            views.setOnClickPendingIntent(
                R.id.widget_root,
                buildRecordPendingIntent(context, widgetId, contactId)
            )
            appWidgetManager.updateAppWidget(widgetId, views)

            scope.launch {
                val db = AppDatabase.getInstance(context)
                val contact = db.contactDao().getById(contactId)
                val refreshed = RemoteViews(context.packageName, R.layout.widget_voicedrop)
                if (contact == null) {
                    refreshed.setTextViewText(
                        R.id.widget_label,
                        context.getString(R.string.widget_contact_missing)
                    )
                    refreshed.setOnClickPendingIntent(
                        R.id.widget_root,
                        buildLauncherPendingIntent(context, widgetId)
                    )
                } else {
                    refreshed.setTextViewText(R.id.widget_label, contact.name)
                    refreshed.setOnClickPendingIntent(
                        R.id.widget_root,
                        buildRecordPendingIntent(context, widgetId, contactId)
                    )
                }
                appWidgetManager.updateAppWidget(widgetId, refreshed)
            }
        }

        fun refreshAll(context: Context) {
            val mgr = AppWidgetManager.getInstance(context)
            val component = android.content.ComponentName(context, VoiceDropWidgetProvider::class.java)
            val ids = mgr.getAppWidgetIds(component)
            for (id in ids) updateWidget(context, mgr, id)
        }

        private fun buildRecordPendingIntent(
            context: Context,
            widgetId: Int,
            contactId: String
        ): PendingIntent {
            val intent = Intent(context, PermissionActivity::class.java).apply {
                action = VoiceDropService.ACTION_RECORD_START
                putExtra(VoiceDropService.EXTRA_CONTACT_ID, contactId)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
            }
            return PendingIntent.getActivity(
                context,
                widgetId,
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
        }

        private fun buildLauncherPendingIntent(context: Context, widgetId: Int): PendingIntent {
            val intent = Intent(context, ContactListActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            return PendingIntent.getActivity(
                context,
                widgetId,
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
        }
    }
}
