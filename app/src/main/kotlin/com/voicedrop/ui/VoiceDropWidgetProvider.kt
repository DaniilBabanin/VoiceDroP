package com.voicedrop.ui

import android.Manifest
import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.view.View
import android.widget.RemoteViews
import com.voicedrop.R
import com.voicedrop.service.PermissionActivity
import com.voicedrop.service.ServiceState
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
            val serviceState = ServiceState.recordingState.value

            if (contactId == null) {
                val views = renderUnbound(context, widgetId)
                appWidgetManager.updateAppWidget(widgetId, views)
                return
            }

            val isRecordingThisContact =
                serviceState.state == ServiceState.State.RECORDING &&
                    contactId in serviceState.activeContactIds

            if (isRecordingThisContact) {
                val views = renderRecording(
                    context,
                    widgetId,
                    serviceState.startedAtElapsedRealtime,
                )
                appWidgetManager.updateAppWidget(widgetId, views)
                return
            }

            // Idle render: show loading first, then resolve the contact name asynchronously.
            val placeholder = renderIdle(
                context = context,
                widgetId = widgetId,
                contactId = contactId,
                label = context.getString(R.string.widget_loading),
            )
            appWidgetManager.updateAppWidget(widgetId, placeholder)

            scope.launch {
                val db = AppDatabase.getInstance(context)
                val contact = db.contactDao().getById(contactId)
                // Re-check state — service could have flipped to recording while we were loading.
                val nowState = ServiceState.recordingState.value
                if (nowState.state == ServiceState.State.RECORDING &&
                    contactId in nowState.activeContactIds
                ) {
                    val v = renderRecording(context, widgetId, nowState.startedAtElapsedRealtime)
                    appWidgetManager.updateAppWidget(widgetId, v)
                    return@launch
                }
                val refreshed = if (contact == null) {
                    renderMissing(context, widgetId)
                } else {
                    renderIdle(context, widgetId, contactId, contact.name)
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

        private fun renderUnbound(context: Context, widgetId: Int): RemoteViews {
            val views = RemoteViews(context.packageName, R.layout.widget_voicedrop)
            views.setInt(R.id.widget_root, "setBackgroundResource", R.drawable.widget_droplet_bg)
            views.setImageViewResource(R.id.widget_icon, R.drawable.ic_widget_droplet)
            views.setViewVisibility(R.id.widget_label, View.VISIBLE)
            views.setViewVisibility(R.id.widget_timer, View.GONE)
            views.setChronometer(R.id.widget_timer, 0L, null, false)
            views.setTextViewText(R.id.widget_label, context.getString(R.string.widget_unbound))
            views.setOnClickPendingIntent(R.id.widget_root, buildConfigurePendingIntent(context, widgetId))
            return views
        }

        private fun renderMissing(context: Context, widgetId: Int): RemoteViews {
            val views = RemoteViews(context.packageName, R.layout.widget_voicedrop)
            views.setInt(R.id.widget_root, "setBackgroundResource", R.drawable.widget_droplet_bg)
            views.setImageViewResource(R.id.widget_icon, R.drawable.ic_widget_droplet)
            views.setViewVisibility(R.id.widget_label, View.VISIBLE)
            views.setViewVisibility(R.id.widget_timer, View.GONE)
            views.setChronometer(R.id.widget_timer, 0L, null, false)
            views.setTextViewText(R.id.widget_label, context.getString(R.string.widget_contact_missing))
            views.setOnClickPendingIntent(R.id.widget_root, buildConfigurePendingIntent(context, widgetId))
            return views
        }

        private fun renderIdle(
            context: Context,
            widgetId: Int,
            contactId: String,
            label: String,
        ): RemoteViews {
            val views = RemoteViews(context.packageName, R.layout.widget_voicedrop)
            views.setInt(R.id.widget_root, "setBackgroundResource", R.drawable.widget_droplet_bg)
            views.setImageViewResource(R.id.widget_icon, R.drawable.ic_widget_droplet)
            views.setViewVisibility(R.id.widget_label, View.VISIBLE)
            views.setViewVisibility(R.id.widget_timer, View.GONE)
            views.setChronometer(R.id.widget_timer, 0L, null, false)
            views.setTextViewText(R.id.widget_label, label)
            views.setOnClickPendingIntent(
                R.id.widget_root,
                buildRecordStartPendingIntent(context, widgetId, contactId)
            )
            return views
        }

        private fun renderRecording(
            context: Context,
            widgetId: Int,
            startedAtElapsedRealtime: Long,
        ): RemoteViews {
            val views = RemoteViews(context.packageName, R.layout.widget_voicedrop)
            views.setInt(R.id.widget_root, "setBackgroundResource", R.drawable.widget_droplet_bg_recording)
            views.setImageViewResource(R.id.widget_icon, R.drawable.ic_widget_stop)
            views.setViewVisibility(R.id.widget_label, View.GONE)
            views.setViewVisibility(R.id.widget_timer, View.VISIBLE)
            views.setChronometer(R.id.widget_timer, startedAtElapsedRealtime, null, true)
            views.setOnClickPendingIntent(
                R.id.widget_root,
                buildRecordStopPendingIntent(context, widgetId)
            )
            return views
        }

        private fun hasMicPermission(context: Context): Boolean =
            context.checkSelfPermission(Manifest.permission.RECORD_AUDIO) ==
                PackageManager.PERMISSION_GRANTED

        private fun buildRecordStartPendingIntent(
            context: Context,
            widgetId: Int,
            contactId: String
        ): PendingIntent {
            val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            return if (hasMicPermission(context)) {
                // Skip PermissionActivity so the widget works from the lock screen without unlocking.
                PendingIntent.getForegroundService(
                    context,
                    widgetId * 2,
                    VoiceDropService.recordStartIntent(context, contactId),
                    flags
                )
            } else {
                val intent = Intent(context, PermissionActivity::class.java).apply {
                    action = VoiceDropService.ACTION_RECORD_START
                    putExtra(VoiceDropService.EXTRA_CONTACT_ID, contactId)
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
                }
                PendingIntent.getActivity(context, widgetId * 2, intent, flags)
            }
        }

        private fun buildRecordStopPendingIntent(
            context: Context,
            widgetId: Int,
        ): PendingIntent {
            // Recording implies mic permission is already granted; always go direct.
            val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            return PendingIntent.getForegroundService(
                context,
                widgetId * 2 + 1,
                VoiceDropService.recordStopIntent(context),
                flags
            )
        }

        private fun buildConfigurePendingIntent(context: Context, widgetId: Int): PendingIntent {
            val intent = Intent(context, VoiceDropWidgetConfigActivity::class.java).apply {
                putExtra(AppWidgetManager.EXTRA_APPWIDGET_ID, widgetId)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
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
