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
import com.voicedrop.storage.ActiveContactsPrefs
import com.voicedrop.storage.AppDatabase
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Multi-recipient ("All") homescreen widget — no per-widget contact binding,
 * no config activity. Tap records and fans out to every checked contact in
 * [ActiveContactsPrefs]. Resolved at tap-time so the user can edit the active
 * set between recordings without reconfiguring the widget.
 *
 * The PendingIntent's recipient list is read synchronously from SharedPreferences
 * (main-thread safe). DB-backed label resolution happens in [scope] off the main
 * thread and triggers a second widget update with the resolved label.
 */
class AllWidgetProvider : AppWidgetProvider() {

    override fun onUpdate(
        context: Context,
        appWidgetManager: AppWidgetManager,
        appWidgetIds: IntArray
    ) {
        for (id in appWidgetIds) {
            updateWidget(context, appWidgetManager, id)
        }
    }

    companion object {
        private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

        fun updateWidget(
            context: Context,
            appWidgetManager: AppWidgetManager,
            widgetId: Int
        ) {
            val state = ServiceState.recordingState.value
            // Only flip to "recording" when at least one of the currently-recording
            // recipients is in the All-widget's active set. Without this guard a
            // per-contact widget recording (for a contact NOT in the All-widget's
            // set) would also flip the All-widget into stop-button mode and tapping
            // it would prematurely stop that unrelated recording.
            val widgetActiveIds = ActiveContactsPrefs.getActiveIds(context)
            val isRecording = state.state == ServiceState.State.RECORDING &&
                state.activeContactIds.any { it in widgetActiveIds }

            if (isRecording) {
                appWidgetManager.updateAppWidget(
                    widgetId,
                    renderRecording(context, widgetId, state.startedAtElapsedRealtime)
                )
                return
            }

            // Idle: render synchronously with the active-ids count for a fast first
            // paint, then refine the label off the main thread by resolving names.
            val activeCount = ActiveContactsPrefs.getActiveIds(context).size
            val initialLabel = when (activeCount) {
                0 -> context.getString(R.string.widget_all_label)
                else -> context.getString(R.string.widget_all_label) + " ($activeCount)"
            }
            appWidgetManager.updateAppWidget(
                widgetId,
                renderIdleSync(context, widgetId, initialLabel)
            )

            scope.launch {
                val db = AppDatabase.getInstance(context)
                val allContacts = db.contactDao().getAllList()
                val recipients = ActiveContactsPrefs.resolveRecipients(context, allContacts)
                val refinedLabel = when (recipients.size) {
                    0 -> context.getString(R.string.widget_all_label)
                    1 -> recipients.first().name
                    else -> context.getString(R.string.widget_all_label) + " (${recipients.size})"
                }
                appWidgetManager.updateAppWidget(
                    widgetId,
                    renderIdleSync(context, widgetId, refinedLabel)
                )
            }
        }

        fun refreshAll(context: Context) {
            val mgr = AppWidgetManager.getInstance(context)
            val component = android.content.ComponentName(context, AllWidgetProvider::class.java)
            val ids = mgr.getAppWidgetIds(component)
            for (id in ids) updateWidget(context, mgr, id)
        }

        private fun renderIdleSync(context: Context, widgetId: Int, label: String): RemoteViews {
            val views = RemoteViews(context.packageName, R.layout.widget_voicedrop)
            views.setInt(R.id.widget_root, "setBackgroundResource", R.drawable.widget_voicedrop_bg)
            views.setImageViewResource(R.id.widget_icon, R.drawable.ic_widget_droplet)
            views.setViewVisibility(R.id.widget_label, View.VISIBLE)
            views.setViewVisibility(R.id.widget_timer, View.GONE)
            views.setChronometer(R.id.widget_timer, 0L, null, false)
            views.setTextViewText(R.id.widget_label, label)
            views.setOnClickPendingIntent(R.id.widget_root, buildRecordStartPendingIntent(context, widgetId))
            return views
        }

        private fun renderRecording(
            context: Context,
            widgetId: Int,
            startedAtElapsedRealtime: Long,
        ): RemoteViews {
            val views = RemoteViews(context.packageName, R.layout.widget_voicedrop)
            views.setInt(R.id.widget_root, "setBackgroundResource", R.drawable.widget_voicedrop_bg_recording)
            views.setImageViewResource(R.id.widget_icon, R.drawable.ic_widget_stop)
            views.setViewVisibility(R.id.widget_label, View.GONE)
            views.setViewVisibility(R.id.widget_timer, View.VISIBLE)
            views.setChronometer(R.id.widget_timer, startedAtElapsedRealtime, null, true)
            views.setOnClickPendingIntent(R.id.widget_root, buildRecordStopPendingIntent(context, widgetId))
            return views
        }

        private fun hasMicPermission(context: Context): Boolean =
            context.checkSelfPermission(Manifest.permission.RECORD_AUDIO) ==
                PackageManager.PERMISSION_GRANTED

        private fun buildRecordStartPendingIntent(context: Context, widgetId: Int): PendingIntent {
            val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            // Recipients resolved synchronously from SharedPreferences (main-thread safe).
            // Stale ids in the set (contact deleted but still in pref) are harmless: the
            // service's stopRecording filters to live recipients before sending. The
            // async DB-backed refresh in updateWidget will re-render with the canonical
            // label on the next update tick.
            val recipientIds = ActiveContactsPrefs.getActiveIds(context).toList()

            return if (hasMicPermission(context) && recipientIds.isNotEmpty()) {
                PendingIntent.getForegroundService(
                    context,
                    widgetId * 2,
                    VoiceDropService.recordStartAllIntent(context, recipientIds),
                    flags
                )
            } else {
                val intent = Intent(context, PermissionActivity::class.java).apply {
                    action = VoiceDropService.ACTION_RECORD_START
                    if (recipientIds.isNotEmpty()) {
                        putExtra(VoiceDropService.EXTRA_CONTACT_IDS, recipientIds.toTypedArray())
                    }
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
                }
                PendingIntent.getActivity(context, widgetId * 2, intent, flags)
            }
        }

        private fun buildRecordStopPendingIntent(context: Context, widgetId: Int): PendingIntent {
            val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            return PendingIntent.getForegroundService(
                context,
                widgetId * 2 + 1,
                VoiceDropService.recordStopIntent(context),
                flags
            )
        }
    }
}
