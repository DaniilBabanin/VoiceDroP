package com.voicedrop.notification

import android.app.Activity
import android.app.Application
import android.os.Bundle

/**
 * Tracks whether any of the app's activities is currently in the resumed/started
 * state. NotificationHelper consults this to suppress heads-up notifications
 * while the user is already in the app — the relevant UI (chat bubble, contact
 * row, recording / playback banner) is visible in-app.
 *
 * Foreground-service notifications posted via [android.app.Service.startForeground]
 * are NOT routed through this gate — the system requires them.
 */
object ForegroundTracker {

    @Volatile
    private var startedActivities: Int = 0

    val isAppInForeground: Boolean
        get() = startedActivities > 0

    fun register(app: Application) {
        app.registerActivityLifecycleCallbacks(object : Application.ActivityLifecycleCallbacks {
            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {}
            override fun onActivityStarted(activity: Activity) { startedActivities++ }
            override fun onActivityResumed(activity: Activity) {}
            override fun onActivityPaused(activity: Activity) {}
            override fun onActivityStopped(activity: Activity) {
                if (startedActivities > 0) startedActivities--
            }
            override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
            override fun onActivityDestroyed(activity: Activity) {}
        })
    }
}
