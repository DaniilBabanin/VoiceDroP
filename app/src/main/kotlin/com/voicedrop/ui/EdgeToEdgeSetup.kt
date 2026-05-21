package com.voicedrop.ui

import android.graphics.Color
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding

/**
 * Applies edge-to-edge layout to an activity and its scrollable / toolbar
 * children. See plan/11-visual-refresh.md §C.
 *
 * Usage pattern in onCreate (after setContentView):
 *
 *   EdgeToEdgeSetup.apply(this)
 *   EdgeToEdgeSetup.applyTopInset(findViewById(R.id.toolbar))
 *   EdgeToEdgeSetup.applyBottomInset(findViewById(R.id.recycler_messages))
 *
 * CoordinatorLayout activities (contact list, message history) handle the
 * toolbar inset automatically via the AppBarLayout — for those, only the
 * recycler's bottom-pad call is needed.
 */
object EdgeToEdgeSetup {

    fun apply(activity: AppCompatActivity) {
        WindowCompat.setDecorFitsSystemWindows(activity.window, false)
        activity.window.statusBarColor = Color.TRANSPARENT
        activity.window.navigationBarColor = Color.TRANSPARENT
        val isLight = (activity.resources.configuration.uiMode and
            android.content.res.Configuration.UI_MODE_NIGHT_MASK) !=
            android.content.res.Configuration.UI_MODE_NIGHT_YES
        WindowCompat.getInsetsController(activity.window, activity.window.decorView)
            .isAppearanceLightStatusBars = isLight
        WindowCompat.getInsetsController(activity.window, activity.window.decorView)
            .isAppearanceLightNavigationBars = isLight
    }

    /** Adds top padding equal to the status-bar inset. Use on toolbars that are
     *  NOT inside a CoordinatorLayout/AppBarLayout. */
    fun applyTopInset(view: View) {
        val initialPadTop = view.paddingTop
        ViewCompat.setOnApplyWindowInsetsListener(view) { v, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.statusBars())
            v.updatePadding(top = initialPadTop + bars.top)
            insets
        }
    }

    /** Adds bottom padding equal to nav-bar + IME insets (whichever is larger).
     *  Use on the scrollable content area so a focused text field isn't hidden
     *  by the keyboard. */
    fun applyBottomInset(view: View) {
        val initialPadBottom = view.paddingBottom
        ViewCompat.setOnApplyWindowInsetsListener(view) { v, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            val ime = insets.getInsets(WindowInsetsCompat.Type.ime())
            v.updatePadding(bottom = initialPadBottom + maxOf(bars.bottom, ime.bottom))
            insets
        }
    }
}
