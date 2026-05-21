package com.voicedrop.ui

import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * §A — pure timestamp → short-form string. Buckets:
 *
 * - < 60 s         → "now"
 * - < 60 min       → "Nm"
 * - same calendar day → "HH:mm"
 * - < 7 days       → short weekday in the locale ("Mon")
 * - older          → "M/d"
 *
 * Returns "" for null or non-positive input (a freshly-added contact has no
 * messages, so [ContactRowMeta.lastMessageAt] is null in that case).
 */
object RelativeTime {

    private const val MINUTE_SEC = 60L
    private const val HOUR_SEC = 60L * 60L
    private const val WEEK_SEC = 7L * 24L * HOUR_SEC

    fun format(
        timestampMs: Long?,
        nowMs: Long,
        locale: Locale = Locale.getDefault(),
        timeZone: TimeZone = TimeZone.getDefault(),
    ): String {
        if (timestampMs == null || timestampMs <= 0L) return ""
        val deltaSec = (nowMs - timestampMs) / 1000L
        return when {
            deltaSec < MINUTE_SEC -> "now"
            deltaSec < HOUR_SEC -> "${deltaSec / MINUTE_SEC}m"
            isSameDay(timestampMs, nowMs, timeZone) ->
                SimpleDateFormat("HH:mm", locale).apply { this.timeZone = timeZone }
                    .format(Date(timestampMs))
            deltaSec < WEEK_SEC ->
                SimpleDateFormat("EEE", locale).apply { this.timeZone = timeZone }
                    .format(Date(timestampMs))
            else ->
                SimpleDateFormat("M/d", locale).apply { this.timeZone = timeZone }
                    .format(Date(timestampMs))
        }
    }

    private fun isSameDay(a: Long, b: Long, timeZone: TimeZone): Boolean {
        val calA = Calendar.getInstance(timeZone).apply { timeInMillis = a }
        val calB = Calendar.getInstance(timeZone).apply { timeInMillis = b }
        return calA.get(Calendar.YEAR) == calB.get(Calendar.YEAR) &&
            calA.get(Calendar.DAY_OF_YEAR) == calB.get(Calendar.DAY_OF_YEAR)
    }
}
