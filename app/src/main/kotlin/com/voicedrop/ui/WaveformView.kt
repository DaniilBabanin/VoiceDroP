package com.voicedrop.ui

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.util.AttributeSet
import android.view.View
import com.google.android.material.color.MaterialColors

class WaveformView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null
) : View(context, attrs) {

    private var peaks: ByteArray = EMPTY_PEAKS
    private var progress: Float = 0f

    private val unplayedPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = MaterialColors.getColor(
            this@WaveformView,
            com.google.android.material.R.attr.colorOnSurfaceVariant,
            Color.GRAY
        )
        alpha = 128
    }
    private val playedPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = MaterialColors.getColor(
            this@WaveformView,
            com.google.android.material.R.attr.colorTertiary,
            Color.CYAN
        )
    }

    private val density = resources.displayMetrics.density
    private val minBarHeightPx = 2f * density
    private val gapPx = 1f * density

    fun setPeaks(p: ByteArray?) {
        val next = p ?: EMPTY_PEAKS
        if (peaks.contentEquals(next)) return
        peaks = next
        invalidate()
    }

    fun setProgress(p: Float) {
        val clamped = p.coerceIn(0f, 1f)
        if (clamped == progress) return
        progress = clamped
        invalidate()
    }

    override fun onDraw(canvas: Canvas) {
        if (peaks.isEmpty() || width <= 0 || height <= 0) return
        val h = height.toFloat()
        val centerY = h / 2f
        val total = peaks.size
        val available = width.toFloat()
        val barWidthPx = (available - gapPx * (total - 1)) / total
        if (barWidthPx <= 0f) return
        val playedUpTo = (total * progress).toInt()
        val cornerRadius = barWidthPx / 2f
        for (i in 0 until total) {
            val amp = (peaks[i].toInt() and 0xFF) / 255f
            val barH = (amp * h).coerceAtLeast(minBarHeightPx)
            val left = i * (barWidthPx + gapPx)
            val top = centerY - barH / 2f
            val paint = if (i < playedUpTo) playedPaint else unplayedPaint
            canvas.drawRoundRect(left, top, left + barWidthPx, top + barH, cornerRadius, cornerRadius, paint)
        }
    }

    companion object {
        private val EMPTY_PEAKS = ByteArray(0)
    }
}
