package com.voicedrop.ui

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Typeface
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import android.util.LruCache
import androidx.core.content.ContextCompat
import androidx.core.content.res.ResourcesCompat
import com.voicedrop.R

/**
 * §A — deterministic letter-on-hue avatars for the contact list. The hue is
 * picked from an 8-color palette by hashing the contact id; the glyph is the
 * first non-whitespace letter of [name] in uppercase (falls back to "•" for
 * empty/whitespace names so we never draw an empty bitmap).
 *
 * Drawables are cached in a small [LruCache] keyed by `id|letter` — the letter
 * is part of the key so renames produce a fresh draw without busting unrelated
 * cache entries.
 */
object AvatarFactory {

    private const val CACHE_CAPACITY = 32

    private val palette = intArrayOf(
        R.color.avatar_hue_0,
        R.color.avatar_hue_1,
        R.color.avatar_hue_2,
        R.color.avatar_hue_3,
        R.color.avatar_hue_4,
        R.color.avatar_hue_5,
        R.color.avatar_hue_6,
        R.color.avatar_hue_7,
    )
    private val onPalette = intArrayOf(
        R.color.avatar_on_hue_0,
        R.color.avatar_on_hue_1,
        R.color.avatar_on_hue_2,
        R.color.avatar_on_hue_3,
        R.color.avatar_on_hue_4,
        R.color.avatar_on_hue_5,
        R.color.avatar_on_hue_6,
        R.color.avatar_on_hue_7,
    )

    private val cache = LruCache<String, Drawable>(CACHE_CAPACITY)

    fun forContact(ctx: Context, id: String, name: String): Drawable {
        val letter = firstLetter(name)
        val cacheKey = "$id|$letter"
        cache.get(cacheKey)?.let { return it }
        val hueIdx = hueIndex(id)
        val drawable = render(ctx, hueIdx, letter)
        cache.put(cacheKey, drawable)
        return drawable
    }

    private fun hueIndex(id: String): Int {
        // Stable mapping of contact id → palette slot. The id is itself derived
        // from the fingerprint so any 3 bytes will do; using sum-of-first-3 keeps
        // identical ids identical without depending on the JDK's hashCode shape.
        val bytes = id.toByteArray(Charsets.UTF_8)
        val a = if (bytes.isNotEmpty()) bytes[0].toInt() and 0xFF else 0
        val b = if (bytes.size > 1) bytes[1].toInt() and 0xFF else 0
        val c = if (bytes.size > 2) bytes[2].toInt() and 0xFF else 0
        return (a xor (b shl 4) xor (c shl 1)).let { ((it % 8) + 8) % 8 }
    }

    private fun firstLetter(name: String): String {
        for (ch in name) {
            if (!ch.isWhitespace()) return ch.uppercaseChar().toString()
        }
        return "•"
    }

    private fun render(ctx: Context, hueIdx: Int, letter: String): Drawable {
        val density = ctx.resources.displayMetrics.density
        val sizePx = (40f * density).toInt()
        val bitmap = Bitmap.createBitmap(sizePx, sizePx, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bitmap)

        val fill = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = ContextCompat.getColor(ctx, palette[hueIdx])
            style = Paint.Style.FILL
        }
        val radius = sizePx / 2f
        canvas.drawCircle(radius, radius, radius, fill)

        val baseTypeface = ResourcesCompat.getFont(ctx, R.font.manrope)
            ?: Typeface.DEFAULT
        val text = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = ContextCompat.getColor(ctx, onPalette[hueIdx])
            textAlign = Paint.Align.CENTER
            textSize = 18f * density
            typeface = Typeface.create(baseTypeface, Typeface.BOLD)
        }
        val baseline = radius - (text.descent() + text.ascent()) / 2f
        canvas.drawText(letter, radius, baseline, text)

        return BitmapDrawable(ctx.resources, bitmap)
    }
}
