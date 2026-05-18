package com.voicedrop.ui

import android.graphics.Bitmap
import com.google.zxing.BarcodeFormat
import com.journeyapps.barcodescanner.BarcodeEncoder

/**
 * DR17.6 — shared QR rendering for the My-QR tab and the in-activity Verify panel.
 * Both call sites must produce identical bytes for a given card JSON so the partner
 * can scan either render. Centralising the encoder also avoids duplicating the
 * try-swallow pattern at two call sites.
 */
object QrEncoder {
    fun encode(content: String, sizePx: Int): Bitmap? = try {
        BarcodeEncoder().encodeBitmap(content, BarcodeFormat.QR_CODE, sizePx, sizePx)
    } catch (_: Exception) {
        null
    }
}
