package com.voicedrop.ui

import android.graphics.drawable.Drawable

/**
 * §A — pre-rendered contact-list row state. Built on `Dispatchers.Default` from
 * `ContactRowMeta` once per emission so the adapter's `bind` does no work
 * beyond view assignment.
 *
 * `avatarDrawable` is intentionally excluded from structural equality (Drawable
 * equality is reference, would force unnecessary rebinds when the same content
 * round-trips through [AvatarFactory]'s cache). Compare elsewhere on
 * `(name, previewText.toString(), timestampText, badgeCount, isActive)`; see
 * `ContactAdapter.DIFF_CALLBACK`.
 */
data class ContactRowUiState(
    val id: String,
    val name: String,
    val avatarDrawable: Drawable,
    val previewText: CharSequence,
    val timestampText: String,
    val badgeCount: Int,
    val isActive: Boolean,
)
