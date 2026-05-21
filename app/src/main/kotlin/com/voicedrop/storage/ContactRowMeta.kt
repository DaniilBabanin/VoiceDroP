package com.voicedrop.storage

import androidx.room.Embedded

/**
 * §A — DAO projection for the contact-list row. Joins one row per contact with
 * four scalar columns describing the contact's most recent message plus an
 * inbound-unplayed count. Consumed by `ui/ContactRowUiState`, never persisted.
 *
 * The trailing scalars are nullable because a freshly-added contact has no
 * messages at all — the subselects return SQL NULL in that case rather than 0.
 * `unreadCount` is `Int` (non-null) because `COUNT(*)` always returns a value.
 */
data class ContactRowMeta(
    @Embedded val contact: ContactEntity,
    val lastMessageAt: Long?,
    val lastMessageDirection: Int?,
    val lastMessageState: Int?,
    val lastMessageDurationMs: Int?,
    val unreadCount: Int,
)
