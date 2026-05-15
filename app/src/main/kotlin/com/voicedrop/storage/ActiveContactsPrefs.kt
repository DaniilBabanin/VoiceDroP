package com.voicedrop.storage

import android.content.Context

object ActiveContactsPrefs {

    private const val PREFS_NAME = "voicedrop_settings"
    private const val KEY_DEFAULT_CONTACT_ID = "pref_default_contact_id"
    private const val KEY_LEGACY_ACTIVE_IDS = "pref_active_contact_ids"
    private const val KEY_LEGACY_MIGRATED = "pref_active_set_migrated_to_default"

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun getDefaultId(context: Context): String? =
        prefs(context).getString(KEY_DEFAULT_CONTACT_ID, null)

    fun setDefaultId(context: Context, id: String?) {
        prefs(context).edit().putString(KEY_DEFAULT_CONTACT_ID, id).apply()
    }

    /** Resolves the default to a [ContactEntity] if it's still present, else null. Clears stale ids. */
    fun getDefault(context: Context, contacts: List<ContactEntity>): ContactEntity? {
        val id = getDefaultId(context) ?: return null
        val match = contacts.firstOrNull { it.id == id }
        if (match == null) setDefaultId(context, null)
        return match
    }

    /**
     * Recipient for the fast-path (tile, headless callers):
     *   explicit default if present → newest by addedAt → null when no contacts exist.
     */
    fun resolveRecipient(context: Context, contacts: List<ContactEntity>): ContactEntity? {
        if (contacts.isEmpty()) return null
        getDefault(context, contacts)?.let { return it }
        return contacts.maxByOrNull { it.addedAt }
    }

    /** One-shot: lift the first id from the pre-v1.1.0.11 active-set pref into the default key. */
    fun migrateLegacyActiveSet(context: Context) {
        val p = prefs(context)
        if (p.getBoolean(KEY_LEGACY_MIGRATED, false)) return
        if (p.getString(KEY_DEFAULT_CONTACT_ID, null) == null) {
            val legacy = p.getStringSet(KEY_LEGACY_ACTIVE_IDS, emptySet()).orEmpty().firstOrNull()
            if (legacy != null) {
                p.edit().putString(KEY_DEFAULT_CONTACT_ID, legacy).apply()
            }
        }
        p.edit()
            .putBoolean(KEY_LEGACY_MIGRATED, true)
            .remove(KEY_LEGACY_ACTIVE_IDS)
            .apply()
    }
}
