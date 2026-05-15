package com.voicedrop.storage

import android.content.Context

object ActiveContactsPrefs {

    private const val PREFS_NAME = "voicedrop_settings"
    private const val KEY_ACTIVE_IDS = "pref_active_contact_ids"

    fun getActiveSet(context: Context): Set<String> =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getStringSet(KEY_ACTIVE_IDS, emptySet())
            ?.toSet()
            ?: emptySet()

    fun setActive(context: Context, ids: Set<String>) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putStringSet(KEY_ACTIVE_IDS, ids)
            .apply()
    }

    fun toggle(context: Context, id: String) {
        val current = getActiveSet(context).toMutableSet()
        if (!current.add(id)) current.remove(id)
        setActive(context, current)
    }

    fun isActive(context: Context, id: String): Boolean =
        getActiveSet(context).contains(id)

    /**
     * Returns the contact the tile should record to:
     *  - first user-picked active contact still present in [contacts], else
     *  - newest contact by addedAt, else
     *  - null if [contacts] is empty.
     */
    fun getPrimaryActive(context: Context, contacts: List<ContactEntity>): ContactEntity? {
        if (contacts.isEmpty()) return null
        val activeIds = getActiveSet(context)
        val picked = contacts.firstOrNull { it.id in activeIds }
        if (picked != null) return picked
        return contacts.maxByOrNull { it.addedAt }
    }
}
