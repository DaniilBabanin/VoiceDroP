package com.voicedrop.storage

import android.content.Context

object ActiveContactsPrefs {

    private const val PREFS_NAME = "voicedrop_settings"
    private const val KEY_ACTIVE_IDS = "pref_active_contact_ids"
    // Legacy v1.1.0.11–v1.2.x single-default key. Migrated lazily on first read.
    private const val KEY_LEGACY_DEFAULT = "pref_default_contact_id"
    private const val KEY_DEFAULT_MIGRATED = "pref_default_migrated_to_set"

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /**
     * Returns the persisted set of "checked" contact ids. Triggers a one-shot
     * migration from the legacy single-default key on first call.
     */
    fun getActiveIds(context: Context): Set<String> {
        migrateDefaultIntoSet(context)
        return prefs(context).getStringSet(KEY_ACTIVE_IDS, emptySet()).orEmpty().toSet()
    }

    fun setActiveIds(context: Context, ids: Set<String>) {
        prefs(context).edit().putStringSet(KEY_ACTIVE_IDS, ids).apply()
    }

    /** Atomic add/remove for a single id. */
    fun setActive(context: Context, id: String, active: Boolean) {
        val current = getActiveIds(context).toMutableSet()
        if (active) current.add(id) else current.remove(id)
        setActiveIds(context, current)
    }

    /**
     * Recipients for fan-out callers (tile, All-widget). Returns the
     * intersection of the persisted set with [contacts] (auto-pruning any
     * stale ids from the pref). If that's empty, falls back to the single
     * newest contact by `addedAt` so a fresh install with one paired contact
     * still works. Returns empty only when [contacts] is empty.
     */
    fun resolveRecipients(context: Context, contacts: List<ContactEntity>): List<ContactEntity> {
        if (contacts.isEmpty()) return emptyList()
        val checked = getActiveIds(context)
        val resolved = contacts.filter { it.id in checked }
        if (resolved.size < checked.size) {
            // Stale-id auto-prune: rewrite the persisted set to the live intersection.
            setActiveIds(context, resolved.map { it.id }.toSet())
        }
        if (resolved.isNotEmpty()) return resolved
        return listOfNotNull(contacts.maxByOrNull { it.addedAt })
    }

    /**
     * One-shot: if a pre-fan-out install left a single default contact in
     * `pref_default_contact_id`, seed the new active set with it. Idempotent
     * via [KEY_DEFAULT_MIGRATED]. The pre-v1.1.0.11 `migrateLegacyActiveSet`
     * helper is gone; the new live key happens to be shape-identical to the
     * pre-v1.1.0.11 legacy key, so no migration is needed for that era.
     */
    private fun migrateDefaultIntoSet(context: Context) {
        val p = prefs(context)
        if (p.getBoolean(KEY_DEFAULT_MIGRATED, false)) return
        val edit = p.edit().putBoolean(KEY_DEFAULT_MIGRATED, true).remove(KEY_LEGACY_DEFAULT)
        val legacyDefault = p.getString(KEY_LEGACY_DEFAULT, null)
        val existingSet = p.getStringSet(KEY_ACTIVE_IDS, null)
        if (legacyDefault != null && existingSet == null) {
            edit.putStringSet(KEY_ACTIVE_IDS, setOf(legacyDefault))
        }
        edit.apply()
    }
}
