package com.voicedrop.storage

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.util.Log

/**
 * Pre-wipe name extraction for v1.x → v1.2 destructive migration.
 *
 * Room's `fallbackToDestructiveMigration` doesn't expose pre-drop hooks, so we open the existing
 * `voicedrop.db` file directly via raw SQLite *before* Room takes ownership, copy the contact
 * `name` values into a private SharedPreferences set, then let Room destructively rebuild at v3.
 * The first v1.2 launch reads this set to populate the "Pair again" screen. There is no silent
 * trust migration — only display names are stashed, never identity material.
 *
 * Idempotent and best-effort: if the file is missing, already at v3, or unreadable, the stash is
 * left unchanged. See plan/08-dr/dr3-db-schema-v3.md.
 */
object RepairNamesStash {

    const val PREFS_NAME = "voicedrop_repair"
    const val KEY_PENDING_NAMES = "pending_repair_names"
    private const val DB_FILE_NAME = "voicedrop.db"
    private const val SCHEMA_VERSION_V3 = 3
    private const val TAG = "RepairNamesStash"

    /**
     * Reads contact names from the on-disk v1.x DB if it's still at schema version < 3, and writes
     * them to the repair-names stash. Safe to call before `Room.databaseBuilder(...)` on every app
     * start — does nothing once the DB has been upgraded.
     */
    fun stashFromV1xIfPresent(context: Context) {
        val dbFile = context.getDatabasePath(DB_FILE_NAME)
        if (!dbFile.exists()) return

        val db = try {
            SQLiteDatabase.openDatabase(dbFile.absolutePath, null, SQLiteDatabase.OPEN_READONLY)
        } catch (e: Exception) {
            Log.w(TAG, "raw open failed; skipping stash — ${e.message}")
            return
        }
        try {
            if (db.version >= SCHEMA_VERSION_V3) return  // already migrated; nothing to stash
            val names = readContactNames(db)
            if (names.isNotEmpty()) {
                context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                    .edit()
                    .putStringSet(KEY_PENDING_NAMES, names.toSet())
                    .apply()
                Log.i(TAG, "stashed ${names.size} contact name(s) for repair UI")
            }
        } catch (e: Exception) {
            Log.w(TAG, "stash failed — ${e.message}")
        } finally {
            db.close()
        }
    }

    /** Names of contacts that existed in the v1.x DB just before the destructive upgrade. */
    fun pendingRepairNames(context: Context): Set<String> =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getStringSet(KEY_PENDING_NAMES, emptySet()) ?: emptySet()

    /** Called once the user has re-paired (or dismissed the screen). */
    fun clearPendingRepairNames(context: Context) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .remove(KEY_PENDING_NAMES)
            .apply()
    }

    private fun readContactNames(db: SQLiteDatabase): List<String> {
        val out = mutableListOf<String>()
        try {
            db.rawQuery("SELECT name FROM contacts", null).use { cursor ->
                while (cursor.moveToNext()) {
                    cursor.getString(0)?.takeIf { it.isNotBlank() }?.let { out += it }
                }
            }
        } catch (e: Exception) {
            // No contacts table or unexpected shape — old DB shape isn't ours to assume.
            Log.w(TAG, "contacts read failed — ${e.message}")
        }
        return out
    }
}
