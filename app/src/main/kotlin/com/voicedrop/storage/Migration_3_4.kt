package com.voicedrop.storage

import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

/**
 * §3.1 — adds identity-verification state to the `contacts` table.
 *
 * Both columns are nullable; existing rows are "not yet verified" after upgrade,
 * which is the correct semantics — users will mark contacts as verified the next
 * time they tap "Match" at re-pair or "Mark as verified" in the chat menu.
 *
 * This is the FIRST real Room migration in this project. `AppDatabase` flips from
 * `fallbackToDestructiveMigration(dropAllTables = true)` to
 * `fallbackToDestructiveMigrationOnDowngrade(dropAllTables = true)` in this same
 * commit so upgrades require a real migration, while downgrades (sideloading an
 * older APK) still wipe cleanly.
 */
val Migration_3_4 = object : Migration(3, 4) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL("ALTER TABLE contacts ADD COLUMN verified_at INTEGER")
        db.execSQL("ALTER TABLE contacts ADD COLUMN verified_fp_pair_hash BLOB")
    }
}
