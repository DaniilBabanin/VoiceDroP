package com.voicedrop.storage

import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

/**
 * §D — adds the cached `waveformPeaks` blob to `messages` for the playback waveform bar.
 *
 * The column is nullable; existing rows are backfilled lazily on first playback via
 * [MessageDao.updateWaveformPeaks] (the `IS NULL` guard there keeps concurrent
 * playbacks idempotent). No data migration required.
 */
val Migration_5_6 = object : Migration(5, 6) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL("ALTER TABLE messages ADD COLUMN waveformPeaks BLOB")
    }
}
