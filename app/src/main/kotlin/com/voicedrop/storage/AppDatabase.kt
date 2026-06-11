package com.voicedrop.storage

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverter
import androidx.room.TypeConverters

/**
 * Schema v7 — v6 → v7 — Finding #2 / Phase B: adds `pending_outbound_frames.acked_uuid`
 * (nullable BLOB) + a `(contact_id, acked_uuid)` index, and `messages.receipt_resends`
 * (INT NOT NULL DEFAULT 0). Backs idempotent duplicate-DATA RECEIPT handling and the
 * per-message resend cap (see Migration_6_7).
 *
 * v1.x → v3 was a hard cutover (destructive). v3 → v4 is the FIRST real migration
 * — adds `verified_at` and `verified_fp_pair_hash` columns to `contacts`. v4 → v5
 * adds the `prekey_epochs` table and wipes ratchet state on all existing contacts
 * (see Migration_4_5). v5 → v6 adds the `waveformPeaks` BLOB column on `messages`
 * (see Migration_5_6). v6 → v7 adds `acked_uuid` + `receipt_resends` (see Migration_6_7).
 * The fallback policy is `fallbackToDestructiveMigrationOnDowngrade`
 * so upgrades require a real `Migration` while downgrades (sideloading an older APK)
 * still wipe cleanly. The "Pair again" UX is wired up via [RepairNamesStash], which
 * copies contact display names out of the old DB file *before* Room takes ownership.
 */
@Database(
    entities = [
        ContactEntity::class,
        MessageEntity::class,
        PendingActionEntity::class,
        SkippedMessageKeyEntity::class,
        PendingOutboundFrameEntity::class,
        PrekeyEpochEntity::class
    ],
    version = 7,
    exportSchema = true
)
@TypeConverters(AppDatabase.Converters::class)
abstract class AppDatabase : RoomDatabase() {

    abstract fun contactDao(): ContactDao
    abstract fun messageDao(): MessageDao
    abstract fun pendingActionDao(): PendingActionDao
    abstract fun pendingOutboundFrameDao(): PendingOutboundFrameDao
    abstract fun skippedMessageKeyDao(): SkippedMessageKeyDao
    abstract fun prekeyEpochDao(): PrekeyEpochDao

    class Converters {
        @TypeConverter
        fun fromTransportType(value: TransportType): Int = value.value

        @TypeConverter
        fun toTransportType(value: Int): TransportType = TransportType.fromInt(value)
    }

    companion object {
        @Volatile
        private var instance: AppDatabase? = null

        fun getInstance(context: Context): AppDatabase =
            instance ?: synchronized(this) {
                instance ?: run {
                    // MUST run before Room opens the file so we still see v1.x rows.
                    RepairNamesStash.stashFromV1xIfPresent(context.applicationContext)
                    Room.databaseBuilder(
                        context.applicationContext,
                        AppDatabase::class.java,
                        "voicedrop.db"
                    )
                        .addMigrations(Migration_3_4, Migration_4_5, Migration_5_6, Migration_6_7)
                        .fallbackToDestructiveMigrationOnDowngrade(dropAllTables = true)
                        .build()
                        .also {
                            instance = it
                            startSkippedKeyExpirySweep(it)
                            startPrekeyPreviousExpirySweep(it)
                        }
                }
            }

        /**
         * DR9 — fire-and-forget 7-day expiry sweep on `skipped_message_keys`. Runs
         * on a daemon thread so `getInstance` never blocks UI startup. Failures are
         * swallowed (sweep is a forward-secrecy hygiene step — not load-bearing for
         * boot; next launch will retry). One sweep per process, single Android
         * process per [00-overview.md §4].
         */
        private fun startSkippedKeyExpirySweep(db: AppDatabase) {
            Thread({
                try {
                    SkippedKeyMaintenance.sweepExpired(
                        db.skippedMessageKeyDao(),
                        System.currentTimeMillis()
                    )
                } catch (t: Throwable) {
                    android.util.Log.w("AppDatabase", "skipped-key expiry sweep failed", t)
                }
            }, "voicedrop-skipped-key-sweep").apply {
                isDaemon = true
                start()
            }
        }

        /**
         * §3.2 §6.7 — fire-and-forget 10-min expiry sweep on `prekey_epochs`
         * status='previous' rows. Same daemon pattern as the dr9 skipped-key
         * sweep above. Runs once per process; in-cycle wipes at §6.6 are the
         * primary path. Failures are logged and swallowed.
         */
        private fun startPrekeyPreviousExpirySweep(db: AppDatabase) {
            Thread({
                try {
                    kotlinx.coroutines.runBlocking {
                        db.prekeyEpochDao().sweepExpiredPrevious(System.currentTimeMillis())
                    }
                } catch (t: Throwable) {
                    android.util.Log.w("AppDatabase", "prekey previous-expiry sweep failed", t)
                }
            }, "voicedrop-prekey-previous-sweep").apply {
                isDaemon = true
                start()
            }
        }
    }
}
