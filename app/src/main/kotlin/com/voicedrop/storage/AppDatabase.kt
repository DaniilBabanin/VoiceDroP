package com.voicedrop.storage

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverter
import androidx.room.TypeConverters

/**
 * Schema v4 — Double Ratchet (plan/08-dr/dr3-db-schema-v3.md) +
 * identity verification (plan/09-security-frontier/3.1-sas-verification-ux.md).
 *
 * v1.x → v3 was a hard cutover (destructive). v3 → v4 is the FIRST real migration
 * — adds `verified_at` and `verified_fp_pair_hash` columns to `contacts`. The
 * fallback policy switches to `fallbackToDestructiveMigrationOnDowngrade` so
 * upgrades require a real `Migration` while downgrades (sideloading an older APK)
 * still wipe cleanly. The "Pair again" UX is wired up via [RepairNamesStash], which
 * copies contact display names out of the old DB file *before* Room takes ownership.
 */
@Database(
    entities = [
        ContactEntity::class,
        MessageEntity::class,
        PendingActionEntity::class,
        SkippedMessageKeyEntity::class,
        PendingOutboundFrameEntity::class
    ],
    version = 4,
    exportSchema = true
)
@TypeConverters(AppDatabase.Converters::class)
abstract class AppDatabase : RoomDatabase() {

    abstract fun contactDao(): ContactDao
    abstract fun messageDao(): MessageDao
    abstract fun pendingActionDao(): PendingActionDao
    abstract fun pendingOutboundFrameDao(): PendingOutboundFrameDao
    abstract fun skippedMessageKeyDao(): SkippedMessageKeyDao

    class Converters {
        @TypeConverter
        fun fromByteArray(value: ByteArray): String = android.util.Base64.encodeToString(value, android.util.Base64.NO_WRAP)

        @TypeConverter
        fun toByteArray(value: String): ByteArray = android.util.Base64.decode(value, android.util.Base64.NO_WRAP)

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
                        .addMigrations(Migration_3_4)
                        .fallbackToDestructiveMigrationOnDowngrade(dropAllTables = true)
                        .build()
                        .also {
                            instance = it
                            startSkippedKeyExpirySweep(it)
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
    }
}
