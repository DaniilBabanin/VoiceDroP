package com.voicedrop.storage

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverter
import androidx.room.TypeConverters

/**
 * Schema v3 — Double Ratchet (plan/08-dr/dr3-db-schema-v3.md).
 *
 * Hard cutover from v1.x: no migration code path. `fallbackToDestructiveMigration` drops everything
 * on first v1.2 launch. The "Pair again" UX is wired up via [RepairNamesStash], which copies contact
 * display names out of the old DB file *before* Room takes ownership.
 */
@Database(
    entities = [
        ContactEntity::class,
        MessageEntity::class,
        PendingActionEntity::class,
        SkippedMessageKeyEntity::class,
        PendingOutboundFrameEntity::class
    ],
    version = 3,
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
                        .fallbackToDestructiveMigration(dropAllTables = true)
                        .build()
                        .also { instance = it }
                }
            }
    }
}
