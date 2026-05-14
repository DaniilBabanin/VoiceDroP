package com.voicedrop.storage

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverter
import androidx.room.TypeConverters
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

@Database(
    entities = [ContactEntity::class, MessageEntity::class, PendingActionEntity::class],
    version = 2,
    exportSchema = true
)
@TypeConverters(AppDatabase.Converters::class)
abstract class AppDatabase : RoomDatabase() {

    abstract fun contactDao(): ContactDao
    abstract fun messageDao(): MessageDao
    abstract fun pendingActionDao(): PendingActionDao

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

        private val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE messages ADD COLUMN transport INTEGER NOT NULL DEFAULT 0")
            }
        }

        fun getInstance(context: Context): AppDatabase =
            instance ?: synchronized(this) {
                instance ?: Room.databaseBuilder(
                    context.applicationContext,
                    AppDatabase::class.java,
                    "voicedrop.db"
                ).addMigrations(MIGRATION_1_2).build().also { instance = it }
            }
    }
}
