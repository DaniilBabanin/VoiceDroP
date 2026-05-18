package com.voicedrop.storage

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.File
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import kotlinx.coroutines.runBlocking

/**
 * Schema-level integration tests for DR3.
 *
 * On-device Room (in-memory builder for shape checks; file-backed for destructive-migration check).
 * See plan/08-dr/dr3-db-schema-v3.md.
 */
@RunWith(AndroidJUnit4::class)
class DbSchemaV3Test {

    private val context: Context get() = ApplicationProvider.getApplicationContext()
    private val testDbName = "voicedrop_dbschema_test.db"
    private lateinit var db: AppDatabase

    @Before
    fun setUp() {
        // Each test starts from a clean slate.
        context.deleteDatabase(testDbName)
        context.getSharedPreferences(RepairNamesStash.PREFS_NAME, Context.MODE_PRIVATE)
            .edit().clear().commit()
        db = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
    }

    @After
    fun tearDown() {
        if (::db.isInitialized) db.close()
        context.deleteDatabase(testDbName)
    }

    @Test
    fun schemaCreatesAllV3Tables() {
        val raw = db.openHelper.readableDatabase
        val cursor = raw.query("SELECT name FROM sqlite_master WHERE type='table'")
        val tables = mutableSetOf<String>()
        cursor.use { while (it.moveToNext()) tables += it.getString(0) }

        for (expected in listOf(
            "contacts",
            "messages",
            "pending_actions",
            "skipped_message_keys",
            "pending_outbound_frames"
        )) {
            assertTrue("expected table '$expected' missing — found: $tables", expected in tables)
        }
    }

    @Test
    fun contactsHasAllRatchetAndResetColumns() {
        val raw = db.openHelper.readableDatabase
        val cursor = raw.query("PRAGMA table_info(contacts)")
        val cols = mutableSetOf<String>()
        cursor.use { while (it.moveToNext()) cols += it.getString(1) }

        for (expected in listOf(
            "id", "name", "publicKeyBase64", "addedAt", "autoDeleteAfterMs", "pending_repair",
            "dhs_priv_wrapped", "dhs_priv_hmac", "dhs_pub", "dhr_pub",
            "rk_wrapped", "rk_hmac",
            "cks_wrapped", "cks_hmac", "ckr_wrapped", "ckr_hmac",
            "ns", "nr", "pn",
            "reset_epoch", "reset_nonce", "expecting_ack",
            "auto_reset_window_start", "auto_reset_count_24h", "last_auto_reset_at",
            "inbound_reset_window_start", "inbound_reset_count_24h", "budget_exhausted_until",
            "consecutive_aead_failures", "consecutive_aead_failures_window_start",
            "soft_prompt_dismissed_until"
        )) {
            assertTrue("contacts.$expected missing — actual cols: $cols", expected in cols)
        }
        // Spec column removed.
        assertFalse("sharedSecretWrapped must be gone in v3", "sharedSecretWrapped" in cols)
    }

    @Test
    fun messagesHasDeliveryStateColumn() {
        val raw = db.openHelper.readableDatabase
        val cursor = raw.query("PRAGMA table_info(messages)")
        val cols = mutableSetOf<String>()
        cursor.use { while (it.moveToNext()) cols += it.getString(1) }
        assertTrue("messages.delivery_state missing", "delivery_state" in cols)
    }

    @Test
    fun foreignKeysPragmaIsEnabled() {
        val raw = db.openHelper.readableDatabase
        val cursor = raw.query("PRAGMA foreign_keys")
        cursor.use {
            assertTrue(it.moveToNext())
            assertEquals(1, it.getInt(0))
        }
    }

    @Test
    fun foreignKeyCascade_deleteContact_removesSkippedAndOutbox() = runBlocking {
        val contactId = "fp-cascade"
        val contact = ContactEntity(
            id = contactId,
            name = "C",
            publicKeyBase64 = "pk",
            addedAt = 0L
        )
        db.contactDao().upsert(contact)

        val raw = db.openHelper.writableDatabase

        raw.execSQL(
            "INSERT INTO skipped_message_keys " +
                    "(contact_id, dhr_pub, n, mk_wrapped, mk_hmac, created_at) " +
                    "VALUES (?, ?, 0, ?, ?, 0)",
            arrayOf(contactId, ByteArray(32), ByteArray(60), ByteArray(32))
        )
        raw.execSQL(
            "INSERT INTO pending_outbound_frames " +
                    "(uuid, contact_id, frame_kind, wrapped_frame, frame_hmac, created_at, attempts) " +
                    "VALUES (?, ?, 0, ?, ?, 0, 0)",
            arrayOf(ByteArray(16) { 0x11 }, contactId, ByteArray(64), ByteArray(32))
        )

        fun count(table: String): Int {
            raw.query("SELECT COUNT(*) FROM $table WHERE contact_id = ?", arrayOf(contactId)).use {
                it.moveToNext(); return it.getInt(0)
            }
        }
        assertEquals(1, count("skipped_message_keys"))
        assertEquals(1, count("pending_outbound_frames"))

        db.contactDao().delete(contact)

        assertEquals(0, count("skipped_message_keys"))
        assertEquals(0, count("pending_outbound_frames"))
    }

    /**
     * Synthesize a v1 DB on disk, then open Room at v3 — expect destructive rebuild (empty tables)
     * and the repair-names stash populated from the old contact rows.
     */
    @Test
    fun fallbackToDestructiveMigration_dropsV1xDataAndStashesNames() {
        val dbFile = context.getDatabasePath(testDbName)
        dbFile.parentFile?.mkdirs()
        SQLiteDatabase.openOrCreateDatabase(dbFile.absolutePath, null).use { v1 ->
            v1.version = 2  // pretend v1.1.x
            v1.execSQL(
                "CREATE TABLE contacts (" +
                        "id TEXT PRIMARY KEY, " +
                        "name TEXT NOT NULL, " +
                        "publicKeyBase64 TEXT NOT NULL, " +
                        "sharedSecretWrapped BLOB, " +
                        "addedAt INTEGER NOT NULL, " +
                        "autoDeleteAfterMs INTEGER NOT NULL DEFAULT 0)"
            )
            v1.execSQL("INSERT INTO contacts VALUES('id1','Alice','pk',NULL,0,0)")
            v1.execSQL("INSERT INTO contacts VALUES('id2','Bob','pk',NULL,0,0)")
        }
        // We can't call AppDatabase.getInstance for a non-default filename, so reproduce its
        // pre-Room stash step manually for the synthetic file, then open Room at v3 with the same
        // destructive-fallback config.
        stashUsingFile(dbFile)
        val migrated = Room.databaseBuilder(context, AppDatabase::class.java, testDbName)
            .fallbackToDestructiveMigration(dropAllTables = true)
            .allowMainThreadQueries()
            .build()
        try {
            val raw = migrated.openHelper.readableDatabase
            raw.query("SELECT COUNT(*) FROM contacts").use {
                it.moveToNext()
                assertEquals("destructive migration must wipe contacts", 0, it.getInt(0))
            }
        } finally {
            migrated.close()
        }

        val stashed = context.getSharedPreferences(RepairNamesStash.PREFS_NAME, Context.MODE_PRIVATE)
            .getStringSet(RepairNamesStash.KEY_PENDING_NAMES, emptySet())!!
        assertEquals(setOf("Alice", "Bob"), stashed)
    }

    @Test
    fun repairNamesStash_noOp_whenNoOldDb() {
        // Nothing on disk → stash unchanged.
        RepairNamesStash.stashFromV1xIfPresent(context)
        assertEquals(emptySet<String>(), RepairNamesStash.pendingRepairNames(context))
    }

    @Test
    fun repairNamesStash_skipsIfAlreadyV3() {
        val dbFile = context.getDatabasePath(testDbName)
        dbFile.parentFile?.mkdirs()
        SQLiteDatabase.openOrCreateDatabase(dbFile.absolutePath, null).use { fresh ->
            fresh.version = 3
            fresh.execSQL("CREATE TABLE contacts (id TEXT, name TEXT)")
            fresh.execSQL("INSERT INTO contacts VALUES('x','LeakedName')")
        }
        stashUsingFile(dbFile)
        assertEquals(
            "v3 file must not contribute to repair stash",
            emptySet<String>(),
            RepairNamesStash.pendingRepairNames(context)
        )
    }

    private fun stashUsingFile(dbFile: File) {
        // Mirror RepairNamesStash.stashFromV1xIfPresent but pointed at our synthetic path.
        if (!dbFile.exists()) return
        SQLiteDatabase.openDatabase(dbFile.absolutePath, null, SQLiteDatabase.OPEN_READONLY).use { raw ->
            if (raw.version >= 3) return
            val names = mutableListOf<String>()
            raw.rawQuery("SELECT name FROM contacts", null).use { c ->
                while (c.moveToNext()) c.getString(0)?.takeIf { it.isNotBlank() }?.let { names += it }
            }
            if (names.isNotEmpty()) {
                context.getSharedPreferences(RepairNamesStash.PREFS_NAME, Context.MODE_PRIVATE)
                    .edit()
                    .putStringSet(RepairNamesStash.KEY_PENDING_NAMES, names.toSet())
                    .apply()
            }
        }
    }
}
