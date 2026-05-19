package com.voicedrop.storage

import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * §3.1 — round-trips setVerified and clearVerified through Room's compiled DAO,
 * verifying the new v4 columns are wired correctly. Uses in-memory Room so it
 * does NOT exercise Migration_3_4 — that test is deferred until schemas/3.json
 * lands in git (requires a real build, see plan/DEFERRED.md).
 */
@RunWith(AndroidJUnit4::class)
class ContactDaoVerificationTest {

    private lateinit var db: AppDatabase

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        db = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
    }

    @After
    fun tearDown() { db.close() }

    @Test
    fun setVerified_thenGetById_returnsBothColumns() = runBlocking {
        val dao = db.contactDao()
        dao.upsert(ContactEntity(
            id = "abc", name = "T", publicKeyBase64 = "AAAA", addedAt = 0L,
        ))
        val hash = ByteArray(16) { it.toByte() }
        dao.setVerified("abc", 12345L, hash)

        val row = dao.getById("abc")!!
        assertEquals(12345L, row.verified_at)
        assertArrayEquals(hash, row.verified_fp_pair_hash)
    }

    @Test
    fun clearVerified_nullsBothColumns() = runBlocking {
        val dao = db.contactDao()
        dao.upsert(ContactEntity(
            id = "abc", name = "T", publicKeyBase64 = "AAAA", addedAt = 0L,
            verified_at = 999L, verified_fp_pair_hash = ByteArray(16) { 0x42 },
        ))
        dao.clearVerified("abc")

        val row = dao.getById("abc")!!
        assertNull(row.verified_at)
        assertNull(row.verified_fp_pair_hash)
    }

    @Test
    fun setVerified_onMissingRow_isNoOp() = runBlocking {
        val dao = db.contactDao()
        // Don't insert anything. UPDATE with WHERE id = 'missing' affects zero rows.
        dao.setVerified("missing", 1L, ByteArray(16))
        assertNull(dao.getById("missing"))
    }
}
