package com.voicedrop.storage

import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class MessageFileRefcountTest {

    private lateinit var db: AppDatabase
    private lateinit var repo: MessageRepository
    private lateinit var tmpDir: File

    @Before
    fun setUp() {
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        db = Room.inMemoryDatabaseBuilder(ctx, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        repo = MessageRepository(db.contactDao(), db.messageDao(), db.pendingActionDao())
        tmpDir = File(ctx.cacheDir, "refcount-test").apply { mkdirs() }
        runBlocking {
            db.contactDao().upsert(
                ContactEntity(id = "c1", name = "C1", publicKeyBase64 = "pk", addedAt = 1L)
            )
            db.contactDao().upsert(
                ContactEntity(id = "c2", name = "C2", publicKeyBase64 = "pk", addedAt = 2L)
            )
            db.contactDao().upsert(
                ContactEntity(id = "c3", name = "C3", publicKeyBase64 = "pk", addedAt = 3L)
            )
        }
    }

    @After
    fun tearDown() {
        db.close()
        tmpDir.deleteRecursively()
    }

    private fun makeRow(uuid: String, contactId: String, path: String) = MessageEntity(
        uuid = uuid,
        contactId = contactId,
        direction = MessageEntity.DIRECTION_OUTBOUND,
        state = MessageEntity.STATE_SENT,
        transport = TransportType.UNKNOWN,
        encryptedFilePath = path,
        durationMs = 100,
        deleteAfterMs = 0L,
        scheduledDeleteAt = 0L,
        transcription = null,
        createdAt = 1L,
        sentAt = 1L,
        deliveredAt = 0L
    )

    @Test
    fun countByEncryptedFilePathReturnsRowCount() = runBlocking {
        val path = File(tmpDir, "shared.opus").apply { writeText("opus") }.absolutePath
        repo.insertMessage(makeRow("u1", "c1", path))
        repo.insertMessage(makeRow("u2", "c2", path))
        repo.insertMessage(makeRow("u3", "c3", path))

        assertEquals(3, db.messageDao().countByEncryptedFilePath(path))
    }

    @Test
    fun deleteMessageWithBlobCleanupKeepsFileWhenOthersReference() = runBlocking {
        val file = File(tmpDir, "shared.opus").apply { writeText("opus") }
        val path = file.absolutePath
        repo.insertMessage(makeRow("u1", "c1", path))
        repo.insertMessage(makeRow("u2", "c2", path))
        repo.insertMessage(makeRow("u3", "c3", path))

        repo.deleteMessageWithBlobCleanup(db.messageDao().getByUuid("u1")!!)
        repo.deleteMessageWithBlobCleanup(db.messageDao().getByUuid("u2")!!)

        assertTrue("file should still exist while u3 references it", file.exists())
        assertEquals(1, db.messageDao().countByEncryptedFilePath(path))
    }

    @Test
    fun deleteMessageWithBlobCleanupDeletesFileOnLastReference() = runBlocking {
        val file = File(tmpDir, "shared.opus").apply { writeText("opus") }
        val path = file.absolutePath
        repo.insertMessage(makeRow("u1", "c1", path))
        repo.insertMessage(makeRow("u2", "c2", path))

        repo.deleteMessageWithBlobCleanup(db.messageDao().getByUuid("u1")!!)
        repo.deleteMessageWithBlobCleanup(db.messageDao().getByUuid("u2")!!)

        assertFalse("file should be removed after last reference", file.exists())
        assertEquals(0, db.messageDao().countByEncryptedFilePath(path))
    }

    @Test
    fun deleteMessageWithBlobCleanupTolerantOfMissingFile() = runBlocking {
        val path = File(tmpDir, "never-existed.opus").absolutePath
        repo.insertMessage(makeRow("u1", "c1", path))

        // Should not throw even though the file is absent.
        repo.deleteMessageWithBlobCleanup(db.messageDao().getByUuid("u1")!!)

        assertEquals(0, db.messageDao().countByEncryptedFilePath(path))
    }

    @Test
    fun deleteAllMessagesForContactWithBlobCleanupCascadesPaths() = runBlocking {
        val sharedFile = File(tmpDir, "shared.opus").apply { writeText("opus") }
        val soloFile = File(tmpDir, "solo.opus").apply { writeText("opus") }
        // c1 owns both a shared row and a solo row.
        repo.insertMessage(makeRow("u1-shared", "c1", sharedFile.absolutePath))
        repo.insertMessage(makeRow("u1-solo", "c1", soloFile.absolutePath))
        // c2 holds the other share on sharedFile.
        repo.insertMessage(makeRow("u2-shared", "c2", sharedFile.absolutePath))

        repo.deleteAllMessagesForContactWithBlobCleanup("c1")

        assertTrue("sharedFile still referenced by c2's row", sharedFile.exists())
        assertFalse("soloFile had only c1's row → must be gone", soloFile.exists())
        assertEquals(1, db.messageDao().countByEncryptedFilePath(sharedFile.absolutePath))
    }
}
