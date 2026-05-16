package com.voicedrop.crypto

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.ContactEntity
import com.voicedrop.storage.MessageEntity
import com.voicedrop.storage.PendingOutboundFrameEntity
import com.voicedrop.storage.SkippedMessageKeyEntity
import com.voicedrop.storage.TransportType
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * DR15 §6.5 — RePairWipe data-layer primitive.
 *
 * Verifies a contact's ratchet/skipped/outbox state is fully cleared while
 * `messages` rows survive untouched, and `pending_repair = 1` flips so the UI
 * can surface the "Pair again" affordance.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class RePairWipeTest {

    private lateinit var db: AppDatabase
    private val contactId = "peer-wipe"

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        db = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        ContactMutexRegistry.clear()
    }

    @After
    fun tearDown() {
        db.close()
        ContactMutexRegistry.clear()
    }

    @Test
    fun wipe_clearsRatchet_andRefuses_priorState() = runBlocking {
        seedFullyPopulatedContact()
        // Sanity: pre-wipe.
        val before = db.contactDao().getById(contactId)!!
        assertTrue("expected non-empty rk_wrapped pre-wipe", before.rk_wrapped.isNotEmpty())
        assertTrue("expected non-empty rk_hmac pre-wipe", before.rk_hmac.isNotEmpty())
        assertNotNull(before.dhs_priv_wrapped)
        assertNotNull(before.dhs_pub)
        assertEquals(5, before.ns)
        assertEquals(3, before.reset_epoch)
        assertEquals(1, before.expecting_ack)
        assertEquals(2, db.skippedMessageKeyDao().getByContact(contactId).size)
        assertEquals(2, db.pendingOutboundFrameDao().getByContact(contactId).size)
        assertEquals(2, countMessages(contactId))

        RePairWipe(db).wipe(contactId)

        // Contact row survives but ratchet/reset/heuristic state is cleared.
        val after = db.contactDao().getById(contactId)!!
        assertEquals(contactId, after.id)
        assertEquals("peer", after.name)
        assertEquals(before.publicKeyBase64, after.publicKeyBase64)
        assertArrayEquals(ByteArray(0), after.rk_wrapped)
        assertArrayEquals(ByteArray(0), after.rk_hmac)
        assertNull(after.dhs_priv_wrapped)
        assertNull(after.dhs_priv_hmac)
        assertNull(after.dhs_pub)
        assertNull(after.dhr_pub)
        assertNull(after.cks_wrapped)
        assertNull(after.cks_hmac)
        assertNull(after.ckr_wrapped)
        assertNull(after.ckr_hmac)
        assertEquals(0, after.ns)
        assertEquals(0, after.nr)
        assertEquals(0, after.pn)
        assertEquals(0, after.reset_epoch)
        assertNull(after.reset_nonce)
        assertEquals(0, after.expecting_ack)
        assertEquals(0L, after.auto_reset_window_start)
        assertEquals(0, after.auto_reset_count_24h)
        assertEquals(0L, after.last_auto_reset_at)
        assertEquals(0L, after.inbound_reset_window_start)
        assertEquals(0, after.inbound_reset_count_24h)
        assertEquals(0L, after.budget_exhausted_until)
        assertEquals(0, after.consecutive_aead_failures)
        assertEquals(0L, after.consecutive_aead_failures_window_start)
        assertEquals(0L, after.soft_prompt_dismissed_until)
        assertEquals(1, after.pending_repair)

        // Skipped keys + outbox cleared.
        assertEquals(0, db.skippedMessageKeyDao().getByContact(contactId).size)
        assertEquals(0, db.pendingOutboundFrameDao().getByContact(contactId).size)

        // Messages preserved — user owns the plaintext.
        assertEquals(2, countMessages(contactId))
    }

    @Test
    fun wipe_unknownContact_isNoOp() = runBlocking {
        // Should not throw.
        RePairWipe(db).wipe("nobody")
    }

    @Test
    fun wipe_otherContact_isUnaffected() = runBlocking {
        seedFullyPopulatedContact()
        seedOtherContact()

        RePairWipe(db).wipe(contactId)

        val other = db.contactDao().getById("peer-other")!!
        assertEquals(0, other.pending_repair)
        assertTrue(other.rk_wrapped.isNotEmpty())
        assertEquals(1, db.skippedMessageKeyDao().getByContact("peer-other").size)
        assertEquals(1, db.pendingOutboundFrameDao().getByContact("peer-other").size)
    }

    // =========================================================================
    // Fixtures
    // =========================================================================

    private fun seedFullyPopulatedContact() {
        runBlocking {
            db.contactDao().upsert(
                ContactEntity(
                    id = contactId,
                    name = "peer",
                    publicKeyBase64 = "AA==",
                    addedAt = 1_000L,
                    rk_wrapped = ByteArray(32) { 0xAA.toByte() },
                    rk_hmac = ByteArray(32) { 0xBB.toByte() },
                    dhs_priv_wrapped = ByteArray(28),
                    dhs_priv_hmac = ByteArray(32),
                    dhs_pub = ByteArray(32),
                    dhr_pub = ByteArray(32),
                    cks_wrapped = ByteArray(28),
                    cks_hmac = ByteArray(32),
                    ckr_wrapped = ByteArray(28),
                    ckr_hmac = ByteArray(32),
                    ns = 5, nr = 4, pn = 2,
                    reset_epoch = 3,
                    reset_nonce = ByteArray(16),
                    expecting_ack = 1,
                    auto_reset_window_start = 1_000_000L,
                    auto_reset_count_24h = 2,
                    last_auto_reset_at = 999_000L,
                    inbound_reset_window_start = 800_000L,
                    inbound_reset_count_24h = 1,
                    budget_exhausted_until = 0L,
                    consecutive_aead_failures = 7,
                    consecutive_aead_failures_window_start = 700_000L,
                    soft_prompt_dismissed_until = 0L
                )
            )
            // Skipped keys
            repeat(2) { i ->
                db.skippedMessageKeyDao().insertBlocking(
                    SkippedMessageKeyEntity(
                        contact_id = contactId,
                        dhr_pub = ByteArray(32) { (it + i).toByte() },
                        n = i,
                        mk_wrapped = ByteArray(28),
                        mk_hmac = ByteArray(32),
                        created_at = 1_000L + i
                    )
                )
            }
            // Outbox rows (one DATA + one RESET)
            db.pendingOutboundFrameDao().insert(
                PendingOutboundFrameEntity(
                    uuid = ByteArray(16) { (it + 1).toByte() },
                    contact_id = contactId,
                    frame_kind = PendingOutboundFrameEntity.FRAME_KIND_DATA,
                    wrapped_frame = ByteArray(64),
                    frame_hmac = ByteArray(32),
                    created_at = 1_000L
                )
            )
            db.pendingOutboundFrameDao().insert(
                PendingOutboundFrameEntity(
                    uuid = ByteArray(16) { (it + 2).toByte() },
                    contact_id = contactId,
                    frame_kind = PendingOutboundFrameEntity.FRAME_KIND_RESET,
                    wrapped_frame = ByteArray(64),
                    frame_hmac = ByteArray(32),
                    created_at = 2_000L
                )
            )
            // Messages (the bit RePairWipe must preserve)
            repeat(2) { i ->
                db.messageDao().insert(
                    MessageEntity(
                        uuid = "msg-$contactId-$i",
                        contactId = contactId,
                        direction = MessageEntity.DIRECTION_INBOUND,
                        state = MessageEntity.STATE_DELIVERED,
                        transport = TransportType.LAN,
                        encryptedFilePath = "/tmp/$i",
                        durationMs = 1000,
                        deleteAfterMs = 0L,
                        scheduledDeleteAt = 0L,
                        transcription = null,
                        createdAt = 5_000L + i,
                        sentAt = 0L,
                        deliveredAt = 0L,
                        delivery_state = MessageEntity.DELIVERY_DELIVERED
                    )
                )
            }
        }
    }

    private fun seedOtherContact() {
        runBlocking {
            db.contactDao().upsert(
                ContactEntity(
                    id = "peer-other",
                    name = "other",
                    publicKeyBase64 = "BB==",
                    addedAt = 2_000L,
                    rk_wrapped = ByteArray(32) { 0xCC.toByte() },
                    rk_hmac = ByteArray(32) { 0xDD.toByte() }
                )
            )
            db.skippedMessageKeyDao().insertBlocking(
                SkippedMessageKeyEntity(
                    contact_id = "peer-other",
                    dhr_pub = ByteArray(32),
                    n = 0,
                    mk_wrapped = ByteArray(28),
                    mk_hmac = ByteArray(32),
                    created_at = 0L
                )
            )
            db.pendingOutboundFrameDao().insert(
                PendingOutboundFrameEntity(
                    uuid = ByteArray(16) { 0x99.toByte() },
                    contact_id = "peer-other",
                    frame_kind = PendingOutboundFrameEntity.FRAME_KIND_DATA,
                    wrapped_frame = ByteArray(64),
                    frame_hmac = ByteArray(32),
                    created_at = 0L
                )
            )
        }
    }

    private fun countMessages(contactId: String): Int =
        db.openHelper.writableDatabase.query(
            "SELECT COUNT(*) FROM messages WHERE contactId = ?", arrayOf(contactId)
        ).use { c -> c.moveToFirst(); c.getInt(0) }
}
