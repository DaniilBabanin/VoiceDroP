package com.voicedrop.ui

import android.app.Activity
import android.widget.Button
import androidx.room.Room
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.voicedrop.R
import com.voicedrop.crypto.Sas
import com.voicedrop.storage.AppDatabase
import com.voicedrop.storage.ContactEntity
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class VerifyIdentityDialogTest {

    private lateinit var db: AppDatabase
    private val contactId = "abc123"
    private val myIdPub = ByteArray(32) { it.toByte() }
    private val theirIdPub = ByteArray(32) { (it + 32).toByte() }

    @Before
    fun setUp() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        db = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        db.contactDao().upsert(ContactEntity(
            id = contactId, name = "Test", publicKeyBase64 = "AAAA", addedAt = 0L,
        ))
    }

    @After
    fun tearDown() { db.close() }

    @Test
    fun markAsVerified_writesBothColumns() = runBlocking {
        val instr = InstrumentationRegistry.getInstrumentation()
        ActivityScenario.launch(Activity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                VerifyIdentityDialog(
                    activity, contactId, myIdPub, theirIdPub,
                    contactDao = db.contactDao(),
                ).show()
            }
            instr.waitForIdleSync()

            scenario.onActivity { activity ->
                val positive = activity.window.decorView.rootView.findViewById<Button>(android.R.id.button1)
                assertNotNull(positive)
                assertEquals(activity.getString(R.string.verify_identity_button_mark), positive.text.toString())
                positive.performClick()
            }
            instr.waitForIdleSync()
        }

        val row = db.contactDao().getById(contactId)!!
        assertNotNull(row.verified_at)
        assertNotNull(row.verified_fp_pair_hash)
        assertEquals(
            Sas.fpPairBinding(myIdPub, theirIdPub).toList(),
            row.verified_fp_pair_hash!!.toList(),
        )
    }

    @Test
    fun clearVerification_nullsBothColumns() = runBlocking {
        db.contactDao().setVerified(
            contactId, 1L, Sas.fpPairBinding(myIdPub, theirIdPub),
        )
        val instr = InstrumentationRegistry.getInstrumentation()
        ActivityScenario.launch(Activity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                VerifyIdentityDialog(
                    activity, contactId, myIdPub, theirIdPub,
                    contactDao = db.contactDao(),
                ).show()
            }
            instr.waitForIdleSync()

            scenario.onActivity { activity ->
                val positive = activity.window.decorView.rootView.findViewById<Button>(android.R.id.button1)
                assertNotNull(positive)
                assertEquals(activity.getString(R.string.verify_identity_button_clear), positive.text.toString())
                positive.performClick()
            }
            instr.waitForIdleSync()
        }

        val row = db.contactDao().getById(contactId)!!
        assertNull(row.verified_at)
        assertNull(row.verified_fp_pair_hash)
    }
}
