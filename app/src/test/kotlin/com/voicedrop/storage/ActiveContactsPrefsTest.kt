package com.voicedrop.storage

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class ActiveContactsPrefsTest {

    private lateinit var context: Context

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        context.getSharedPreferences("voicedrop_settings", Context.MODE_PRIVATE)
            .edit().clear().commit()
    }

    @After
    fun tearDown() {
        context.getSharedPreferences("voicedrop_settings", Context.MODE_PRIVATE)
            .edit().clear().commit()
    }

    private fun contact(id: String, addedAt: Long) =
        ContactEntity(
            id = id,
            name = "name-$id",
            publicKeyBase64 = "pk",
            sharedSecretWrapped = ByteArray(0),
            addedAt = addedAt
        )

    @Test
    fun defaultIdRoundTrip() {
        assertNull(ActiveContactsPrefs.getDefaultId(context))
        ActiveContactsPrefs.setDefaultId(context, "abc")
        assertEquals("abc", ActiveContactsPrefs.getDefaultId(context))
        ActiveContactsPrefs.setDefaultId(context, null)
        assertNull(ActiveContactsPrefs.getDefaultId(context))
    }

    @Test
    fun resolveRecipientReturnsExplicitDefaultWhenPresent() {
        val a = contact("a", 100L)
        val b = contact("b", 200L) // newer
        ActiveContactsPrefs.setDefaultId(context, "a")

        val resolved = ActiveContactsPrefs.resolveRecipient(context, listOf(a, b))

        assertEquals("a", resolved?.id)
    }

    @Test
    fun resolveRecipientFallsBackToNewestWhenDefaultUnset() {
        val a = contact("a", 100L)
        val b = contact("b", 200L)

        val resolved = ActiveContactsPrefs.resolveRecipient(context, listOf(a, b))

        assertEquals("b", resolved?.id)
    }

    @Test
    fun resolveRecipientFallsBackAndClearsStaleDefault() {
        val a = contact("a", 100L)
        ActiveContactsPrefs.setDefaultId(context, "ghost") // no longer present

        val resolved = ActiveContactsPrefs.resolveRecipient(context, listOf(a))

        assertEquals("a", resolved?.id)
        assertNull(ActiveContactsPrefs.getDefaultId(context))
    }

    @Test
    fun resolveRecipientNullForEmptyContactList() {
        assertNull(ActiveContactsPrefs.resolveRecipient(context, emptyList()))
    }

    @Test
    fun migrateLegacyActiveSetLiftsFirstIdIntoDefault() {
        val prefs = context.getSharedPreferences("voicedrop_settings", Context.MODE_PRIVATE)
        prefs.edit().putStringSet("pref_active_contact_ids", setOf("legacy-a")).commit()

        ActiveContactsPrefs.migrateLegacyActiveSet(context)

        assertEquals("legacy-a", ActiveContactsPrefs.getDefaultId(context))
        // Legacy set is cleared so it can't drift out of sync.
        assertEquals(emptySet<String>(), prefs.getStringSet("pref_active_contact_ids", emptySet()))
    }

    @Test
    fun migrateLegacyActiveSetDoesNotClobberExistingDefault() {
        val prefs = context.getSharedPreferences("voicedrop_settings", Context.MODE_PRIVATE)
        prefs.edit()
            .putString("pref_default_contact_id", "explicit")
            .putStringSet("pref_active_contact_ids", setOf("legacy-a"))
            .commit()

        ActiveContactsPrefs.migrateLegacyActiveSet(context)

        assertEquals("explicit", ActiveContactsPrefs.getDefaultId(context))
    }

    @Test
    fun migrateLegacyActiveSetIsIdempotent() {
        val prefs = context.getSharedPreferences("voicedrop_settings", Context.MODE_PRIVATE)
        prefs.edit().putStringSet("pref_active_contact_ids", setOf("legacy-a")).commit()

        ActiveContactsPrefs.migrateLegacyActiveSet(context)
        // Simulate a later run after the user set a different default explicitly.
        ActiveContactsPrefs.setDefaultId(context, "explicit-later")
        // Re-seed the legacy set as if some other code wrote it (shouldn't happen, but covers re-runs).
        prefs.edit().putStringSet("pref_active_contact_ids", setOf("legacy-b")).commit()

        ActiveContactsPrefs.migrateLegacyActiveSet(context)

        assertEquals("explicit-later", ActiveContactsPrefs.getDefaultId(context))
    }
}
