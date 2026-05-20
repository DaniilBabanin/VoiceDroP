package com.voicedrop.storage

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
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
        prefs().edit().clear().commit()
    }

    @After
    fun tearDown() {
        prefs().edit().clear().commit()
    }

    private fun prefs() = context.getSharedPreferences("voicedrop_settings", Context.MODE_PRIVATE)

    private fun contact(id: String, addedAt: Long) =
        ContactEntity(
            id = id,
            name = "name-$id",
            publicKeyBase64 = "pk",
            addedAt = addedAt
        )

    @Test
    fun activeIdsRoundTrip() {
        assertEquals(emptySet<String>(), ActiveContactsPrefs.getActiveIds(context))
        ActiveContactsPrefs.setActiveIds(context, setOf("a", "b"))
        assertEquals(setOf("a", "b"), ActiveContactsPrefs.getActiveIds(context))
    }

    @Test
    fun setActiveAddsAndRemovesAtomically() {
        ActiveContactsPrefs.setActive(context, "a", true)
        ActiveContactsPrefs.setActive(context, "b", true)
        assertEquals(setOf("a", "b"), ActiveContactsPrefs.getActiveIds(context))
        ActiveContactsPrefs.setActive(context, "a", false)
        assertEquals(setOf("b"), ActiveContactsPrefs.getActiveIds(context))
        ActiveContactsPrefs.setActive(context, "b", false)
        assertEquals(emptySet<String>(), ActiveContactsPrefs.getActiveIds(context))
    }

    @Test
    fun resolveRecipientsReturnsCheckedSubset() {
        val a = contact("a", 100L)
        val b = contact("b", 200L)
        val c = contact("c", 300L)
        ActiveContactsPrefs.setActiveIds(context, setOf("a", "c"))

        val resolved = ActiveContactsPrefs.resolveRecipients(context, listOf(a, b, c))

        assertEquals(setOf("a", "c"), resolved.map { it.id }.toSet())
    }

    @Test
    fun resolveRecipientsFallsBackToNewestWhenSetEmpty() {
        val a = contact("a", 100L)
        val b = contact("b", 200L)

        val resolved = ActiveContactsPrefs.resolveRecipients(context, listOf(a, b))

        assertEquals(listOf("b"), resolved.map { it.id })
    }

    @Test
    fun resolveRecipientsPrunesStaleIds() {
        val a = contact("a", 100L)
        ActiveContactsPrefs.setActiveIds(context, setOf("a", "ghost"))

        val resolved = ActiveContactsPrefs.resolveRecipients(context, listOf(a))

        assertEquals(listOf("a"), resolved.map { it.id })
        // The ghost id is auto-pruned from the persisted set.
        assertEquals(setOf("a"), ActiveContactsPrefs.getActiveIds(context))
    }

    @Test
    fun resolveRecipientsEmptyForEmptyContactList() {
        assertTrue(ActiveContactsPrefs.resolveRecipients(context, emptyList()).isEmpty())
    }

    @Test
    fun migratesLegacyDefaultIntoSet() {
        prefs().edit().putString("pref_default_contact_id", "legacy-a").commit()

        val ids = ActiveContactsPrefs.getActiveIds(context)

        assertEquals(setOf("legacy-a"), ids)
        // Old key removed; migration marker set.
        assertNull(prefs().getString("pref_default_contact_id", null))
        assertTrue(prefs().getBoolean("pref_default_migrated_to_set", false))
    }

    @Test
    fun migrationIsIdempotent() {
        prefs().edit().putString("pref_default_contact_id", "legacy-a").commit()
        ActiveContactsPrefs.getActiveIds(context) // first call migrates

        // Simulate user later editing the set explicitly:
        ActiveContactsPrefs.setActiveIds(context, setOf("x", "y"))

        // A second call must not re-introduce "legacy-a".
        assertEquals(setOf("x", "y"), ActiveContactsPrefs.getActiveIds(context))
    }

    @Test
    fun migrationDoesNothingWhenNoLegacyDefault() {
        // Fresh install: no legacy key, no set yet.
        val ids = ActiveContactsPrefs.getActiveIds(context)

        assertEquals(emptySet<String>(), ids)
        assertTrue(prefs().getBoolean("pref_default_migrated_to_set", false))
    }

    @Test
    fun migrationDoesNotClobberExistingSet() {
        // User somehow ended up with both keys (would only happen if downgraded then re-upgraded).
        prefs().edit()
            .putString("pref_default_contact_id", "legacy-a")
            .putStringSet("pref_active_contact_ids", setOf("explicit-b"))
            .commit()

        val ids = ActiveContactsPrefs.getActiveIds(context)

        assertEquals(setOf("explicit-b"), ids)
        assertNull(prefs().getString("pref_default_contact_id", null))
        assertTrue(prefs().getBoolean("pref_default_migrated_to_set", false))
    }

    @Test
    fun migrationRemovesLegacyKeyEvenWhenItsValueIsNull() {
        // Verify the "remove old key" step runs even on a fresh install.
        val ids = ActiveContactsPrefs.getActiveIds(context)
        assertFalse(prefs().contains("pref_default_contact_id"))
        assertEquals(emptySet<String>(), ids)
    }
}
