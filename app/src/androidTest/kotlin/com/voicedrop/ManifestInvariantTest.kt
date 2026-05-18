package com.voicedrop

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.ComponentInfo
import android.content.pm.PackageManager
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.xmlpull.v1.XmlPullParser

/**
 * Locks the manifest invariants v1.2.0.0 depends on. Runs against the merged
 * manifest (PackageManager reports merged state, post-AAR-merge), so an AAR
 * that injects android:process or flips allowBackup also trips these tests.
 *
 * See plan/08-dr/dr1-manifest.md and 00-overview.md §1 / §4.
 */
@RunWith(AndroidJUnit4::class)
class ManifestInvariantTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    /**
     * Load-bearing — protects the single-process invariant required by the
     * per-contact mutex in dr7/dr8. ComponentInfo.processName defaults to the
     * application's processName when android:process is absent, so any
     * mismatch means someone declared android:process= on that component.
     */
    @Test
    fun noComponentDeclaresAndroidProcess() {
        val pm = context.packageManager
        val flags = (PackageManager.GET_ACTIVITIES
                or PackageManager.GET_SERVICES
                or PackageManager.GET_RECEIVERS
                or PackageManager.GET_PROVIDERS)
        val info = pm.getPackageInfo(context.packageName, flags)
        val appProcess = info.applicationInfo!!.processName

        val components: List<ComponentInfo> = buildList {
            info.activities?.let { addAll(it) }
            info.services?.let { addAll(it) }
            info.receivers?.let { addAll(it) }
            info.providers?.let { addAll(it) }
        }
        assertTrue("merged manifest has no components", components.isNotEmpty())

        val offenders = components
            .filter { it.processName != appProcess }
            .map { "${it.javaClass.simpleName}:${it.name} -> ${it.processName}" }
        assertTrue(
            "components declaring android:process=: $offenders",
            offenders.isEmpty()
        )
    }

    @Test
    fun allowBackupFalse() {
        val appInfo = context.applicationInfo
        val backupAllowed = (appInfo.flags and ApplicationInfo.FLAG_ALLOW_BACKUP) != 0
        assertTrue("android:allowBackup must be false", !backupAllowed)
    }

    @Test
    fun noBackupAgentDeclared() {
        assertNull(
            "android:backupAgent must not be declared",
            context.applicationInfo.backupAgentName
        )
    }

    /**
     * Asserts data_extraction_rules.xml excludes the ratchet-bearing storage
     * surfaces. The merged manifest's reference to this resource is exercised
     * indirectly: if the attribute were removed, the resource would still
     * compile but stop being applied — caught at code review on diff.
     */
    @Test
    fun dataExtractionRulesExcludeRatchetTables() {
        val parser = context.resources.getXml(R.xml.data_extraction_rules)
        data class Exclude(val domain: String, val path: String, val section: String)
        val excludes = mutableListOf<Exclude>()
        var currentSection = ""
        var event = parser.eventType
        while (event != XmlPullParser.END_DOCUMENT) {
            if (event == XmlPullParser.START_TAG) {
                when (parser.name) {
                    "cloud-backup", "device-transfer" -> currentSection = parser.name
                    "exclude" -> {
                        val domain = parser.getAttributeValue(null, "domain") ?: ""
                        val path = parser.getAttributeValue(null, "path") ?: ""
                        excludes += Exclude(domain, path, currentSection)
                    }
                }
            }
            event = parser.next()
        }
        parser.close()

        val required = listOf(
            "database" to "voicedrop.db",
            "database" to "voicedrop.db-wal",
            "database" to "voicedrop.db-shm",
            "sharedpref" to "voicedrop_keys.xml",
            "file" to "messages/"
        )
        for (section in listOf("cloud-backup", "device-transfer")) {
            for ((domain, path) in required) {
                val hit = excludes.any {
                    it.section == section && it.domain == domain && it.path == path
                }
                assertTrue(
                    "missing <exclude domain=\"$domain\" path=\"$path\"/> in <$section>",
                    hit
                )
            }
        }
        assertEquals(
            "must declare both cloud-backup and device-transfer sections",
            setOf("cloud-backup", "device-transfer"),
            excludes.map { it.section }.toSet()
        )
    }
}
