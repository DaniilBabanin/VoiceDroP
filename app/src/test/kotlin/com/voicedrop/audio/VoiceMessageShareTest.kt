package com.voicedrop.audio

import android.app.Application
import android.content.Intent
import android.net.Uri
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class VoiceMessageShareTest {

    private val context: Application = ApplicationProvider.getApplicationContext()

    @Test
    fun shareUriFiresActionSendChooserWithWavMime() {
        val uri = Uri.parse("content://${context.packageName}.fileprovider/share/voicedrop-test.wav")

        VoiceMessageShare.shareUri(context, uri)

        val started = Shadows.shadowOf(context).nextStartedActivity
            ?: error("expected chooser activity to be started")
        assertEquals(Intent.ACTION_CHOOSER, started.action)

        val inner = started.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
            ?: error("chooser missing EXTRA_INTENT")
        assertEquals(Intent.ACTION_SEND, inner.action)
        assertEquals("audio/wav", inner.type)

        val streamUri = inner.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
        assertNotNull("EXTRA_STREAM missing", streamUri)
        assertEquals(uri, streamUri)

        assertTrue(
            "inner intent must grant read URI permission",
            inner.flags and Intent.FLAG_GRANT_READ_URI_PERMISSION != 0
        )
        assertTrue(
            "chooser must propagate read URI grant for the resolver",
            started.flags and Intent.FLAG_GRANT_READ_URI_PERMISSION != 0
        )
        assertTrue(
            "chooser must use NEW_TASK so notification-context launches work",
            started.flags and Intent.FLAG_ACTIVITY_NEW_TASK != 0
        )
    }
}
