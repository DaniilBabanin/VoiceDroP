package com.voicedrop.ui

import org.junit.Assert.assertEquals
import org.junit.Test

class PlaybackBannerSpeedCycleTest {

    @Test
    fun speedCycleMatchesSpec() {
        // Spec §6.3: 1× → 1.5× → 2× → 0.5× → 1×.
        assertEquals(1.5f, PlaybackBanner.nextSpeed(1f))
        assertEquals(2f, PlaybackBanner.nextSpeed(1.5f))
        assertEquals(0.5f, PlaybackBanner.nextSpeed(2f))
        assertEquals(1f, PlaybackBanner.nextSpeed(0.5f))
    }

    @Test
    fun formatSpeedRendersAllStops() {
        assertEquals("0.5×", PlaybackBanner.formatSpeed(0.5f))
        assertEquals("1×", PlaybackBanner.formatSpeed(1f))
        assertEquals("1.5×", PlaybackBanner.formatSpeed(1.5f))
        assertEquals("2×", PlaybackBanner.formatSpeed(2f))
    }
}
