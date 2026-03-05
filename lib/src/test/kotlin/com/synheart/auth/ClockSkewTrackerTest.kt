package com.synheart.auth

import com.synheart.auth.internal.ClockSkewTracker
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class ClockSkewTrackerTest {
    private lateinit var tracker: ClockSkewTracker

    @BeforeEach
    fun setUp() {
        tracker = ClockSkewTracker()
    }

    @Test
    fun `initial offset is zero`() {
        assertEquals(0.0, tracker.currentOffset(), 0.001)
    }

    @Test
    fun `corrected timestamp returns ISO 8601 format`() {
        val ts = tracker.correctedTimestamp()
        assertTrue(ts.contains("T"))
        assertTrue(ts.endsWith("Z"))
    }

    @Test
    fun `update with positive skew`() {
        val future = System.currentTimeMillis() / 1000.0 + 60.0
        tracker.update(future)
        assertTrue(tracker.currentOffset() > 50.0)
        assertTrue(tracker.currentOffset() < 70.0)
    }

    @Test
    fun `update with negative skew`() {
        val past = System.currentTimeMillis() / 1000.0 - 60.0
        tracker.update(past)
        assertTrue(tracker.currentOffset() < -50.0)
        assertTrue(tracker.currentOffset() > -70.0)
    }

    @Test
    fun `corrected epoch seconds reflects offset`() {
        val now = System.currentTimeMillis() / 1000.0
        val serverTime = now + 100.0
        tracker.update(serverTime)
        val corrected = tracker.correctedEpochSeconds()
        assertTrue(corrected > now + 90.0)
        assertTrue(corrected < now + 110.0)
    }

    @Test
    fun `reset clears offset`() {
        tracker.update(System.currentTimeMillis() / 1000.0 + 100.0)
        assertTrue(tracker.currentOffset() > 90.0)
        tracker.reset()
        assertEquals(0.0, tracker.currentOffset(), 0.001)
    }
}
