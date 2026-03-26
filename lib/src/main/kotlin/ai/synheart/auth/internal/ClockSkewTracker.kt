package ai.synheart.auth.internal

import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

class ClockSkewTracker {
    @Volatile
    private var offsetSeconds: Double = 0.0

    @Synchronized
    fun update(serverTimestamp: Double) {
        val now = System.currentTimeMillis() / 1000.0
        offsetSeconds = serverTimestamp - now
    }

    @Synchronized
    fun correctedTimestamp(): String {
        val correctedEpoch = System.currentTimeMillis() / 1000.0 + offsetSeconds
        val instant = Instant.ofEpochMilli((correctedEpoch * 1000).toLong())
        return DateTimeFormatter.ISO_INSTANT.format(instant)
    }

    @Synchronized
    fun correctedEpochSeconds(): Double =
        System.currentTimeMillis() / 1000.0 + offsetSeconds

    @Synchronized
    fun currentOffset(): Double = offsetSeconds

    @Synchronized
    fun reset() {
        offsetSeconds = 0.0
    }
}
