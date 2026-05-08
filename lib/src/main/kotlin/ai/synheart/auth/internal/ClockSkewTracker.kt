package ai.synheart.auth.internal

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
        // Header contract requires Unix timestamp seconds.
        val correctedEpoch = correctedEpochSeconds()
        return correctedEpoch.toLong().toString()
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
