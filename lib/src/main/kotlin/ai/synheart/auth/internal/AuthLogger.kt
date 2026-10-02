package ai.synheart.auth.internal

import java.util.logging.Level
import java.util.logging.Logger

internal object AuthLogger {
    private val logger = Logger.getLogger("SynheartAuth")

    var enabled: Boolean = false

    private fun emit(level: Level, tag: String, message: String) {
        if (!enabled) return
        // java.util.logging is not consistently surfaced in Android/Flutter logs.
        // Also print to stdout so it shows up in `flutter run` / logcat (System.out).
        kotlin.io.println("[SynheartAuth][$tag][${level.name}] $message")
        logger.log(level, "[$tag] $message")
    }

    /**
     * A warning that is emitted even when logging is disabled.
     *
     * Reserved for misconfigurations that silently weaken security (a
     * software key or in-memory identity in a production app), which an
     * integrator would otherwise only find in the field.
     */
    fun securityWarning(tag: String, message: String) {
        System.err.println("[SynheartAuth][$tag][WARNING] $message")
        logger.log(Level.WARNING, "[$tag] $message")
    }

    fun debug(tag: String, message: String) {
        emit(Level.FINE, tag, message)
    }

    fun info(tag: String, message: String) {
        emit(Level.INFO, tag, message)
    }

    fun warn(tag: String, message: String) {
        emit(Level.WARNING, tag, message)
    }

    fun error(tag: String, message: String) {
        emit(Level.SEVERE, tag, message)
    }
}
