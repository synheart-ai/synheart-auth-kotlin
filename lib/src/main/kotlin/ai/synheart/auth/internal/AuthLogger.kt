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
