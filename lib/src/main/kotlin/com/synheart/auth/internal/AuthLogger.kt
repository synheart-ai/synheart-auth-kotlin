package com.synheart.auth.internal

import java.util.logging.Level
import java.util.logging.Logger

internal object AuthLogger {
    private val logger = Logger.getLogger("SynheartAuth")

    var enabled: Boolean = false

    fun debug(tag: String, message: String) {
        if (enabled) logger.log(Level.FINE, "[$tag] $message")
    }

    fun info(tag: String, message: String) {
        if (enabled) logger.log(Level.INFO, "[$tag] $message")
    }

    fun warn(tag: String, message: String) {
        if (enabled) logger.log(Level.WARNING, "[$tag] $message")
    }

    fun error(tag: String, message: String) {
        if (enabled) logger.log(Level.SEVERE, "[$tag] $message")
    }
}
