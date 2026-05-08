package ai.synheart.auth.models

enum class DeviceAuthState(val value: String) {
    UNREGISTERED("unregistered"),
    CHALLENGE_RECEIVED("challengeReceived"),
    KEY_READY("keyReady"),
    REGISTERING("registering"),
    REGISTERED("registered"),
    KEY_INVALID("keyInvalid");

    fun canTransition(to: DeviceAuthState): Boolean = when (this) {
        UNREGISTERED -> to == CHALLENGE_RECEIVED
        CHALLENGE_RECEIVED -> to == KEY_READY
        KEY_READY -> to == REGISTERING
        REGISTERING -> to == REGISTERED || to == UNREGISTERED
        REGISTERED -> to == REGISTERING || to == KEY_INVALID
        KEY_INVALID -> to == UNREGISTERED
    }

    fun transition(to: DeviceAuthState): DeviceAuthState {
        if (!canTransition(to)) {
            throw SynheartAuthError.InvalidStateTransition(this.value, to.value)
        }
        return to
    }

    companion object {
        fun fromValue(value: String): DeviceAuthState? =
            entries.find { it.value == value }
    }
}
