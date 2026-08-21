package ai.synheart.auth.models

sealed class SynheartAuthError(message: String, cause: Throwable? = null) : Exception(message, cause) {
    class NetworkError(message: String) : SynheartAuthError(message)
    class ChallengeExpired : SynheartAuthError("Challenge has expired")
    class KeyInvalidated : SynheartAuthError("Signing key has been invalidated")
    class ClockSkew : SynheartAuthError("Client clock is too far from server time")
    class AlreadyRegistered : SynheartAuthError("Device is already registered")
    class NotRegistered : SynheartAuthError("Device is not registered")
    class NotConfigured : SynheartAuthError("SDK has not been configured")
    class RegistrationInProgress : SynheartAuthError("Registration is already in progress")
    class ServerError(val code: String, override val message: String) : SynheartAuthError("Server error [$code]: $message")
    /**
     * Cause is optional but should be supplied when one exists: the
     * underlying Keystore exception carries the only actionable detail, and
     * dropping it left callers with a message and no chain to inspect.
     */
    class CryptoError(message: String, cause: Throwable? = null) :
        SynheartAuthError(message, cause)
    class StorageError(message: String) : SynheartAuthError(message)
    class InvalidStateTransition(val from: String, val to: String) :
        SynheartAuthError("Invalid state transition from $from to $to")
}
