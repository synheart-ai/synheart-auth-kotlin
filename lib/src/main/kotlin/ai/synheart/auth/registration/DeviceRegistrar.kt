package ai.synheart.auth.registration

import ai.synheart.auth.crypto.KeyManaging
import ai.synheart.auth.internal.AuthLogger
import ai.synheart.auth.models.*
import ai.synheart.auth.network.*
import ai.synheart.auth.storage.StorageManaging
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.security.MessageDigest
import java.util.Base64
import kotlin.math.min
import kotlin.math.pow
import kotlin.random.Random

class DeviceRegistrar(
    private val keyManager: KeyManaging,
    private val storage: StorageManaging,
    private val network: AuthNetworking,
    private val attestationProvider: AttestationProvider = NoOpAttestationProvider()
) {
    private val tag = "DeviceRegistrar"

    /**
     * In-flight register/rotate appIds. Provides an atomic test-and-set so two
     * concurrent calls for the same appId can't both proceed past the state guard.
     */
    private val inFlightLock = Any()
    private val inFlight = mutableSetOf<String>()

    private fun claim(appId: String): Boolean = synchronized(inFlightLock) {
        if (inFlight.contains(appId)) false else { inFlight.add(appId); true }
    }

    private fun release(appId: String) = synchronized(inFlightLock) {
        inFlight.remove(appId)
    }

    suspend fun register(appId: String): RegistrationResult {
        val currentState = storage.loadState(appId)
        if (currentState == DeviceAuthState.REGISTERED) {
            return RegistrationResult(
                status = RegistrationResult.RegistrationStatus.ALREADY_REGISTERED,
                deviceId = storage.loadDeviceId(appId)
            )
        }
        if (currentState == DeviceAuthState.REGISTERING) {
            throw SynheartAuthError.RegistrationInProgress()
        }

        if (!claim(appId)) {
            throw SynheartAuthError.RegistrationInProgress()
        }

        try {
            // Step 1: Fetch challenge (with retry)
            AuthLogger.debug(tag, "Fetching challenge")
            val challengeResponse = withRetry { network.fetchChallenge(appId) }
            storage.saveState(DeviceAuthState.CHALLENGE_RECEIVED, appId)
            AuthLogger.debug(
                tag,
                "Challenge received: challenge=${challengeResponse.challenge} expiresAt=${challengeResponse.expiresAt}"
            )

            // Step 2: Generate key pair.
            //
            // `KeyManaging.generateKeyPair` is a synchronous (non-suspend)
            // call into Android Keystore. On API 28+ devices with StrongBox
            // hardware, the first key generation can take 1–2 s — long
            // enough to trip the ANR watchdog if it happens on the UI
            // thread. We don't fully control which thread the FFI runtime
            // hands us, so be defensive and dispatch the blocking call to
            // `Dispatchers.IO` explicitly.
            AuthLogger.debug(tag, "Generating key pair")
            val publicKeyBytes = withContext(Dispatchers.IO) {
                keyManager.generateKeyPair(appId)
            }
            storage.saveState(DeviceAuthState.KEY_READY, appId)

            // Step 3: Compute nonce and generate attestation proof
            val publicKeyBase64 = Base64.getEncoder().encodeToString(publicKeyBytes)
            // Per RFC-AUTH-MOBILE-0001 §13, public key material must not be logged in prod.
            AuthLogger.debug(tag, "Public key generated: bytes=${publicKeyBytes.size}")
            val nonce = computeNonce(challengeResponse.challenge, publicKeyBase64)


            AuthLogger.debug(tag, "Requesting attestation token")
            val attestation = attestationProvider.generateProof(nonce)

            // Validate challenge hasn't expired before registering (90s TTL per RFC)
            if (challengeResponse.isExpired) {
                throw SynheartAuthError.ChallengeExpired()
            }

            // Step 4: Register with server
            storage.saveState(DeviceAuthState.REGISTERING, appId)
            val request = RegisterRequest(
                appId = appId,
                challenge = challengeResponse.challenge,
                publicKey = publicKeyBase64,
                attestation = attestation,
                deviceMetadata = DeviceMetadata(platform = "Android")
            )
            AuthLogger.debug(
                tag,
                "Registering with server (attestation=${if (attestation == null) "none" else "${attestation.length} chars"})",
            )
            val response = network.registerDevice(request)

            // Step 5: Store device ID
            storage.saveDeviceId(response.deviceId, appId)
            storage.saveState(DeviceAuthState.REGISTERED, appId)

            // Step 6: Return result
            // Per RFC-AUTH-MOBILE-0001 §13, device_id is logged truncated.
            AuthLogger.info(tag, "Registration successful: ${response.deviceId.take(8)}…")
            return RegistrationResult(
                status = RegistrationResult.RegistrationStatus.SUCCESS,
                deviceId = response.deviceId
            )
        } catch (e: SynheartAuthError) {
            AuthLogger.error(tag, "Registration failed: ${e.message}")
            cleanup(appId)
            throw e
        } catch (e: Exception) {
            AuthLogger.error(tag, "Registration failed: ${e.message}")
            cleanup(appId)
            throw SynheartAuthError.NetworkError(e.message ?: "Unknown error")
        } finally {
            release(appId)
        }
    }

    suspend fun rotateKey(appId: String): RotationResult {
        val currentState = storage.loadState(appId)
        if (currentState != DeviceAuthState.REGISTERED) {
            throw SynheartAuthError.NotRegistered()
        }
        val deviceId = storage.loadDeviceId(appId)
            ?: throw SynheartAuthError.NotRegistered()

        if (!claim(appId)) {
            throw SynheartAuthError.RegistrationInProgress()
        }

        try {
            // Same threading discipline as `register()` — Keystore key
            // generation and signing are synchronous calls that may block
            // for hundreds of ms (and seconds for StrongBox-backed keys).
            // Force them onto `Dispatchers.IO` so a rotate triggered from
            // a UI-thread coroutine doesn't park the main thread.
            val newPublicKeyBytes = withContext(Dispatchers.IO) {
                keyManager.generateNextKeyPair(appId)
            }
            val newPublicKeyBase64 = Base64.getEncoder().encodeToString(newPublicKeyBytes)

            val oldKeySignatureBytes = withContext(Dispatchers.IO) {
                keyManager.sign(newPublicKeyBytes, appId)
            }
            val oldKeySignatureBase64 = Base64.getEncoder().encodeToString(oldKeySignatureBytes)

            storage.saveState(DeviceAuthState.REGISTERING, appId)

            val request = RotateKeyRequest(
                appId = appId,
                deviceId = deviceId,
                newPublicKey = newPublicKeyBase64,
                oldKeySignature = oldKeySignatureBase64
            )
            AuthLogger.debug(tag, "Rotating key with server")
            val response = withRetry { network.rotateKey(request) }

            if (response.status != "ok" && response.status != "success") {
                throw SynheartAuthError.ServerError("ROTATION_FAILED", "Server returned: ${response.status}")
            }

            keyManager.promoteNextKey(appId)
            storage.saveState(DeviceAuthState.REGISTERED, appId)

            AuthLogger.info(tag, "Key rotation successful")
            return RotationResult(status = RotationResult.RotationStatus.SUCCESS)
        } catch (e: SynheartAuthError) {
            AuthLogger.error(tag, "Key rotation failed: ${e.message}")
            try { keyManager.deleteNextKey(appId) } catch (_: Exception) {}
            try { storage.saveState(DeviceAuthState.REGISTERED, appId) } catch (_: Exception) {}
            throw e
        } catch (e: Exception) {
            AuthLogger.error(tag, "Key rotation failed: ${e.message}")
            try { keyManager.deleteNextKey(appId) } catch (_: Exception) {}
            try { storage.saveState(DeviceAuthState.REGISTERED, appId) } catch (_: Exception) {}
            throw SynheartAuthError.NetworkError(e.message ?: "Unknown error")
        } finally {
            release(appId)
        }
    }

    private fun cleanup(appId: String) {
        try { keyManager.deleteKey(appId) } catch (_: Exception) {}
        try { storage.deleteAll(appId) } catch (_: Exception) {}
    }

    /**
     * Retry an async operation with exponential backoff and jitter.
     * Per RFC-AUTH-MOBILE-0001 §12: base 1s, jitter 500ms, max 30s, max 5 attempts.
     */
    private suspend fun <T> withRetry(maxAttempts: Int = 5, operation: suspend () -> T): T {
        var lastError: Exception? = null
        for (attempt in 0 until maxAttempts) {
            try {
                return operation()
            } catch (e: Exception) {
                lastError = e
                // Don't retry non-transient errors
                when (e) {
                    is SynheartAuthError.ChallengeExpired,
                    is SynheartAuthError.NotRegistered,
                    is SynheartAuthError.NotConfigured,
                    is SynheartAuthError.AlreadyRegistered,
                    is SynheartAuthError.RegistrationInProgress,
                    is SynheartAuthError.InvalidStateTransition,
                    is SynheartAuthError.KeyInvalidated -> throw e
                    is SynheartAuthError.ServerError -> {
                        if (e.code.startsWith("4")) throw e // 4xx = client error
                    }
                    else -> {} // Retryable
                }

                if (attempt < maxAttempts - 1) {
                    val baseDelay = 1000.0 * 2.0.pow(attempt)
                    val jitter = Random.nextLong(0, 500)
                    val delayMs = min(baseDelay.toLong() + jitter, 30_000L)
                    AuthLogger.info(tag, "Retry ${attempt + 1}/${maxAttempts - 1} after ${delayMs}ms")
                    delay(delayMs)
                }
            }
        }
        throw lastError!!
    }

    /// nonce = SHA256(challenge + public_key) per attestation flow spec
    /// Play Integrity requires URL-safe base64 without padding
    private fun computeNonce(challenge: String, publicKey: String): String {
        val input = challenge + publicKey
        val digest = MessageDigest.getInstance("SHA-256").digest(input.toByteArray())
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }
}
