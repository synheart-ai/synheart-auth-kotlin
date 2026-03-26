package ai.synheart.auth.registration

import ai.synheart.auth.crypto.KeyManaging
import ai.synheart.auth.internal.AuthLogger
import ai.synheart.auth.models.*
import ai.synheart.auth.network.*
import ai.synheart.auth.storage.StorageManaging
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID

class DeviceRegistrar(
    private val keyManager: KeyManaging,
    private val storage: StorageManaging,
    private val network: AuthNetworking,
    private val attestationProvider: AttestationProvider = NoOpAttestationProvider()
) {
    private val tag = "DeviceRegistrar"

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

        try {
            // Step 1: Fetch challenge
            AuthLogger.debug(tag, "Fetching challenge")
            val challengeResponse = network.fetchChallenge(appId)
            storage.saveState(DeviceAuthState.CHALLENGE_RECEIVED, appId)

            // Step 2: Generate key pair
            AuthLogger.debug(tag, "Generating key pair")
            val publicKeyBytes = keyManager.generateKeyPair(appId)
            storage.saveState(DeviceAuthState.KEY_READY, appId)

            // Step 3: Compute nonce and generate attestation proof
            val publicKeyBase64 = Base64.getEncoder().encodeToString(publicKeyBytes)
            val nonce = computeNonce(challengeResponse.challenge, publicKeyBase64)
            val deviceId = storage.loadDeviceId(appId) ?: UUID.randomUUID().toString()

            AuthLogger.debug(tag, "Requesting attestation proof")
            val proof = attestationProvider.generateProof(nonce) ?: "none"

            // Step 4: Register with server
            storage.saveState(DeviceAuthState.REGISTERING, appId)
            val request = RegisterRequest(
                appId = appId,
                deviceId = deviceId,
                challenge = challengeResponse.challenge,
                publicKey = publicKeyBase64,
                platform = "android",
                proof = proof
            )
            AuthLogger.debug(tag, "Registering with server (proof=${if (proof == "none") "none" else "${proof.length} chars"})")
            val response = network.registerDevice(request)

            // Step 5: Store device ID
            storage.saveDeviceId(response.deviceId, appId)
            storage.saveState(DeviceAuthState.REGISTERED, appId)

            // Step 6: Return result
            AuthLogger.info(tag, "Registration successful: ${response.deviceId}")
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
        }
    }

    suspend fun rotateKey(appId: String): RotationResult {
        val currentState = storage.loadState(appId)
        if (currentState != DeviceAuthState.REGISTERED) {
            throw SynheartAuthError.NotRegistered()
        }
        val deviceId = storage.loadDeviceId(appId)
            ?: throw SynheartAuthError.NotRegistered()

        try {
            val newPublicKeyBytes = keyManager.generateNextKeyPair(appId)
            val newPublicKeyBase64 = Base64.getEncoder().encodeToString(newPublicKeyBytes)

            val oldKeySignatureBytes = keyManager.sign(newPublicKeyBytes, appId)
            val oldKeySignatureBase64 = Base64.getEncoder().encodeToString(oldKeySignatureBytes)

            storage.saveState(DeviceAuthState.REGISTERING, appId)

            val request = RotateKeyRequest(
                appId = appId,
                deviceId = deviceId,
                newPublicKey = newPublicKeyBase64,
                oldKeySignature = oldKeySignatureBase64
            )
            AuthLogger.debug(tag, "Rotating key with server")
            val response = network.rotateKey(request)

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
        }
    }

    private fun cleanup(appId: String) {
        try { keyManager.deleteKey(appId) } catch (_: Exception) {}
        try { storage.deleteAll(appId) } catch (_: Exception) {}
    }

    /// nonce = SHA256(challenge + public_key) per attestation flow spec
    /// Play Integrity requires URL-safe base64 without padding
    private fun computeNonce(challenge: String, publicKey: String): String {
        val input = challenge + publicKey
        val digest = MessageDigest.getInstance("SHA-256").digest(input.toByteArray())
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }
}
