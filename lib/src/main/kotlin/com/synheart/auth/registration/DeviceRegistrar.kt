package com.synheart.auth.registration

import com.synheart.auth.crypto.KeyManaging
import com.synheart.auth.internal.AuthLogger
import com.synheart.auth.models.*
import com.synheart.auth.network.*
import com.synheart.auth.storage.StorageManaging
import java.util.Base64

class DeviceRegistrar(
    private val keyManager: KeyManaging,
    private val storage: StorageManaging,
    private val network: AuthNetworking
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

            // Step 3: Attestation (skipped on Android — Play Integrity is a future RFC)
            val attestation: String? = null

            // Step 4: Register with server
            storage.saveState(DeviceAuthState.REGISTERING, appId)
            val publicKeyBase64 = Base64.getEncoder().encodeToString(publicKeyBytes)
            val request = RegisterRequest(
                appId = appId,
                challenge = challengeResponse.challenge,
                publicKey = publicKeyBase64,
                attestation = attestation,
                deviceMetadata = DeviceMetadata()
            )
            AuthLogger.debug(tag, "Registering with server")
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
            // Generate new key pair
            val newPublicKeyBytes = keyManager.generateNextKeyPair(appId)
            val newPublicKeyBase64 = Base64.getEncoder().encodeToString(newPublicKeyBytes)

            // Sign new public key with old key (proof of possession)
            val oldKeySignatureBytes = keyManager.sign(newPublicKeyBytes, appId)
            val oldKeySignatureBase64 = Base64.getEncoder().encodeToString(oldKeySignatureBytes)

            // Transition to registering state
            storage.saveState(DeviceAuthState.REGISTERING, appId)

            // Send rotation request
            val request = RotateKeyRequest(
                appId = appId,
                deviceId = deviceId,
                newPublicKey = newPublicKeyBase64,
                oldKeySignature = oldKeySignatureBase64
            )
            AuthLogger.debug(tag, "Rotating key with server")
            val response = network.rotateKey(request)

            // Verify server response
            if (response.status != "ok" && response.status != "success") {
                throw SynheartAuthError.ServerError("ROTATION_FAILED", "Server returned: ${response.status}")
            }

            // Atomic promotion
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
}
