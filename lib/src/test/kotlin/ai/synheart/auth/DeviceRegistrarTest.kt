package ai.synheart.auth

import ai.synheart.auth.crypto.MockKeyManager
import ai.synheart.auth.models.DeviceAuthState
import ai.synheart.auth.models.RegistrationResult
import ai.synheart.auth.models.RotationResult
import ai.synheart.auth.models.SynheartAuthError
import ai.synheart.auth.network.ChallengeResponse
import ai.synheart.auth.network.MockAuthNetworkClient
import ai.synheart.auth.network.RegisterResponse
import ai.synheart.auth.network.RotateKeyResponse
import ai.synheart.auth.registration.DeviceRegistrar
import ai.synheart.auth.storage.StorageManager
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class DeviceRegistrarTest {
    private lateinit var keyManager: MockKeyManager
    private lateinit var storage: StorageManager
    private lateinit var network: MockAuthNetworkClient
    private lateinit var registrar: DeviceRegistrar
    private val appId = "com.test.app"

    @BeforeEach
    fun setUp() {
        keyManager = MockKeyManager()
        storage = StorageManager()
        network = MockAuthNetworkClient()
        registrar = DeviceRegistrar(keyManager, storage, network)

        network.challengeResponse = ChallengeResponse("test-challenge-abc", "2026-12-31T23:59:59Z")
        network.registerResponse = RegisterResponse("device-uuid-123", "ok")
    }

    @Test
    fun `successful registration flow`() = runTest {
        val result = registrar.register(appId)
        assertEquals(RegistrationResult.RegistrationStatus.SUCCESS, result.status)
        assertEquals("device-uuid-123", result.deviceId)
        assertEquals(DeviceAuthState.REGISTERED, storage.loadState(appId))
        assertEquals("device-uuid-123", storage.loadDeviceId(appId))
        assertTrue(keyManager.hasKey(appId))
    }

    @Test
    fun `registration sends correct request`() = runTest {
        registrar.register(appId)
        val req = network.lastRegisterRequest!!
        assertEquals(appId, req.appId)
        assertEquals("test-challenge-abc", req.challenge)
        assertTrue(req.publicKey.isNotEmpty())
        assertNull(req.attestation) // NoOp attestation provider returns null
        assertEquals("Android", req.deviceMetadata.platform)
    }

    @Test
    fun `already registered returns status`() = runTest {
        keyManager.generateKeyPair(appId)
        storage.saveState(DeviceAuthState.REGISTERED, appId)
        storage.saveDeviceId("existing-device", appId)
        // Need to set state through a valid path for the test
        val result = registrar.register(appId)
        assertEquals(RegistrationResult.RegistrationStatus.ALREADY_REGISTERED, result.status)
        assertEquals("existing-device", result.deviceId)
    }

    @Test
    fun `registration in progress throws`() = runTest {
        // A second call while the first is genuinely in flight.
        val gate = kotlinx.coroutines.CompletableDeferred<Unit>()
        val slowNetwork = object : ai.synheart.auth.network.AuthNetworking by network {
            override suspend fun fetchChallenge(appId: String): ChallengeResponse {
                gate.await()
                return network.fetchChallenge(appId)
            }
        }
        val registrar = DeviceRegistrar(keyManager, storage, slowNetwork)
        val first = async { registrar.register(appId) }
        kotlinx.coroutines.yield()
        try {
            registrar.register(appId)
            fail("Should have thrown")
        } catch (_: SynheartAuthError.RegistrationInProgress) {}
        gate.complete(Unit)
        assertEquals(RegistrationResult.RegistrationStatus.SUCCESS, first.await().status)
    }

    @Test
    fun `a persisted REGISTERING state from a dead process does not block registration`() = runTest {
        // 0.1.x only ever kept state in memory, so this could not outlive the
        // process. With persistent storage it can, and used to block forever.
        storage.saveState(DeviceAuthState.REGISTERING, appId)
        keyManager.generateKeyPair(appId) // half-registered key, no device_id
        val result = registrar.register(appId)
        assertEquals(RegistrationResult.RegistrationStatus.SUCCESS, result.status)
        assertEquals("device-uuid-123", storage.loadDeviceId(appId))
    }

    @Test
    fun `an interrupted rotation is recovered, not re-registered`() = runTest {
        storage.saveDeviceId("device-123", appId)
        val active = keyManager.generateKeyPair(appId)
        storage.saveState(DeviceAuthState.REGISTERING, appId) // rotation in progress when the app died
        val result = registrar.register(appId)
        assertEquals(RegistrationResult.RegistrationStatus.ALREADY_REGISTERED, result.status)
        assertEquals("device-123", result.deviceId)
        assertEquals(DeviceAuthState.REGISTERED, storage.loadState(appId))
        assertArrayEquals(active, keyManager.getPublicKey(appId))
        assertNull(network.lastRegisterRequest)
    }

    @Test
    fun `an interrupted rotation can rotate again`() = runTest {
        storage.saveDeviceId("device-123", appId)
        keyManager.generateKeyPair(appId)
        storage.saveState(DeviceAuthState.REGISTERING, appId)
        network.rotateKeyResponse = RotateKeyResponse("ok")
        assertEquals(RotationResult.RotationStatus.SUCCESS, registrar.rotateKey(appId).status)
    }

    @Test
    fun `registered state without a key re-registers`() = runTest {
        // e.g. registration state restored onto a device whose Keystore never
        // had the key. It can never sign, so it must not report registered.
        storage.saveDeviceId("stale-device", appId)
        storage.saveState(DeviceAuthState.REGISTERED, appId)
        val result = registrar.register(appId)
        assertEquals(RegistrationResult.RegistrationStatus.SUCCESS, result.status)
        assertEquals("device-uuid-123", storage.loadDeviceId(appId))
        assertTrue(keyManager.hasKey(appId))
    }

    @Test
    fun `network failure cleans up`() = runTest {
        network.shouldFail = SynheartAuthError.NetworkError("Connection refused")
        try {
            registrar.register(appId)
            fail("Should have thrown")
        } catch (e: SynheartAuthError.NetworkError) {
            assertEquals(DeviceAuthState.UNREGISTERED, storage.loadState(appId))
            assertNull(storage.loadDeviceId(appId))
        }
    }

    @Test
    fun `successful key rotation`() = runTest {
        // Set up registered state
        storage.saveDeviceId("device-123", appId)
        keyManager.generateKeyPair(appId)
        storage.saveState(DeviceAuthState.CHALLENGE_RECEIVED, appId)
        storage.saveState(DeviceAuthState.KEY_READY, appId)
        storage.saveState(DeviceAuthState.REGISTERING, appId)
        storage.saveState(DeviceAuthState.REGISTERED, appId)

        network.rotateKeyResponse = RotateKeyResponse("ok")
        val result = registrar.rotateKey(appId)
        assertEquals(RotationResult.RotationStatus.SUCCESS, result.status)
        assertEquals(DeviceAuthState.REGISTERED, storage.loadState(appId))
    }

    @Test
    fun `key rotation fails when not registered`() = runTest {
        assertThrows(SynheartAuthError.NotRegistered::class.java) {
            kotlinx.coroutines.test.runTest { registrar.rotateKey(appId) }
        }
    }

    @Test
    fun `key rotation sends correct request`() = runTest {
        storage.saveDeviceId("device-123", appId)
        keyManager.generateKeyPair(appId)
        storage.saveState(DeviceAuthState.CHALLENGE_RECEIVED, appId)
        storage.saveState(DeviceAuthState.KEY_READY, appId)
        storage.saveState(DeviceAuthState.REGISTERING, appId)
        storage.saveState(DeviceAuthState.REGISTERED, appId)

        network.rotateKeyResponse = RotateKeyResponse("ok")
        registrar.rotateKey(appId)

        val req = network.lastRotateKeyRequest!!
        assertEquals(appId, req.appId)
        assertEquals("device-123", req.deviceId)
        assertTrue(req.newPublicKey.isNotEmpty())
        assertTrue(req.oldKeySignature.isNotEmpty())
    }

    @Test
    fun `key rotation network failure restores state`() = runTest {
        storage.saveDeviceId("device-123", appId)
        keyManager.generateKeyPair(appId)
        storage.saveState(DeviceAuthState.CHALLENGE_RECEIVED, appId)
        storage.saveState(DeviceAuthState.KEY_READY, appId)
        storage.saveState(DeviceAuthState.REGISTERING, appId)
        storage.saveState(DeviceAuthState.REGISTERED, appId)

        network.shouldFail = SynheartAuthError.NetworkError("timeout")
        try {
            registrar.rotateKey(appId)
            fail("Should have thrown")
        } catch (e: SynheartAuthError.NetworkError) {
            assertEquals(DeviceAuthState.REGISTERED, storage.loadState(appId))
            assertTrue(keyManager.hasKey(appId))
        }
    }

    @Test
    fun `a local promotion failure after the server accepted keeps the new key`() = runTest {
        // Once the server holds the new key, deleting it locally would strand
        // the device: the old key is no longer accepted and the new one is gone.
        var nextDeleted = false
        val failingPromote = object : ai.synheart.auth.crypto.KeyManaging by keyManager {
            override fun promoteNextKey(appId: String) =
                throw SynheartAuthError.CryptoError("promote failed")
            override fun deleteNextKey(appId: String) { nextDeleted = true }
        }
        val registrar = DeviceRegistrar(failingPromote, storage, network)
        storage.saveDeviceId("device-123", appId)
        keyManager.generateKeyPair(appId)
        storage.saveState(DeviceAuthState.REGISTERED, appId)
        network.rotateKeyResponse = RotateKeyResponse("ok")

        assertThrows(SynheartAuthError.CryptoError::class.java) {
            kotlinx.coroutines.test.runTest { registrar.rotateKey(appId) }
        }
        assertFalse(nextDeleted, "the server-accepted key must not be deleted")
    }

    @Test
    fun `a rejected rotation deletes the pending key`() = runTest {
        storage.saveDeviceId("device-123", appId)
        val active = keyManager.generateKeyPair(appId)
        storage.saveState(DeviceAuthState.REGISTERED, appId)
        network.rotateKeyResponse = RotateKeyResponse("rejected")

        assertThrows(SynheartAuthError.ServerError::class.java) {
            kotlinx.coroutines.test.runTest { registrar.rotateKey(appId) }
        }
        assertArrayEquals(active, keyManager.getPublicKey(appId))
        assertThrows(SynheartAuthError.CryptoError::class.java) { keyManager.promoteNextKey(appId) }
    }
}
