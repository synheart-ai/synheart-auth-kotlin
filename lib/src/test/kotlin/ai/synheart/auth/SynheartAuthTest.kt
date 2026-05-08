package ai.synheart.auth

import ai.synheart.auth.crypto.MockKeyManager
import ai.synheart.auth.models.DeviceAuthState
import ai.synheart.auth.models.RegistrationResult
import ai.synheart.auth.models.SynheartAuthError
import ai.synheart.auth.network.ChallengeResponse
import ai.synheart.auth.network.MockAuthNetworkClient
import ai.synheart.auth.network.RegisterResponse
import ai.synheart.auth.network.RotateKeyResponse
import ai.synheart.auth.storage.StorageManager
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class SynheartAuthTest {
    private lateinit var keyManager: MockKeyManager
    private lateinit var storage: StorageManager
    private lateinit var network: MockAuthNetworkClient
    private lateinit var auth: SynheartAuth

    private val appId = "com.test.app"

    @BeforeEach
    fun setUp() {
        keyManager = MockKeyManager()
        storage = StorageManager()
        network = MockAuthNetworkClient()
        auth = SynheartAuth.createForTesting(keyManager, storage, network)

        network.challengeResponse = ChallengeResponse("challenge-abc", "2026-12-31T23:59:59Z")
        network.registerResponse = RegisterResponse("device-xyz-789", "ok")
    }

    @Test
    fun `isRegistered returns false initially`() {
        assertFalse(auth.isRegistered(appId))
    }

    @Test
    fun `register device and check isRegistered`() = runTest {
        val result = auth.registerDevice(appId)
        assertEquals(RegistrationResult.RegistrationStatus.SUCCESS, result.status)
        assertTrue(auth.isRegistered(appId))
        assertEquals("device-xyz-789", auth.getDeviceId(appId))
    }

    @Test
    fun `sign request after registration`() = runTest {
        auth.registerDevice(appId)
        val headers = auth.signRequest(appId, "GET", "/v1/health")
        assertEquals(appId, headers.appId)
        assertEquals("device-xyz-789", headers.deviceId)
        assertTrue(headers.signature.isNotEmpty())
        assertEquals("1", headers.signatureVersion)
    }

    @Test
    fun `sign request with body`() = runTest {
        auth.registerDevice(appId)
        val body = """{"data":"test"}""".toByteArray()
        val headers = auth.signRequest(appId, "POST", "/v1/data", body)
        assertTrue(headers.signature.isNotEmpty())
    }

    @Test
    fun `sign request throws when not registered`() {
        assertThrows(SynheartAuthError.NotRegistered::class.java) {
            auth.signRequest(appId, "GET", "/v1/data")
        }
    }

    @Test
    fun `reset device identity clears everything`() = runTest {
        auth.registerDevice(appId)
        assertTrue(auth.isRegistered(appId))
        auth.resetDeviceIdentity(appId)
        assertFalse(auth.isRegistered(appId))
        assertNull(auth.getDeviceId(appId))
    }

    @Test
    fun `key rotation after registration`() = runTest {
        auth.registerDevice(appId)
        network.rotateKeyResponse = RotateKeyResponse("ok")
        val result = auth.rotateKey(appId)
        assertEquals(ai.synheart.auth.models.RotationResult.RotationStatus.SUCCESS, result.status)
        assertTrue(auth.isRegistered(appId))
    }

    @Test
    fun `multi app isolation`() = runTest {
        val appId2 = "com.test.app2"
        network.registerResponse = RegisterResponse("device-A", "ok")
        auth.registerDevice(appId)

        network.registerResponse = RegisterResponse("device-B", "ok")
        auth.registerDevice(appId2)

        assertEquals("device-A", auth.getDeviceId(appId))
        assertEquals("device-B", auth.getDeviceId(appId2))

        auth.resetDeviceIdentity(appId)
        assertFalse(auth.isRegistered(appId))
        assertTrue(auth.isRegistered(appId2))
    }

    @Test
    fun `clock skew correction`() = runTest {
        auth.registerDevice(appId)
        val futureTimestamp = System.currentTimeMillis() / 1000.0 + 300.0
        auth.correctClockSkew(futureTimestamp)
        val headers = auth.signRequest(appId, "GET", "/v1/data")
        // Timestamp should be corrected
        assertTrue(headers.timestamp.isNotEmpty())
    }

    @Test
    fun `getDeviceId returns null when not registered`() {
        assertNull(auth.getDeviceId(appId))
    }

    @Test
    fun `registration failure does not leave partial state`() = runTest {
        network.shouldFail = SynheartAuthError.NetworkError("Connection refused")
        try {
            auth.registerDevice(appId)
            fail("Should have thrown")
        } catch (e: SynheartAuthError.NetworkError) {
            assertFalse(auth.isRegistered(appId))
            assertNull(auth.getDeviceId(appId))
        }
    }

    @Test
    fun `double registration returns already registered`() = runTest {
        auth.registerDevice(appId)
        val result = auth.registerDevice(appId)
        assertEquals(RegistrationResult.RegistrationStatus.ALREADY_REGISTERED, result.status)
    }

    @Test
    fun `sign request after reset throws`() = runTest {
        auth.registerDevice(appId)
        auth.resetDeviceIdentity(appId)
        assertThrows(SynheartAuthError.NotRegistered::class.java) {
            auth.signRequest(appId, "GET", "/v1/data")
        }
    }
}
