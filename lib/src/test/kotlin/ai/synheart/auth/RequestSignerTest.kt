package ai.synheart.auth

import ai.synheart.auth.crypto.MockKeyManager
import ai.synheart.auth.crypto.RequestSigner
import ai.synheart.auth.internal.ClockSkewTracker
import ai.synheart.auth.models.DeviceAuthState
import ai.synheart.auth.models.SynheartAuthError
import ai.synheart.auth.storage.StorageManager
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.Base64

class RequestSignerTest {
    private lateinit var keyManager: MockKeyManager
    private lateinit var storage: StorageManager
    private lateinit var clockSkew: ClockSkewTracker
    private lateinit var signer: RequestSigner
    private val appId = "com.test.app"

    @BeforeEach
    fun setUp() {
        keyManager = MockKeyManager()
        storage = StorageManager()
        clockSkew = ClockSkewTracker()
        signer = RequestSigner(keyManager, storage, clockSkew)

        // Set up registered state
        keyManager.generateKeyPair(appId)
        storage.saveDeviceId("device-123", appId)
        storage.saveState(DeviceAuthState.REGISTERED, appId)
    }

    @Test
    fun `canonical message format`() {
        val msg = RequestSigner.buildMessage("POST", "/v1/data", "2026-01-01T00:00:00Z", null)
        val expected = "POST\n/v1/data\n2026-01-01T00:00:00Z\n"
        assertEquals(expected, String(msg, Charsets.UTF_8))
    }

    @Test
    fun `canonical message with body`() {
        val body = """{"key":"value"}""".toByteArray()
        val msg = RequestSigner.buildMessage("POST", "/v1/data", "2026-01-01T00:00:00Z", body)
        val expected = "POST\n/v1/data\n2026-01-01T00:00:00Z\n{\"key\":\"value\"}"
        assertEquals(expected, String(msg, Charsets.UTF_8))
    }

    @Test
    fun `method is uppercased`() {
        val msg = RequestSigner.buildMessage("get", "/v1/data", "2026-01-01T00:00:00Z", null)
        assertTrue(String(msg, Charsets.UTF_8).startsWith("GET\n"))
    }

    @Test
    fun `sign returns all 6 headers`() {
        val headers = signer.sign(appId, "GET", "/v1/data")
        assertEquals(appId, headers.appId)
        assertEquals("device-123", headers.deviceId)
        assertTrue(headers.signature.isNotEmpty())
        assertTrue(headers.timestamp.isNotEmpty())
        assertTrue(headers.nonce.isNotEmpty())
        assertEquals("1", headers.signatureVersion)
    }

    @Test
    fun `toMap returns 6 header entries`() {
        val headers = signer.sign(appId, "GET", "/v1/data")
        val map = headers.toMap()
        assertEquals(6, map.size)
        assertNotNull(map["X-App-ID"])
        assertNotNull(map["X-Device-ID"])
        assertNotNull(map["X-Synheart-Signature"])
        assertNotNull(map["X-Synheart-Timestamp"])
        assertNotNull(map["X-Synheart-Nonce"])
        assertNotNull(map["X-Synheart-Sig-Version"])
    }

    @Test
    fun `signature is valid base64`() {
        val headers = signer.sign(appId, "GET", "/v1/data")
        val decoded = Base64.getDecoder().decode(headers.signature)
        assertTrue(decoded.isNotEmpty())
    }

    @Test
    fun `signature verifies with key manager`() {
        val headers = signer.sign(appId, "POST", "/v1/data", """{"test":1}""".toByteArray())
        val signatureBytes = Base64.getDecoder().decode(headers.signature)
        val message = RequestSigner.buildMessage("POST", "/v1/data", headers.timestamp, """{"test":1}""".toByteArray())
        assertTrue(keyManager.verify(message, signatureBytes, appId))
    }

    @Test
    fun `nonce is unique per call`() {
        val h1 = signer.sign(appId, "GET", "/v1/data")
        val h2 = signer.sign(appId, "GET", "/v1/data")
        assertNotEquals(h1.nonce, h2.nonce)
    }

    @Test
    fun `sign throws when not registered`() {
        val freshStorage = StorageManager()
        val freshSigner = RequestSigner(keyManager, freshStorage, clockSkew)
        assertThrows(SynheartAuthError.NotRegistered::class.java) {
            freshSigner.sign(appId, "GET", "/v1/data")
        }
    }
}
