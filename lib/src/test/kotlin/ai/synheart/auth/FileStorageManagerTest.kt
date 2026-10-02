package ai.synheart.auth

import ai.synheart.auth.crypto.MockKeyManager
import ai.synheart.auth.models.DeviceAuthState
import ai.synheart.auth.models.RegistrationResult
import ai.synheart.auth.network.ChallengeResponse
import ai.synheart.auth.network.MockAuthNetworkClient
import ai.synheart.auth.network.RegisterResponse
import ai.synheart.auth.network.RotateKeyResponse
import ai.synheart.auth.storage.FileStorageManager
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.util.Base64

/**
 * Guards persistence of registration state.
 *
 * The bug these exist for: `SynheartAuth.initialize` could not take a storage
 * implementation, so `device_id` and registration state lived in memory and
 * were lost on every process restart — the device re-registered as a new
 * identity on each launch.
 */
class FileStorageManagerTest {
    private val appId = "com.test.app"

    @TempDir
    lateinit var dir: File

    @Test
    fun `state survives re-creating the storage`() {
        FileStorageManager(dir).apply {
            saveDeviceId("device-123", appId)
            saveState(DeviceAuthState.REGISTERED, appId)
            saveMetadata(mapOf("k" to "v"), appId)
        }
        val reopened = FileStorageManager(dir)
        assertEquals("device-123", reopened.loadDeviceId(appId))
        assertEquals(DeviceAuthState.REGISTERED, reopened.loadState(appId))
        assertEquals(mapOf("k" to "v"), reopened.loadMetadata(appId))
    }

    @Test
    fun `empty storage reports unregistered`() {
        val storage = FileStorageManager(File(dir, "does/not/exist/yet"))
        assertNull(storage.loadDeviceId(appId))
        assertEquals(DeviceAuthState.UNREGISTERED, storage.loadState(appId))
        assertNull(storage.loadMetadata(appId))
    }

    @Test
    fun `deleteAll is persisted`() {
        FileStorageManager(dir).apply {
            saveDeviceId("device-123", appId)
            saveState(DeviceAuthState.REGISTERED, appId)
            deleteAll(appId)
        }
        val reopened = FileStorageManager(dir)
        assertNull(reopened.loadDeviceId(appId))
        assertEquals(DeviceAuthState.UNREGISTERED, reopened.loadState(appId))
    }

    @Test
    fun `app ids are isolated, including ones that look like paths`() {
        val tricky = "../../etc/passwd"
        FileStorageManager(dir).apply {
            saveDeviceId("A", appId)
            saveDeviceId("B", tricky)
            saveDeviceId("C", "${appId}_next")
            deleteAll(appId)
        }
        val reopened = FileStorageManager(dir)
        assertNull(reopened.loadDeviceId(appId))
        assertEquals("B", reopened.loadDeviceId(tricky))
        assertEquals("C", reopened.loadDeviceId("${appId}_next"))
        // Every file stays inside the directory.
        assertTrue(dir.listFiles()!!.all { it.parentFile.canonicalPath == dir.canonicalPath })
    }

    @Test
    fun `a corrupt file reads as unregistered instead of failing`() {
        FileStorageManager(dir).saveDeviceId("device-123", appId)
        dir.listFiles()!!.single().writeBytes(byteArrayOf(0x5c, 0x75, 0x5a)) // "\uZ": invalid escape
        val reopened = FileStorageManager(dir)
        assertEquals(DeviceAuthState.UNREGISTERED, reopened.loadState(appId))
        reopened.saveDeviceId("device-456", appId) // and it can be overwritten
        assertEquals("device-456", FileStorageManager(dir).loadDeviceId(appId))
    }

    @Test
    fun `no temp files are left behind`() {
        val storage = FileStorageManager(dir)
        repeat(5) { storage.saveState(DeviceAuthState.REGISTERED, appId) }
        assertEquals(1, dir.listFiles()!!.size, dir.listFiles()!!.joinToString { it.name })
    }

    @Test
    fun `registration survives re-creating the SDK with the same storage, and no key material is written`() = runTest {
        val keyStore = FakeKeyStore() // the Keystore outlives the process
        val network = MockAuthNetworkClient().apply {
            challengeResponse = ChallengeResponse("challenge", "2099-12-31T23:59:59Z")
            registerResponse = RegisterResponse("device-xyz", "ok")
            rotateKeyResponse = RotateKeyResponse("ok")
        }
        val first = SynheartAuth.createForTesting(fakeHardwareKeyManager(keyStore), FileStorageManager(dir), network)
        first.registerDevice(appId)
        first.rotateKey(appId)
        val registeredKey = network.lastRotateKeyRequest!!.newPublicKey

        // "Process restart": fresh SDK, fresh key manager and storage objects.
        val second = SynheartAuth.createForTesting(fakeHardwareKeyManager(keyStore), FileStorageManager(dir), network)
        assertTrue(second.isRegistered(appId))
        assertEquals("device-xyz", second.getDeviceId(appId))
        val again = second.registerDevice(appId)
        assertEquals(RegistrationResult.RegistrationStatus.ALREADY_REGISTERED, again.status)

        val headers = second.signRequest(appId, "GET", "/v1/data")
        val message = ai.synheart.auth.crypto.RequestSigner.buildMessage("GET", "/v1/data", headers.timestamp)
        assertTrue(
            verifyEs256(Base64.getDecoder().decode(registeredKey), message, Base64.getDecoder().decode(headers.signature))
        )

        val persisted = dir.listFiles()!!.joinToString("\n") { it.readText() }
        assertFalse(persisted.contains(registeredKey), "public key must not be persisted")
        assertFalse(persisted.contains("PRIVATE", ignoreCase = true))
        val keys = persisted.lines().filter { it.isNotBlank() && !it.startsWith("#") }.map { it.substringBefore('=') }
        assertEquals(setOf("app_id", "device_id", "state"), keys.toSet())
    }

    @Test
    fun `in-memory storage still loses state, as documented`() = runTest {
        val km = MockKeyManager()
        val network = MockAuthNetworkClient().apply {
            challengeResponse = ChallengeResponse("challenge", "2099-12-31T23:59:59Z")
            registerResponse = RegisterResponse("device-xyz", "ok")
        }
        SynheartAuth.createForTesting(km, ai.synheart.auth.storage.StorageManager(), network).registerDevice(appId)
        val restarted = SynheartAuth.createForTesting(km, ai.synheart.auth.storage.StorageManager(), network)
        assertFalse(restarted.isRegistered(appId))
    }
}
