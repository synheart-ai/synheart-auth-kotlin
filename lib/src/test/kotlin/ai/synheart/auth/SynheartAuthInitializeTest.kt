package ai.synheart.auth

import ai.synheart.auth.crypto.MockKeyManager
import ai.synheart.auth.crypto.SoftwareKeyManager
import ai.synheart.auth.models.DeviceAuthState
import ai.synheart.auth.models.RegistrationResult
import ai.synheart.auth.storage.FileStorageManager
import ai.synheart.auth.storage.StorageManager
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

/**
 * Guards the setup paths of the shared instance.
 *
 * The bug these exist for: the only supported setup was
 * `initialize(keyManager)`, which always used in-memory storage, and skipping
 * it silently ran the SDK on an in-memory software key. The safe path —
 * Keystore key, persistent state — was not reachable through the public API.
 */
class SynheartAuthInitializeTest {
    private val appId = "com.test.app"

    @TempDir
    lateinit var dir: File

    /** Shape of an Android Context as far as the SDK uses it (resolved reflectively). */
    @Suppress("unused")
    class FakeContext(private val noBackup: File?, private val files: File) {
        fun getApplicationContext(): Any = this
        fun getNoBackupFilesDir(): File? = noBackup
        fun getFilesDir(): File = files
    }

    @AfterEach
    fun restoreShared() {
        SynheartAuth.initialize(SoftwareKeyManager(), StorageManager())
    }

    @Test
    fun `initialize(context) persists state in the no-backup directory`() {
        val noBackup = File(dir, "no_backup")
        val store = FakeKeyStore()
        SynheartAuth.initialize(FakeContext(noBackup, File(dir, "files"))) { fakeHardwareKeyManager(store) }

        // State written by a previous process is visible...
        FileStorageManager(File(noBackup, SynheartAuth.STORAGE_DIRECTORY_NAME)).apply {
            saveDeviceId("device-from-last-launch", appId)
            saveState(DeviceAuthState.REGISTERED, appId)
        }
        SynheartAuth.initialize(FakeContext(noBackup, File(dir, "files"))) { fakeHardwareKeyManager(store) }
        assertEquals("device-from-last-launch", SynheartAuth.shared.getDeviceId(appId))
        // ...and the key presence check uses the Keystore-backed manager.
        assertFalse(SynheartAuth.shared.isRegistered(appId))
        store.generate("synheart_auth_$appId")
        assertTrue(SynheartAuth.shared.isRegistered(appId))
        assertFalse(File(dir, "files").exists(), "must not fall back to the backed-up files dir")
    }

    @Test
    fun `initialize(context) falls back to filesDir below API 21`() {
        val files = File(dir, "files")
        assertEquals(File(files, "").canonicalFile, SynheartAuth.noBackupFilesDir(FakeContext(null, files)).canonicalFile)
    }

    @Test
    fun `initialize(context) rejects something that is not a Context`() {
        assertThrows(IllegalArgumentException::class.java) { SynheartAuth.initialize("not a context") }
    }

    @Test
    fun `initialize(context) uses the Android Keystore`() {
        // There is no AndroidKeyStore provider on the JVM, so the production
        // overload must fail here rather than quietly fall back to software.
        val error = assertThrows(Exception::class.java) {
            SynheartAuth.initialize(FakeContext(File(dir, "nb"), File(dir, "files")))
        }
        assertTrue(error is java.security.KeyStoreException, "got $error")
    }

    @Test
    fun `initialize after configure rebuilds the registrar with the new components`() = runTest {
        SynheartAuth.shared.configure("http://127.0.0.1:9") // nothing listens; must not be contacted
        val km = MockKeyManager().apply { generateKeyPair(appId) }
        val storage = StorageManager().apply {
            saveDeviceId("device-123", appId)
            saveState(DeviceAuthState.REGISTERED, appId)
        }
        SynheartAuth.initialize(km, storage)
        val result = SynheartAuth.shared.registerDevice(appId)
        assertEquals(RegistrationResult.RegistrationStatus.ALREADY_REGISTERED, result.status)
        assertEquals("device-123", result.deviceId)
    }

    @Test
    fun `software key and in-memory storage warn on Android`() {
        val warnings = SynheartAuth.insecureDefaultWarnings(SoftwareKeyManager(), StorageManager(), isAndroid = true)
        assertEquals(2, warnings.size)
        assertTrue(warnings[0].contains("SoftwareKeyManager"))
        assertTrue(warnings[1].contains("in-memory"))
    }

    @Test
    fun `the production setup does not warn`() {
        val warnings = SynheartAuth.insecureDefaultWarnings(
            fakeHardwareKeyManager(), FileStorageManager(dir), isAndroid = true,
        )
        assertTrue(warnings.isEmpty(), "$warnings")
    }

    @Test
    fun `JVM tests are not warned about software defaults`() {
        assertTrue(SynheartAuth.insecureDefaultWarnings(SoftwareKeyManager(), StorageManager(), isAndroid = false).isEmpty())
    }
}
