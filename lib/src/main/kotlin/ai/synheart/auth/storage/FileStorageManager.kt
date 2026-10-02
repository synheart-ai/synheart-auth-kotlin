package ai.synheart.auth.storage

import ai.synheart.auth.internal.AuthLogger
import ai.synheart.auth.models.DeviceAuthState
import ai.synheart.auth.models.SynheartAuthError
import java.io.File
import java.io.IOException
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.util.Properties

/**
 * Persistent [StorageManaging] backed by one small file per `app_id` in
 * [directory].
 *
 * Holds only non-secret registration state: `device_id`, the auth state and
 * metadata. Private keys never pass through here — they stay in the Android
 * Keystore (see [ai.synheart.auth.crypto.HardwareKeyManager]).
 *
 * On Android, [ai.synheart.auth.SynheartAuth.initialize] with a `Context` puts
 * this in `Context.getNoBackupFilesDir()`. That location matters: a Keystore
 * key never leaves the device, so registration state restored onto another
 * device by Auto Backup would point at a key that does not exist there.
 * SharedPreferences are backed up by default; the no-backup directory is not.
 *
 * Writes are atomic (temp file + rename), so a crash mid-write leaves the
 * previous state rather than a truncated file. Reads are served from memory
 * after the first load. A single process is assumed: two processes sharing
 * the directory would not see each other's writes until restart.
 */
class FileStorageManager(private val directory: File) : StorageManaging {

    private companion object {
        const val TAG = "FileStorageManager"
        const val K_APP_ID = "app_id"
        const val K_DEVICE_ID = "device_id"
        const val K_STATE = "state"
        const val K_METADATA = "metadata"
    }

    private val lock = Any()
    private val cache = mutableMapOf<String, Properties>()

    /**
     * File name for [appId]: a hash, so an app_id can never escape the
     * directory or collide with another after sanitising.
     */
    private fun fileFor(appId: String): File {
        val digest = MessageDigest.getInstance("SHA-256").digest(appId.toByteArray(Charsets.UTF_8))
        val hex = digest.joinToString("") { "%02x".format(it) }
        return File(directory, "synheart_auth_$hex.properties")
    }

    private fun load(appId: String): Properties = cache.getOrPut(appId) {
        val file = fileFor(appId)
        val props = Properties()
        if (file.isFile) {
            try {
                file.inputStream().use { props.load(it) }
            } catch (e: Exception) {
                // An unreadable file is treated as "not registered": the SDK
                // re-registers rather than failing every call forever.
                AuthLogger.warn(TAG, "Discarding unreadable auth state for appId=$appId: ${e.message}")
                props.clear()
            }
            if (props.getProperty(K_APP_ID) != appId) props.clear()
        }
        props
    }

    private fun persist(appId: String, props: Properties) {
        try {
            if (!directory.isDirectory && !directory.mkdirs() && !directory.isDirectory) {
                throw IOException("cannot create $directory")
            }
            val target = fileFor(appId)
            val tmp = File.createTempFile("synheart_auth_", ".tmp", directory)
            try {
                tmp.outputStream().use { out ->
                    props.store(out, null)
                    out.flush()
                    (out as? java.io.FileOutputStream)?.fd?.sync()
                }
                try {
                    Files.move(
                        tmp.toPath(), target.toPath(),
                        StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING,
                    )
                } catch (_: AtomicMoveNotSupportedException) {
                    Files.move(tmp.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING)
                }
            } finally {
                tmp.delete()
            }
        } catch (e: IOException) {
            throw SynheartAuthError.StorageError("Failed to persist auth state for appId=$appId: ${e.message}")
        }
    }

    private fun mutate(appId: String, block: (Properties) -> Unit) = synchronized(lock) {
        val updated = Properties().apply { putAll(load(appId)) }
        updated.setProperty(K_APP_ID, appId)
        block(updated)
        persist(appId, updated)
        // Only after the write succeeded, so memory never runs ahead of disk.
        cache[appId] = updated
    }

    override fun saveDeviceId(deviceId: String, appId: String) =
        mutate(appId) { it.setProperty(K_DEVICE_ID, deviceId) }

    override fun loadDeviceId(appId: String): String? =
        synchronized(lock) { load(appId).getProperty(K_DEVICE_ID) }

    override fun saveState(state: DeviceAuthState, appId: String) =
        mutate(appId) { it.setProperty(K_STATE, state.value) }

    override fun loadState(appId: String): DeviceAuthState =
        synchronized(lock) {
            load(appId).getProperty(K_STATE)?.let { DeviceAuthState.fromValue(it) }
                ?: DeviceAuthState.UNREGISTERED
        }

    override fun saveMetadata(metadata: Map<String, String>, appId: String) =
        mutate(appId) { it.setProperty(K_METADATA, org.json.JSONObject(metadata).toString()) }

    override fun loadMetadata(appId: String): Map<String, String>? =
        synchronized(lock) {
            load(appId).getProperty(K_METADATA)?.let { raw ->
                val json = org.json.JSONObject(raw)
                json.keys().asSequence().associateWith { json.getString(it) }
            }
        }

    override fun deleteAll(appId: String) = synchronized(lock) {
        val file = fileFor(appId)
        if (file.exists() && !file.delete()) {
            throw SynheartAuthError.StorageError("Failed to delete auth state for appId=$appId")
        }
        cache[appId] = Properties()
    }
}
