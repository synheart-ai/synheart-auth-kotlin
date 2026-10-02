package ai.synheart.auth

import ai.synheart.auth.crypto.HardwareKeyManager
import ai.synheart.auth.crypto.KeyManaging
import ai.synheart.auth.crypto.RequestSigner
import ai.synheart.auth.crypto.SoftwareKeyManager
import ai.synheart.auth.internal.AuthLogger
import ai.synheart.auth.internal.ClockSkewTracker
import ai.synheart.auth.models.*
import ai.synheart.auth.network.AuthNetworkClient
import ai.synheart.auth.network.AuthNetworking
import ai.synheart.auth.registration.AttestationProvider
import ai.synheart.auth.registration.DeviceRegistrar
import ai.synheart.auth.registration.NoOpAttestationProvider
import ai.synheart.auth.storage.FileStorageManager
import ai.synheart.auth.storage.StorageManager
import ai.synheart.auth.storage.StorageManaging
import java.io.File

class SynheartAuth private constructor(
    private val keyManager: KeyManaging,
    private val storage: StorageManaging,
    private val clockSkewTracker: ClockSkewTracker,
    private var network: AuthNetworking?,
    private var registrar: DeviceRegistrar?
) {
    private var baseUrl: String? = null
    private val requestSigner = RequestSigner(keyManager, storage, clockSkewTracker)

    companion object {
        private const val TAG = "SynheartAuth"

        /** Sub-directory of the app's no-backup files dir used by [initialize] (Context). */
        const val STORAGE_DIRECTORY_NAME: String = "synheart_auth"

        /**
         * Default singleton. Until [initialize] is called it uses a
         * [SoftwareKeyManager] and in-memory [StorageManager] — fine for JVM
         * tests, NOT for an app: the private key lives in process memory and
         * the device identity is lost on every restart. On Android call
         * `SynheartAuth.initialize(context)` before [configure]; the SDK logs a
         * security warning when an Android app configures it with these
         * defaults.
         */
        val shared: SynheartAuth = SynheartAuth(
            keyManager = SoftwareKeyManager(),
            storage = StorageManager(),
            clockSkewTracker = ClockSkewTracker(),
            network = null,
            registrar = null
        )

        /**
         * Production setup for Android. Call once from `Application.onCreate()`,
         * before [configure]:
         *
         *     SynheartAuth.initialize(applicationContext)
         *
         * Uses [HardwareKeyManager] (Android Keystore, StrongBox-preferred,
         * TEE fallback) and a [FileStorageManager] in the app's no-backup files
         * directory, so `device_id` and registration state survive process
         * restarts. Private keys stay in the Keystore and are never written to
         * that storage.
         *
         * @param context an `android.content.Context`. Typed as [Any] because
         *   this library is plain Kotlin/JVM with no Android compile
         *   dependency (the same reason [HardwareKeyManager] reaches Keystore
         *   through reflection). Anything else throws [IllegalArgumentException].
         */
        fun initialize(context: Any) {
            initialize(context) { HardwareKeyManager.create() }
        }

        /** [initialize] with an injectable key manager, so the Context path is testable on the JVM. */
        internal fun initialize(context: Any, keyManagerFactory: () -> KeyManaging) {
            val directory = File(noBackupFilesDir(context), STORAGE_DIRECTORY_NAME)
            initialize(keyManagerFactory(), FileStorageManager(directory))
        }

        /**
         * Initialize the shared instance with an explicit key manager and
         * storage — e.g. `HardwareKeyManager.create()` with your own persistent
         * [StorageManaging]. Must be called BEFORE [configure] (calling it
         * afterwards rebuilds the registrar with the new components).
         */
        fun initialize(keyManager: KeyManaging, storage: StorageManaging) {
            shared.replaceInternals(keyManager, storage, ClockSkewTracker())
            warnOnInsecureDefaults(keyManager, storage)
        }

        /**
         * Initialize the shared instance with a key manager and the in-memory
         * [StorageManager].
         *
         * Kept for source compatibility. The device identity does NOT survive
         * a process restart with this overload — on Android prefer
         * [initialize] with a `Context`, or pass a persistent
         * [StorageManaging] to the two-argument overload.
         */
        fun initialize(keyManager: KeyManaging) {
            initialize(keyManager, StorageManager())
        }

        /**
         * Security warnings for a component set, empty when it is safe for an
         * app. Only an Android runtime warns: on the JVM the software defaults
         * are what tests are supposed to use.
         */
        internal fun insecureDefaultWarnings(
            keyManager: KeyManaging,
            storage: StorageManaging,
            isAndroid: Boolean = isAndroidRuntime(),
        ): List<String> {
            if (!isAndroid) return emptyList()
            val warnings = mutableListOf<String>()
            if (keyManager is SoftwareKeyManager) {
                warnings += "Using SoftwareKeyManager: the device private key is held in process " +
                    "memory, not the Android Keystore, and is lost on restart. Call " +
                    "SynheartAuth.initialize(context) before configure()."
            }
            if (storage is StorageManager) {
                warnings += "Using in-memory StorageManager: device_id and registration state are " +
                    "lost on every process restart. Call SynheartAuth.initialize(context), or " +
                    "pass a persistent StorageManaging to initialize(keyManager, storage)."
            }
            return warnings
        }

        private fun warnOnInsecureDefaults(keyManager: KeyManaging, storage: StorageManaging) {
            insecureDefaultWarnings(keyManager, storage).forEach { AuthLogger.securityWarning(TAG, it) }
        }

        private fun isAndroidRuntime(): Boolean =
            System.getProperty("java.vm.vendor")?.contains("Android", ignoreCase = true) == true ||
                runCatching { Class.forName("android.os.Build") }.isSuccess

        /**
         * `context.getApplicationContext().getNoBackupFilesDir()` (API 21+),
         * falling back to `getFilesDir()`, via reflection.
         */
        internal fun noBackupFilesDir(context: Any): File {
            fun call(target: Any, name: String): Any? =
                runCatching { target.javaClass.getMethod(name).invoke(target) }.getOrNull()

            val app = call(context, "getApplicationContext") ?: context
            val dir = (call(app, "getNoBackupFilesDir") ?: call(app, "getFilesDir")) as? File
            return dir ?: throw IllegalArgumentException(
                "SynheartAuth.initialize(context) expects an android.content.Context, got " +
                    context.javaClass.name
            )
        }

        fun createForTesting(
            keyManager: KeyManaging,
            storage: StorageManaging,
            network: AuthNetworking
        ): SynheartAuth {
            val clockSkew = ClockSkewTracker()
            return SynheartAuth(
                keyManager = keyManager,
                storage = storage,
                clockSkewTracker = clockSkew,
                network = network,
                registrar = DeviceRegistrar(keyManager, storage, network)
            )
        }
    }

    // Mutable field to allow initialize() to swap in hardware KeyManager
    @Volatile private var _keyManager: KeyManaging = keyManager
    @Volatile private var _storage: StorageManaging = storage
    @Volatile private var _clockSkewTracker: ClockSkewTracker = clockSkewTracker
    @Volatile private var _requestSigner: RequestSigner = requestSigner

    private var attestationProvider: AttestationProvider = NoOpAttestationProvider()

    @Synchronized
    private fun replaceInternals(
        keyManager: KeyManaging,
        storage: StorageManaging,
        clockSkewTracker: ClockSkewTracker,
    ) {
        this._keyManager = keyManager
        this._storage = storage
        this._clockSkewTracker = clockSkewTracker
        this._requestSigner = RequestSigner(keyManager, storage, clockSkewTracker)
        // initialize() after configure() used to leave the registrar on the
        // previous key manager and storage; rebuild it so every path agrees.
        val url = baseUrl
        if (url != null) {
            val networkClient = AuthNetworkClient(url, clockSkewTracker)
            this.network = networkClient
            this.registrar = DeviceRegistrar(keyManager, storage, networkClient, attestationProvider)
        }
    }

    fun setLoggingEnabled(enabled: Boolean) {
        AuthLogger.enabled = enabled
    }

    /**
     * Configure the SDK with auth service base URL and optional attestation provider.
     *
     * On Android, if [initialize] was called with a [HardwareKeyManager], keys will
     * be stored in Android Keystore (StrongBox/TEE). Otherwise, software keys are used.
     *
     * @param attestationProvider Platform attestation provider. On Android, pass
     *   PlayIntegrityAttestationProvider(context) for production. Defaults to NoOp.
     */
    fun configure(baseUrl: String, attestationProvider: AttestationProvider? = null) {
        this.baseUrl = baseUrl
        if (attestationProvider != null) {
            this.attestationProvider = attestationProvider
        }
        val networkClient = AuthNetworkClient(baseUrl, _clockSkewTracker)
        this.network = networkClient
        this.registrar = DeviceRegistrar(_keyManager, _storage, networkClient, this.attestationProvider)
        warnOnInsecureDefaults(_keyManager, _storage)
        AuthLogger.info("SynheartAuth", "Configured with baseUrl: $baseUrl, keyManager=${_keyManager.javaClass.simpleName}, attestation=${this.attestationProvider.javaClass.simpleName}")
    }

    /**
     * True when registration state says REGISTERED *and* the signing key is
     * present. With persistent storage the two can disagree (Keystore cleared,
     * key invalidated, state restored onto another device); a device without
     * its key cannot sign and is not registered in any useful sense.
     */
    fun isRegistered(appId: String): Boolean =
        _storage.loadState(appId) == DeviceAuthState.REGISTERED && _keyManager.hasKey(appId)

    suspend fun registerDevice(appId: String): RegistrationResult {
        val reg = registrar ?: throw SynheartAuthError.NotConfigured()
        return reg.register(appId)
    }

    fun signRequest(
        appId: String,
        method: String,
        path: String,
        bodyBytes: ByteArray? = null
    ): SignedHeaders {
        return _requestSigner.sign(appId, method, path, bodyBytes)
    }

    fun getDeviceId(appId: String): String? = _storage.loadDeviceId(appId)

    suspend fun rotateKey(appId: String): RotationResult {
        val reg = registrar ?: throw SynheartAuthError.NotConfigured()
        return reg.rotateKey(appId)
    }

    fun resetDeviceIdentity(appId: String) {
        _keyManager.deleteKey(appId)
        try { _keyManager.deleteNextKey(appId) } catch (_: Exception) {}
        _storage.deleteAll(appId)
        AuthLogger.info("SynheartAuth", "Reset device identity for appId: $appId")
    }

    fun correctClockSkew(serverTimestamp: Double) {
        _clockSkewTracker.update(serverTimestamp)
    }
}
