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
import ai.synheart.auth.storage.StorageManager
import ai.synheart.auth.storage.StorageManaging

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
        /**
         * Default singleton uses SoftwareKeyManager. On Android, call [initialize]
         * before [configure] to switch to hardware-backed keys.
         */
        val shared: SynheartAuth = SynheartAuth(
            keyManager = SoftwareKeyManager(),
            storage = StorageManager(),
            clockSkewTracker = ClockSkewTracker(),
            network = null,
            registrar = null
        )

        /**
         * Initialize the shared instance with a hardware-backed KeyManager.
         * Call this once from Application.onCreate() on Android:
         *
         *     SynheartAuth.initialize(HardwareKeyManager.create())
         *
         * Must be called BEFORE [configure]. On JVM (tests, desktop), skip this
         * and the default SoftwareKeyManager will be used.
         */
        fun initialize(keyManager: KeyManaging) {
            val instance = SynheartAuth(
                keyManager = keyManager,
                storage = StorageManager(),
                clockSkewTracker = ClockSkewTracker(),
                network = null,
                registrar = null
            )
            // Replace the shared singleton's internal state
            shared.replaceInternals(instance)
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

    private fun replaceInternals(other: SynheartAuth) {
        this._keyManager = other._keyManager
        this._storage = other._storage
        this._clockSkewTracker = other._clockSkewTracker
        this._requestSigner = RequestSigner(other._keyManager, other._storage, other._clockSkewTracker)
    }

    private var attestationProvider: AttestationProvider = NoOpAttestationProvider()

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
        val networkClient = AuthNetworkClient(baseUrl)
        this.network = networkClient
        this.registrar = DeviceRegistrar(_keyManager, _storage, networkClient, this.attestationProvider)
        AuthLogger.info("SynheartAuth", "Configured with baseUrl: $baseUrl, keyManager=${_keyManager.javaClass.simpleName}, attestation=${this.attestationProvider.javaClass.simpleName}")
    }

    fun isRegistered(appId: String): Boolean =
        _storage.loadState(appId) == DeviceAuthState.REGISTERED

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
