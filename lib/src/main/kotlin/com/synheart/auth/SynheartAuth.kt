package com.synheart.auth

import com.synheart.auth.crypto.KeyManaging
import com.synheart.auth.crypto.RequestSigner
import com.synheart.auth.crypto.SoftwareKeyManager
import com.synheart.auth.internal.AuthLogger
import com.synheart.auth.internal.ClockSkewTracker
import com.synheart.auth.models.*
import com.synheart.auth.network.AuthNetworkClient
import com.synheart.auth.network.AuthNetworking
import com.synheart.auth.registration.DeviceRegistrar
import com.synheart.auth.storage.StorageManager
import com.synheart.auth.storage.StorageManaging

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
        val shared: SynheartAuth = SynheartAuth(
            keyManager = SoftwareKeyManager(),
            storage = StorageManager(),
            clockSkewTracker = ClockSkewTracker(),
            network = null,
            registrar = null
        )

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

    fun configure(baseUrl: String) {
        this.baseUrl = baseUrl
        val networkClient = AuthNetworkClient(baseUrl)
        this.network = networkClient
        this.registrar = DeviceRegistrar(keyManager, storage, networkClient)
        AuthLogger.info("SynheartAuth", "Configured with baseUrl: $baseUrl")
    }

    fun isRegistered(appId: String): Boolean =
        storage.loadState(appId) == DeviceAuthState.REGISTERED

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
        return requestSigner.sign(appId, method, path, bodyBytes)
    }

    fun getDeviceId(appId: String): String? = storage.loadDeviceId(appId)

    suspend fun rotateKey(appId: String): RotationResult {
        val reg = registrar ?: throw SynheartAuthError.NotConfigured()
        return reg.rotateKey(appId)
    }

    fun resetDeviceIdentity(appId: String) {
        keyManager.deleteKey(appId)
        try { keyManager.deleteNextKey(appId) } catch (_: Exception) {}
        storage.deleteAll(appId)
        AuthLogger.info("SynheartAuth", "Reset device identity for appId: $appId")
    }

    fun correctClockSkew(serverTimestamp: Double) {
        clockSkewTracker.update(serverTimestamp)
    }
}
