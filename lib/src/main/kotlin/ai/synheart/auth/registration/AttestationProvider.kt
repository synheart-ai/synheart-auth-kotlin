package ai.synheart.auth.registration

import ai.synheart.auth.internal.AuthLogger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Interface for platform-specific attestation proof generation.
 * Android: Play Integrity API
 * iOS: App Attest (handled in Swift)
 */
interface AttestationProvider {
    /**
     * Generate attestation proof for the given nonce.
     * Returns the proof token string, or null if attestation is unavailable.
     */
    suspend fun generateProof(nonce: String): String?
}

/**
 * No-op provider for environments where attestation is not available.
 * Used in unit tests and emulator/development environments.
 */
class NoOpAttestationProvider : AttestationProvider {
    override suspend fun generateProof(nonce: String): String? = null
}

/**
 * Play Integrity attestation provider for Android production devices.
 *
 * Usage from Android application code:
 * ```kotlin
 * // In Application.onCreate():
 * val provider = PlayIntegrityAttestationProvider.create(applicationContext)
 * SynheartAuth.shared.configure(baseUrl, attestationProvider = provider)
 * ```
 *
 * Requires the `com.google.android.play:integrity` dependency in the app's build.gradle.
 * If Play Integrity is unavailable (e.g., non-GMS device), falls back to returning null.
 *
 * NOTE: This class uses Play Integrity APIs via reflection to avoid a compile-time
 * dependency on Google Play Services in this library module. The hosting Android app
 * must include the play-integrity dependency.
 */
class PlayIntegrityAttestationProvider private constructor(
    private val context: Any // android.content.Context, passed as Any for JVM compat
) : AttestationProvider {

    companion object {
        private const val TAG = "PlayIntegrity"

        /**
         * Create a PlayIntegrityAttestationProvider.
         * @param context Android application Context
         */
        fun create(context: Any): PlayIntegrityAttestationProvider {
            return PlayIntegrityAttestationProvider(context)
        }
    }

    override suspend fun generateProof(nonce: String): String? = withContext(Dispatchers.IO) {
        // CRITICAL: dispatch onto `Dispatchers.IO`. Both blocking operations
        // below — the IntegrityService bind (`requestIntegrityToken`) and the
        // synchronous `Tasks.await(...)` that follows — can park the calling
        // thread for several seconds on a cold boot. When `register()` is
        // invoked from a JNI / FFI thread that happens to be the Android main
        // thread (which downstream consumers don't always control directly),
        // the calling thread is the UI thread and the ANR watchdog fires
        // (signal 3 / "Wrote stack traces to tombstoned") after ~5s. Forcing
        // `Dispatchers.IO` here makes the dispatch contract explicit at the
        // leaf, independent of how the caller's coroutine context was set up.
        try {
            // Use reflection to call Play Integrity APIs without compile-time dependency.
            // IntegrityManagerFactory.create(context)
            val factoryClass = Class.forName("com.google.android.play.core.integrity.IntegrityManagerFactory")
            val createMethod = factoryClass.getMethod("create", Class.forName("android.content.Context"))
            val integrityManager = createMethod.invoke(null, context)

            // IntegrityTokenRequest.builder().setNonce(nonce).build()
            val requestBuilderClass = Class.forName("com.google.android.play.core.integrity.IntegrityTokenRequest\$Builder")
            val builder = requestBuilderClass.getDeclaredConstructor().newInstance()
            requestBuilderClass.getMethod("setNonce", String::class.java).invoke(builder, nonce)
            val request = requestBuilderClass.getMethod("build").invoke(builder)

            // integrityManager.requestIntegrityToken(request) → Task<IntegrityTokenResponse>
            val requestMethod = integrityManager.javaClass.getMethod("requestIntegrityToken", request.javaClass)
            val task = requestMethod.invoke(integrityManager, request)

            // Await the Task using Tasks.await() — safe to block here because
            // the surrounding `withContext(Dispatchers.IO)` guarantees we're
            // not on the main thread.
            val tasksClass = Class.forName("com.google.android.gms.tasks.Tasks")
            val awaitMethod = tasksClass.getMethod("await", Class.forName("com.google.android.gms.tasks.Task"))
            val response = awaitMethod.invoke(null, task)

            // response.token()
            val token = response.javaClass.getMethod("token").invoke(response) as? String
            AuthLogger.info(TAG, "Play Integrity token obtained (${token?.length ?: 0} chars)")
            token
        } catch (e: ClassNotFoundException) {
            AuthLogger.info(TAG, "Play Integrity not available: ${e.message}")
            null
        } catch (e: Exception) {
            AuthLogger.info(TAG, "Play Integrity failed: ${e.cause?.message ?: e.message}")
            null
        }
    }
}
