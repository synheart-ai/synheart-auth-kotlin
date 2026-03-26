package ai.synheart.auth.network

import ai.synheart.auth.models.SynheartAuthError
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URI

interface AuthNetworking {
    suspend fun fetchChallenge(appId: String): ChallengeResponse
    suspend fun registerDevice(request: RegisterRequest): RegisterResponse
    suspend fun rotateKey(request: RotateKeyRequest): RotateKeyResponse
}

class AuthNetworkClient(private val baseUrl: String) : AuthNetworking {

    override suspend fun fetchChallenge(appId: String): ChallengeResponse =
        withContext(Dispatchers.IO) {
            val body = ChallengeRequest(appId).toJson()
            val response = post("/v1/device/challenge", body)
            ChallengeResponse.fromJson(response)
        }

    override suspend fun registerDevice(request: RegisterRequest): RegisterResponse =
        withContext(Dispatchers.IO) {
            val response = post("/v1/device/register", request.toJson())
            RegisterResponse.fromJson(response)
        }

    override suspend fun rotateKey(request: RotateKeyRequest): RotateKeyResponse =
        withContext(Dispatchers.IO) {
            val response = post("/v1/device/rotate-key", request.toJson())
            RotateKeyResponse.fromJson(response)
        }

    private fun post(path: String, body: String): String {
        val url = URI("$baseUrl$path").toURL()
        val conn = url.openConnection() as HttpURLConnection
        try {
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json")
            conn.doOutput = true

            OutputStreamWriter(conn.outputStream, Charsets.UTF_8).use { it.write(body) }

            val code = conn.responseCode
            if (code in 200..299) {
                return conn.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
            }

            val errorBody = conn.errorStream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() } ?: ""
            if (errorBody.isNotEmpty()) {
                try {
                    val errorResponse = AuthErrorResponse.fromJson(errorBody)
                    if (errorResponse.code == "CLOCK_SKEW") {
                        throw SynheartAuthError.ClockSkew()
                    }
                    throw SynheartAuthError.ServerError(errorResponse.code, errorResponse.message)
                } catch (e: SynheartAuthError) {
                    throw e
                } catch (_: Exception) {
                    // JSON parse failed, fall through
                }
            }
            throw SynheartAuthError.NetworkError("HTTP $code")
        } finally {
            conn.disconnect()
        }
    }
}

class MockAuthNetworkClient : AuthNetworking {
    var challengeResponse: ChallengeResponse? = null
    var registerResponse: RegisterResponse? = null
    var rotateKeyResponse: RotateKeyResponse? = null
    var shouldFail: SynheartAuthError? = null

    var lastRegisterRequest: RegisterRequest? = null
    var lastRotateKeyRequest: RotateKeyRequest? = null

    override suspend fun fetchChallenge(appId: String): ChallengeResponse {
        shouldFail?.let { throw it }
        return challengeResponse ?: throw SynheartAuthError.NetworkError("No mock challenge configured")
    }

    override suspend fun registerDevice(request: RegisterRequest): RegisterResponse {
        lastRegisterRequest = request
        shouldFail?.let { throw it }
        return registerResponse ?: throw SynheartAuthError.NetworkError("No mock register response configured")
    }

    override suspend fun rotateKey(request: RotateKeyRequest): RotateKeyResponse {
        lastRotateKeyRequest = request
        shouldFail?.let { throw it }
        return rotateKeyResponse ?: throw SynheartAuthError.NetworkError("No mock rotate response configured")
    }
}
