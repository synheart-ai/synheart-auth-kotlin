package ai.synheart.auth.network

import org.json.JSONObject

data class ChallengeRequest(val appId: String) {
    fun toJson(): String = JSONObject().apply {
        put("app_id", appId)
    }.toString()
}

data class ChallengeResponse(val challenge: String, val expiresAt: String) {
    /** Check if the challenge has expired based on expiresAt timestamp. */
    val isExpired: Boolean
        get() = try {
            java.time.Instant.parse(expiresAt).isBefore(java.time.Instant.now())
        } catch (_: Exception) {
            false // If we can't parse, let the server decide
        }

    companion object {
        private fun resolveChallenge(data: JSONObject): String {
            val direct = data.optString("challenge", "")
            if (direct.isNotEmpty()) return direct
            val nonce = data.optString("challenge_nonce", "")
            if (nonce.isNotEmpty()) return nonce
            val challengeId = data.optString("challenge_id", "")
            if (challengeId.isNotEmpty()) return challengeId

            val preview = data.toString().take(240)
            throw IllegalArgumentException(
                "No challenge/challenge_nonce/challenge_id in challenge response. payload=$preview",
            )
        }

        fun fromJson(json: String): ChallengeResponse {
            val obj = JSONObject(json)
            // API wraps response in {"success":true,"data":{...}}
            val data = if (obj.has("data")) obj.getJSONObject("data") else obj
            val challenge = resolveChallenge(data)
            // API returns expires_in (seconds) instead of expires_at (ISO timestamp)
            val expiresAt = if (data.has("expires_at")) {
                data.getString("expires_at")
            } else if (data.has("expires_in")) {
                val seconds = data.getLong("expires_in")
                java.time.Instant.now().plusSeconds(seconds).toString()
            } else {
                java.time.Instant.now().plusSeconds(90).toString() // RFC default: 90s
            }
            return ChallengeResponse(challenge = challenge, expiresAt = expiresAt)
        }
    }
}

data class RegisterRequest(
    val appId: String,
    val challenge: String,
    val publicKey: String,
    val attestation: String?,
    val deviceMetadata: DeviceMetadata
) {
    fun toJson(): String = JSONObject().apply {
        put("app_id", appId)
        put("challenge", challenge)
        put("public_key", publicKey)
        put("attestation", attestation)
        put(
            "device_metadata",
            JSONObject().apply {
                put("platform", deviceMetadata.platform)
                deviceMetadata.osVersion?.let { put("os_version", it) }
                deviceMetadata.model?.let { put("model", it) }
                deviceMetadata.secureEnclave?.let { put("secure_enclave", it) }
            },
        )
    }.toString()
}

data class DeviceMetadata(
    val platform: String,
    val osVersion: String? = null,
    val model: String? = null,
    val secureEnclave: Boolean? = null,
)

data class RegisterResponse(val deviceId: String, val status: String) {
    companion object {
        fun fromJson(json: String): RegisterResponse {
            val obj = JSONObject(json)
            val data = if (obj.has("data")) obj.getJSONObject("data") else obj
            val deviceId = data.getString("device_id")
            // API returns "registered": true instead of "status" field
            val status = if (data.has("status")) {
                data.getString("status")
            } else if (data.optBoolean("registered", false)) {
                "success"
            } else {
                "failed"
            }
            return RegisterResponse(deviceId = deviceId, status = status)
        }
    }
}

data class RotateKeyRequest(
    val appId: String,
    val deviceId: String,
    val newPublicKey: String,
    val oldKeySignature: String
) {
    fun toJson(): String = JSONObject().apply {
        put("app_id", appId)
        put("device_id", deviceId)
        put("new_public_key", newPublicKey)
        put("old_key_signature", oldKeySignature)
    }.toString()
}

data class RotateKeyResponse(val status: String) {
    companion object {
        fun fromJson(json: String): RotateKeyResponse {
            val obj = JSONObject(json)
            val data = if (obj.has("data")) obj.getJSONObject("data") else obj
            return RotateKeyResponse(status = data.getString("status"))
        }
    }
}

data class AuthErrorResponse(
    val code: String,
    val message: String,
    val serverTimestamp: Double? = null
) {
    companion object {
        fun fromJson(json: String): AuthErrorResponse {
            val obj = JSONObject(json)
            // API uses {"error":"DEV_001","error_description":"...","error_code":"DEV_001"}
            // or legacy {"code":"...","message":"..."}
            val code = when {
                obj.has("error_code") -> obj.getString("error_code")
                obj.has("code") -> obj.getString("code")
                obj.has("error") -> obj.getString("error")
                else -> "UNKNOWN"
            }
            val message = when {
                obj.has("error_description") -> obj.getString("error_description")
                obj.has("message") -> obj.getString("message")
                else -> "Unknown error"
            }
            return AuthErrorResponse(
                code = code,
                message = message,
                serverTimestamp = if (obj.has("server_timestamp")) obj.getDouble("server_timestamp") else null
            )
        }
    }
}
