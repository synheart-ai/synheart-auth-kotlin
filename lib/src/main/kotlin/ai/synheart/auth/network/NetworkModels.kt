package ai.synheart.auth.network

import org.json.JSONObject

data class ChallengeRequest(val appId: String) {
    fun toJson(): String = JSONObject().apply {
        put("app_id", appId)
    }.toString()
}

data class ChallengeResponse(val challenge: String, val expiresAt: String) {
    companion object {
        fun fromJson(json: String): ChallengeResponse {
            val obj = JSONObject(json)
            return ChallengeResponse(
                challenge = obj.getString("challenge"),
                expiresAt = obj.getString("expires_at")
            )
        }
    }
}

data class DeviceMetadata(
    val platform: String = "Android",
    val osVersion: String = System.getProperty("os.version") ?: "unknown",
    val model: String = "unknown",
    val strongBox: Boolean = false
) {
    fun toJsonObject(): JSONObject = JSONObject().apply {
        put("platform", platform)
        put("os_version", osVersion)
        put("model", model)
        put("strong_box", strongBox)
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
        if (attestation != null) put("attestation", attestation)
        put("device_metadata", deviceMetadata.toJsonObject())
    }.toString()
}

data class RegisterResponse(val deviceId: String, val status: String) {
    companion object {
        fun fromJson(json: String): RegisterResponse {
            val obj = JSONObject(json)
            return RegisterResponse(
                deviceId = obj.getString("device_id"),
                status = obj.getString("status")
            )
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
            return RotateKeyResponse(status = obj.getString("status"))
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
            return AuthErrorResponse(
                code = obj.getString("code"),
                message = obj.getString("message"),
                serverTimestamp = if (obj.has("server_timestamp")) obj.getDouble("server_timestamp") else null
            )
        }
    }
}
