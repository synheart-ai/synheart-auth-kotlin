package com.synheart.auth.models

data class RegistrationResult(
    val status: RegistrationStatus,
    val deviceId: String? = null,
    val error: SynheartAuthError? = null
) {
    enum class RegistrationStatus { SUCCESS, FAILED, ALREADY_REGISTERED }
}

data class RotationResult(
    val status: RotationStatus,
    val error: SynheartAuthError? = null
) {
    enum class RotationStatus { SUCCESS, FAILED }
}

data class SignedHeaders(
    val appId: String,
    val deviceId: String,
    val signature: String,
    val timestamp: String,
    val nonce: String,
    val signatureVersion: String = "1"
) {
    fun toMap(): Map<String, String> = mapOf(
        "X-App-ID" to appId,
        "X-Device-ID" to deviceId,
        "X-Synheart-Signature" to signature,
        "X-Synheart-Timestamp" to timestamp,
        "X-Synheart-Nonce" to nonce,
        "X-Synheart-Sig-Version" to signatureVersion
    )
}
