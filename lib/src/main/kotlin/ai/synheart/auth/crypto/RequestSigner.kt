package ai.synheart.auth.crypto

import ai.synheart.auth.internal.ClockSkewTracker
import ai.synheart.auth.models.SignedHeaders
import ai.synheart.auth.models.SynheartAuthError
import ai.synheart.auth.storage.StorageManaging
import java.util.Base64
import java.util.UUID

class RequestSigner(
    private val keyManager: KeyManaging,
    private val storage: StorageManaging,
    private val clockSkewTracker: ClockSkewTracker
) {
    fun sign(
        appId: String,
        method: String,
        path: String,
        bodyBytes: ByteArray? = null
    ): SignedHeaders {
        val deviceId = storage.loadDeviceId(appId)
            ?: throw SynheartAuthError.NotRegistered()

        val timestamp = clockSkewTracker.correctedTimestamp()
        val nonce = UUID.randomUUID().toString()
        val message = buildMessage(method, path, timestamp, bodyBytes)
        val signatureBytes = keyManager.sign(message, appId)
        val signature = Base64.getEncoder().encodeToString(signatureBytes)

        return SignedHeaders(
            appId = appId,
            deviceId = deviceId,
            signature = signature,
            timestamp = timestamp,
            nonce = nonce
        )
    }

    companion object {
        fun buildMessage(
            method: String,
            path: String,
            timestamp: String,
            bodyBytes: ByteArray? = null
        ): ByteArray {
            val header = "${method.uppercase()}\n$path\n$timestamp\n"
            val headerBytes = header.toByteArray(Charsets.UTF_8)
            return if (bodyBytes != null) {
                headerBytes + bodyBytes
            } else {
                headerBytes
            }
        }
    }
}
