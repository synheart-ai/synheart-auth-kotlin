package ai.synheart.auth.crypto

import ai.synheart.auth.models.SynheartAuthError
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.util.Base64

interface KeyManaging {
    fun generateKeyPair(appId: String): ByteArray
    fun sign(data: ByteArray, appId: String): ByteArray
    fun getPublicKey(appId: String): ByteArray?
    fun generateNextKeyPair(appId: String): ByteArray
    fun promoteNextKey(appId: String)
    fun deleteKey(appId: String)
    fun deleteNextKey(appId: String)
    fun hasKey(appId: String): Boolean
}

class SoftwareKeyManager : KeyManaging {
    private val keys = mutableMapOf<String, KeyPair>()

    private fun tag(appId: String): String = "ai.synheart.auth.$appId"
    private fun nextTag(appId: String): String = "ai.synheart.auth.${appId}_next"

    override fun generateKeyPair(appId: String): ByteArray {
        val kp = createP256KeyPair()
        synchronized(keys) { keys[tag(appId)] = kp }
        return exportPublicKey(kp.public)
    }

    override fun sign(data: ByteArray, appId: String): ByteArray {
        val kp = synchronized(keys) { keys[tag(appId)] }
            ?: throw SynheartAuthError.CryptoError("No key found for appId: $appId")
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(kp.private)
        sig.update(data)
        return sig.sign()
    }

    override fun getPublicKey(appId: String): ByteArray? {
        val kp = synchronized(keys) { keys[tag(appId)] } ?: return null
        return exportPublicKey(kp.public)
    }

    override fun generateNextKeyPair(appId: String): ByteArray {
        val kp = createP256KeyPair()
        synchronized(keys) { keys[nextTag(appId)] = kp }
        return exportPublicKey(kp.public)
    }

    override fun promoteNextKey(appId: String) {
        synchronized(keys) {
            val nextKp = keys[nextTag(appId)]
                ?: throw SynheartAuthError.CryptoError("No next key to promote for appId: $appId")
            keys.remove(tag(appId))
            keys[tag(appId)] = nextKp
            keys.remove(nextTag(appId))
        }
    }

    override fun deleteKey(appId: String) {
        synchronized(keys) { keys.remove(tag(appId)) }
    }

    override fun deleteNextKey(appId: String) {
        synchronized(keys) { keys.remove(nextTag(appId)) }
    }

    override fun hasKey(appId: String): Boolean =
        synchronized(keys) { keys.containsKey(tag(appId)) }

    private fun createP256KeyPair(): KeyPair {
        val gen = KeyPairGenerator.getInstance("EC")
        gen.initialize(ECGenParameterSpec("secp256r1"))
        return gen.generateKeyPair()
    }

    private fun exportPublicKey(pub: PublicKey): ByteArray {
        // X.509 encoded EC public key — extract the uncompressed point (last 65 bytes)
        val encoded = pub.encoded
        // X.509 SubjectPublicKeyInfo for P-256 is 91 bytes; the last 65 bytes are the uncompressed point
        return if (encoded.size >= 65) {
            val point = encoded.copyOfRange(encoded.size - 65, encoded.size)
            if (point[0] == 0x04.toByte()) point
            else encoded // fallback
        } else {
            encoded
        }
    }

    fun verify(data: ByteArray, signatureBytes: ByteArray, appId: String): Boolean {
        val kp = synchronized(keys) { keys[tag(appId)] } ?: return false
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initVerify(kp.public)
        sig.update(data)
        return sig.verify(signatureBytes)
    }
}

class MockKeyManager : KeyManaging {
    private val delegate = SoftwareKeyManager()
    var shouldFailGenerate = false
    var shouldFailSign = false

    override fun generateKeyPair(appId: String): ByteArray {
        if (shouldFailGenerate) throw SynheartAuthError.CryptoError("Mock key generation failure")
        return delegate.generateKeyPair(appId)
    }

    override fun sign(data: ByteArray, appId: String): ByteArray {
        if (shouldFailSign) throw SynheartAuthError.CryptoError("Mock signing failure")
        return delegate.sign(data, appId)
    }

    override fun getPublicKey(appId: String): ByteArray? = delegate.getPublicKey(appId)
    override fun generateNextKeyPair(appId: String): ByteArray = delegate.generateNextKeyPair(appId)
    override fun promoteNextKey(appId: String) = delegate.promoteNextKey(appId)
    override fun deleteKey(appId: String) = delegate.deleteKey(appId)
    override fun deleteNextKey(appId: String) = delegate.deleteNextKey(appId)
    override fun hasKey(appId: String): Boolean = delegate.hasKey(appId)

    fun verify(data: ByteArray, signatureBytes: ByteArray, appId: String): Boolean =
        delegate.verify(data, signatureBytes, appId)
}
