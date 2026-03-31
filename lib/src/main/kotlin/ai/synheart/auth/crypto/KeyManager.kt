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

/**
 * Android Keystore-backed KeyManager. Keys are hardware-protected (StrongBox or TEE)
 * and non-exportable. This is the production implementation for Android devices.
 *
 * Requires Android API 23+ (Keystore EC support) and API 28+ for StrongBox.
 *
 * NOTE: This class uses Android Keystore APIs via reflection/direct import in the
 * Android build variant. For JVM unit tests, use SoftwareKeyManager or MockKeyManager.
 */
class HardwareKeyManager(private val keyStore: KeyStore) : KeyManaging {

    companion object {
        /**
         * Create a HardwareKeyManager backed by the Android Keystore.
         * Call this from Android application code where android.security.keystore is available.
         */
        fun create(): HardwareKeyManager {
            val ks = KeyStore.getInstance("AndroidKeyStore")
            ks.load(null)
            return HardwareKeyManager(ks)
        }
    }

    private fun tag(appId: String): String = "synheart_auth_$appId"
    private fun nextTag(appId: String): String = "synheart_auth_${appId}_next"

    override fun generateKeyPair(appId: String): ByteArray {
        return generateKeyForAlias(tag(appId))
    }

    override fun generateNextKeyPair(appId: String): ByteArray {
        return generateKeyForAlias(nextTag(appId))
    }

    private fun generateKeyForAlias(alias: String): ByteArray {
        try {
            // Use Android Keystore KeyGenParameterSpec via reflection to avoid compile-time
            // dependency on android.* classes in JVM tests. In the actual Android build,
            // these classes are available at runtime.
            val specBuilderClass = Class.forName("android.security.keystore.KeyGenParameterSpec\$Builder")
            val purposeSign = 4 // KeyProperties.PURPOSE_SIGN = 4
            val builder = specBuilderClass
                .getConstructor(String::class.java, Int::class.javaPrimitiveType)
                .newInstance(alias, purposeSign)

            // .setDigests(KeyProperties.DIGEST_SHA256)
            val digestSha256 = "SHA-256"
            specBuilderClass.getMethod("setDigests", Array<String>::class.java)
                .invoke(builder, arrayOf(digestSha256))

            // .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            specBuilderClass.getMethod("setAlgorithmParameterSpec", java.security.spec.AlgorithmParameterSpec::class.java)
                .invoke(builder, ECGenParameterSpec("secp256r1"))

            // Try StrongBox first (API 28+)
            try {
                specBuilderClass.getMethod("setIsStrongBoxBacked", Boolean::class.javaPrimitiveType)
                    .invoke(builder, true)
            } catch (_: NoSuchMethodException) {
                // StrongBox not available (pre-API 28), TEE fallback is automatic
            } catch (_: Exception) {
                // StrongBox failed, TEE fallback
            }

            val spec = specBuilderClass.getMethod("build").invoke(builder)
                as java.security.spec.AlgorithmParameterSpec

            val gen = KeyPairGenerator.getInstance("EC", "AndroidKeyStore")
            gen.initialize(spec)
            val kp = gen.generateKeyPair()
            return exportPublicKey(kp.public)
        } catch (e: Exception) {
            // If StrongBox was set but device doesn't support it, retry without
            if (e.cause?.javaClass?.name == "android.security.keystore.StrongBoxUnavailableException") {
                return generateKeyForAliasFallback(alias)
            }
            throw SynheartAuthError.CryptoError("Failed to generate hardware key: ${e.message}")
        }
    }

    private fun generateKeyForAliasFallback(alias: String): ByteArray {
        val specBuilderClass = Class.forName("android.security.keystore.KeyGenParameterSpec\$Builder")
        val purposeSign = 4
        val builder = specBuilderClass
            .getConstructor(String::class.java, Int::class.javaPrimitiveType)
            .newInstance(alias, purposeSign)
        specBuilderClass.getMethod("setDigests", Array<String>::class.java)
            .invoke(builder, arrayOf("SHA-256"))
        specBuilderClass.getMethod("setAlgorithmParameterSpec", java.security.spec.AlgorithmParameterSpec::class.java)
            .invoke(builder, ECGenParameterSpec("secp256r1"))
        // No StrongBox — TEE only
        val spec = specBuilderClass.getMethod("build").invoke(builder)
            as java.security.spec.AlgorithmParameterSpec
        val gen = KeyPairGenerator.getInstance("EC", "AndroidKeyStore")
        gen.initialize(spec)
        val kp = gen.generateKeyPair()
        return exportPublicKey(kp.public)
    }

    override fun sign(data: ByteArray, appId: String): ByteArray {
        val alias = tag(appId)
        try {
            val entry = keyStore.getEntry(alias, null)
                ?: throw SynheartAuthError.CryptoError("No key found for appId: $appId")
            val privateKey = (entry as KeyStore.PrivateKeyEntry).privateKey
            val sig = Signature.getInstance("SHA256withECDSA")
            sig.initSign(privateKey)
            sig.update(data)
            return sig.sign()
        } catch (e: SynheartAuthError) {
            throw e
        } catch (e: Exception) {
            // Detect key invalidation from Android Keystore exceptions
            val exName = e.javaClass.name
            val causeName = e.cause?.javaClass?.name
            if (exName == "android.security.keystore.KeyPermanentlyInvalidatedException" ||
                exName == "java.security.UnrecoverableKeyException" ||
                exName == "java.security.InvalidKeyException" ||
                causeName == "android.security.keystore.KeyPermanentlyInvalidatedException") {
                throw SynheartAuthError.KeyInvalidated()
            }
            throw SynheartAuthError.CryptoError("Signing failed: ${e.message}")
        }
    }

    override fun getPublicKey(appId: String): ByteArray? {
        val alias = tag(appId)
        val cert = keyStore.getCertificate(alias) ?: return null
        return exportPublicKey(cert.publicKey)
    }

    override fun promoteNextKey(appId: String) {
        // Android Keystore doesn't support rename — delete old, re-alias by
        // copying the next key's public cert reference. In practice on Keystore,
        // we delete the old alias and keep the next alias as the new primary.
        // We track alias mapping in the storage layer.
        val currentAlias = tag(appId)
        val nextAlias = nextTag(appId)
        if (!keyStore.containsAlias(nextAlias)) {
            throw SynheartAuthError.CryptoError("No next key to promote for appId: $appId")
        }
        keyStore.deleteEntry(currentAlias)
        // Keystore doesn't support rename, so we re-generate current from next's material.
        // Instead, we keep next as-is and update the alias mapping in StorageManager.
        // The caller (DeviceRegistrar) must update the storage alias mapping.
    }

    override fun deleteKey(appId: String) {
        val alias = tag(appId)
        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias)
        }
    }

    override fun deleteNextKey(appId: String) {
        val alias = nextTag(appId)
        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias)
        }
    }

    override fun hasKey(appId: String): Boolean =
        keyStore.containsAlias(tag(appId))

    private fun exportPublicKey(pub: PublicKey): ByteArray {
        val encoded = pub.encoded
        return if (encoded.size >= 65) {
            val point = encoded.copyOfRange(encoded.size - 65, encoded.size)
            if (point[0] == 0x04.toByte()) point else encoded
        } else {
            encoded
        }
    }
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
