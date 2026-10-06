package ai.synheart.auth.crypto

import ai.synheart.auth.models.SynheartAuthError
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import kotlin.concurrent.read
import kotlin.concurrent.write

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
class HardwareKeyManager internal constructor(
    private val keyStore: KeyStore,
    /**
     * Test seam: creates a key under the given alias *inside [keyStore]* and
     * returns its public key. `null` (production) builds a real Android
     * Keystore key with the StrongBox → TEE fallback. JVM tests have no
     * `android.security.keystore`, so they supply a generator that writes a
     * software key into an in-memory KeyStore — enough to exercise the alias
     * bookkeeping that rotation depends on.
     */
    private val keyGenerator: ((alias: String) -> PublicKey)?,
) : KeyManaging {

    constructor(keyStore: KeyStore) : this(keyStore, null)

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

    // ---------------------------------------------------------------------
    // Alias scheme
    //
    // Android Keystore cannot rename an entry, so a rotated key can never be
    // moved onto the original alias. Instead every key belongs to a numbered
    // *generation*, and the generation is encoded in its alias:
    //
    //   generation 0  ->  synheart_auth_{appId}          (the 0.1.x primary alias)
    //   generation 1  ->  synheart_auth_{appId}_next     (the 0.1.x "next" alias)
    //   generation n  ->  synheart_auth_{appId}_g{n}     (n >= 2)
    //
    // Invariant: the ACTIVE key is the LOWEST generation present; a pending
    // rotation key is always active + 1. Promotion therefore only has to delete
    // the active alias — the pending key becomes the lowest one and is active
    // from the next lookup on. No mapping needs to be persisted anywhere, so the
    // Keystore is the single source of truth and it cannot drift from app
    // storage (cleared prefs, backup restore, a crash between two writes).
    //
    // Generations 0 and 1 reuse the 0.1.x aliases, which keeps upgrades free:
    // a device registered on 0.1.4 has only generation 0 and keeps signing with
    // it, and a device that already rotated on 0.1.4 — whose primary alias was
    // deleted, leaving the new key stranded under `_next` — resolves `_next` as
    // its active key and starts signing again.
    //
    // Mutations take the write lock; lookups (sign, public key) take the read
    // lock, so a request signed concurrently with a promotion never resolves an
    // alias that is deleted before it is read.
    // ---------------------------------------------------------------------

    private val lock = java.util.concurrent.locks.ReentrantReadWriteLock()

    private fun baseAlias(appId: String): String = "synheart_auth_$appId"

    internal fun aliasFor(appId: String, generation: Long): String = when (generation) {
        0L -> baseAlias(appId)
        1L -> "${baseAlias(appId)}_next"
        else -> "${baseAlias(appId)}_g$generation"
    }

    private fun generationOf(appId: String, alias: String): Long? {
        val base = baseAlias(appId)
        if (alias == base) return 0L
        if (!alias.startsWith("${base}_")) return null
        val suffix = alias.substring(base.length + 1)
        if (suffix == "next") return 1L
        if (!suffix.startsWith("g")) return null
        // Reject anything that is not exactly the canonical rendering
        // (`g02`, `g+3`), so a foreign alias is never mistaken for ours.
        val n = suffix.substring(1).toLongOrNull() ?: return null
        return if (n >= 2 && suffix == "g$n") n else null
    }

    /** All generations present for [appId], ascending. */
    private fun generations(appId: String): List<Long> =
        keyStore.aliases().toList().mapNotNull { generationOf(appId, it) }.sorted()

    // Fast path for the common case: generation 0 is always the lowest, so a
    // never-rotated key needs no alias enumeration on the signing path.
    private fun activeGeneration(appId: String): Long? =
        if (keyStore.containsAlias(baseAlias(appId))) 0L else generations(appId).firstOrNull()

    private fun activeAlias(appId: String): String? =
        activeGeneration(appId)?.let { aliasFor(appId, it) }

    private fun deleteAlias(alias: String) {
        if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
    }

    override fun generateKeyPair(appId: String): ByteArray = lock.write {
        // A fresh identity starts at generation 0. Clear every generation first:
        // a leftover higher-generation key would otherwise be mistaken for a
        // pending rotation of the new one.
        generations(appId).forEach { deleteAlias(aliasFor(appId, it)) }
        generateKeyForAlias(aliasFor(appId, 0L))
    }

    override fun generateNextKeyPair(appId: String): ByteArray = lock.write {
        val active = activeGeneration(appId) ?: 0L
        // Drop any stale pending key (an earlier rotation that crashed or was
        // never promoted) so at most two generations exist at once.
        generations(appId).filter { it > active }.forEach { deleteAlias(aliasFor(appId, it)) }
        generateKeyForAlias(aliasFor(appId, active + 1))
    }

    /**
     * Create a hardware-backed P-256 signing key, preferring StrongBox and
     * falling back to the TEE.
     *
     * StrongBox is an *upgrade*, not a requirement: a key in the TEE is still
     * hardware-backed and non-exportable, which is what device identity needs.
     * So a StrongBox failure must never fail the whole operation — it must
     * retry without it.
     *
     * The previous implementation tried to detect that case by matching
     * `StrongBoxUnavailableException` at cause depth 1. That misses the shape
     * Android actually throws on a TEE-only device: `KeyPairGenerator` reports
     * `java.security.ProviderException: Failed to generated key pair.` with the
     * StrongBox cause nested deeper or absent entirely. On an SM-A235F
     * (`hardware_keystore=4`, no `strongbox_keystore`) the match failed, the
     * fallback never ran, and device registration was impossible — which is
     * most mid-range Android hardware, not an edge case.
     *
     * Rather than enumerate exception shapes, this attempts StrongBox and
     * retries on the TEE after ANY failure. It only gives up when the TEE
     * attempt also fails, and then reports both causes.
     */
    private fun generateKeyForAlias(alias: String): ByteArray {
        keyGenerator?.let { return exportPublicKey(it(alias)) }
        val strongBoxFailure = try {
            return generateKeyForAlias(alias, useStrongBox = true)
        } catch (e: Exception) {
            e
        }

        // A failed generation can leave a partial entry behind, and Keystore
        // will not overwrite one cleanly on every OEM. Clear it so the retry
        // starts from nothing.
        runCatching { if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias) }

        return try {
            generateKeyForAlias(alias, useStrongBox = false)
        } catch (e: Exception) {
            // Both causes, because either can be the real story: the TEE
            // message alone hides that StrongBox was tried first, and the
            // StrongBox message alone reads as a StrongBox problem when the
            // device simply has no usable keystore.
            throw SynheartAuthError.CryptoError(
                "Failed to generate hardware key for alias=$alias. " +
                    "StrongBox attempt: ${describe(strongBoxFailure)}. " +
                    "TEE attempt: ${describe(e)}",
                cause = e,
            )
        }
    }

    /**
     * One key-generation attempt.
     *
     * Built through reflection so this class still loads in JVM unit tests,
     * where `android.security.keystore` is absent — the Android build resolves
     * it at runtime.
     */
    private fun generateKeyForAlias(alias: String, useStrongBox: Boolean): ByteArray {
        val specBuilderClass =
            Class.forName("android.security.keystore.KeyGenParameterSpec\$Builder")
        val purposeSign = 4 // KeyProperties.PURPOSE_SIGN = 4
        val builder = specBuilderClass
            .getConstructor(String::class.java, Int::class.javaPrimitiveType)
            .newInstance(alias, purposeSign)

        // .setDigests(KeyProperties.DIGEST_SHA256)
        specBuilderClass.getMethod("setDigests", Array<String>::class.java)
            .invoke(builder, arrayOf("SHA-256"))

        // .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        specBuilderClass
            .getMethod("setAlgorithmParameterSpec", java.security.spec.AlgorithmParameterSpec::class.java)
            .invoke(builder, ECGenParameterSpec("secp256r1"))

        if (useStrongBox) {
            // Absent below API 28. Let a genuine reflection failure propagate:
            // the caller retries without StrongBox anyway, so swallowing it
            // here only hid which spec was actually built.
            specBuilderClass.getMethod("setIsStrongBoxBacked", Boolean::class.javaPrimitiveType)
                .invoke(builder, true)
        }

        val spec = specBuilderClass.getMethod("build").invoke(builder)
            as java.security.spec.AlgorithmParameterSpec

        val gen = KeyPairGenerator.getInstance("EC", "AndroidKeyStore")
        gen.initialize(spec)
        return exportPublicKey(gen.generateKeyPair().public)
    }

    /**
     * Render a throwable and its cause chain as one line.
     *
     * The chain is the point: Android reports StrongBox unavailability as a
     * `ProviderException` wrapping `StrongBoxUnavailableException`, so a
     * message-only description drops the very fact that explains the failure.
     */
    private fun describe(t: Throwable): String {
        val parts = mutableListOf<String>()
        var current: Throwable? = t
        var depth = 0
        // Bounded, and tracks seen links: a self-referencing cause chain would
        // otherwise loop forever inside an error path.
        val seen = mutableSetOf<Throwable>()
        while (current != null && depth < 8 && seen.add(current)) {
            parts += "${current.javaClass.name}: ${current.message}"
            current = current.cause
            depth++
        }
        return parts.joinToString(" <- ")
    }

    override fun sign(data: ByteArray, appId: String): ByteArray = lock.read {
        try {
            val alias = activeAlias(appId)
                ?: throw SynheartAuthError.CryptoError("No key found for appId: $appId")
            val entry = keyStore.getEntry(alias, null)
                ?: throw SynheartAuthError.CryptoError("No key found for appId: $appId")
            val privateKey = (entry as KeyStore.PrivateKeyEntry).privateKey
            val sig = Signature.getInstance("SHA256withECDSA")
            sig.initSign(privateKey)
            sig.update(data)
            sig.sign()
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
            throw SynheartAuthError.CryptoError("Signing failed: ${e.message}", cause = e)
        }
    }

    override fun getPublicKey(appId: String): ByteArray? = lock.read {
        val alias = activeAlias(appId) ?: return null
        val cert = keyStore.getCertificate(alias) ?: return null
        exportPublicKey(cert.publicKey)
    }

    /**
     * Make the pending key (generation active + 1) the active one.
     *
     * Keystore cannot rename, so this deletes the active alias; by the
     * lowest-generation-wins rule the pending key is active from the next
     * lookup on. 0.1.4 deleted the primary alias the same way but kept
     * resolving it, so every signature after a successful rotation failed.
     */
    override fun promoteNextKey(appId: String) = lock.write {
        val active = activeGeneration(appId)
            ?: throw SynheartAuthError.CryptoError("No next key to promote for appId: $appId")
        val pending = aliasFor(appId, active + 1)
        if (!keyStore.containsAlias(pending)) {
            throw SynheartAuthError.CryptoError("No next key to promote for appId: $appId")
        }
        keyStore.deleteEntry(aliasFor(appId, active))
    }

    /**
     * Delete the identity for [appId]: every generation, including a pending
     * rotation key. Deleting only the active key would silently promote the
     * pending one under the lowest-generation rule.
     */
    override fun deleteKey(appId: String) = lock.write {
        generations(appId).forEach { deleteAlias(aliasFor(appId, it)) }
    }

    /** Delete a pending rotation key, leaving the active key untouched. */
    override fun deleteNextKey(appId: String) = lock.write {
        val active = activeGeneration(appId) ?: 0L
        generations(appId).filter { it > active }.forEach { deleteAlias(aliasFor(appId, it)) }
    }

    override fun hasKey(appId: String): Boolean = lock.read { activeGeneration(appId) != null }

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
