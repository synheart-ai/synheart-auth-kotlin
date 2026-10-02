package ai.synheart.auth

import ai.synheart.auth.crypto.HardwareKeyManager
import java.io.InputStream
import java.io.OutputStream
import java.math.BigInteger
import java.security.Key
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreSpi
import java.security.PrivateKey
import java.security.Provider
import java.security.PublicKey
import java.security.Signature
import java.security.cert.Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.Collections
import java.util.Date
import java.util.Enumeration

/**
 * An in-memory stand-in for the Android Keystore, for driving
 * [HardwareKeyManager]'s alias bookkeeping on the JVM.
 *
 * It mirrors the two Keystore properties rotation depends on: entries are
 * addressed only by alias, and there is no rename. A JDK PKCS12 store cannot be
 * used instead because it needs a real X.509 chain, which the JDK cannot mint
 * without internal APIs.
 */
internal class FakeKeyStoreSpi : KeyStoreSpi() {
    private class FakeCertificate(private val key: PublicKey) : Certificate("FAKE") {
        override fun getEncoded(): ByteArray = key.encoded
        override fun verify(key: PublicKey?) {}
        override fun verify(key: PublicKey?, sigProvider: String?) {}
        override fun toString(): String = "FakeCertificate"
        override fun getPublicKey(): PublicKey = key
    }

    private val entries = linkedMapOf<String, Pair<PrivateKey, Certificate>>()

    fun put(alias: String, private: PrivateKey, public: PublicKey) {
        entries[alias] = private to FakeCertificate(public)
    }

    override fun engineGetKey(alias: String, password: CharArray?): Key? = entries[alias]?.first
    override fun engineGetCertificateChain(alias: String): Array<Certificate>? =
        entries[alias]?.let { arrayOf(it.second) }
    override fun engineGetCertificate(alias: String): Certificate? = entries[alias]?.second
    override fun engineGetCreationDate(alias: String): Date? = if (alias in entries) Date() else null
    override fun engineSetKeyEntry(alias: String, key: Key, password: CharArray?, chain: Array<out Certificate>?) =
        throw UnsupportedOperationException()
    override fun engineSetKeyEntry(alias: String, key: ByteArray, chain: Array<out Certificate>?) =
        throw UnsupportedOperationException()
    override fun engineSetCertificateEntry(alias: String, cert: Certificate) =
        throw UnsupportedOperationException()
    override fun engineDeleteEntry(alias: String) { entries.remove(alias) }
    override fun engineAliases(): Enumeration<String> = Collections.enumeration(entries.keys.toList())
    override fun engineContainsAlias(alias: String): Boolean = alias in entries
    override fun engineSize(): Int = entries.size
    override fun engineIsKeyEntry(alias: String): Boolean = alias in entries
    override fun engineIsCertificateEntry(alias: String): Boolean = false
    override fun engineGetCertificateAlias(cert: Certificate): String? = null
    override fun engineStore(stream: OutputStream?, password: CharArray?) {}
    override fun engineLoad(stream: InputStream?, password: CharArray?) {}

    // AndroidKeyStore hands out PrivateKeyEntry with a null protection
    // parameter; the JDK default implementation demands a password.
    override fun engineGetEntry(alias: String, protParam: KeyStore.ProtectionParameter?): KeyStore.Entry? =
        entries[alias]?.let { KeyStore.PrivateKeyEntry(it.first, arrayOf(it.second)) }
}

internal class FakeKeyStore(val spi: FakeKeyStoreSpi = FakeKeyStoreSpi()) :
    KeyStore(spi, object : Provider("FakeKeyStore", "1.0", "test") {}, "Fake") {
    init { load(null, null) }

    val aliases: List<String> get() = aliases().toList()

    /** Generate a P-256 key into this store, the way AndroidKeyStore does. */
    fun generate(alias: String): PublicKey {
        val gen = KeyPairGenerator.getInstance("EC")
        gen.initialize(ECGenParameterSpec("secp256r1"))
        val kp = gen.generateKeyPair()
        spi.put(alias, kp.private, kp.public)
        return kp.public
    }
}

/** A [HardwareKeyManager] over a [FakeKeyStore], with a JCA key generator. */
internal fun fakeHardwareKeyManager(store: FakeKeyStore = FakeKeyStore()): HardwareKeyManager =
    HardwareKeyManager(store) { alias -> store.generate(alias) }

/** Rebuild a P-256 public key from the 65-byte uncompressed point the SDK exports. */
internal fun p256FromUncompressed(point: ByteArray): PublicKey {
    require(point.size == 65 && point[0] == 0x04.toByte())
    val gen = KeyPairGenerator.getInstance("EC")
    gen.initialize(ECGenParameterSpec("secp256r1"))
    val params = (gen.generateKeyPair().public as ECPublicKey).params
    val x = BigInteger(1, point.copyOfRange(1, 33))
    val y = BigInteger(1, point.copyOfRange(33, 65))
    return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), params))
}

internal fun verifyEs256(publicKeyPoint: ByteArray, data: ByteArray, der: ByteArray): Boolean {
    val sig = Signature.getInstance("SHA256withECDSA")
    sig.initVerify(p256FromUncompressed(publicKeyPoint))
    sig.update(data)
    return sig.verify(der)
}
