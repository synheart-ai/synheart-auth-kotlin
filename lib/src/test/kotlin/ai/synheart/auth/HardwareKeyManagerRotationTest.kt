package ai.synheart.auth

import ai.synheart.auth.models.DeviceAuthState
import ai.synheart.auth.models.RotationResult
import ai.synheart.auth.models.SynheartAuthError
import ai.synheart.auth.network.ChallengeResponse
import ai.synheart.auth.network.MockAuthNetworkClient
import ai.synheart.auth.network.RegisterResponse
import ai.synheart.auth.network.RotateKeyResponse
import ai.synheart.auth.registration.DeviceRegistrar
import ai.synheart.auth.storage.StorageManager
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.util.Base64

/**
 * Guards key rotation on [ai.synheart.auth.crypto.HardwareKeyManager].
 *
 * The bug these exist for: Android Keystore cannot rename an entry, so 0.1.4's
 * `promoteNextKey` deleted the primary alias and left the new key under
 * `_next` — while `sign` and `getPublicKey` kept resolving the primary alias.
 * Every request after a *successful* rotation failed with "No key found". The
 * software manager could rename and so never showed it, which is why the old
 * tests passed.
 */
class HardwareKeyManagerRotationTest {
    private val appId = "com.test.app"
    private val data = "GET\n/v1/data\n1700000000\n".toByteArray()

    private fun rotateLocally(km: ai.synheart.auth.crypto.HardwareKeyManager): ByteArray {
        val next = km.generateNextKeyPair(appId)
        km.promoteNextKey(appId)
        return next
    }

    @Test
    fun `sign works after one, two and three rotations`() {
        val store = FakeKeyStore()
        val km = fakeHardwareKeyManager(store)
        var current = km.generateKeyPair(appId)
        assertTrue(verifyEs256(current, data, km.sign(data, appId)))

        repeat(3) { i ->
            val next = rotateLocally(km)
            assertFalse(next.contentEquals(current), "rotation ${i + 1} must produce a new key")
            assertArrayEquals(next, km.getPublicKey(appId), "public key after rotation ${i + 1}")
            assertTrue(km.hasKey(appId))
            val sig = km.sign(data, appId)
            assertTrue(verifyEs256(next, data, sig), "new key must sign after rotation ${i + 1}")
            assertFalse(verifyEs256(current, data, sig), "old key must be retired after rotation ${i + 1}")
            // Never more than one key per identity once a rotation completes.
            assertEquals(1, store.aliases.size, "aliases after rotation ${i + 1}: ${store.aliases}")
            current = next
        }
    }

    @Test
    fun `a key registered on 0_1_4 keeps signing and can rotate`() {
        // 0.1.4 stored the identity key under exactly this alias.
        val store = FakeKeyStore()
        val legacy = store.generate("synheart_auth_$appId")
        val legacyPoint = p256Point(legacy)
        val km = fakeHardwareKeyManager(store)

        assertTrue(km.hasKey(appId))
        assertArrayEquals(legacyPoint, km.getPublicKey(appId))
        assertTrue(verifyEs256(legacyPoint, data, km.sign(data, appId)))

        val next = rotateLocally(km)
        assertTrue(verifyEs256(next, data, km.sign(data, appId)))
    }

    @Test
    fun `a device already rotated on 0_1_4 resolves its stranded key`() {
        // After a 0.1.4 rotation the primary alias was deleted and the key the
        // server now holds sat under `_next`, unreachable. It must be found.
        val store = FakeKeyStore()
        val stranded = p256Point(store.generate("synheart_auth_${appId}_next"))
        val km = fakeHardwareKeyManager(store)

        assertTrue(km.hasKey(appId))
        assertArrayEquals(stranded, km.getPublicKey(appId))
        assertTrue(verifyEs256(stranded, data, km.sign(data, appId)))

        val next = rotateLocally(km)
        assertTrue(verifyEs256(next, data, km.sign(data, appId)))
    }

    @Test
    fun `a pending key does not replace the active key until promoted`() {
        val km = fakeHardwareKeyManager()
        val active = km.generateKeyPair(appId)
        km.generateNextKeyPair(appId)
        assertArrayEquals(active, km.getPublicKey(appId))
        assertTrue(verifyEs256(active, data, km.sign(data, appId)))
    }

    @Test
    fun `a failed rotation leaves the active key in place`() {
        val store = FakeKeyStore()
        val km = fakeHardwareKeyManager(store)
        val active = km.generateKeyPair(appId)
        km.generateNextKeyPair(appId)
        km.deleteNextKey(appId)
        assertEquals(listOf("synheart_auth_$appId"), store.aliases)
        assertTrue(verifyEs256(active, data, km.sign(data, appId)))
        assertThrows(SynheartAuthError.CryptoError::class.java) { km.promoteNextKey(appId) }
    }

    @Test
    fun `a stale pending key is replaced by the next rotation`() {
        val store = FakeKeyStore()
        val km = fakeHardwareKeyManager(store)
        km.generateKeyPair(appId)
        val stale = km.generateNextKeyPair(appId) // e.g. the app died before promotion
        val fresh = km.generateNextKeyPair(appId)
        assertFalse(stale.contentEquals(fresh))
        km.promoteNextKey(appId)
        assertArrayEquals(fresh, km.getPublicKey(appId))
        assertEquals(1, store.aliases.size)
    }

    @Test
    fun `deleteKey removes every generation, including a pending key`() {
        val store = FakeKeyStore()
        val km = fakeHardwareKeyManager(store)
        km.generateKeyPair(appId)
        rotateLocally(km)
        km.generateNextKeyPair(appId)
        km.deleteKey(appId)
        assertFalse(km.hasKey(appId))
        assertNull(km.getPublicKey(appId))
        assertTrue(store.aliases.isEmpty(), "left behind: ${store.aliases}")
    }

    @Test
    fun `re-registering after rotations starts a clean identity`() {
        val store = FakeKeyStore()
        val km = fakeHardwareKeyManager(store)
        km.generateKeyPair(appId)
        rotateLocally(km)
        rotateLocally(km)
        val fresh = km.generateKeyPair(appId)
        assertEquals(listOf("synheart_auth_$appId"), store.aliases)
        assertTrue(verifyEs256(fresh, data, km.sign(data, appId)))
    }

    @Test
    fun `identities are isolated per appId`() {
        val km = fakeHardwareKeyManager()
        val other = "com.test.other"
        km.generateKeyPair(appId)
        val otherKey = km.generateKeyPair(other)
        rotateLocally(km)
        rotateLocally(km)
        assertArrayEquals(otherKey, km.getPublicKey(other))
        assertTrue(verifyEs256(otherKey, data, km.sign(data, other)))
    }

    @Test
    fun `end to end - register then rotate three times through DeviceRegistrar`() = runTest {
        val km = fakeHardwareKeyManager()
        val storage = StorageManager()
        val network = MockAuthNetworkClient().apply {
            challengeResponse = ChallengeResponse("challenge", "2099-12-31T23:59:59Z")
            registerResponse = RegisterResponse("device-1", "ok")
            rotateKeyResponse = RotateKeyResponse("ok")
        }
        val registrar = DeviceRegistrar(km, storage, network)
        val auth = SynheartAuth.createForTesting(km, storage, network)

        registrar.register(appId)
        // What the server believes the device key is.
        var serverKey = Base64.getDecoder().decode(network.lastRegisterRequest!!.publicKey)

        repeat(3) { i ->
            val result = registrar.rotateKey(appId)
            assertEquals(RotationResult.RotationStatus.SUCCESS, result.status)
            val req = network.lastRotateKeyRequest!!
            val newKey = Base64.getDecoder().decode(req.newPublicKey)
            // The server accepts the rotation only if the key it already holds
            // signed the new one.
            assertTrue(
                verifyEs256(serverKey, newKey, Base64.getDecoder().decode(req.oldKeySignature)),
                "rotation ${i + 1}: old-key signature must verify against the server's key",
            )
            serverKey = newKey

            val headers = auth.signRequest(appId, "GET", "/v1/data")
            val message = ai.synheart.auth.crypto.RequestSigner.buildMessage("GET", "/v1/data", headers.timestamp)
            assertTrue(
                verifyEs256(serverKey, message, Base64.getDecoder().decode(headers.signature)),
                "rotation ${i + 1}: request signature must verify against the rotated key",
            )
            assertEquals(DeviceAuthState.REGISTERED, storage.loadState(appId))
        }
    }

    private fun p256Point(key: java.security.PublicKey): ByteArray {
        val encoded = key.encoded
        return encoded.copyOfRange(encoded.size - 65, encoded.size)
    }
}
