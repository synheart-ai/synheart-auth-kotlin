package ai.synheart.auth

import ai.synheart.auth.crypto.HardwareKeyManager
import ai.synheart.auth.models.SynheartAuthError
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.security.KeyStore

/**
 * Guards the StrongBox → TEE fallback in [HardwareKeyManager].
 *
 * The bug these exist for: StrongBox is an upgrade, not a requirement — a TEE
 * key is still hardware-backed and non-exportable — but a StrongBox failure
 * used to fail the whole operation. The fallback was gated on matching
 * `StrongBoxUnavailableException` at cause depth 1, which is not the shape
 * Android throws on a TEE-only device: `KeyPairGenerator` reports
 * `java.security.ProviderException: Failed to generated key pair.` with the
 * StrongBox cause nested deeper or absent. The match failed, the fallback never
 * ran, and device registration was impossible on an SM-A235F
 * (`hardware_keystore=4`, no `strongbox_keystore`) — most mid-range Android
 * hardware, not an edge case.
 *
 * The Keystore path itself cannot run here: `android.security.keystore` does not
 * exist on the JVM, which is why [ai.synheart.auth.crypto.SoftwareKeyManager]
 * exists for the other tests. That absence is what makes these assertions
 * possible — BOTH attempts fail identically, so the error proves both were made
 * and that the cause survived. Under the old single-attempt code the message
 * named one attempt and the cause was dropped.
 */
class HardwareKeyManagerFallbackTest {

    /** A JVM keystore, enough for the alias bookkeeping around generation. */
    private fun manager(): HardwareKeyManager {
        val ks = KeyStore.getInstance(KeyStore.getDefaultType())
        ks.load(null, null)
        return HardwareKeyManager(ks)
    }

    @Test
    fun `both attempts are made before giving up`() {
        val error = assertThrows<SynheartAuthError.CryptoError> {
            manager().generateKeyPair("com.test.app")
        }

        val message = error.message ?: ""
        // Naming both is the observable proof the retry happened at all.
        assertTrue(
            message.contains("StrongBox attempt"),
            "expected the StrongBox attempt to be reported, got: $message",
        )
        assertTrue(
            message.contains("TEE attempt"),
            "expected a TEE retry after StrongBox failed, got: $message",
        )
    }

    @Test
    fun `the underlying cause is chained, not dropped`() {
        val error = assertThrows<SynheartAuthError.CryptoError> {
            manager().generateKeyPair("com.test.app")
        }

        // Without this the runtime could only report "platform crypto: null
        // callback result", which is indistinguishable from an unwired callback
        // — a completely different fix.
        assertNotNull(error.cause, "CryptoError must carry the Keystore cause")
    }

    @Test
    fun `the failure names the alias it was generating`() {
        val error = assertThrows<SynheartAuthError.CryptoError> {
            manager().generateKeyPair("com.test.app")
        }

        // Keys are per-device-id; without the alias a failure cannot be tied to
        // the identity it belonged to.
        assertTrue(
            error.message?.contains("synheart_auth_com.test.app") == true,
            "expected the alias in the message, got: ${error.message}",
        )
    }

    @Test
    fun `the next-key path gets the same fallback`() {
        // Key rotation generates through the same helper. A fallback that
        // covered only the primary key would strand rotation on exactly the
        // devices this fixes.
        val error = assertThrows<SynheartAuthError.CryptoError> {
            manager().generateNextKeyPair("com.test.app")
        }

        assertTrue(error.message?.contains("TEE attempt") == true)
        assertTrue(error.message?.contains("synheart_auth_com.test.app_next") == true)
    }
}
