package com.synheart.auth

import com.synheart.auth.crypto.MockKeyManager
import com.synheart.auth.crypto.SoftwareKeyManager
import com.synheart.auth.models.SynheartAuthError
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class KeyManagerTest {
    private lateinit var keyManager: SoftwareKeyManager
    private val appId = "com.test.app"

    @BeforeEach
    fun setUp() {
        keyManager = SoftwareKeyManager()
    }

    @Test
    fun `generate key pair returns 65 byte uncompressed point`() {
        val pubKey = keyManager.generateKeyPair(appId)
        assertEquals(65, pubKey.size)
        assertEquals(0x04.toByte(), pubKey[0])
    }

    @Test
    fun `has key returns true after generation`() {
        assertFalse(keyManager.hasKey(appId))
        keyManager.generateKeyPair(appId)
        assertTrue(keyManager.hasKey(appId))
    }

    @Test
    fun `sign and verify roundtrip`() {
        keyManager.generateKeyPair(appId)
        val data = "test message".toByteArray()
        val signature = keyManager.sign(data, appId)
        assertTrue(signature.isNotEmpty())
        assertTrue(keyManager.verify(data, signature, appId))
    }

    @Test
    fun `verify fails with wrong data`() {
        keyManager.generateKeyPair(appId)
        val data = "test message".toByteArray()
        val signature = keyManager.sign(data, appId)
        assertFalse(keyManager.verify("wrong message".toByteArray(), signature, appId))
    }

    @Test
    fun `sign throws when no key exists`() {
        assertThrows(SynheartAuthError.CryptoError::class.java) {
            keyManager.sign("test".toByteArray(), appId)
        }
    }

    @Test
    fun `delete key removes key`() {
        keyManager.generateKeyPair(appId)
        assertTrue(keyManager.hasKey(appId))
        keyManager.deleteKey(appId)
        assertFalse(keyManager.hasKey(appId))
    }

    @Test
    fun `key rotation - generate next and promote`() {
        val originalPub = keyManager.generateKeyPair(appId)
        val nextPub = keyManager.generateNextKeyPair(appId)
        assertFalse(originalPub.contentEquals(nextPub))

        keyManager.promoteNextKey(appId)
        val currentPub = keyManager.getPublicKey(appId)
        assertArrayEquals(nextPub, currentPub)
    }

    @Test
    fun `promote next key throws when no next key`() {
        keyManager.generateKeyPair(appId)
        assertThrows(SynheartAuthError.CryptoError::class.java) {
            keyManager.promoteNextKey(appId)
        }
    }

    @Test
    fun `mock key manager failure injection`() {
        val mock = MockKeyManager()
        mock.shouldFailGenerate = true
        assertThrows(SynheartAuthError.CryptoError::class.java) {
            mock.generateKeyPair(appId)
        }
        mock.shouldFailGenerate = false
        mock.generateKeyPair(appId)
        mock.shouldFailSign = true
        assertThrows(SynheartAuthError.CryptoError::class.java) {
            mock.sign("test".toByteArray(), appId)
        }
    }
}
