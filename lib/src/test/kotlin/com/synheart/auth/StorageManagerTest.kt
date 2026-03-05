package com.synheart.auth

import com.synheart.auth.models.DeviceAuthState
import com.synheart.auth.storage.StorageManager
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class StorageManagerTest {
    private lateinit var storage: StorageManager
    private val appId = "com.test.app"

    @BeforeEach
    fun setUp() {
        storage = StorageManager()
    }

    @Test
    fun `save and load device id`() {
        storage.saveDeviceId("device-123", appId)
        assertEquals("device-123", storage.loadDeviceId(appId))
    }

    @Test
    fun `load device id returns null when not set`() {
        assertNull(storage.loadDeviceId(appId))
    }

    @Test
    fun `save and load state`() {
        storage.saveState(DeviceAuthState.REGISTERED, appId)
        assertEquals(DeviceAuthState.REGISTERED, storage.loadState(appId))
    }

    @Test
    fun `load state returns unregistered by default`() {
        assertEquals(DeviceAuthState.UNREGISTERED, storage.loadState(appId))
    }

    @Test
    fun `save and load metadata`() {
        val metadata = mapOf("version" to "1", "build" to "42")
        storage.saveMetadata(metadata, appId)
        val loaded = storage.loadMetadata(appId)
        assertEquals(metadata, loaded)
    }

    @Test
    fun `load metadata returns null when not set`() {
        assertNull(storage.loadMetadata(appId))
    }

    @Test
    fun `delete all removes all keys`() {
        storage.saveDeviceId("device-123", appId)
        storage.saveState(DeviceAuthState.REGISTERED, appId)
        storage.saveMetadata(mapOf("k" to "v"), appId)
        storage.deleteAll(appId)
        assertNull(storage.loadDeviceId(appId))
        assertEquals(DeviceAuthState.UNREGISTERED, storage.loadState(appId))
        assertNull(storage.loadMetadata(appId))
    }

    @Test
    fun `app isolation - different apps do not share data`() {
        val appId2 = "com.test.app2"
        storage.saveDeviceId("device-A", appId)
        storage.saveDeviceId("device-B", appId2)
        assertEquals("device-A", storage.loadDeviceId(appId))
        assertEquals("device-B", storage.loadDeviceId(appId2))
    }

    @Test
    fun `delete all only affects specified app`() {
        val appId2 = "com.test.app2"
        storage.saveDeviceId("device-A", appId)
        storage.saveDeviceId("device-B", appId2)
        storage.deleteAll(appId)
        assertNull(storage.loadDeviceId(appId))
        assertEquals("device-B", storage.loadDeviceId(appId2))
    }

    @Test
    fun `overwrite existing device id`() {
        storage.saveDeviceId("device-old", appId)
        storage.saveDeviceId("device-new", appId)
        assertEquals("device-new", storage.loadDeviceId(appId))
    }
}
