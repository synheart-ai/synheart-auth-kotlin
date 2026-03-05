package com.synheart.auth.storage

import com.synheart.auth.models.DeviceAuthState

interface StorageManaging {
    fun saveDeviceId(deviceId: String, appId: String)
    fun loadDeviceId(appId: String): String?
    fun saveState(state: DeviceAuthState, appId: String)
    fun loadState(appId: String): DeviceAuthState
    fun saveMetadata(metadata: Map<String, String>, appId: String)
    fun loadMetadata(appId: String): Map<String, String>?
    fun deleteAll(appId: String)
}

class StorageManager : StorageManaging {
    private val store = mutableMapOf<String, String>()

    private fun key(appId: String, suffix: String): String =
        "synheart_auth_${appId}_$suffix"

    override fun saveDeviceId(deviceId: String, appId: String) {
        synchronized(store) { store[key(appId, "device_id")] = deviceId }
    }

    override fun loadDeviceId(appId: String): String? =
        synchronized(store) { store[key(appId, "device_id")] }

    override fun saveState(state: DeviceAuthState, appId: String) {
        synchronized(store) { store[key(appId, "state")] = state.value }
    }

    override fun loadState(appId: String): DeviceAuthState =
        synchronized(store) {
            store[key(appId, "state")]
                ?.let { DeviceAuthState.fromValue(it) }
                ?: DeviceAuthState.UNREGISTERED
        }

    override fun saveMetadata(metadata: Map<String, String>, appId: String) {
        synchronized(store) {
            val json = org.json.JSONObject(metadata).toString()
            store[key(appId, "metadata")] = json
        }
    }

    override fun loadMetadata(appId: String): Map<String, String>? =
        synchronized(store) {
            store[key(appId, "metadata")]?.let { raw ->
                val json = org.json.JSONObject(raw)
                json.keys().asSequence().associateWith { json.getString(it) }
            }
        }

    override fun deleteAll(appId: String) {
        synchronized(store) {
            store.keys.filter { it.startsWith("synheart_auth_${appId}_") }
                .toList()
                .forEach { store.remove(it) }
        }
    }
}
