# SynheartAuth (Kotlin)

[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](https://github.com/synheart-ai/synheart-auth-kotlin)
[![Kotlin](https://img.shields.io/badge/kotlin-2.1-purple.svg)](https://kotlinlang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)


> **Source-available.** This repository is open for reading, auditing, and
> filing issues. We do **not** accept pull requests — see
> [CONTRIBUTING.md](CONTRIBUTING.md) for the rationale and how to contribute
> via issues. Security reports go through [SECURITY.md](SECURITY.md).
Device authentication SDK for Kotlin/JVM. Provides ECDSA P-256 device identity and request signing for Synheart mobile clients. Hardware-backed key storage (Android Keystore, StrongBox-preferred) is wired via a pluggable `KeyManaging` provider.

> See [RFC-AUTH-MOBILE-0001](https://github.com/synheart-ai/synheart-auth/blob/main/docs/RFC-AUTH-MOBILE-0001.md) for the full specification.

## Repository Structure

| Repository | Purpose |
|------------|---------|
| [synheart-auth](https://github.com/synheart-ai/synheart-auth) | RFC and specification |
| [synheart-auth-kotlin](https://github.com/synheart-ai/synheart-auth-kotlin) | Android/Kotlin native SDK (this repository) |
| [synheart-auth-swift](https://github.com/synheart-ai/synheart-auth-swift) | iOS/Swift native SDK |
| [synheart-auth-flutter](https://github.com/synheart-ai/synheart-auth-flutter) | Flutter plugin |

## Installation

Add to your `build.gradle.kts`:

```kotlin
dependencies {
    implementation("ai.synheart:synheart-auth:0.1.0")
}
```

Or as a local project dependency:

```kotlin
dependencies {
    implementation(project(":synheart-auth"))
}
```

## Quick Start

```kotlin
import ai.synheart.auth.SynheartAuth
import ai.synheart.auth.crypto.HardwareKeyManager

// 1. Initialize once at app launch with a hardware-backed key manager.
//    Production apps must do this before `configure(...)` — otherwise
//    the SDK falls back to SoftwareKeyManager + in-memory storage.
SynheartAuth.initialize(HardwareKeyManager.create())

// 2. Configure the auth service URL
SynheartAuth.shared.configure("https://api.synheart.ai/auth")

// 3. Register device (one-time)
val result = SynheartAuth.shared.registerDevice("com.myapp")
println("Device ID: ${result.deviceId}")

// 4. Sign every HTTP request
val headers = SynheartAuth.shared.signRequest(
    appId = "com.myapp",
    method = "POST",
    path = "/ingest/v1/hsi",
    bodyBytes = bodyJson.toByteArray()
)
// Apply headers to your HTTP request
```

## API Reference

### `SynheartAuth`

| Method | Description |
|--------|-------------|
| `configure(baseUrl)` | Set the auth service URL. Must be called first. |
| `setLoggingEnabled(enabled)` | Enable/disable debug logging. Disabled by default. |
| `isRegistered(appId)` | Check if device is registered for this app. |
| `registerDevice(appId)` | Register device with auth service. Returns `RegistrationResult` with `status` ∈ `{SUCCESS, FAILED, ALREADY_REGISTERED}` — idempotent on retry. Suspend function. |
| `signRequest(...)` | Sign an HTTP request. Returns `SignedHeaders`. |
| `getDeviceId(appId)` | Get the device ID, or null if not registered. |
| `rotateKey(appId)` | Rotate the device key. Old key signs new key. Suspend function. |
| `resetDeviceIdentity(appId)` | Delete all local auth state. |
| `correctClockSkew(serverTimestamp)` | Correct clock offset using server timestamp. |

### Security Architecture

- **Key storage**: Pluggable. The default is a software ECDSA P-256
  manager (Java Security API) suitable for tests; production hosts
  inject `HardwareKeyManager` via `SynheartAuth.initialize(...)` to
  bind the key into the Android Keystore (StrongBox-preferred,
  TEE-fallback).
- **Algorithm**: SHA256withECDSA (secp256r1 / P-256).
- **Concurrency**: Kotlin coroutines for async operations.

> ⚠️ **Persistence note** — the default `StorageManager` is **in-memory
> only**. Device identity is lost on every process restart unless the
> host injects a persistent `StorageManaging` (e.g. an
> `EncryptedSharedPreferences`-backed implementation) in
> `SynheartAuth.initialize(...)`. Production apps must wire one.

### Error Handling

All errors are subclasses of sealed class `SynheartAuthError`:

| Error | Description |
|-------|-------------|
| `NetworkError` | Network connectivity failure |
| `ChallengeExpired` | Registration challenge timed out |
| `KeyInvalidated` | Key was invalidated by the OS (biometric reset, factory reset, etc.) |
| `ClockSkew` | Client/server clock difference too large |
| `AlreadyRegistered` | Device already registered for this app |
| `NotRegistered` | Device not yet registered |
| `NotConfigured` | `configure()` not called |
| `RegistrationInProgress` | A concurrent `registerDevice` call is already running |
| `ServerError` | Server returned an error response |
| `CryptoError` | Cryptographic operation failed |
| `StorageError` | Storage operation failed |
| `InvalidStateTransition` | State machine refused the requested transition |

## Testing

```bash
./gradlew test
```

Mock implementations (`MockKeyManager`, `MockAuthNetworkClient`) are included for testing.

## Not a Medical Device

This SDK is intended for wellness and research use only. It is not a medical device, is not intended to diagnose, treat, cure, or prevent any disease or condition, and has not been evaluated by the FDA or any other regulatory body.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
