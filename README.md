# SynheartAuth (Kotlin)

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/synheart-ai/synheart-auth-kotlin)
[![Kotlin](https://img.shields.io/badge/kotlin-2.1-purple.svg)](https://kotlinlang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

Device authentication SDK for Android. Provides ECDSA P-256 device identity and request signing for Synheart mobile clients.

> See [RFC-AUTH-MOBILE-0001](https://github.com/synheart-ai/synheart-auth/blob/main/docs/RFC-AUTH-MOBILE-0001.md) for the full specification.

## Repository Structure

| Repository | Purpose |
|------------|---------|
| [synheart-auth](https://github.com/synheart-ai/synheart-auth) | RFC and specification |
| [synheart-auth-kotlin](https://github.com/synheart-ai/synheart-auth-kotlin) | Android/Kotlin native SDK (this repository) |
| [synheart-auth-swift](https://github.com/synheart-ai/synheart-auth-swift) | iOS/Swift native SDK |
| [synheart-auth-dart](https://github.com/synheart-ai/synheart-auth-dart) | Flutter plugin |

## Installation

Add to your `build.gradle.kts`:

```kotlin
dependencies {
    implementation("ai.synheart:synheart-auth:1.0.0")
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

// 1. Configure once at app launch
SynheartAuth().configure("https://auth.synheart.ai")

// 2. Register device (one-time)
val result = synheartAuth.registerDevice("com.myapp")
println("Device ID: ${result.deviceId}")

// 3. Sign every HTTP request
val headers = synheartAuth.signRequest(
    appId = "com.myapp",
    method = "POST",
    path = "/v1/ingest/hsi",
    bodyBytes = bodyJson.toByteArray()
)
// Apply headers to your HTTP request
```

## API Reference

### `SynheartAuth`

| Method | Description |
|--------|-------------|
| `configure(baseUrl)` | Set the auth service URL. Must be called first. |
| `isRegistered(appId)` | Check if device is registered for this app. |
| `registerDevice(appId)` | Register device with auth service. Idempotent. Suspend function. |
| `signRequest(...)` | Sign an HTTP request. Returns `SignedHeaders`. |
| `getDeviceId(appId)` | Get the device ID, or null if not registered. |
| `rotateKey(appId)` | Rotate the device key. Old key signs new key. Suspend function. |
| `resetDeviceIdentity(appId)` | Delete all local auth state. |
| `correctClockSkew(serverTimestamp)` | Correct clock offset using server timestamp. |

### Security Architecture

- **Key Storage**: Software key manager (ECDSA P-256 via Java Security API)
- **Algorithm**: SHA256withECDSA (secp256r1 / P-256)
- **Persistence**: In-memory key storage with `StorageManager`
- **Concurrency**: Kotlin coroutines for async operations

### Error Handling

All errors are subclasses of sealed class `SynheartAuthError`:

| Error | Description |
|-------|-------------|
| `NetworkError` | Network connectivity failure |
| `ChallengeExpired` | Registration challenge timed out |
| `AttestationUnavailable` | Platform attestation not available |
| `KeyInvalidated` | Key was invalidated |
| `ClockSkew` | Client/server clock difference too large |
| `AlreadyRegistered` | Device already registered |
| `NotRegistered` | Device not yet registered |
| `NotConfigured` | `configure()` not called |
| `CryptoError` | Cryptographic operation failed |
| `StorageError` | Storage operation failed |
| `ServerError` | Server returned an error |

## Testing

```bash
./gradlew test
```

Mock implementations (`MockKeyManager`, `MockAuthNetworkClient`) are included for testing.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
