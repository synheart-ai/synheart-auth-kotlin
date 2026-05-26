# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2026-05-26

### Fixed
- Android: `PlayIntegrityAttestationProvider.generateProof` now wraps
  its body in `withContext(Dispatchers.IO)`. Both the IntegrityService
  bind (`requestIntegrityToken`) and the subsequent
  synchronous `Tasks.await(...)` can park the calling thread for one
  to two seconds on a cold boot — long enough to trip the ANR
  watchdog when the caller's coroutine context happens to resolve to
  the main thread.
- Android: `DeviceRegistrar` wraps the three synchronous
  `KeyManaging` calls (`generateKeyPair`, `generateNextKeyPair`,
  `sign`) in `withContext(Dispatchers.IO)`. Android Keystore
  key generation against StrongBox-backed hardware (API 28+) can
  take one to two seconds for the first key on a device, with the
  same ANR risk if it lands on the UI thread.

The dispatch contract is now explicit at the leaf, independent of how
upstream callers structure their coroutine context.

## [0.1.1] - 2026-05-08

Source-available release. Maven Central artifact `ai.synheart:synheart-auth:0.1.0`
remains the published binary; 0.1.1 will land on Maven Central as a follow-up.

### Fixed
- `DeviceRegistrar`: closed a register/rotate race that could allow two
  concurrent rotation attempts to use the same outgoing nonce.
- `ClockSkewTracker`: skew is now auto-applied on every signed request
  rather than requiring an explicit `correctClockSkew()` call before
  each signing.
- `AuthNetworkClient`: HTTP connect/read timeouts added (previously
  inherited platform defaults, which on some Android networks meant
  effectively-unbounded waits).
- Logging: `§13` (audit-trail) log lines redact PII; `setLoggingEnabled`
  is now safe to enable in production.

### Documentation
- README documents `setLoggingEnabled`, `HardwareKeyManager`,
  `setBatchIngestOnStop`, and clarifies `registerDevice()` idempotency.
- Auth service URLs corrected to `api.synheart.ai`.
- Source-available governance (CONTRIBUTING.md, SECURITY.md) added.

## [0.1.0] - 2026-03-04

### Added

- **SynheartAuth** facade — coroutine-based API for device authentication
- **Software key management** — ECDSA P-256 via Java Security API (`SoftwareKeyManager`)
- **Request signing** — `signRequest()` constructs signed message with all 6 RFC-required headers
- **Device registration** — challenge-response flow with `DeviceRegistrar`
- **Key rotation** — old key signs new public key as proof of possession
- **Clock skew correction** — `ClockSkewTracker` with server timestamp alignment
- **Network client** — `HttpURLConnection`-based `AuthNetworkClient` with coroutine support
- **Storage management** — `StorageManager` for device ID and auth state persistence
- **Logging** — `AuthLogger` with configurable enable/disable (disabled by default)
- **Error types** — sealed class `SynheartAuthError` with 12 subtypes matching RFC
- **State machine** — `DeviceAuthState` enum with validated transitions
- **Unit tests** — 7 test files with JUnit 5 and kotlinx-coroutines-test
- **Mock implementations** — `MockKeyManager`, `MockAuthNetworkClient` for testing
