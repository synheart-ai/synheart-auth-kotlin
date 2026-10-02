# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- Android: signing failed after every successful key rotation with
  `HardwareKeyManager`. Keystore cannot rename an entry, so `promoteNextKey`
  deleted the primary alias `synheart_auth_{appId}` and left the new key under
  `synheart_auth_{appId}_next`, expecting a caller to remap the alias —
  nothing did, and `sign` / `getPublicKey` / `hasKey` kept resolving the
  deleted alias ("No key found"). Keys now belong to numbered generations
  encoded in the alias (`synheart_auth_{appId}`, `…_next`, `…_g{n}`); the
  lowest generation present is the active key and a pending key is always
  the next one, so promotion only deletes the active alias and no mapping
  has to be persisted. Rotating any number of times works. Keys registered
  on 0.1.4 keep working unchanged, and a device that already rotated on
  0.1.4 resolves its stranded `_next` key and signs again.
- `HardwareKeyManager.deleteKey` now removes every key generation for the
  app id, including a pending rotation key.
- Key rotation no longer deletes the new key when a local step fails after
  the server has accepted it.
- Device identity no longer disappears on process restart when the app
  uses the new `initialize(context)` (see Added).
- A registration or rotation interrupted by process death no longer leaves
  persisted state that blocks `registerDevice` with `RegistrationInProgress`
  forever; it is repaired on the next `registerDevice` / `rotateKey`.
- `initialize(...)` after `configure(...)` now takes effect for registration
  and rotation too (the registrar kept the previous key manager and storage).

### Added
- `SynheartAuth.initialize(context)`: the production setup on Android —
  `HardwareKeyManager` plus persistent storage in
  `Context.getNoBackupFilesDir()/synheart_auth`. `context` is typed `Any`
  (this library has no Android compile dependency) and must be an
  `android.content.Context`.
- `SynheartAuth.initialize(keyManager, storage)`.
- `FileStorageManager`: persistent `StorageManaging` (one atomically-written
  file per app id; `device_id`, state and metadata only — never key
  material).
- On an Android runtime, an always-on security warning is logged when the
  SDK is configured with `SoftwareKeyManager` or the in-memory
  `StorageManager`.

### Changed
- `isRegistered(appId)` now also requires the signing key to be present,
  and `registerDevice` re-registers when the stored state is REGISTERED but
  the key is gone (Keystore cleared, state restored onto another device)
  instead of returning `ALREADY_REGISTERED` for an identity that cannot sign.
- `initialize(keyManager)` is unchanged and still uses in-memory storage;
  it is now documented as such. Migrate Android apps to
  `initialize(context)`.

## [0.1.4] - 2026-09-24

### Fixed
- Android: `HardwareKeyManager` could not generate a signing key on TEE-only
  devices, so device registration was impossible on most mid-range Android.
  `generateKeyForAlias` requested StrongBox and tried to recover by matching
  `StrongBoxUnavailableException` at cause depth 1 — not the shape Android
  actually throws. `KeyPairGenerator` reports
  `java.security.ProviderException: Failed to generated key pair.` with the
  StrongBox cause nested deeper or absent entirely, so on a device without
  StrongBox (e.g. SM-A235F: `hardware_keystore=4`, no `strongbox_keystore`) the
  match failed, the TEE fallback never ran, and registration died with
  `ERR_DEVICE_AUTH: platform crypto: null callback result`. The fallback code
  itself was correct — nothing could reach it.

  StrongBox is an upgrade, not a requirement: a TEE key is still hardware-backed
  and non-exportable, which is what device identity needs, so a StrongBox failure
  must never fail the operation. Rather than enumerate exception shapes — the
  approach that broke — generation now attempts StrongBox and retries on the TEE
  after *any* failure, giving up only when both fail and reporting both cause
  chains. The alias is cleared between attempts, since a failed generation can
  leave a partial entry that not every OEM overwrites cleanly.
- `SynheartAuthError.CryptoError` now forwards its cause. The base class already
  accepted one and `CryptoError` was discarding it, so the underlying Keystore
  exception — the only actionable detail — never reached callers, leaving them a
  message and no chain to inspect.

### Documentation
- README: version badge and Maven coordinate now match the released version
  (they still said `0.1.1` against a `0.1.3` build).

## [0.1.3] - 2026-06-28

### Fixed
- Android: `PlayIntegrityAttestationProvider.generateProof` now awaits the
  Play Integrity `Task` with a 30-second timeout (the bounded
  `Tasks.await(Task, long, TimeUnit)` overload) instead of the unbounded
  one-argument `Tasks.await(Task)`. Play Integrity is supposed to invoke a
  success/failure listener, but a stalled `IntegrityService` bind — no Play
  Store, an unlinked package, or a sideloaded debug build whose cloud project
  can't be resolved — can leave the `Task` pending indefinitely, parking the
  calling thread forever so registration never reaches a terminal state. A
  timeout now raises `TimeoutException`, which is treated as "attestation
  unavailable" (`generateProof` returns `null`), letting the caller fall back
  or retry. This complements 0.1.2 (which moved the blocking work off the main
  thread to avoid ANRs); that addressed *slow* resolution, this addresses
  resolution that *never arrives*.

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
