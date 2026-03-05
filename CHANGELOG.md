# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-03-04

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
- **Error types** — sealed class `SynheartAuthError` with 11 subtypes matching RFC
- **State machine** — `DeviceAuthState` enum with validated transitions
- **Unit tests** — 7 test files with JUnit 5 and kotlinx-coroutines-test
- **Mock implementations** — `MockKeyManager`, `MockAuthNetworkClient` for testing
