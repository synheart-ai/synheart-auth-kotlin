package ai.synheart.auth.registration

/// Interface for platform-specific attestation proof generation.
/// Android: Play Integrity API
/// iOS: App Attest (handled in Swift)
interface AttestationProvider {
    /// Generate attestation proof for the given nonce.
    /// Returns the proof token string, or null if attestation is unavailable.
    suspend fun generateProof(nonce: String): String?
}

/// No-op provider for environments where attestation is not available.
class NoOpAttestationProvider : AttestationProvider {
    override suspend fun generateProof(nonce: String): String? = null
}
