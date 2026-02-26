//! Message types.

use serde::{Deserialize, Serialize};

use tlsn_core::connection::{ServerCertData, ServerName};

/// Message sent from Prover to Verifier to prove the server identity.
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerIdentityProof {
    /// Server name.
    pub name: ServerName,
    /// Server identity data.
    pub data: ServerCertData,
}

/// TDX attestation payload returned by an attestation provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TdxAttestation {
    /// TDX evidence body.
    pub tdx: TdxEvidence,
}

/// TDX evidence fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TdxEvidence {
    /// Report custom data (provider-encoded string).
    pub runtime_data: String,
    /// TEE quote string (provider-encoded, commonly base64).
    pub quote: String,
    /// Anti-replay verifier nonce metadata.
    pub verifier_nonce: VerifierNonce,
}

/// Verifier-issued nonce metadata for freshness validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierNonce {
    /// Fresh nonce value.
    pub val: String,
    /// Issued-at timestamp.
    pub iat: String,
    /// Verifier signature over the nonce payload.
    pub signature: String,
}

/// Wrapper message for sending TDX attestation alongside protocol data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeAttestation {
    /// Parsed TDX attestation payload.
    pub tdx_attestation: TdxAttestation
}
