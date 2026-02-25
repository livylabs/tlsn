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

/// TDX attestattion sent from Notary to Prover 
#[derive(Debug, Serialize , Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdxAttestation{
    /// Type of tee attestation
   pub tdx: TdxEvidence
}
#[derive(Debug, Serialize , Deserialize)]
/// Tee attestation data
pub struct TdxEvidence{
    /// Report customs data 64 bytes
    pub runtime_data: String,
    /// Tee quote used for verification
    pub quote: String,
    /// Anti-replay nonce
    pub verifier_nonce: VerifierNonce,
}
#[derive(Debug, Serialize , Deserialize)]
/// Extra metadata from the attestation
pub struct VerifierNonce{
    /// Random fresh value
    pub val: String,
    /// Timestamp
    pub iat: String,
    /// Signature from the verifier service
    pub signature: String,
}
