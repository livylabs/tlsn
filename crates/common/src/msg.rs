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

/// TDX attestation payload sent from Verifier (Notary) to Prover.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdxPayload {
    /// Session identifier tied to this payload.
    pub session_id: String,
    /// Raw quote bytes encoded as lowercase hex.
    pub raw_quote: Option<String>,
    /// SGX/TDX signer measurement.
    pub mrsigner: Option<String>,
    /// SGX/TDX enclave measurement.
    pub mrenclave: Option<String>,
    /// Optional error message if attestation generation failed.
    pub error: Option<String>,
}
