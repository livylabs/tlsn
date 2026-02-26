use serde::{Serialize, Deserialize};
use tokio::process::Command;

use crate::NotaryServerError;
#[derive(Debug, Serialize , Deserialize)]
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

async fn tee_attestation(reportdata: String) -> Result<TdxAttestation, NotaryServerError> {
    let attestation = Command::new("trustauthority-cli")
        .args(["evidence", "--tdx" , "-u", &reportdata])
        .output()
        .await
        .map_err(|e|NotaryServerError::TeeAttestation(format!("Failed to produce Tee Attestation : {e}")))?;

    if !attestation.status.success(){
        let stdout = String::from_utf8_lossy(&attestation.stdout);
        let stderr = String::from_utf8_lossy(&attestation.stderr);
        return Err(NotaryServerError::TeeAttestation(format!("Tee attestation failed status: {}, \nstdout: \n{} , \nstderr: \n{}", attestation.status, stdout , stderr)));
    }

    let tee_attestation = serde_json::from_slice::<TdxAttestation>(&attestation.stdout).map_err(|e| {
        NotaryServerError::TeeAttestation(format!(
            "Could not parse TEE attestation JSON: {e}"
        ))
    })?;

    Ok(tee_attestation)
}

async fn check_tee() -> Result<(), NotaryServerError> 
{
    let trust_authority = Command::new("trustauthority-cli")
        .args(["--help"])
        .output()
        .await
        .map_err(|e|NotaryServerError::TeeAttestation(format!("Failed to produce Tee Attestation : {e}")))?;

    if !trust_authority.status.success() {
        return Err(NotaryServerError::TeeAttestation(format!("Trust authority not installed")))
    }
    Ok(())
}