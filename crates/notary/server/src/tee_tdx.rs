use serde::{Serialize, Deserialize};
use tokio::process::Command;

use tlsn_common::msg::TdxAttestation;
use crate::NotaryServerError;

use base64::prelude::*;

pub async fn tee_attestation(reportdata: String) -> Result<TdxAttestation, NotaryServerError> {
    let attestation = Command::new("trustauthority-cli")
        .args(["evidence", "--tdx" , "-u", &reportdata.to_base64()])
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

pub async fn check_tee() -> Result<(), NotaryServerError> 
{
    let trust_authority = Command::new("trustauthority-cli")
        .args(["--help"])
        .output()
        .await
        .map_err(|e|NotaryServerError::TeeAttestation(format!("Trustauthority is not available : {e}")))?;

    if !trust_authority.status.success() {
        return Err(NotaryServerError::TeeAttestation(format!("Trust authority not installed")))
    }
    Ok(())
}


//Helper for the report data 
pub trait ToBase64 {
    fn to_base64(&self) -> String;
}

// Implement it for anything that can be viewed as bytes String, &str, Vec<u8>, etc.
impl<T: AsRef<[u8]>> ToBase64 for T {
    fn to_base64(&self) -> String {
        BASE64_STANDARD.encode(self)
    }
}