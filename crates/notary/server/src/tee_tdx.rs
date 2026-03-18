use std::env;

use base64::prelude::*;
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tlsn_common::msg::TdxAttestation as TeeQuote;

use crate::NotaryServerError;

/// Cached TDX quote payload for the `/info` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializationTeeQuote {
    /// Parsed TDX attestation returned by Trust Authority.
    pub tdx_attestation: Option<TeeQuote>,
    /// Error message when TDX attestation is unavailable.
    pub error: Option<String>,
}

impl InitializationTeeQuote {
    /// Returns a successful cached TDX quote value.
    pub fn ready(tdx_attestation: TeeQuote) -> Self {
        Self {
            tdx_attestation: Some(tdx_attestation),
            error: None,
        }
    }

    /// Returns an unavailable cached TDX quote value with a reason.
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self {
            tdx_attestation: None,
            error: Some(message.into()),
        }
    }
}

/// Produces a per-notarization TDX attestation from Trust Authority.
pub async fn tee_attestation(reportdata: String) -> Result<TeeQuote, NotaryServerError> {
    tee_attestation_bytes(reportdata.as_bytes()).await
}

/// Produces an initialization TDX quote payload for `/info`.
pub async fn initialization_quote(reportdata: &[u8]) -> InitializationTeeQuote {
    match tee_attestation_bytes(reportdata).await {
        Ok(quote) => InitializationTeeQuote::ready(quote),
        Err(err) => InitializationTeeQuote::unavailable(format!("Tdx Not available: {}", err)),
    }
}

async fn tee_attestation_bytes(reportdata: &[u8]) -> Result<TeeQuote, NotaryServerError> {
    let mut cmd = Command::new("trustauthority-cli");
    cmd.args([
        "evidence",
        "--tdx",
        "-u",
        &BASE64_STANDARD.encode(reportdata),
    ]);

    let config_path = tee_config_path().ok_or_else(|| {
        NotaryServerError::TeeAttestation(
            "No Trust Authority config found. Set PATH_TEE_CONFIG (or path_tee_config).".into(),
        )
    })?;
    cmd.args(["-c", &config_path]);

    let output = cmd.output().await.map_err(|e| {
        NotaryServerError::TeeAttestation(format!("Failed to produce Tee Attestation : {e}"))
    })?;

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NotaryServerError::TeeAttestation(format!(
            "Tee attestation failed status: {}, \nstdout: \n{} , \nstderr: \n{}",
            output.status, stdout, stderr
        )));
    }

    parse_tdx_attestation(&output.stdout)
}

fn parse_tdx_attestation(stdout: &[u8]) -> Result<TeeQuote, NotaryServerError> {
    match serde_json::from_slice::<TeeQuote>(stdout) {
        Ok(parsed) => Ok(parsed),
        Err(primary_err) => {
            let Some(start_idx) = stdout.iter().position(|b| *b == b'{') else {
                return Err(NotaryServerError::TeeAttestation(format!(
                    "Could not parse TEE attestation JSON: {primary_err}"
                )));
            };

            serde_json::from_slice::<TeeQuote>(&stdout[start_idx..]).map_err(|trimmed_err| {
                NotaryServerError::TeeAttestation(format!(
                    "Could not parse TEE attestation JSON: {primary_err}; after trimming preamble: {trimmed_err}"
                ))
            })
        }
    }
}

fn tee_config_path() -> Option<String> {
    env::var("PATH_TEE_CONFIG")
        .ok()
        .or_else(|| env::var("path_tee_config").ok())
        .filter(|value| !value.trim().is_empty())
}

/// Validates that the Trust Authority CLI binary is available.
pub async fn check_tee() -> Result<(), NotaryServerError> {
    let trust_authority = Command::new("trustauthority-cli")
        .args(["--help"])
        .output()
        .await
        .map_err(|e| {
            NotaryServerError::TeeAttestation(format!("Trustauthority is not available : {e}"))
        })?;

    if !trust_authority.status.success() {
        return Err(NotaryServerError::TeeAttestation(
            "Trust authority not installed".into(),
        ));
    }

    Ok(())
}