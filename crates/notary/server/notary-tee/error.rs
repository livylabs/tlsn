#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("TEE initialization error: {0}")]
    InitializationError(String),
    
    #[error("TEE operation error: {0}")]
    OperationError(String),

    #[error("proxy io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("proxy http error: {0}")]
    Http(#[from] http::Error),

    #[error("proxy http error: {0}")]
    HttpError(String),

    #[error("proxy upstream error: {0}")]
    Upstream(String),

    #[error("proxy tdx attestation error: {0}")]
    TdxAttestation(String),

    #[error("proxy serde json error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    #[error("proxy configuration error: {0}")]
    Configuration(String),
}
