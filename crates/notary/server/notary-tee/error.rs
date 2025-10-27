#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("TEE initialization error: {0}")]
    InitializationError(String),
    
    #[error("TEE operation error: {0}")]
    OperationError(String),
}
