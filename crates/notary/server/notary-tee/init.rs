use crate::error::Error;

#[cfg(feature = "notary_tee")]
pub async fn initiate_tee_notary() -> Result<(), Error> {
    tracing::info!("Initializing mock TEE notary (feature=notary_tee)...");
    // Initiate Tee
    Ok(())
}

#[cfg(not(feature = "notary_tee"))]
pub async fn initiate_tee_notary() -> Result<(), Error> {
    Ok(())
}


