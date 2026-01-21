use notary_tee::run_proxy;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    run_proxy().await?;
    Ok(())
}
