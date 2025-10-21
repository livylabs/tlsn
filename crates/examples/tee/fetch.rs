use std::env;

use http_body_util::Empty;
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use spansy::Spanned;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::info;

use notary_client::{Accepted, NotarizationRequest, NotaryClient};
use tlsn_core::{request::RequestConfig, transcript::TranscriptCommitConfig, CryptoProvider};
use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};
use tlsn_prover::{Prover, ProverConfig};

const USER_AGENT: &str = "TLSNotary-Fetch/1.0";


#[cfg(feature = "notary_tee")]
async fn initiate_tee_notary() -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("Initializing mock TEE notary (feature=notary_tee)...");
    // Initiate Tee
    Ok(())
}

#[cfg(not(feature = "notary_tee"))]
async fn initiate_tee_notary() -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    // If feature enabled, initialize (mock) TEE notary bootstrap
    initiate_tee_notary().await?;

    let notary_host: String = env::var("NOTARY_HOST").unwrap_or("127.0.0.1".into());
    let notary_port: u16 = env::var("NOTARY_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(7047);

    let server_domain: String = env::var("SERVER_DOMAIN").unwrap_or("jsonplaceholder.typicode.com".into());
    let server_port: u16 = env::var("SERVER_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(443);
    let path: String = env::var("SERVER_PATH").unwrap_or("/todos/1".into());

    // Connect to notary (no TLS for local dev)
    let notary_client = NotaryClient::builder()
        .host(notary_host)
        .port(notary_port)
        .enable_tls(false)
        .build()
        .unwrap();

    let notarization_request = NotarizationRequest::builder()
        .max_sent_data(1 << 12)
        .max_recv_data(1 << 14)
        .build()?;

    let Accepted { io: notary_connection, .. } = notary_client
        .request_notarization(notarization_request)
        .await
        .expect("notary must be running");

    // Use default web PKI
    let crypto_provider = CryptoProvider::default();

    let prover_config = ProverConfig::builder()
        .server_name(server_domain.as_str())
        .protocol_config(
            tlsn_common::config::ProtocolConfig::builder()
                .max_sent_data(1 << 12)
                .max_recv_data(1 << 14)
                .build()?,
        )
        .crypto_provider(crypto_provider)
        .build()?;

    let prover = Prover::new(prover_config)
        .setup(notary_connection.compat())
        .await?;

    // Connect to target site
    let client_socket = tokio::net::TcpStream::connect((server_domain.as_str(), server_port)).await?;

    // Bind MPC-TLS
    let (mpc_tls_connection, prover_fut) = prover.connect(client_socket.compat()).await?;
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());

    let prover_task = tokio::spawn(prover_fut);

    // HTTP over MPC-TLS
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection).await?;
    tokio::spawn(connection);

    let request = Request::builder()
        .uri(&path)
        .header("Host", &server_domain)
        .header("Accept", "*/*")
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header("User-Agent", USER_AGENT)
        .body(Empty::<Bytes>::new())?;

    info!("Starting MPC TLS connection with server");
    let response = request_sender.send_request(request).await?;
    info!("Got response: {}", response.status());
    assert!(response.status() == StatusCode::OK);

    let mut prover = prover_task.await??;

    let transcript = HttpTranscript::parse(prover.transcript())?;
    let body_content = &transcript.responses[0].body.as_ref().unwrap().content;
    let body = String::from_utf8_lossy(body_content.span().as_bytes());
    info!("Body: {}", body);

    let mut builder = TranscriptCommitConfig::builder(prover.transcript());
    DefaultHttpCommitter::default().commit_transcript(&mut builder, &transcript)?;
    let transcript_commit = builder.build()?;

    let mut builder = RequestConfig::builder();
    builder.transcript_commit(transcript_commit);
    let request_config = builder.build()?;

    #[allow(deprecated)]
    let (attestation, secrets) = prover.notarize(&request_config).await?;

    tokio::fs::write("fetch.attestation.tlsn", bincode::serialize(&attestation)?).await?;
    tokio::fs::write("fetch.secrets.tlsn", bincode::serialize(&secrets)?).await?;

    println!("Notarization completed. Files: fetch.attestation.tlsn, fetch.secrets.tlsn");
    Ok(())
}
