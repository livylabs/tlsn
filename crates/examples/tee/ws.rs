use std::env;

use async_tungstenite::{
    tokio::{connect_async, connect_async_with_tls_connector_and_config},
    tungstenite::protocol::WebSocketConfig,
};
use attestation_verifier::{decode_tdx_quote_json, extract_report_data_hex, verify_tdx_quote_json};
use clap::Parser;
use futures::{AsyncRead, AsyncWrite};
use http_body_util::{BodyExt as _, Empty, Full};
use hyper::{body::Bytes, Request, StatusCode};
use hyper_tls::HttpsConnector;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Builder},
    rt::{TokioExecutor, TokioIo},
};
use notary_common::{ClientType, NotarizationSessionRequest, NotarizationSessionResponse};
use tls_core::verify::WebPkiVerifier;
use tls_server_fixture::CA_CERT_DER;
use tlsn_core::{request::RequestConfig, CryptoProvider};
use tlsn_prover::{Prover, ProverConfig};
use tokio_native_tls::native_tls::TlsConnector as NativeTlsConnector;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::info;
use ws_stream_tungstenite::WsStream;

const USER_AGENT: &str = "TLSNotary-WS-TDX-Test/1.0";
const DEFAULT_MAX_SENT_DATA: usize = 1 << 13;
const DEFAULT_MAX_RECV_DATA: usize = 1 << 14;

trait NotaryIo: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> NotaryIo for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

#[derive(Debug, Parser)]
struct Args {
    /// Verify the returned TDX quote locally.
    #[arg(long)]
    verify: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let notary_scheme = env::var("NOTARY_SCHEME").unwrap_or("http".into());
    let notary_host: String = env::var("NOTARY_HOST").unwrap_or("127.0.0.1".into());
    let notary_port: u16 = env::var("NOTARY_PORT")
        .ok()
        .and_then(|port| port.parse().ok())
        .unwrap_or(7047);

    let target_host: String = env::var("TARGET_HOST").unwrap_or("127.0.0.1".into());
    let target_port: u16 = env::var("TARGET_PORT")
        .ok()
        .and_then(|port| port.parse().ok())
        .unwrap_or(4000);
    let target_server_name: String =
        env::var("TARGET_SERVER_NAME").unwrap_or("test-server.io".into());
    let target_uri: String = env::var("TARGET_URI").unwrap_or("/formats/json".into());
    let max_sent_data: usize = env::var("MAX_SENT_DATA")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_MAX_SENT_DATA);
    let max_recv_data: usize = env::var("MAX_RECV_DATA")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_MAX_RECV_DATA);
    let use_fixture_ca = env::var("USE_FIXTURE_CA")
        .map(|value| value == "true" || value == "1")
        .unwrap_or(true);

    let session_id =
        create_websocket_session(&notary_scheme, &notary_host, notary_port, max_sent_data, max_recv_data)
            .await?;
    info!(%session_id, "Created websocket notarization session");

    let notary_ws_socket =
        connect_notary_websocket(&notary_scheme, &notary_host, notary_port, &session_id).await?;

    let crypto_provider = build_target_crypto_provider(use_fixture_ca)?;

    let prover_config = ProverConfig::builder()
        .server_name(target_server_name.as_str())
        .protocol_config(
            tlsn_common::config::ProtocolConfig::builder()
                .max_sent_data(max_sent_data)
                .max_recv_data(max_recv_data)
                .build()?,
        )
        .crypto_provider(crypto_provider)
        .build()?;

    let prover = Prover::new(prover_config).setup(notary_ws_socket).await?;

    let client_socket = tokio::net::TcpStream::connect((target_host.as_str(), target_port)).await?;
    let (mpc_tls_connection, prover_fut) = prover.connect(client_socket.compat()).await?;
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());

    let prover_task = tokio::spawn(prover_fut);

    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection).await?;
    tokio::spawn(connection);

    let request = Request::builder()
        .uri(target_uri)
        .header("Host", target_server_name.as_str())
        .header("Accept", "*/*")
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header("User-Agent", USER_AGENT)
        .body(Empty::<Bytes>::new())?;

    let response = request_sender.send_request(request).await?;
    println!("Application server response: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);
    let _ = response.into_body().collect().await?;

    let mut prover = prover_task.await??;

    let (sent_len, recv_len) = prover.transcript().len();
    let mut builder = tlsn_core::transcript::TranscriptCommitConfig::builder(prover.transcript());
    builder.commit_sent(&(0..sent_len))?;
    builder.commit_recv(&(0..recv_len))?;

    let mut request_builder = RequestConfig::builder();
    request_builder.transcript_commit(builder.build()?);
    let request_config = request_builder.build()?;

    #[allow(deprecated)]
    let (attestation, secrets, tee_attestation) = prover.notarize_with_tee(&request_config).await?;

    println!("TLSN attestation received from notary");
    if args.verify {
        println!(
            "TDX attestation packet:\n{}",
            serde_json::to_string_pretty(&tee_attestation)?
        );

        let tdx_attestation_json = serde_json::to_string(&tee_attestation.tdx_attestation)?;
        let quote = decode_tdx_quote_json(&tdx_attestation_json)?;
        let report_data_hex = extract_report_data_hex(&quote)?;
        verify_tdx_quote_json(&tdx_attestation_json).await?;
        println!("TDX attestation verified successfully");
        println!("Extracted TDX report data: {report_data_hex}");
    } else {
        println!("Skipping local TDX attestation verification (pass --verify to enable)");
    }

    tokio::fs::write("ws-test.attestation.tlsn", bincode::serialize(&attestation)?).await?;
    tokio::fs::write("ws-test.secrets.tlsn", bincode::serialize(&secrets)?).await?;

    prover.close().await?;

    Ok(())
}

fn build_target_crypto_provider(
    use_fixture_ca: bool,
) -> Result<CryptoProvider, Box<dyn std::error::Error>> {
    if !use_fixture_ca {
        return Ok(CryptoProvider::default());
    }

    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store.add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))?;

    Ok(CryptoProvider {
        cert: WebPkiVerifier::new(root_store, None),
        ..Default::default()
    })
}

async fn connect_notary_websocket(
    notary_scheme: &str,
    notary_host: &str,
    notary_port: u16,
    session_id: &str,
) -> Result<Box<dyn NotaryIo>, Box<dyn std::error::Error>> {
    let ws_scheme = websocket_scheme(notary_scheme)?;
    let ws_url = format!(
        "{ws_scheme}://{notary_host}:{notary_port}/notarize?sessionId={session_id}"
    );

    if notary_scheme == "https" {
        let tls_connector = NativeTlsConnector::builder().build()?;
        let (notary_ws_stream, _) = connect_async_with_tls_connector_and_config(
            ws_url,
            Some(tokio_native_tls::TlsConnector::from(tls_connector)),
            Some(WebSocketConfig::default()),
        )
        .await?;

        Ok(Box::new(WsStream::new(notary_ws_stream)))
    } else {
        let (notary_ws_stream, _) = connect_async(ws_url).await?;
        Ok(Box::new(WsStream::new(notary_ws_stream)))
    }
}

async fn create_websocket_session(
    notary_scheme: &str,
    notary_host: &str,
    notary_port: u16,
    max_sent_data: usize,
    max_recv_data: usize,
) -> Result<String, Box<dyn std::error::Error>> {
    let payload = serde_json::to_vec(&NotarizationSessionRequest {
        client_type: ClientType::Websocket,
        max_sent_data: Some(max_sent_data),
        max_recv_data: Some(max_recv_data),
        tee_attestation: Some(true),
    })?;
    let session_uri = format!("{notary_scheme}://{notary_host}:{notary_port}/session");

    let response = if notary_scheme == "https" {
        let tls_connector = NativeTlsConnector::builder().build()?;
        let mut http_connector = HttpConnector::new();
        http_connector.enforce_http(false);
        let https_connector =
            HttpsConnector::from((http_connector, tokio_native_tls::TlsConnector::from(tls_connector)));
        let client = Builder::new(TokioExecutor::new()).build(https_connector);

        client
            .request(
                Request::builder()
                    .uri(session_uri)
                    .method("POST")
                    .header("Host", notary_host)
                    .header("Content-Type", "application/json")
                    .body(Full::new(Bytes::from(payload)))?,
            )
            .await?
    } else {
        let notary_socket = tokio::net::TcpStream::connect((notary_host, notary_port)).await?;
        let (mut request_sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(notary_socket)).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });

        request_sender
            .send_request(
                Request::builder()
                    .uri(session_uri)
                    .method("POST")
                    .header("Host", notary_host)
                    .header("Content-Type", "application/json")
                    .body(Full::new(Bytes::from(payload)))?,
            )
            .await?
    };

    if response.status() != StatusCode::OK {
        return Err(format!("Session creation failed with status {}", response.status()).into());
    }

    let payload = response.into_body().collect().await?.to_bytes();
    let session = serde_json::from_slice::<NotarizationSessionResponse>(&payload)?;

    Ok(session.session_id)
}

fn websocket_scheme(notary_scheme: &str) -> Result<&'static str, Box<dyn std::error::Error>> {
    match notary_scheme {
        "http" => Ok("ws"),
        "https" => Ok("wss"),
        _ => Err(format!("Unsupported NOTARY_SCHEME: {notary_scheme}").into()),
    }
}
