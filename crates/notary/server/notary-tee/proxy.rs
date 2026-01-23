use crate::error::Error;
use crate::types::{env_var, env_var_parse};
use http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::{debug, info};
use url::Url;

use notary_client::{Accepted, NotarizationRequest, NotaryClient};
use tlsn_common::config::ProtocolConfig;
use tlsn_core::{request::RequestConfig, transcript::TranscriptCommitConfig, CryptoProvider};
use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};
use tlsn_prover::{Prover, ProverConfig};

// Constants are loaded from .env file via ProxyConfig::from_env()

#[derive(Clone)]
pub struct ProxyConfig {
    listen: SocketAddr,
    upstream: Uri,
    jobs_dir: PathBuf,
    max_body_bytes: usize,
    tdx_cmd: String,
}

impl ProxyConfig {
    pub fn from_env() -> Result<Self, Error> {
        let _ = dotenvy::dotenv();

        if std::env::var("TLSN_PROXY_LISTEN").is_err() {
            dotenvy::from_filename(".env.example")
                .map_err(|e| Error::Configuration(format!("Failed to load .env.example: {}", e)))?;
        }

        let listen = env_var_parse::<SocketAddr>("TLSN_PROXY_LISTEN", "0.0.0.0:7048")?;
        let upstream = env_var_parse::<Uri>("TLSN_PROXY_UPSTREAM", "http://127.0.0.1:7047")?;
        let jobs_dir = PathBuf::from(env_var("TLSN_PROXY_JOBS_DIR")?);
        let max_body_bytes = env_var_parse::<usize>("TLSN_PROXY_MAX_BODY_BYTES", "positive integer")?;
        let tdx_cmd = env_var("TLSN_PROXY_TDX_CMD")?;

        Ok(Self {
            listen,
            upstream,
            jobs_dir,
            max_body_bytes,
            tdx_cmd,
        })
    }
}


#[derive(Clone)]
struct ProxyState {
    client: Client<HttpConnector, Full<Bytes>>,
    config: ProxyConfig,
}

type ResponseBody = Full<Bytes>;

#[derive(Serialize)]
struct Meta {
    job_id: String,
    input_hash_hex: String,
    output_hash_hex: String,
    commit_hex: String,
    nonce_hex: String,
    timestamp_ms: u128,
}

#[derive(Serialize)]
struct AttestationPayload {
    job_id: String,
    input_hash_hex: String,
    output_hash_hex: String,
    commit_hex: String,
    nonce_hex: String,
    reportdata_hex: String,
    quote_hex: String,
}

#[derive(Deserialize)]
struct ProveRequest {
    url: String,
    #[serde(default)]
    headers: Vec<HeaderEntry>,
}

#[derive(Deserialize)]
struct HeaderEntry {
    name: String,
    value: String,
}

#[derive(Serialize)]
struct ProveResponse {
    job_id: String,
    attestation_hash_hex: String,
    secrets_hash_hex: String,
    tdx_attestation: Value,
}

pub async fn run_proxy() -> Result<(), Error> {
    let config = ProxyConfig::from_env()?;
    run_proxy_with_config(config).await
}

pub async fn run_proxy_with_config(config: ProxyConfig) -> Result<(), Error> {
    fs::create_dir_all(&config.jobs_dir).await?;

    let mut http_connector = HttpConnector::new();
    http_connector.enforce_http(true);
    let client = Client::builder(TokioExecutor::new()).build(http_connector);

    let state = Arc::new(ProxyState { client, config });
    let listener = TcpListener::bind(state.config.listen).await?;

    info!("TLSN proxy listening on {}", state.config.listen);

    loop {
        let (stream, addr) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| route_request(req, state.clone()));
            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                debug!("connection error from {}: {}", addr, err);
            }
        });
    }
}

async fn route_request(
    req: Request<Incoming>,
    state: Arc<ProxyState>,
) -> Result<Response<ResponseBody>, Infallible> {
    let response = if req.method() == Method::POST && req.uri().path() == "/api/v1/prove" {
        prove_handler(req, state).await
    } else {
        handle_request(req, state).await
    };
    Ok(response)
}

async fn prove_handler(req: Request<Incoming>, state: Arc<ProxyState>) -> Response<ResponseBody> {
    let body = req.into_body();
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(err) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                Error::Upstream(format!("failed to read request body: {err}")),
            )
        }
    };
    if body_bytes.len() > state.config.max_body_bytes {
        return error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            Error::Upstream("request body too large".into()),
        );
    }
    let payload: ProveRequest = match serde_json::from_slice(&body_bytes) {
        Ok(payload) => payload,
        Err(err) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                Error::OperationError(format!("invalid json body: {err}")),
            )
        }
    };

    match prove_handler_inner(payload, state).await {
        Ok(response) => response,
        Err(err) => error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    }
}

async fn prove_handler_inner(
    payload: ProveRequest,
    state: Arc<ProxyState>,
) -> Result<Response<ResponseBody>, Error> {
    let url = Url::parse(&payload.url)
        .map_err(|e| Error::OperationError(format!("invalid url: {e}")))?;
    let scheme = url.scheme();
    if scheme != "https" {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            Error::OperationError("only https urls are supported".into()),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| Error::OperationError("url missing host".into()))?;
    let port = url.port_or_known_default().unwrap_or(443);
    let mut path = url.path().to_string();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }

    let notary_authority = state
        .config
        .upstream
        .authority()
        .ok_or_else(|| Error::Configuration("TLSN_PROXY_UPSTREAM missing authority".into()))?;
    let notary_host = notary_authority.host().to_string();
    let notary_port = notary_authority
        .port_u16()
        .unwrap_or_else(|| if state.config.upstream.scheme_str() == Some("https") { 443 } else { 80 });
    let notary_tls = state.config.upstream.scheme_str() == Some("https");

    let notary_client = NotaryClient::builder()
        .host(notary_host)
        .port(notary_port)
        .enable_tls(notary_tls)
        .build()
        .map_err(|e| Error::OperationError(format!("failed to build notary client: {e}")))?;

    let notarization_request = NotarizationRequest::builder()
        .max_sent_data(1 << 12)
        .max_recv_data(1 << 14)
        .build()
        .map_err(|e| Error::OperationError(format!("failed to build notarization request: {e}")))?;

    let Accepted {
        io: notary_connection,
        id: _session_id,
        ..
    } = notary_client
        .request_notarization(notarization_request)
        .await
        .map_err(|e| Error::OperationError(format!("notary request failed: {e}")))?;

    let crypto_provider = CryptoProvider::default();
    let prover_config = ProverConfig::builder()
        .server_name(host)
        .protocol_config(
            ProtocolConfig::builder()
                .max_sent_data(1 << 12)
                .max_recv_data(1 << 14)
                .build()
                .map_err(|e| Error::OperationError(format!("invalid protocol config: {e}")))?,
        )
        .crypto_provider(crypto_provider)
        .build()
        .map_err(|e| Error::OperationError(format!("failed to build prover config: {e}")))?;

    let prover = Prover::new(prover_config)
        .setup(notary_connection.compat())
        .await
        .map_err(|e| Error::OperationError(format!("prover setup failed: {e}")))?;

    let client_socket = tokio::net::TcpStream::connect((host, port))
        .await
        .map_err(|e| Error::OperationError(format!("failed to connect to target: {e}")))?;

    let (mpc_tls_connection, prover_fut) = prover
        .connect(client_socket.compat())
        .await
        .map_err(|e| Error::OperationError(format!("prover connect failed: {e}")))?;
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());
    let prover_task = tokio::spawn(prover_fut);

    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection)
            .await
            .map_err(|e| Error::OperationError(format!("http1 handshake failed: {e}")))?;
    tokio::spawn(connection);

    let mut request_builder = Request::builder()
        .method("GET")
        .uri(&path)
        .header("Host", host)
        .header("Accept", "*/*")
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header("User-Agent", "TLSNotary-Prover/1.0");
    for header in payload.headers {
        request_builder = request_builder.header(header.name, header.value);
    }
    let request = request_builder
        .body(Empty::<Bytes>::new())
        .map_err(|e| Error::OperationError(format!("failed to build request: {e}")))?;

    let response = request_sender
        .send_request(request)
        .await
        .map_err(|e| Error::OperationError(format!("request failed: {e}")))?;

    let status = response.status();
    if !status.is_success() {
        return Ok(error_response(
            StatusCode::BAD_GATEWAY,
            Error::OperationError(format!("upstream returned status {status}")),
        ));
    }

    let mut prover = prover_task
        .await
        .map_err(|e| Error::OperationError(format!("prover task failed: {e}")))?
        .map_err(|e| Error::OperationError(format!("prover failed: {e}")))?;

    let transcript = HttpTranscript::parse(prover.transcript())
        .map_err(|e| Error::OperationError(format!("transcript parse failed: {e}")))?;
    let mut commit_builder = TranscriptCommitConfig::builder(prover.transcript());
    DefaultHttpCommitter::default()
        .commit_transcript(&mut commit_builder, &transcript)
        .map_err(|e| Error::OperationError(format!("transcript commit failed: {e}")))?;
    let transcript_commit = commit_builder
        .build()
        .map_err(|e| Error::OperationError(format!("transcript commit build failed: {e}")))?;

    let mut request_builder = RequestConfig::builder();
    request_builder.transcript_commit(transcript_commit);
    let request_config = request_builder
        .build()
        .map_err(|e| Error::OperationError(format!("request config build failed: {e}")))?;

    #[allow(deprecated)]
    let (attestation, secrets) = prover
        .notarize(&request_config)
        .await
        .map_err(|e| Error::OperationError(format!("notarize failed: {e}")))?;

    let job_id = random_hex(16);
    let job_dir = state.config.jobs_dir.join(&job_id);
    fs::create_dir_all(&job_dir).await?;

    let attestation_bytes =
        bincode::serialize(&attestation).map_err(|e| Error::OperationError(e.to_string()))?;
    let secrets_bytes =
        bincode::serialize(&secrets).map_err(|e| Error::OperationError(e.to_string()))?;
    let attestation_hash = sha256_bytes(&attestation_bytes);
    let secrets_hash = sha256_bytes(&secrets_bytes);

    let attestation_path = job_dir.join("attestation.tlsn");
    let secrets_path = job_dir.join("secrets.tlsn");
    write_atomic(&attestation_path, &attestation_bytes).await?;
    write_atomic(&secrets_path, &secrets_bytes).await?;

    let nonce = random_bytes_32();
    let commit = sha256_commit(&attestation_hash, &secrets_hash);
    let reportdata = build_reportdata(&commit, &nonce);
    let quote_path = job_dir.join("quote.bin");
    let tdx_attestation = match run_tdx_quote(&state.config.tdx_cmd, &reportdata, &quote_path).await
    {
        Ok(quote) => {
            let attestation = AttestationPayload {
                job_id: job_id.clone(),
                input_hash_hex: hex::encode(attestation_hash),
                output_hash_hex: hex::encode(secrets_hash),
                commit_hex: hex::encode(commit),
                nonce_hex: hex::encode(nonce),
                reportdata_hex: hex::encode(reportdata),
                quote_hex: hex::encode(quote),
            };
            serde_json::to_value(attestation)?
        }
        Err(Error::TdxCliNotFound) => {
            serde_json::json!({
                "error": Error::TdxCliNotFound.to_string(),
                "job_id": job_id,
            })
        }
        Err(Error::TdxCliPermissionDenied) => {
            serde_json::json!({
                "error": Error::TdxCliPermissionDenied.to_string(),
                "job_id": job_id,
            })
        }
        Err(Error::TdxAttestation(msg)) => {
            let message = if msg.contains("sudo:") || msg.contains("password") {
                Error::TdxCliPermissionDenied.to_string()
            } else {
                "TDX attestation failed".into()
            };
            serde_json::json!({
                "error": message,
                "job_id": job_id,
            })
        }
        Err(err) => return Err(err),
    };

    let response = ProveResponse {
        job_id,
        attestation_hash_hex: hex::encode(attestation_hash),
        secrets_hash_hex: hex::encode(secrets_hash),
        tdx_attestation,
    };

    Ok(Response::new(Full::new(Bytes::from(
        serde_json::to_vec(&response).unwrap_or_else(|_| b"{}".to_vec()),
    ))))
}

async fn handle_request(req: Request<Incoming>, state: Arc<ProxyState>) -> Response<ResponseBody> {
    match handle_request_inner(req, state).await {
        Ok(response) => response,
        Err(err) => error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    }
}

async fn handle_request_inner(
    req: Request<Incoming>,
    state: Arc<ProxyState>,
) -> Result<Response<ResponseBody>, Error> {
    if is_upgrade_request(&req) {
        return Ok(error_response(
            StatusCode::NOT_IMPLEMENTED,
            Error::Upstream("proxy does not support upgrade requests".into()),
        ));
    }
    if req.method() == Method::CONNECT {
        return Ok(error_response(
            StatusCode::NOT_IMPLEMENTED,
            Error::Upstream("proxy does not support CONNECT".into()),
        ));
    }

    let (parts, body) = req.into_parts();
    let body_bytes = body
        .collect()
        .await
        .map_err(|err| Error::Upstream(format!("failed to read request body: {err}")))?
        .to_bytes();
    if body_bytes.len() > state.config.max_body_bytes {
        return Ok(error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            Error::Upstream("request body too large".into()),
        ));
    }

    let job_id = random_hex(16);
    let job_dir = state.config.jobs_dir.join(&job_id);
    fs::create_dir_all(&job_dir).await?;

    let request_bytes = canonical_request_bytes(&parts, body_bytes.as_ref());
    let request_path = job_dir.join("request.bin");
    write_atomic(&request_path, &request_bytes).await?;
    let input_hash = sha256_bytes(&request_bytes);

    let upstream_uri = join_upstream_uri(&state.config.upstream, &parts.uri)?;
    let upstream_url = upstream_uri.to_string();

    let mut upstream_req_builder = Request::builder()
        .method(parts.method.clone())
        .uri(upstream_uri);

    // Copy headers
    for (name, value) in parts.headers.iter() {
        if name != header::HOST && name != header::CONNECTION {
            upstream_req_builder = upstream_req_builder.header(name, value);
        }
    }

    // Set body
    let upstream_req = upstream_req_builder
        .body(Full::new(Bytes::from(body_bytes.to_vec())))
        .map_err(|e| Error::Upstream(format!("failed to build upstream request: {e}")))?;

    debug!("proxy forward -> {}", upstream_url);
    let upstream_res = state
        .client
        .request(upstream_req)
        .await
        .map_err(|e| Error::Upstream(format!("client request failed: {}", e)))?;
    
    let status = StatusCode::from_u16(upstream_res.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let headers = upstream_res.headers().clone();
    let response_bytes: Vec<u8> = upstream_res
        .into_body()
        .collect()
        .await
        .map_err(|e| Error::Upstream(format!("failed to read response body: {}", e)))?
        .to_bytes()
        .to_vec();

    if response_bytes.len() > state.config.max_body_bytes {
        return Ok(error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            Error::Upstream("response body too large".into()),
        ));
    }

    let response_path = job_dir.join("response.bin");
    write_atomic(&response_path, &response_bytes).await?;
    let output_hash = sha256_bytes(&response_bytes);

    let nonce = extract_nonce(parts.headers.get("x-tdx-nonce"));
    let commit = sha256_commit(&input_hash, &output_hash);
    let reportdata = build_reportdata(&commit, &nonce);

    let meta = Meta {
        job_id: job_id.clone(),
        input_hash_hex: hex::encode(input_hash),
        output_hash_hex: hex::encode(output_hash),
        commit_hex: hex::encode(commit),
        nonce_hex: hex::encode(nonce),
        timestamp_ms: current_time_ms(),
    };
    let meta_path = job_dir.join("meta.json");
    write_atomic(&meta_path, serde_json::to_string(&meta)?.as_bytes()).await?;

    let quote_path = job_dir.join("quote.bin");
    let tdx_attestation = match run_tdx_quote(&state.config.tdx_cmd, &reportdata, &quote_path).await
    {
        Ok(quote) => {
    let attestation = AttestationPayload {
        job_id,
        input_hash_hex: meta.input_hash_hex,
        output_hash_hex: meta.output_hash_hex,
        commit_hex: meta.commit_hex,
        nonce_hex: meta.nonce_hex,
        reportdata_hex: hex::encode(reportdata),
        quote_hex: hex::encode(quote),
            };
            serde_json::to_value(attestation)?
        }
        Err(Error::TdxCliNotFound) => {
            serde_json::json!({
                "error": Error::TdxCliNotFound.to_string(),
                "job_id": job_id,
            })
        }
        Err(Error::TdxCliPermissionDenied) => {
            serde_json::json!({
                "error": Error::TdxCliPermissionDenied.to_string(),
                "job_id": job_id,
            })
        }
        Err(Error::TdxAttestation(msg)) => {
            let message = if msg.contains("sudo:") || msg.contains("password") {
                Error::TdxCliPermissionDenied.to_string()
            } else {
                "TDX attestation failed".into()
            };
            serde_json::json!({
                "error": message,
                "job_id": job_id,
            })
        }
        Err(err) => return Err(err),
    };

    Ok(build_response(
        status,
        headers,
        response_bytes,
        tdx_attestation,
    ))
}


fn join_upstream_uri(upstream: &Uri, path: &Uri) -> Result<Uri, Error> {
    let path_and_query = path
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let mut builder = Uri::builder();
    if let Some(scheme) = upstream.scheme_str() {
        builder = builder.scheme(scheme);
    }
    if let Some(authority) = upstream.authority() {
        builder = builder.authority(authority.as_str());
    }
    Ok(builder.path_and_query(path_and_query).build()?)
}

fn build_response(
    status: StatusCode,
    headers: HeaderMap,
    response_bytes: Vec<u8>,
    tdx_attestation: Value,
) -> Response<ResponseBody> {
    // Always wrap response in JSON with attestation
    let json = match serde_json::from_slice::<Value>(&response_bytes) {
            Ok(mut value) if value.is_object() => {
                value
                    .as_object_mut()
                    .expect("checked object")
                .insert("tdx_attestation".into(), tdx_attestation);
                value
            }
            Ok(value) => {
                let mut map = serde_json::Map::new();
            map.insert("body".into(), value);
            map.insert("tdx_attestation".into(), tdx_attestation);
                Value::Object(map)
            }
            Err(_) => {
                let mut map = serde_json::Map::new();
            map.insert("body_hex".into(), Value::String(hex::encode(&response_bytes)));
            map.insert("tdx_attestation".into(), tdx_attestation);
                Value::Object(map)
            }
        };

        let body = serde_json::to_vec(&json).unwrap_or_else(|_| b"{}".to_vec());
        let mut response = Response::new(Full::new(Bytes::from(body)));
        *response.status_mut() = status;
        copy_response_headers(&headers, response.headers_mut());
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
    response
}

fn error_response(status: StatusCode, err: Error) -> Response<ResponseBody> {
    let body = serde_json::json!({
        "error": err.to_string(),
    });
    let mut response = Response::new(Full::new(Bytes::from(body.to_string())));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

fn copy_response_headers(src: &HeaderMap, dst: &mut HeaderMap) {
    for (name, value) in src.iter() {
        if name == header::CONNECTION
            || name == header::TRANSFER_ENCODING
            || name == header::CONTENT_LENGTH
        {
            continue;
        }
        dst.insert(name, value.clone());
    }
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn sha256_commit(input_hash: &[u8; 32], output_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    // REPORTDATA_DOMAIN defaults to "TLSN_TDX_V1" if not set in env
    let domain = std::env::var("TLSN_PROXY_REPORTDATA_DOMAIN")
        .unwrap_or_else(|_| "TLSN_TDX_V1".into());
    hasher.update(domain.as_bytes());
    hasher.update(input_hash);
    hasher.update(output_hash);
    hasher.finalize().into()
}

fn build_reportdata(commit: &[u8; 32], nonce: &[u8; 32]) -> [u8; 64] {
    let mut reportdata = [0u8; 64];
    reportdata[..32].copy_from_slice(commit);
    reportdata[32..].copy_from_slice(nonce);
    reportdata
}

fn extract_nonce(header: Option<&HeaderValue>) -> [u8; 32] {
    if let Some(value) = header.and_then(|v| v.to_str().ok()) {
        if let Ok(bytes) = hex::decode(value) {
            if bytes.len() == 32 {
                let mut nonce = [0u8; 32];
                nonce.copy_from_slice(&bytes);
                return nonce;
            }
        }
    }
    random_bytes_32()
}

fn random_hex(len: usize) -> String {
    let mut rng = rand::rng();
    let bytes: Vec<u8> = (0..len).map(|_| rng.random()).collect();
    hex::encode(bytes)
}

fn random_bytes_32() -> [u8; 32] {
    let mut rng = rand::rng();
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    bytes
}

fn is_upgrade_request(req: &Request<Incoming>) -> bool {
    if req.headers().contains_key(header::UPGRADE) {
        return true;
    }
    req.headers()
        .get(header::CONNECTION)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_ascii_lowercase().contains("upgrade"))
        .unwrap_or(false)
}

fn canonical_request_bytes(parts: &http::request::Parts, body: &[u8]) -> Vec<u8> {
    let mut buffer = Vec::new();
    buffer.extend_from_slice(parts.method.as_str().as_bytes());
    buffer.push(b' ');
    buffer.extend_from_slice(parts.uri.to_string().as_bytes());
    buffer.push(b'\n');
    let mut header_pairs: Vec<(String, String)> = parts
        .headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_ascii_lowercase(),
                value.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    header_pairs.sort_by(|a, b| a.cmp(b));
    for (name, value) in header_pairs {
        buffer.extend_from_slice(name.as_bytes());
        buffer.push(b':');
        buffer.extend_from_slice(value.as_bytes());
        buffer.push(b'\n');
    }
    buffer.push(b'\n');
    buffer.extend_from_slice(body);
    buffer
}


async fn write_atomic(path: &Path, data: &[u8]) -> Result<(), Error> {
    let tmp_path = path.with_extension("tmp");
    let mut file = fs::File::create(&tmp_path).await?;
    file.write_all(data).await?;
    file.sync_all().await?;
    fs::rename(&tmp_path, path).await?;
    Ok(())
}

async fn run_tdx_quote(
    cmd_template: &str,
    reportdata: &[u8; 64],
    output_path: &Path,
) -> Result<Vec<u8>, Error> {
    let reportdata_hex = hex::encode(reportdata);
    let tmp_path = output_path.with_extension("tmp");
    let output_arg = tmp_path.to_string_lossy();

    let cmd = if cmd_template.contains("{reportdata}") || cmd_template.contains("{output}") {
        cmd_template
            .replace("{reportdata}", &reportdata_hex)
            .replace("{output}", &output_arg)
    } else {
        format!("{cmd_template} --report-data {reportdata_hex} --output {output_arg}")
    };

    let mut parts = cmd.split_whitespace();
    let program = parts
        .next()
        .ok_or_else(|| Error::TdxAttestation("empty tdx command".into()))?;
    let args: Vec<&str> = parts.collect();
    let output = Command::new(program).args(args).output().await.map_err(|e| {
        match e.kind() {
            std::io::ErrorKind::NotFound => Error::TdxCliNotFound,
            std::io::ErrorKind::PermissionDenied => Error::TdxCliPermissionDenied,
            _ => Error::TdxAttestation(format!("failed to execute tdx command: {}", e)),
        }
    })?;
    if !output.status.success() {
        return Err(Error::TdxAttestation(format!(
            "tdx command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    let quote = fs::read(&tmp_path).await.map_err(Error::Io)?;
    fs::rename(&tmp_path, output_path).await?;
    Ok(quote)
}

fn current_time_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}
