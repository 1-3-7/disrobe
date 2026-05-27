#![allow(
    clippy::needless_pass_by_value,
    clippy::too_many_lines,
    clippy::too_many_arguments
)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{
    DefaultBodyLimit, Path, State,
    ws::{Message, WebSocket, WebSocketUpgrade},
};
use axum::http::{HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::runtime::Builder as RuntimeBuilder;
use tokio_util::sync::CancellationToken;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;

const SERVE_VERSION: &str = env!("CARGO_PKG_VERSION");

pub(crate) fn run(
    bind: String,
    stdio: bool,
    grpc: bool,
    cors_origins: Vec<String>,
    max_body_size: usize,
) -> miette::Result<()> {
    if stdio {
        return run_stdio_lsp();
    }
    let addr: SocketAddr = bind
        .parse::<SocketAddr>()
        .map_err(|e| miette::miette!("DR-CLI-0171: invalid --bind value `{bind}`: {e}"))?;
    let runtime: tokio::runtime::Runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| miette::miette!("DR-CLI-0172: tokio runtime build failed: {e}"))?;
    if grpc {
        let grpc_addr: SocketAddr = SocketAddr::new(addr.ip(), addr.port().saturating_add(1));
        return runtime.block_on(async move {
            let http_handle: tokio::task::JoinHandle<miette::Result<()>> =
                tokio::spawn(async move { serve_http(addr, cors_origins, max_body_size).await });
            let grpc_handle: tokio::task::JoinHandle<miette::Result<()>> =
                tokio::spawn(async move { crate::cli::grpc::serve_grpc(grpc_addr).await });
            let (h, g): (
                Result<miette::Result<()>, tokio::task::JoinError>,
                Result<miette::Result<()>, tokio::task::JoinError>,
            ) = tokio::join!(http_handle, grpc_handle);
            h.map_err(|e| miette::miette!("DR-CLI-0222: http join: {e}"))??;
            g.map_err(|e| miette::miette!("DR-CLI-0223: grpc join: {e}"))??;
            Ok(())
        });
    }
    runtime.block_on(async move { serve_http(addr, cors_origins, max_body_size).await })
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "disrobe HTTP API",
        version = SERVE_VERSION,
        description = "disrobe serve: HTTP + WebSocket daemon for deobfuscation pipelines",
    ),
    paths(
        health,
        version,
        list_passes,
        analyze,
        explain_endpoint,
        envelope_verify,
        envelope_create,
        stream_ws_docstub,
    ),
    components(schemas(
        HealthResponse,
        VersionResponse,
        PassesResponse,
        PassDescriptor,
        AnalyzeRequest,
        AnalyzeResponse,
        ExplainResponse,
        EnvelopeCreateRequest,
        EnvelopeCreateResponse,
        EnvelopeVerifyRequest,
        EnvelopeVerifyResponse,
    )),
    tags(
        (name = "core", description = "Core lifecycle"),
        (name = "passes", description = "Pass discovery"),
        (name = "analyze", description = "Binary analysis"),
        (name = "envelope", description = ".dr container ops"),
        (name = "explain", description = "DR-* code explainer"),
        (name = "stream", description = "WebSocket NDJSON stream"),
    )
)]
struct ApiDoc;

#[derive(Debug)]
struct ServerState {
    cancel: CancellationToken,
}

impl Default for ServerState {
    fn default() -> Self {
        Self {
            cancel: CancellationToken::new(),
        }
    }
}

async fn serve_http(
    addr: SocketAddr,
    cors_origins: Vec<String>,
    max_body_size: usize,
) -> miette::Result<()> {
    let state: Arc<ServerState> = Arc::new(ServerState::default());

    let mut cors: CorsLayer = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(Any);
    if cors_origins.is_empty() {
        cors = cors.allow_origin(Any);
    } else {
        let mut origins: Vec<HeaderValue> = Vec::with_capacity(cors_origins.len());
        for origin in &cors_origins {
            let v: HeaderValue = HeaderValue::from_str(origin)
                .map_err(|e| miette::miette!("DR-CLI-0175: invalid --cors-origin {origin}: {e}"))?;
            origins.push(v);
        }
        cors = cors.allow_origin(origins);
    }

    let app: Router = Router::new()
        .route("/v1/health", get(health))
        .route("/v1/version", get(version))
        .route("/v1/passes", get(list_passes))
        .route("/v1/analyze", post(analyze))
        .route("/v1/explain/{code}", post(explain_endpoint))
        .route("/v1/envelope/verify", post(envelope_verify))
        .route("/v1/envelope/create", post(envelope_create))
        .route("/v1/stream", get(stream_ws))
        .route("/openapi.json", get(openapi))
        .route("/v1/openapi.json", get(openapi))
        .layer(DefaultBodyLimit::max(max_body_size))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(Arc::clone(&state));

    let listener: TcpListener = TcpListener::bind(addr)
        .await
        .map_err(|e| miette::miette!("DR-CLI-0173: bind {addr}: {e}"))?;
    if !addr.ip().is_loopback() {
        tracing::warn!(
            ?addr,
            "disrobe serve is bound to a non-loopback address; ensure no untrusted clients can reach this port"
        );
        println!(
            "WARNING: disrobe serve is bound to a non-loopback address ({addr}); ensure no untrusted clients can reach this port"
        );
    }
    println!("disrobe serve: listening on http://{addr}");
    println!("  GET  /v1/health");
    println!("  GET  /v1/version");
    println!("  GET  /v1/passes");
    println!("  POST /v1/analyze            (bytes_b64 only; server never reads from disk)");
    println!("  POST /v1/explain/{{code}}");
    println!("  POST /v1/envelope/verify    (bytes_b64 only; server never reads from disk)");
    println!("  POST /v1/envelope/create    (bytes_b64 only; envelope returned inline)");
    println!("  WS   /v1/stream             (bytes_b64 only; server never reads from disk)");
    println!("  GET  /openapi.json");
    let cancel: CancellationToken = state.cancel.clone();
    let shutdown: tokio::task::JoinHandle<()> = tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        cancel.cancel();
    });
    let serve_fut = axum::serve(listener, app)
        .with_graceful_shutdown(async move { state.cancel.cancelled().await });
    serve_fut
        .await
        .map_err(|e| miette::miette!("DR-CLI-0174: axum serve failed: {e}"))?;
    shutdown.abort();
    Ok(())
}

#[utoipa::path(get, path = "/v1/health", tag = "core", responses((status = 200, body = HealthResponse)))]
async fn health(State(_state): State<Arc<ServerState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "serving".to_owned(),
        version: SERVE_VERSION.to_owned(),
    })
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
struct HealthResponse {
    status: String,
    version: String,
}

#[utoipa::path(get, path = "/v1/version", tag = "core", responses((status = 200, body = VersionResponse)))]
async fn version(State(_state): State<Arc<ServerState>>) -> Json<VersionResponse> {
    Json(VersionResponse {
        name: "disrobe".to_owned(),
        version: SERVE_VERSION.to_owned(),
        api: "v1".to_owned(),
    })
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
struct VersionResponse {
    name: String,
    version: String,
    api: String,
}

#[utoipa::path(get, path = "/v1/passes", tag = "passes", responses((status = 200, body = PassesResponse)))]
async fn list_passes(State(_state): State<Arc<ServerState>>) -> Json<PassesResponse> {
    Json(PassesResponse {
        passes: PASS_DESCRIPTORS
            .iter()
            .map(PassDescriptorRef::to_owned)
            .collect(),
    })
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
struct PassesResponse {
    passes: Vec<PassDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
struct PassDescriptor {
    name: String,
    description: String,
}

struct PassDescriptorRef {
    name: &'static str,
    description: &'static str,
}

impl PassDescriptorRef {
    fn to_owned(&self) -> PassDescriptor {
        PassDescriptor {
            name: self.name.to_owned(),
            description: self.description.to_owned(),
        }
    }
}

const PASS_DESCRIPTORS: &[PassDescriptorRef] = &[
    PassDescriptorRef {
        name: "pyarmor",
        description: "v6/v7 (dyn-hook) + v8/v9 static unpack",
    },
    PassDescriptorRef {
        name: "pyinstaller",
        description: "PI 2.1..6.x extract + AES-CTR/CFB decrypt",
    },
    PassDescriptorRef {
        name: "pyfreeze",
        description: "cx_Freeze / py2exe / shiv / pex detect + extract",
    },
    PassDescriptorRef {
        name: "nuitka",
        description: "--onefile payload extract + symbol scan",
    },
    PassDescriptorRef {
        name: "py-deob",
        description: "encoder peel + ruff-AST cleanup",
    },
    PassDescriptorRef {
        name: "py-disasm",
        description: "Python 2.7..3.14 disassembler",
    },
    PassDescriptorRef {
        name: "py-decompile",
        description: "pycdc subprocess or disasm-fallback",
    },
    PassDescriptorRef {
        name: "py-sourcedefender",
        description: ".pye AES-CTR decrypt",
    },
    PassDescriptorRef {
        name: "js-deob",
        description: "string-array + unminify + scope-aware rename",
    },
    PassDescriptorRef {
        name: "js-unbundle",
        description: "webpack / vite / rollup / esbuild / turbopack / bun module slice",
    },
    PassDescriptorRef {
        name: "wasm",
        description: "analyze / lift to rust|ts|wat / 5 obfuscator family deob",
    },
    PassDescriptorRef {
        name: "envelope",
        description: ".dr container create / inspect / verify",
    },
    PassDescriptorRef {
        name: "native-symbols",
        description: "object crate PE/ELF/Mach-O symbol dump",
    },
];

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct AnalyzeRequest {
    bytes_b64: String,
    hint: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
struct AnalyzeResponse {
    routed_action: String,
    bytes_read: usize,
    blake3_hash: String,
    reason: String,
    candidates: Vec<String>,
}

#[utoipa::path(
    post,
    path = "/v1/analyze",
    tag = "analyze",
    request_body = AnalyzeRequest,
    responses((status = 200, body = AnalyzeResponse))
)]
async fn analyze(
    State(_state): State<Arc<ServerState>>,
    Json(req): Json<AnalyzeRequest>,
) -> Result<Json<AnalyzeResponse>, ApiError> {
    let bytes: Vec<u8> = decode_inline_bytes(&req.bytes_b64)?;
    let hash: String = hex32(blake3::hash(&bytes).as_bytes());
    let classification: disrobe_binfmt::InputClassification =
        disrobe_binfmt::classify_input(std::path::Path::new("inline"), &bytes);
    let candidates: Vec<String> = classification
        .candidates
        .iter()
        .map(|(a, c)| format!("{a:?} (confidence={:.2})", c.0))
        .collect();
    Ok(Json(AnalyzeResponse {
        routed_action: format!("{:?}", classification.primary_action),
        bytes_read: bytes.len(),
        blake3_hash: hash,
        reason: classification.reason,
        candidates,
    }))
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
struct ExplainResponse {
    code: String,
    known: bool,
    title: Option<String>,
    description: Option<String>,
    crate_path: Option<String>,
}

#[utoipa::path(
    post,
    path = "/v1/explain/{code}",
    tag = "explain",
    params(("code" = String, Path, description = "DR-* error code")),
    responses((status = 200, body = ExplainResponse))
)]
async fn explain_endpoint(
    State(_state): State<Arc<ServerState>>,
    Path(code): Path<String>,
) -> Json<ExplainResponse> {
    let normalized: String = normalize_dr_code(&code);
    if let Some(entry) = crate::cli::explain::lookup_for_serve(&normalized) {
        Json(ExplainResponse {
            code: normalized,
            known: true,
            title: Some(entry.title.to_owned()),
            description: Some(entry.description.to_owned()),
            crate_path: Some(entry.crate_path.to_owned()),
        })
    } else {
        Json(ExplainResponse {
            code: normalized,
            known: false,
            title: None,
            description: None,
            crate_path: None,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct EnvelopeVerifyRequest {
    bytes_b64: String,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
struct EnvelopeVerifyResponse {
    verified: bool,
    version: u16,
    rung: String,
    hot_bytes: usize,
    cold_bytes: usize,
    root_hash_blake3: String,
}

#[utoipa::path(
    post,
    path = "/v1/envelope/verify",
    tag = "envelope",
    request_body = EnvelopeVerifyRequest,
    responses((status = 200, body = EnvelopeVerifyResponse))
)]
async fn envelope_verify(
    State(_state): State<Arc<ServerState>>,
    Json(req): Json<EnvelopeVerifyRequest>,
) -> Result<Json<EnvelopeVerifyResponse>, ApiError> {
    let bytes: Vec<u8> = decode_inline_bytes(&req.bytes_b64)?;
    let env: disrobe_ir::Envelope = disrobe_ir::Envelope::decode(&bytes).map_err(|e| ApiError {
        code: StatusCode::BAD_REQUEST,
        error_code: "DR-CLI-0184",
        message: format!("verify failed: {e}"),
    })?;
    Ok(Json(EnvelopeVerifyResponse {
        verified: true,
        version: env.version,
        rung: format!("{:?}", env.rung),
        hot_bytes: env.hot.len(),
        cold_bytes: env.cold.len(),
        root_hash_blake3: hex32(&env.root_hash),
    }))
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct EnvelopeCreateRequest {
    bytes_b64: String,
    source_label: Option<String>,
    produced_by: Option<String>,
    detected_format: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
struct EnvelopeCreateResponse {
    envelope_b64: String,
    envelope_bytes: usize,
    bytes_in: usize,
    root_hash_blake3: String,
    source_hash_blake3: String,
}

#[utoipa::path(
    post,
    path = "/v1/envelope/create",
    tag = "envelope",
    request_body = EnvelopeCreateRequest,
    responses((status = 200, body = EnvelopeCreateResponse))
)]
async fn envelope_create(
    State(_state): State<Arc<ServerState>>,
    Json(req): Json<EnvelopeCreateRequest>,
) -> Result<Json<EnvelopeCreateResponse>, ApiError> {
    let bytes: Vec<u8> = decode_inline_bytes(&req.bytes_b64)?;
    let source_hash: [u8; 32] = *blake3::hash(&bytes).as_bytes();
    let bytes_len: usize = bytes.len();
    let source_label: String = req.source_label.unwrap_or_else(|| "inline".to_owned());
    let payload: disrobe_ir::RawPayload = disrobe_ir::RawPayload {
        source_path: source_label,
        source_bytes: bytes,
        source_hash,
        detected_format: req.detected_format,
    };
    let hot: Vec<u8> = disrobe_ir::encode_raw(&payload).map_err(|e| ApiError {
        code: StatusCode::INTERNAL_SERVER_ERROR,
        error_code: "DR-CLI-0186",
        message: format!("encode_raw: {e}"),
    })?;
    let sidecar: disrobe_ir::Sidecar = disrobe_ir::Sidecar {
        produced_by: req
            .produced_by
            .unwrap_or_else(|| "disrobe-serve".to_owned()),
        produced_by_version: SERVE_VERSION.to_owned(),
        capabilities: vec![disrobe_core::Capability::produces("raw", 1)],
        provenance: BTreeMap::default(),
    };
    let cold: Vec<u8> = sidecar.encode().map_err(|e| ApiError {
        code: StatusCode::INTERNAL_SERVER_ERROR,
        error_code: "DR-CLI-0187",
        message: format!("sidecar encode: {e}"),
    })?;
    let env: disrobe_ir::Envelope = disrobe_ir::Envelope::new(disrobe_ir::Rung::Raw, hot, cold);
    let envelope_bytes: Vec<u8> = env.encode().map_err(|e| ApiError {
        code: StatusCode::INTERNAL_SERVER_ERROR,
        error_code: "DR-CLI-0188",
        message: format!("encode envelope: {e}"),
    })?;
    let envelope_len: usize = envelope_bytes.len();
    Ok(Json(EnvelopeCreateResponse {
        envelope_b64: encode_base64(&envelope_bytes),
        envelope_bytes: envelope_len,
        bytes_in: bytes_len,
        root_hash_blake3: hex32(&env.root_hash),
        source_hash_blake3: hex32(&source_hash),
    }))
}

#[utoipa::path(get, path = "/v1/stream", tag = "stream", responses((status = 101, description = "WebSocket upgrade")))]
#[allow(dead_code, clippy::unused_async)]
async fn stream_ws_docstub() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "schema": "disrobe.serve.stream.doc/v0",
        "note": "WebSocket upgrade endpoint; connect with Sec-WebSocket-Protocol disrobe-stream.v1",
    }))
}

async fn stream_ws(State(state): State<Arc<ServerState>>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

async fn handle_ws(mut socket: WebSocket, state: Arc<ServerState>) {
    let cancel: CancellationToken = state.cancel.clone();
    loop {
        tokio::select! {
            () = cancel.cancelled() => break,
            recv = socket.recv() => match recv {
                Some(Ok(Message::Text(text))) => {
                    let parsed: Result<StreamRequest, _> = serde_json::from_str(text.as_str());
                    match parsed {
                        Ok(req) => stream_dispatch(&mut socket, req).await,
                        Err(e) => {
                            let err: serde_json::Value = serde_json::json!({
                                "stage": "error",
                                "error_code": "DR-CLI-0189",
                                "message": format!("malformed StreamRequest: {e}"),
                            });
                            let _ = socket.send(Message::Text(err.to_string().into())).await;
                        }
                    }
                }
                Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                Some(Ok(_)) => {}
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamRequest {
    op: String,
    bytes_b64: String,
}

async fn stream_dispatch(socket: &mut WebSocket, req: StreamRequest) {
    let bytes: Vec<u8> = match decode_inline_bytes(&req.bytes_b64) {
        Ok(b) => b,
        Err(api) => {
            let line: serde_json::Value = serde_json::json!({
                "stage": "error",
                "error_code": api.error_code,
                "message": api.message,
            });
            let _ = socket.send(Message::Text(line.to_string().into())).await;
            return;
        }
    };
    let line0: serde_json::Value = serde_json::json!({
        "stage": "received",
        "op": req.op,
        "bytes": bytes.len(),
        "blake3": hex32(blake3::hash(&bytes).as_bytes()),
    });
    if socket
        .send(Message::Text(line0.to_string().into()))
        .await
        .is_err()
    {
        return;
    }
    let classification: disrobe_binfmt::InputClassification =
        disrobe_binfmt::classify_input(std::path::Path::new("inline"), &bytes);
    let line1: serde_json::Value = serde_json::json!({
        "stage": "classified",
        "action": format!("{:?}", classification.primary_action),
        "reason": classification.reason,
    });
    if socket
        .send(Message::Text(line1.to_string().into()))
        .await
        .is_err()
    {
        return;
    }
    let line2: serde_json::Value = serde_json::json!({
        "stage": "completed",
        "op": req.op,
    });
    let _ = socket.send(Message::Text(line2.to_string().into())).await;
}

async fn openapi(State(_state): State<Arc<ServerState>>) -> Json<serde_json::Value> {
    let raw: String = ApiDoc::openapi().to_json().unwrap_or_default();
    let value: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|_| serde_json::json!({ "error": "openapi serialize failed" }));
    Json(value)
}

#[derive(Debug)]
struct ApiError {
    code: StatusCode,
    error_code: &'static str,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body: serde_json::Value = serde_json::json!({
            "error_code": self.error_code,
            "message": self.message,
        });
        (self.code, Json(body)).into_response()
    }
}

fn decode_inline_bytes(bytes_b64: &str) -> Result<Vec<u8>, ApiError> {
    if bytes_b64.is_empty() {
        return Err(ApiError {
            code: StatusCode::BAD_REQUEST,
            error_code: "DR-CLI-0182",
            message: "`bytes_b64` is required and must be non-empty; disrobe serve never reads from disk based on client input".to_owned(),
        });
    }
    decode_base64(bytes_b64).map_err(|e| ApiError {
        code: StatusCode::BAD_REQUEST,
        error_code: "DR-CLI-0181",
        message: format!("bytes_b64 decode: {e}"),
    })
}

fn decode_base64(input: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let mut out: Vec<u8> = Vec::with_capacity(cleaned.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    let mut pad: usize = 0;
    for c in cleaned.chars() {
        let v: u32 = match c {
            'A'..='Z' => u32::from(c as u8 - b'A'),
            'a'..='z' => u32::from(c as u8 - b'a' + 26),
            '0'..='9' => u32::from(c as u8 - b'0' + 52),
            '+' | '-' => 62,
            '/' | '_' => 63,
            '=' => {
                pad += 1;
                continue;
            }
            _ => return Err(format!("invalid base64 char: {c:?}")),
        };
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            let byte: u8 = ((buf >> bits) & 0xFF) as u8;
            out.push(byte);
        }
    }
    if pad > 2 {
        return Err("too many padding chars".to_owned());
    }
    Ok(out)
}

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn encode_base64(input: &[u8]) -> String {
    let mut out: String = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut chunks: std::slice::ChunksExact<'_, u8> = input.chunks_exact(3);
    for chunk in chunks.by_ref() {
        let n: u32 = (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
        out.push(BASE64_ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(BASE64_ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push(BASE64_ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        out.push(BASE64_ALPHABET[(n & 0x3F) as usize] as char);
    }
    let rem: &[u8] = chunks.remainder();
    match rem.len() {
        1 => {
            let n: u32 = u32::from(rem[0]) << 16;
            out.push(BASE64_ALPHABET[((n >> 18) & 0x3F) as usize] as char);
            out.push(BASE64_ALPHABET[((n >> 12) & 0x3F) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n: u32 = (u32::from(rem[0]) << 16) | (u32::from(rem[1]) << 8);
            out.push(BASE64_ALPHABET[((n >> 18) & 0x3F) as usize] as char);
            out.push(BASE64_ALPHABET[((n >> 12) & 0x3F) as usize] as char);
            out.push(BASE64_ALPHABET[((n >> 6) & 0x3F) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

fn hex32(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s: String = String::with_capacity(64);
    for b in bytes {
        let _: std::fmt::Result = write!(s, "{b:02x}");
    }
    s
}

fn normalize_dr_code(raw: &str) -> String {
    let upper: String = raw.trim().to_ascii_uppercase();
    if upper.starts_with("DR-") {
        return upper;
    }
    format!("DR-{upper}")
}

fn run_stdio_lsp() -> miette::Result<()> {
    use lsp_server::{Connection, Message as LspMessage, Response};
    use lsp_types::{ServerCapabilities, ServerInfo};

    let (connection, io_threads): (Connection, lsp_server::IoThreads) = Connection::stdio();
    let server_caps: ServerCapabilities = ServerCapabilities::default();
    let init_value: serde_json::Value = serde_json::json!({
        "capabilities": server_caps,
        "serverInfo": ServerInfo {
            name: "disrobe-serve".to_owned(),
            version: Some(SERVE_VERSION.to_owned()),
        },
    });
    let _init_params: serde_json::Value = connection
        .initialize(init_value)
        .map_err(|e| miette::miette!("DR-CLI-0201: initialize failed: {e}"))?;

    while let Ok(msg) = connection.receiver.recv() {
        match msg {
            LspMessage::Request(req) => {
                if connection.handle_shutdown(&req).unwrap_or(false) {
                    break;
                }
                let response: Response = build_lsp_response(req);
                let _ = connection.sender.send(LspMessage::Response(response));
            }
            LspMessage::Notification(_) | LspMessage::Response(_) => {}
        }
    }
    io_threads
        .join()
        .map_err(|e| miette::miette!("DR-CLI-0203: io thread join: {e}"))?;
    Ok(())
}

#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct LspAnalyzeParams {
    bytes_b64: String,
    #[serde(default)]
    label: Option<String>,
}

fn build_lsp_response(req: lsp_server::Request) -> lsp_server::Response {
    use lsp_server::{ErrorCode, Response, ResponseError};
    match req.method.as_str() {
        "disrobe/analyze" => {
            let parsed: Result<LspAnalyzeParams, serde_json::Error> =
                serde_json::from_value::<LspAnalyzeParams>(req.params.clone());
            let parsed: LspAnalyzeParams = match parsed {
                Ok(p) => p,
                Err(e) => {
                    return Response {
                        id: req.id,
                        result: None,
                        error: Some(ResponseError {
                            code: ErrorCode::InvalidParams as i32,
                            message: format!(
                                "DR-CLI-0210: disrobe/analyze requires `bytes_b64` (string); \
                                 path-based reads are not supported over LSP-stdio: {e}"
                            ),
                            data: None,
                        }),
                    };
                }
            };
            let bytes: Vec<u8> = match decode_base64(&parsed.bytes_b64) {
                Ok(b) if !b.is_empty() => b,
                Ok(_) => {
                    return Response {
                        id: req.id,
                        result: None,
                        error: Some(ResponseError {
                            code: ErrorCode::InvalidParams as i32,
                            message: "DR-CLI-0211: `bytes_b64` decoded to empty payload".to_owned(),
                            data: None,
                        }),
                    };
                }
                Err(e) => {
                    return Response {
                        id: req.id,
                        result: None,
                        error: Some(ResponseError {
                            code: ErrorCode::InvalidParams as i32,
                            message: format!("DR-CLI-0212: `bytes_b64` decode failed: {e}"),
                            data: None,
                        }),
                    };
                }
            };
            let label: String = parsed.label.unwrap_or_else(|| "<inline>".to_owned());
            let cl: disrobe_binfmt::InputClassification =
                disrobe_binfmt::classify_input(std::path::Path::new(&label), &bytes);
            let response: serde_json::Value = serde_json::json!({
                "label": label,
                "bytes": bytes.len(),
                "action": format!("{:?}", cl.primary_action),
                "reason": cl.reason,
                "blake3": hex32(blake3::hash(&bytes).as_bytes()),
            });
            Response {
                id: req.id,
                result: Some(response),
                error: None,
            }
        }
        "disrobe/explain" => {
            let code: String = req
                .params
                .get("code")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            let normalized: String = normalize_dr_code(&code);
            let response: serde_json::Value = crate::cli::explain::lookup_for_serve(&normalized)
                .map_or_else(
                    || serde_json::json!({ "code": normalized.clone(), "known": false }),
                    |entry| {
                        serde_json::json!({
                            "code": normalized.clone(),
                            "known": true,
                            "title": entry.title,
                            "description": entry.description,
                            "crate_path": entry.crate_path,
                        })
                    },
                );
            Response {
                id: req.id,
                result: Some(response),
                error: None,
            }
        }
        other => Response {
            id: req.id,
            result: None,
            error: Some(ResponseError {
                code: ErrorCode::MethodNotFound as i32,
                message: format!("disrobe LSP: unsupported method `{other}`"),
                data: None,
            }),
        },
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trip_simple() {
        let raw: Vec<u8> = b"hello world".to_vec();
        let encoded: &str = "aGVsbG8gd29ybGQ=";
        assert_eq!(decode_base64(encoded).expect("decode"), raw);
    }

    #[test]
    fn base64_rejects_garbage() {
        let bad: Result<Vec<u8>, String> = decode_base64("!!!not base64!!!");
        assert!(bad.is_err());
    }

    #[test]
    fn base64_encode_matches_decode() {
        let raw: &[u8] = b"hello world";
        let encoded: String = encode_base64(raw);
        assert_eq!(encoded, "aGVsbG8gd29ybGQ=");
        assert_eq!(decode_base64(&encoded).expect("decode"), raw.to_vec());
    }

    #[test]
    fn base64_encode_handles_all_pad_widths() {
        for n in 0..=64usize {
            let raw: Vec<u8> = (0..n)
                .map(|i| u8::try_from(i & 0xFF).unwrap_or(0))
                .collect();
            let encoded: String = encode_base64(&raw);
            let decoded: Vec<u8> = decode_base64(&encoded).expect("decode");
            assert_eq!(decoded, raw, "round-trip failed at n={n}");
        }
    }

    #[test]
    fn decode_inline_bytes_rejects_empty() {
        let err: ApiError = decode_inline_bytes("").expect_err("must reject empty");
        assert_eq!(err.error_code, "DR-CLI-0182");
    }

    #[test]
    fn decode_inline_bytes_rejects_garbage() {
        let err: ApiError = decode_inline_bytes("!!!").expect_err("must reject garbage");
        assert_eq!(err.error_code, "DR-CLI-0181");
    }

    #[test]
    fn analyze_request_rejects_path_field() {
        let raw: &str = r#"{"path":"/etc/passwd"}"#;
        let parsed: Result<AnalyzeRequest, _> = serde_json::from_str(raw);
        assert!(parsed.is_err(), "AnalyzeRequest must not accept `path`");
    }

    #[test]
    fn envelope_verify_request_rejects_path_field() {
        let raw: &str = r#"{"path":"/etc/passwd"}"#;
        let parsed: Result<EnvelopeVerifyRequest, _> = serde_json::from_str(raw);
        assert!(
            parsed.is_err(),
            "EnvelopeVerifyRequest must not accept `path`"
        );
    }

    #[test]
    fn envelope_create_request_rejects_source_path_field() {
        let raw: &str = r#"{"source_path":"/etc/passwd","out_path":"/tmp/x"}"#;
        let parsed: Result<EnvelopeCreateRequest, _> = serde_json::from_str(raw);
        assert!(
            parsed.is_err(),
            "EnvelopeCreateRequest must not accept `source_path`/`out_path`"
        );
    }

    #[test]
    fn pass_descriptors_present() {
        assert!(PASS_DESCRIPTORS.iter().any(|p| p.name == "pyarmor"));
        assert!(PASS_DESCRIPTORS.iter().any(|p| p.name == "wasm"));
    }

    #[test]
    fn normalize_adds_dr_prefix() {
        assert_eq!(normalize_dr_code("pyarm-0007"), "DR-PYARM-0007");
        assert_eq!(normalize_dr_code("DR-PYARM-0007"), "DR-PYARM-0007");
    }

    #[test]
    fn lsp_analyze_params_reject_path_field() {
        let raw: serde_json::Value = serde_json::json!({ "path": "/etc/passwd" });
        let parsed: Result<LspAnalyzeParams, _> = serde_json::from_value(raw);
        assert!(
            parsed.is_err(),
            "LSP-stdio `disrobe/analyze` must not accept `path` field"
        );
    }

    #[test]
    fn lsp_analyze_params_accept_bytes_b64() {
        let raw: serde_json::Value =
            serde_json::json!({ "bytes_b64": "aGVsbG8=", "label": "x.bin" });
        let parsed: LspAnalyzeParams =
            serde_json::from_value(raw).expect("must accept bytes_b64 + label");
        assert_eq!(parsed.bytes_b64, "aGVsbG8=");
        assert_eq!(parsed.label.as_deref(), Some("x.bin"));
    }

    #[test]
    fn lsp_analyze_params_reject_arbitrary_extra_field() {
        let raw: serde_json::Value =
            serde_json::json!({ "bytes_b64": "aGVsbG8=", "uri": "file:///etc/passwd" });
        let parsed: Result<LspAnalyzeParams, _> = serde_json::from_value(raw);
        assert!(
            parsed.is_err(),
            "LSP-stdio `disrobe/analyze` must reject unknown fields (deny_unknown_fields)"
        );
    }
}
