#![allow(
    clippy::needless_pass_by_value,
    clippy::too_many_lines,
    clippy::too_many_arguments
)]

mod handlers;
mod lsp;
mod util;
mod ws;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderValue, Method};
use axum::routing::{get, post};
use tokio::net::TcpListener;
use tokio::runtime::Builder as RuntimeBuilder;
use tokio_util::sync::CancellationToken;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;

use handlers::{
    AnalyzeRequest, AnalyzeResponse, EnvelopeCreateRequest, EnvelopeCreateResponse,
    EnvelopeVerifyRequest, EnvelopeVerifyResponse, ExplainResponse, HealthResponse, PassDescriptor,
    PassesResponse, ServerState, VersionResponse, analyze, envelope_create, envelope_verify,
    explain_endpoint, health, list_passes, openapi, version,
};

const SERVE_VERSION: &str = env!("CARGO_PKG_VERSION");

pub(crate) fn run(
    bind: String,
    stdio: bool,
    grpc: bool,
    cors_origins: Vec<String>,
    max_body_size: usize,
) -> miette::Result<()> {
    if stdio {
        return lsp::run_stdio_lsp();
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
        handlers::health,
        handlers::version,
        handlers::list_passes,
        handlers::analyze,
        handlers::explain_endpoint,
        handlers::envelope_verify,
        handlers::envelope_create,
        handlers::stream_ws_docstub,
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
        .route("/v1/stream", get(ws::stream_ws))
        .route("/v2/health", get(health))
        .route("/v2/version", get(version))
        .route("/v2/passes", get(list_passes))
        .route("/v2/analyze", post(analyze))
        .route("/v2/explain/{code}", post(explain_endpoint))
        .route("/v2/envelope/verify", post(envelope_verify))
        .route("/v2/envelope/create", post(envelope_create))
        .route("/v2/stream", get(ws::stream_ws))
        .route("/openapi.json", get(openapi))
        .route("/v1/openapi.json", get(openapi))
        .route("/v2/openapi.json", get(openapi))
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
    println!("  (/v2/* aliases /v1/* for forward-compatible clients)");
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::handlers::{
        AnalyzeRequest, EnvelopeCreateRequest, EnvelopeVerifyRequest, PASS_DESCRIPTORS,
    };
    use super::lsp::LspAnalyzeParams;
    use super::util::{
        ApiError, decode_base64, decode_inline_bytes, encode_base64, normalize_dr_code,
    };

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
