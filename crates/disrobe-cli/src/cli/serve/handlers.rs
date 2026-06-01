use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use utoipa::OpenApi;

use super::SERVE_VERSION;
use super::util::{ApiError, decode_inline_bytes, encode_base64, hex32, normalize_dr_code};

#[derive(Debug)]
pub(super) struct ServerState {
    pub(super) cancel: CancellationToken,
}

impl Default for ServerState {
    fn default() -> Self {
        Self {
            cancel: CancellationToken::new(),
        }
    }
}

#[utoipa::path(get, path = "/v1/health", tag = "core", responses((status = 200, body = HealthResponse)))]
pub(super) async fn health(State(_state): State<Arc<ServerState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "serving".to_owned(),
        version: SERVE_VERSION.to_owned(),
    })
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub(super) struct HealthResponse {
    status: String,
    version: String,
}

#[utoipa::path(get, path = "/v1/version", tag = "core", responses((status = 200, body = VersionResponse)))]
pub(super) async fn version(State(_state): State<Arc<ServerState>>) -> Json<VersionResponse> {
    Json(VersionResponse {
        name: "disrobe".to_owned(),
        version: SERVE_VERSION.to_owned(),
        api: "v1".to_owned(),
    })
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub(super) struct VersionResponse {
    name: String,
    version: String,
    api: String,
}

#[utoipa::path(get, path = "/v1/passes", tag = "passes", responses((status = 200, body = PassesResponse)))]
pub(super) async fn list_passes(State(_state): State<Arc<ServerState>>) -> Json<PassesResponse> {
    Json(PassesResponse {
        passes: PASS_DESCRIPTORS
            .iter()
            .map(PassDescriptorRef::to_owned)
            .collect(),
    })
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub(super) struct PassesResponse {
    passes: Vec<PassDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub(super) struct PassDescriptor {
    name: String,
    description: String,
}

pub(super) struct PassDescriptorRef {
    pub(super) name: &'static str,
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

pub(super) const PASS_DESCRIPTORS: &[PassDescriptorRef] = &[
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
pub(super) struct AnalyzeRequest {
    bytes_b64: String,
    hint: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub(super) struct AnalyzeResponse {
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
pub(super) async fn analyze(
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
pub(super) struct ExplainResponse {
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
pub(super) async fn explain_endpoint(
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
pub(super) struct EnvelopeVerifyRequest {
    bytes_b64: String,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub(super) struct EnvelopeVerifyResponse {
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
pub(super) async fn envelope_verify(
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
pub(super) struct EnvelopeCreateRequest {
    bytes_b64: String,
    source_label: Option<String>,
    produced_by: Option<String>,
    detected_format: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub(super) struct EnvelopeCreateResponse {
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
pub(super) async fn envelope_create(
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
pub(super) async fn stream_ws_docstub() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "schema": "disrobe.serve.stream.doc/v0",
        "note": "WebSocket upgrade endpoint; connect with Sec-WebSocket-Protocol disrobe-stream.v1",
    }))
}

pub(super) async fn openapi(State(_state): State<Arc<ServerState>>) -> Json<serde_json::Value> {
    let raw: String = super::ApiDoc::openapi().to_json().unwrap_or_default();
    let value: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|_| serde_json::json!({ "error": "openapi serialize failed" }));
    Json(value)
}
