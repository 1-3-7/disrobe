#![allow(clippy::needless_pass_by_value)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use tonic::{Request, Response, Status};

pub(crate) mod pb {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::all,
        clippy::cargo,
        unreachable_pub,
        missing_debug_implementations,
        unused
    )]
    tonic::include_proto!("disrobe.v1");
    pub(crate) const FILE_DESCRIPTOR_SET: &[u8] = include_bytes!(env!("DISROBE_DESCRIPTOR_PATH"));
}

use pb::disrobe_server::{Disrobe as DisrobeService, DisrobeServer};
use pb::{
    AnalyzeRequest as PbAnalyzeRequest, AnalyzeResponse as PbAnalyzeResponse,
    EnvelopeCreateRequest as PbEnvelopeCreateRequest,
    EnvelopeCreateResponse as PbEnvelopeCreateResponse,
    EnvelopeVerifyRequest as PbEnvelopeVerifyRequest,
    EnvelopeVerifyResponse as PbEnvelopeVerifyResponse, ExplainRequest as PbExplainRequest,
    ExplainResponse as PbExplainResponse, HealthRequest as PbHealthRequest,
    HealthResponse as PbHealthResponse, PassDescriptor as PbPassDescriptor,
    PassesRequest as PbPassesRequest, PassesResponse as PbPassesResponse,
    VersionRequest as PbVersionRequest, VersionResponse as PbVersionResponse,
};

const GRPC_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Default)]
pub(crate) struct DisrobeRpc;

#[tonic::async_trait]
impl DisrobeService for DisrobeRpc {
    async fn analyze(
        &self,
        request: Request<PbAnalyzeRequest>,
    ) -> Result<Response<PbAnalyzeResponse>, Status> {
        let req: PbAnalyzeRequest = request.into_inner();
        let path_buf: Option<PathBuf> = if req.path.is_empty() {
            None
        } else {
            Some(PathBuf::from(&req.path))
        };
        let bytes: Vec<u8> = match (path_buf.as_deref(), req.bytes_inline.as_slice()) {
            (Some(p), _) => std::fs::read(p)
                .map_err(|e| Status::invalid_argument(format!("DR-CLI-0180: read {e}")))?,
            (None, b) if !b.is_empty() => b.to_vec(),
            (None, _) => {
                return Err(Status::invalid_argument(
                    "DR-CLI-0182: must provide either path or bytes_inline",
                ));
            }
        };
        let hash: String = hex32(blake3::hash(&bytes).as_bytes());
        let classification: disrobe_binfmt::InputClassification = disrobe_binfmt::classify_input(
            path_buf
                .as_deref()
                .unwrap_or_else(|| std::path::Path::new("inline")),
            &bytes,
        );
        let candidates: Vec<String> = classification
            .candidates
            .iter()
            .map(|(a, c)| format!("{a:?} (confidence={:.2})", c.0))
            .collect();
        Ok(Response::new(PbAnalyzeResponse {
            routed_action: format!("{:?}", classification.primary_action),
            bytes_read: bytes.len() as u64,
            blake3_hash: hash,
            reason: classification.reason,
            candidates,
        }))
    }

    async fn explain(
        &self,
        request: Request<PbExplainRequest>,
    ) -> Result<Response<PbExplainResponse>, Status> {
        let req: PbExplainRequest = request.into_inner();
        let normalized: String = normalize_dr_code(&req.code);
        let response: PbExplainResponse = match crate::cli::explain::lookup_for_serve(&normalized) {
            Some(entry) => PbExplainResponse {
                code: normalized,
                known: true,
                title: entry.title.to_owned(),
                description: entry.description.to_owned(),
                crate_path: entry.crate_path.to_owned(),
            },
            None => PbExplainResponse {
                code: normalized,
                known: false,
                title: String::new(),
                description: String::new(),
                crate_path: String::new(),
            },
        };
        Ok(Response::new(response))
    }

    async fn envelope_verify(
        &self,
        request: Request<PbEnvelopeVerifyRequest>,
    ) -> Result<Response<PbEnvelopeVerifyResponse>, Status> {
        let req: PbEnvelopeVerifyRequest = request.into_inner();
        let path: PathBuf = PathBuf::from(&req.path);
        let view: disrobe_ir::MmapView = disrobe_ir::mmap_envelope_view(&path)
            .map_err(|e| Status::invalid_argument(format!("DR-CLI-0184: verify failed: {e}")))?;
        Ok(Response::new(PbEnvelopeVerifyResponse {
            verified: true,
            version: u32::from(view.version),
            rung: format!("{:?}", view.rung),
            hot_bytes: view.hot().len() as u64,
            cold_bytes: view.cold().len() as u64,
            root_hash_blake3: hex32(&view.root_hash),
        }))
    }

    async fn envelope_create(
        &self,
        request: Request<PbEnvelopeCreateRequest>,
    ) -> Result<Response<PbEnvelopeCreateResponse>, Status> {
        let req: PbEnvelopeCreateRequest = request.into_inner();
        let source_path: PathBuf = PathBuf::from(&req.source_path);
        let out_path: PathBuf = PathBuf::from(&req.out_path);
        let bytes: Vec<u8> = std::fs::read(&source_path)
            .map_err(|e| Status::invalid_argument(format!("DR-CLI-0185: read source: {e}")))?;
        let source_hash: [u8; 32] = *blake3::hash(&bytes).as_bytes();
        let bytes_len: usize = bytes.len();
        let detected_format: Option<String> = if req.detected_format.is_empty() {
            None
        } else {
            Some(req.detected_format.clone())
        };
        let payload: disrobe_ir::RawPayload = disrobe_ir::RawPayload {
            source_path: source_path.display().to_string(),
            source_bytes: bytes,
            source_hash,
            detected_format,
        };
        let hot: Vec<u8> = disrobe_ir::encode_raw(&payload)
            .map_err(|e| Status::internal(format!("DR-CLI-0186: encode_raw: {e}")))?;
        let produced_by: String = if req.produced_by.is_empty() {
            "disrobe-grpc".to_owned()
        } else {
            req.produced_by
        };
        let sidecar: disrobe_ir::Sidecar = disrobe_ir::Sidecar {
            produced_by,
            produced_by_version: GRPC_VERSION.to_owned(),
            capabilities: vec![disrobe_core::Capability::produces("raw", 1)],
            provenance: BTreeMap::default(),
        };
        let cold: Vec<u8> = sidecar
            .encode()
            .map_err(|e| Status::internal(format!("DR-CLI-0187: sidecar encode: {e}")))?;
        let envelope: disrobe_ir::Envelope =
            disrobe_ir::Envelope::new(disrobe_ir::Rung::Raw, hot, cold);
        envelope
            .write_to_path(&out_path)
            .map_err(|e| Status::internal(format!("DR-CLI-0188: write envelope: {e}")))?;
        Ok(Response::new(PbEnvelopeCreateResponse {
            out_path: out_path.display().to_string(),
            bytes_in: bytes_len as u64,
            root_hash_blake3: hex32(&envelope.root_hash),
            source_hash_blake3: hex32(&source_hash),
        }))
    }

    async fn passes(
        &self,
        _request: Request<PbPassesRequest>,
    ) -> Result<Response<PbPassesResponse>, Status> {
        let passes: Vec<PbPassDescriptor> = PASSES
            .iter()
            .map(|(name, description)| PbPassDescriptor {
                name: (*name).to_owned(),
                description: (*description).to_owned(),
            })
            .collect();
        Ok(Response::new(PbPassesResponse { passes }))
    }

    async fn health(
        &self,
        _request: Request<PbHealthRequest>,
    ) -> Result<Response<PbHealthResponse>, Status> {
        Ok(Response::new(PbHealthResponse {
            status: "serving".to_owned(),
            version: GRPC_VERSION.to_owned(),
        }))
    }

    async fn version(
        &self,
        _request: Request<PbVersionRequest>,
    ) -> Result<Response<PbVersionResponse>, Status> {
        Ok(Response::new(PbVersionResponse {
            name: "disrobe".to_owned(),
            version: GRPC_VERSION.to_owned(),
            api: "v1".to_owned(),
        }))
    }
}

const PASSES: &[(&str, &str)] = &[
    ("pyarmor", "v6/v7 (dyn-hook) + v8/v9 static unpack"),
    ("pyinstaller", "PI 2.1..6.x extract + AES-CTR/CFB decrypt"),
    (
        "pyfreeze",
        "cx_Freeze / py2exe / shiv / pex detect + extract",
    ),
    ("nuitka", "--onefile payload extract + symbol scan"),
    ("py-deob", "encoder peel + ruff-AST cleanup"),
    ("py-disasm", "Python 2.7..3.14 disassembler"),
    ("py-decompile", "pycdc subprocess or disasm-fallback"),
    ("py-sourcedefender", ".pye AES-CTR decrypt"),
    ("js-deob", "string-array + unminify + scope-aware rename"),
    (
        "js-unbundle",
        "webpack / vite / rollup / esbuild / turbopack / bun module slice",
    ),
    (
        "wasm",
        "analyze / lift to rust|ts|wat / 5 obfuscator family deob",
    ),
    ("envelope", ".dr container create / inspect / verify"),
    ("native-symbols", "object crate PE/ELF/Mach-O symbol dump"),
];

pub(crate) async fn serve_grpc(addr: SocketAddr) -> miette::Result<()> {
    println!("disrobe serve: gRPC listening on {addr}");
    println!("  service: disrobe.v1.Disrobe");
    println!("  health:  grpc.health.v1.Health");
    println!("  reflect: grpc.reflection.v1.ServerReflection");
    let disrobe_service: DisrobeServer<DisrobeRpc> = DisrobeServer::new(DisrobeRpc);
    let (reporter, health_service) = tonic_health::server::health_reporter();
    reporter.set_serving::<DisrobeServer<DisrobeRpc>>().await;
    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(pb::FILE_DESCRIPTOR_SET)
        .build_v1()
        .map_err(|e| miette::miette!("DR-CLI-0220: reflection setup failed: {e}"))?;
    tonic::transport::Server::builder()
        .add_service(disrobe_service)
        .add_service(health_service)
        .add_service(reflection_service)
        .serve(addr)
        .await
        .map_err(|e| miette::miette!("DR-CLI-0221: tonic serve: {e}"))?;
    Ok(())
}

#[inline]
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn normalize_adds_prefix() {
        assert_eq!(normalize_dr_code("pyarm-0007"), "DR-PYARM-0007");
        assert_eq!(normalize_dr_code("DR-CLI-0001"), "DR-CLI-0001");
    }

    #[test]
    fn passes_table_has_pyarmor() {
        assert!(PASSES.iter().any(|(n, _)| *n == "pyarmor"));
        assert!(PASSES.iter().any(|(n, _)| *n == "wasm"));
    }

    #[test]
    fn hex32_lowercase_padded() {
        let bytes: [u8; 32] = [0u8; 32];
        let s: String = hex32(&bytes);
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c == '0'));
    }
}
