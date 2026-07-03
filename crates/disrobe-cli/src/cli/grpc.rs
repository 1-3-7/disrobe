#![allow(clippy::needless_pass_by_value)]
use std::collections::BTreeMap;
use std::net::SocketAddr;

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
        let bytes: &[u8] = require_inline_bytes(&req.bytes_inline)?;
        let hash: String = hex32(blake3::hash(bytes).as_bytes());
        let classification: disrobe_binfmt::InputClassification =
            disrobe_binfmt::classify_input(std::path::Path::new("inline"), bytes);
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
        let bytes: &[u8] = require_inline_bytes(&req.bytes_inline)?;
        let envelope: disrobe_ir::Envelope = disrobe_ir::Envelope::decode(bytes)
            .map_err(|e| Status::invalid_argument(format!("DR-CLI-0184: verify failed: {e}")))?;
        Ok(Response::new(PbEnvelopeVerifyResponse {
            verified: true,
            version: u32::from(envelope.version),
            rung: format!("{:?}", envelope.rung),
            hot_bytes: envelope.hot.len() as u64,
            cold_bytes: envelope.cold.len() as u64,
            root_hash_blake3: hex32(&envelope.root_hash),
        }))
    }

    async fn envelope_create(
        &self,
        request: Request<PbEnvelopeCreateRequest>,
    ) -> Result<Response<PbEnvelopeCreateResponse>, Status> {
        let req: PbEnvelopeCreateRequest = request.into_inner();
        let bytes: Vec<u8> = require_inline_bytes(&req.bytes_inline)?.to_vec();
        let source_hash: [u8; 32] = *blake3::hash(&bytes).as_bytes();
        let bytes_len: usize = bytes.len();
        let source_label: String = if req.source_label.is_empty() {
            "inline".to_owned()
        } else {
            req.source_label
        };
        let detected_format: Option<String> = if req.detected_format.is_empty() {
            None
        } else {
            Some(req.detected_format.clone())
        };
        let payload: disrobe_ir::RawPayload = disrobe_ir::RawPayload {
            source_path: source_label,
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
        let envelope_inline: Vec<u8> = envelope
            .encode()
            .map_err(|e| Status::internal(format!("DR-CLI-0188: encode envelope: {e}")))?;
        let envelope_len: u64 = envelope_inline.len() as u64;
        Ok(Response::new(PbEnvelopeCreateResponse {
            envelope_inline,
            envelope_bytes: envelope_len,
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
    (
        "py-decompile",
        "in-tree native CPython 1.0..3.15 decompiler",
    ),
    ("py-sourcedefender", ".pye AES-CTR decrypt"),
    ("js-deob", "string-array + unminify + scope-aware rename"),
    (
        "js-unbundle",
        "webpack / vite / rollup / esbuild / turbopack / bun module slice",
    ),
    (
        "wasm",
        "analyze / lift to rust|ts|wat / 4 obfuscator family deob",
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

#[allow(clippy::result_large_err)]
fn require_inline_bytes(bytes_inline: &[u8]) -> Result<&[u8], Status> {
    if bytes_inline.is_empty() {
        return Err(Status::invalid_argument(
            "DR-CLI-0182: `bytes_inline` is required & must be non-empty; disrobe serve never reads from disk based on client input",
        ));
    }
    Ok(bytes_inline)
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
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
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

    #[test]
    fn require_inline_bytes_rejects_empty() {
        let err: Status = require_inline_bytes(&[]).expect_err("empty must be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("DR-CLI-0182"));
        assert!(err.message().contains("never reads from disk"));
    }

    #[test]
    fn require_inline_bytes_accepts_nonempty() {
        let got: &[u8] = require_inline_bytes(b"abc").expect("non-empty accepted");
        assert_eq!(got, b"abc");
    }

    async fn spawn_in_process_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener: tokio::net::TcpListener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral grpc port");
        let addr: std::net::SocketAddr = listener.local_addr().expect("local addr");
        let incoming: tokio_stream::wrappers::TcpListenerStream =
            tokio_stream::wrappers::TcpListenerStream::new(listener);
        let handle: tokio::task::JoinHandle<()> = tokio::spawn(async move {
            let _: Result<(), tonic::transport::Error> = tonic::transport::Server::builder()
                .add_service(DisrobeServer::new(DisrobeRpc))
                .serve_with_incoming(incoming)
                .await;
        });
        (addr, handle)
    }

    async fn connect_client(
        addr: std::net::SocketAddr,
    ) -> pb::disrobe_client::DisrobeClient<tonic::transport::Channel> {
        let endpoint: String = format!("http://{addr}");
        for _ in 0..50 {
            if let Ok(client) = pb::disrobe_client::DisrobeClient::connect(endpoint.clone()).await {
                return client;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("grpc client could not connect to {endpoint}");
    }

    #[tokio::test]
    async fn analyze_rpc_round_trip_returns_correct_classification() {
        let (addr, server): (std::net::SocketAddr, tokio::task::JoinHandle<()>) =
            spawn_in_process_server().await;
        let mut client: pb::disrobe_client::DisrobeClient<tonic::transport::Channel> =
            connect_client(addr).await;

        let payload: Vec<u8> = {
            let mut bytes: Vec<u8> = vec![0x00, b'a', b's', b'm', 0x01, 0x00, 0x00, 0x00];
            bytes.extend_from_slice(&[0u8; 16]);
            bytes
        };

        let expected_hash: String = hex32(blake3::hash(&payload).as_bytes());
        let expected: disrobe_binfmt::InputClassification =
            disrobe_binfmt::classify_input(std::path::Path::new("inline"), &payload);
        let expected_action: String = format!("{:?}", expected.primary_action);

        let response: PbAnalyzeResponse = client
            .analyze(Request::new(PbAnalyzeRequest {
                bytes_inline: payload.clone(),
                hint: String::new(),
            }))
            .await
            .expect("Analyze RPC over the wire")
            .into_inner();

        assert_eq!(
            response.bytes_read,
            payload.len() as u64,
            "server read the exact bytes we sent"
        );
        assert_eq!(
            response.blake3_hash, expected_hash,
            "server-reported blake3 must match an independent hash of the same bytes"
        );
        assert_eq!(
            response.routed_action, expected_action,
            "routed action over the wire must match a local classify_input of the same bytes"
        );
        assert_ne!(
            response.routed_action, "Unknown",
            "a wasm-magic module must classify to a concrete action, not Unknown"
        );

        server.abort();
    }

    #[tokio::test]
    async fn analyze_rpc_rejects_empty_inline_bytes_over_the_wire() {
        let (addr, server): (std::net::SocketAddr, tokio::task::JoinHandle<()>) =
            spawn_in_process_server().await;
        let mut client: pb::disrobe_client::DisrobeClient<tonic::transport::Channel> =
            connect_client(addr).await;

        let status: Status = client
            .analyze(Request::new(PbAnalyzeRequest {
                bytes_inline: Vec::new(),
                hint: String::new(),
            }))
            .await
            .expect_err("empty inline bytes must be rejected by the server");
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert!(
            status.message().contains("DR-CLI-0182"),
            "the server's rejection message must travel back: {}",
            status.message()
        );

        server.abort();
    }
}
