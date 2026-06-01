use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use disrobe_core::chain::{ChainPassRecovery, ChainRecoveryReport};
use disrobe_core::provenance_map::{LineProvenance, ProvenanceMap};
use disrobe_core::recovery::ConfidenceTier;
use disrobe_llm_metadata::annotation::{ANNOTATION_SCHEMA, AnnotationFile, SymbolAnnotation};
use rmcp::ErrorData;
use rmcp::Json;
use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use serde::{Deserialize, Serialize};

const RENAMES_SCHEMA: &str = "disrobe.renames/v1";

#[derive(Debug, Clone)]
pub struct DisrobeMcp {
    tool_router: ToolRouter<Self>,
}

impl Default for DisrobeMcp {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub struct VerifyParams {
    pub bytes_b64: String,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct VerifyOut {
    pub verified: bool,
    pub version: u16,
    pub rung: String,
    pub hot_bytes: usize,
    pub cold_bytes: usize,
    pub root_hash_blake3: String,
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub struct RenameParams {
    pub old: String,
    pub new: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct RenameOut {
    pub path: String,
    pub schema: String,
    pub old: String,
    pub new: String,
    pub record_count: usize,
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub struct AnnotParams {
    pub target: String,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct AnnotOut {
    pub target: String,
    pub annotation_path: String,
    pub schema: String,
    pub symbol_count: usize,
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub struct ProvenanceLookupParams {
    pub map_json: String,
    pub line: u32,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct LineProvenanceOut {
    pub line: u32,
    pub pass: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opcode_range: Option<[u64; 2]>,
    pub confidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl From<LineProvenance> for LineProvenanceOut {
    fn from(lp: LineProvenance) -> Self {
        Self {
            line: lp.line,
            pass: lp.pass,
            source_offset: lp.source_offset,
            opcode_range: lp.opcode_range,
            confidence: lp.confidence.as_str().to_owned(),
            note: lp.note,
        }
    }
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ProvenanceLookupOut {
    pub found: bool,
    pub file: String,
    pub tool_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<LineProvenanceOut>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RenameRecord {
    old: String,
    new: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    recorded_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RenamesFile {
    #[serde(default = "renames_schema")]
    schema: String,
    records: Vec<RenameRecord>,
}

impl Default for RenamesFile {
    fn default() -> Self {
        Self {
            schema: RENAMES_SCHEMA.to_owned(),
            records: Vec::new(),
        }
    }
}

#[inline]
fn renames_schema() -> String {
    RENAMES_SCHEMA.to_owned()
}

#[rmcp::tool_router(vis = "pub")]
#[allow(clippy::unused_self)]
impl DisrobeMcp {
    #[rmcp::tool(
        name = "verify",
        description = "Verify a disrobe .dr envelope (blake3 root hash, rung, hot/cold sizes) from inline base64 bytes; never reads disk."
    )]
    fn verify(
        &self,
        Parameters(p): Parameters<VerifyParams>,
    ) -> Result<Json<VerifyOut>, ErrorData> {
        let bytes: Vec<u8> = decode_inline_bytes(&p.bytes_b64)?;
        let env: disrobe_ir::Envelope = disrobe_ir::Envelope::decode(&bytes).map_err(
            |e: disrobe_ir::error::EnvelopeError| {
                ErrorData::invalid_params(format!("DR-MCP-0184: verify failed: {e}"), None)
            },
        )?;
        Ok(Json(VerifyOut {
            verified: true,
            version: env.version,
            rung: format!("{:?}", env.rung),
            hot_bytes: env.hot.len(),
            cold_bytes: env.cold.len(),
            root_hash_blake3: hex32(&env.root_hash),
        }))
    }

    #[rmcp::tool(
        name = "rename",
        description = "Append a symbol rename record (disrobe.renames/v1) to .disrobe/notes/renames.json in the current workspace."
    )]
    fn rename(
        &self,
        Parameters(p): Parameters<RenameParams>,
    ) -> Result<Json<RenameOut>, ErrorData> {
        let disrobe: PathBuf = disrobe_dir()?;
        let notes_dir: PathBuf = disrobe.join("notes");
        std::fs::create_dir_all(&notes_dir).map_err(|e: std::io::Error| {
            ErrorData::internal_error(
                format!("DR-MCP-0333: cannot create .disrobe/notes: {e}"),
                None,
            )
        })?;
        let path: PathBuf = notes_dir.join("renames.json");
        let mut file: RenamesFile = load_renames_or_default(&path)?;
        file.records.push(RenameRecord {
            old: p.old.clone(),
            new: p.new.clone(),
            note: p.note,
            recorded_at: iso8601_now(),
        });
        let json: String =
            serde_json::to_string_pretty(&file).map_err(|e: serde_json::Error| {
                ErrorData::internal_error(format!("DR-MCP-0334: renames serialize: {e}"), None)
            })?;
        std::fs::write(&path, json.as_bytes()).map_err(|e: std::io::Error| {
            ErrorData::internal_error(
                format!("DR-MCP-0335: cannot write {}: {e}", path.display()),
                None,
            )
        })?;
        Ok(Json(RenameOut {
            path: path.display().to_string(),
            schema: file.schema.clone(),
            old: p.old,
            new: p.new,
            record_count: file.records.len(),
        }))
    }

    #[rmcp::tool(
        name = "annot",
        description = "Regenerate and validate a disrobe.annotations/v1 sidecar for a target file under .disrobe/annotations/."
    )]
    fn annot(&self, Parameters(p): Parameters<AnnotParams>) -> Result<Json<AnnotOut>, ErrorData> {
        let disrobe: PathBuf = disrobe_dir()?;
        let target: PathBuf = PathBuf::from(&p.target);
        let path: PathBuf = annotation_path(&disrobe, &target)?;
        let file: AnnotationFile = build_from_target(&target)?;
        file.validate()
            .map_err(|e: disrobe_llm_metadata::AnnotationError| {
                ErrorData::invalid_params(
                    format!("DR-MCP-0329: annotation validation failed: {e}"),
                    None,
                )
            })?;
        write_annotation(&path, &file)?;
        Ok(Json(AnnotOut {
            target: target.display().to_string(),
            annotation_path: path.display().to_string(),
            schema: ANNOTATION_SCHEMA.to_owned(),
            symbol_count: file.annotations.len(),
        }))
    }

    #[rmcp::tool(
        name = "provenance_lookup",
        description = "Look up the LineProvenance entry for a line number in a disrobe.provenance-map/v1 JSON document supplied inline."
    )]
    fn provenance_lookup(
        &self,
        Parameters(p): Parameters<ProvenanceLookupParams>,
    ) -> Result<Json<ProvenanceLookupOut>, ErrorData> {
        let map: ProvenanceMap = serde_json::from_str::<ProvenanceMap>(&p.map_json).map_err(
            |e: serde_json::Error| {
                ErrorData::invalid_params(
                    format!("DR-MCP-0530: not a disrobe.provenance-map/v1 doc: {e}"),
                    None,
                )
            },
        )?;
        let entry: Option<LineProvenance> = map
            .lines
            .iter()
            .find(|lp: &&LineProvenance| lp.line == p.line)
            .cloned();
        Ok(Json(ProvenanceLookupOut {
            found: entry.is_some(),
            file: map.file,
            tool_version: map.tool_version,
            entry: entry.map(LineProvenanceOut::from),
        }))
    }
}

#[rmcp::tool_handler]
impl rmcp::ServerHandler for DisrobeMcp {
    fn get_info(&self) -> rmcp::model::ServerInfo {
        rmcp::model::ServerInfo {
            capabilities: rmcp::model::ServerCapabilities::builder().enable_tools().build(),
            instructions: Some(
                "disrobe MCP companion: verify .dr envelopes, record symbol renames, regenerate annotation sidecars, and look up provenance-map lines.".to_owned(),
            ),
            ..rmcp::model::ServerInfo::default()
        }
    }
}

impl DisrobeMcp {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }
}

fn decode_inline_bytes(bytes_b64: &str) -> Result<Vec<u8>, ErrorData> {
    if bytes_b64.is_empty() {
        return Err(ErrorData::invalid_params(
            "DR-MCP-0182: `bytes_b64` is required & must be non-empty; disrobe-mcp never reads from disk based on client input".to_owned(),
            None,
        ));
    }
    let cleaned: String = bytes_b64
        .chars()
        .filter(|c: &char| !c.is_ascii_whitespace())
        .collect();
    BASE64_STANDARD
        .decode(cleaned.as_bytes())
        .map_err(|e: base64::DecodeError| {
            ErrorData::invalid_params(format!("DR-MCP-0181: bytes_b64 decode: {e}"), None)
        })
}

fn hex32(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s: String = String::with_capacity(64);
    for b in bytes {
        let _: std::fmt::Result = write!(s, "{b:02x}");
    }
    s
}

fn disrobe_dir() -> Result<PathBuf, ErrorData> {
    let cwd: PathBuf = std::env::current_dir().map_err(|e: std::io::Error| {
        ErrorData::internal_error(format!("DR-MCP-0322: cannot read cwd: {e}"), None)
    })?;
    let dir: PathBuf = cwd.join(".disrobe");
    if !dir.is_dir() {
        return Err(ErrorData::invalid_params(
            format!(
                "DR-MCP-0323: no `.disrobe/` workspace in {} - run `disrobe init` first",
                cwd.display()
            ),
            None,
        ));
    }
    Ok(dir)
}

fn annotation_path(disrobe: &Path, target: &Path) -> Result<PathBuf, ErrorData> {
    let stem: &str = target
        .file_stem()
        .and_then(|s: &std::ffi::OsStr| s.to_str())
        .ok_or_else(|| {
            ErrorData::invalid_params(
                format!(
                    "DR-MCP-0324: target {} has no usable file stem",
                    target.display()
                ),
                None,
            )
        })?;
    Ok(disrobe
        .join("annotations")
        .join(format!("{stem}.annot.json")))
}

fn write_annotation(path: &Path, file: &AnnotationFile) -> Result<(), ErrorData> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e: std::io::Error| {
            ErrorData::internal_error(
                format!("DR-MCP-0325: cannot create .disrobe/annotations: {e}"),
                None,
            )
        })?;
    }
    let json: String = serde_json::to_string_pretty(file).map_err(|e: serde_json::Error| {
        ErrorData::internal_error(format!("DR-MCP-0326: annotation serialize: {e}"), None)
    })?;
    std::fs::write(path, json.as_bytes()).map_err(|e: std::io::Error| {
        ErrorData::internal_error(
            format!("DR-MCP-0327: cannot write {}: {e}", path.display()),
            None,
        )
    })
}

fn build_from_target(target: &Path) -> Result<AnnotationFile, ErrorData> {
    let bytes: Vec<u8> = std::fs::read(target).map_err(|e: std::io::Error| {
        ErrorData::invalid_params(
            format!("DR-MCP-0324: cannot read target {}: {e}", target.display()),
            None,
        )
    })?;
    let mut file: AnnotationFile = AnnotationFile::new(target.display().to_string());
    if let Ok(report) = serde_json::from_slice::<ChainRecoveryReport>(&bytes) {
        for pass in &report.passes {
            let pass: &ChainPassRecovery = pass;
            let note: String = format!(
                "status={} format_out={}",
                pass.status.as_str(),
                pass.format_out.as_deref().unwrap_or("-")
            );
            file.push(SymbolAnnotation::new(
                pass.name.clone(),
                "pass",
                note,
                pass.confidence,
            ))
            .map_err(|e: disrobe_llm_metadata::AnnotationError| {
                ErrorData::invalid_params(
                    format!("DR-MCP-0329: annotation validation failed: {e}"),
                    None,
                )
            })?;
        }
        return Ok(file);
    }
    let text: String = String::from_utf8_lossy(&bytes).into_owned();
    let line_count: usize = text.lines().count();
    let byte_len: usize = bytes.len();
    let stem: &str = target
        .file_stem()
        .and_then(|s: &std::ffi::OsStr| s.to_str())
        .ok_or_else(|| {
            ErrorData::invalid_params(
                format!(
                    "DR-MCP-0324: target {} has no usable file stem",
                    target.display()
                ),
                None,
            )
        })?;
    file.push(SymbolAnnotation::new(
        stem,
        "module",
        format!("{line_count} lines, {byte_len} bytes"),
        ConfidenceTier::Skeleton,
    ))
    .map_err(|e: disrobe_llm_metadata::AnnotationError| {
        ErrorData::invalid_params(
            format!("DR-MCP-0329: annotation validation failed: {e}"),
            None,
        )
    })?;
    Ok(file)
}

fn load_renames_or_default(path: &Path) -> Result<RenamesFile, ErrorData> {
    let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(path) else {
        return Ok(RenamesFile::default());
    };
    serde_json::from_slice::<RenamesFile>(&bytes).map_err(|e: serde_json::Error| {
        ErrorData::invalid_params(
            format!(
                "DR-MCP-0330: {} is not a valid disrobe.renames/v1 file: {e}",
                path.display()
            ),
            None,
        )
    })
}

#[allow(clippy::disallowed_methods)]
fn iso8601_now() -> String {
    let now: SystemTime = SystemTime::now();
    let dur: Duration = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs: u64 = dur.as_secs();
    let nanos: u32 = dur.subsec_nanos();
    let seconds_per_day: u64 = 86_400;
    let days_since_epoch: u64 = secs / seconds_per_day;
    let time_in_day: u64 = secs % seconds_per_day;
    let hh: u64 = time_in_day / 3600;
    let mm: u64 = (time_in_day % 3600) / 60;
    let ss: u64 = time_in_day % 60;
    let (year, month, day): (i32, u32, u32) = civil_from_days(days_since_epoch as i64);
    format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}.{nanos:09}Z")
}

fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z: i64 = z + 719_468;
    let era: i64 = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe: u64 = (z - era * 146_097) as u64;
    let yoe: u64 = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y: i64 = (yoe as i64) + era * 400;
    let doy: u64 = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp: u64 = (5 * doy + 2) / 153;
    let d: u64 = doy - (153 * mp + 2) / 5 + 1;
    let m: u64 = if mp < 10 { mp + 3 } else { mp - 9 };
    let year_out: i32 = (y + i64::from(m <= 2)) as i32;
    (year_out, m as u32, d as u32)
}

pub fn run_stdio() -> miette::Result<()> {
    let runtime: tokio::runtime::Runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e: std::io::Error| {
            miette::miette!("DR-MCP-0001: tokio runtime build failed: {e}")
        })?;
    runtime.block_on(async {
        let service: rmcp::service::RunningService<rmcp::RoleServer, DisrobeMcp> =
            rmcp::serve_server(DisrobeMcp::new(), rmcp::transport::io::stdio())
                .await
                .map_err(|e| miette::miette!("DR-MCP-0002: mcp serve failed: {e}"))?;
        service
            .waiting()
            .await
            .map_err(|e| miette::miette!("DR-MCP-0003: mcp serve loop failed: {e}"))?;
        Ok::<(), miette::Report>(())
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use disrobe_core::provenance_map::ProvenanceMapBuilder;
    use disrobe_ir::Rung;
    use rmcp::handler::server::tool::ToolRouter;

    fn expect_err<T>(result: Result<T, ErrorData>) -> ErrorData {
        match result {
            Ok(_) => panic!("expected Err, got Ok"),
            Err(e) => e,
        }
    }

    #[test]
    fn tools_list_exposes_four_real_tools_with_object_schemas() {
        let router: ToolRouter<DisrobeMcp> = DisrobeMcp::tool_router();
        let tools: Vec<rmcp::model::Tool> = router.list_all();
        let names: Vec<&str> = tools
            .iter()
            .map(|t: &rmcp::model::Tool| t.name.as_ref())
            .collect();
        for expected in ["verify", "rename", "annot", "provenance_lookup"] {
            assert!(names.contains(&expected), "missing tool {expected}");
        }
        assert_eq!(tools.len(), 4);
        for t in &tools {
            let schema: &serde_json::Map<String, serde_json::Value> = t.input_schema.as_ref();
            assert_eq!(
                schema
                    .get("type")
                    .and_then(|v: &serde_json::Value| v.as_str()),
                Some("object")
            );
            assert!(
                schema
                    .get("properties")
                    .and_then(|v: &serde_json::Value| v.as_object())
                    .is_some_and(|p: &serde_json::Map<String, serde_json::Value>| !p.is_empty())
            );
        }
        let verify: &rmcp::model::Tool = tools
            .iter()
            .find(|t: &&rmcp::model::Tool| t.name == "verify")
            .unwrap();
        assert!(verify.input_schema["properties"].get("bytes_b64").is_some());
        let plk: &rmcp::model::Tool = tools
            .iter()
            .find(|t: &&rmcp::model::Tool| t.name == "provenance_lookup")
            .unwrap();
        assert!(plk.input_schema["properties"].get("line").is_some());
        assert!(plk.input_schema["properties"].get("map_json").is_some());
    }

    #[test]
    fn verify_accepts_round_tripped_envelope() {
        let env: disrobe_ir::Envelope =
            disrobe_ir::Envelope::new(Rung::Disasm, vec![1, 2, 3, 4], vec![5, 6]);
        let encoded: Vec<u8> = env.encode().unwrap();
        let b64: String = BASE64_STANDARD.encode(&encoded);
        let mcp: DisrobeMcp = DisrobeMcp::new();
        let Json(out): Json<VerifyOut> = mcp
            .verify(Parameters(VerifyParams { bytes_b64: b64 }))
            .unwrap();
        assert!(out.verified);
        assert_eq!(out.hot_bytes, 4);
        assert_eq!(out.cold_bytes, 2);
        assert_eq!(out.rung, "Disasm");
        assert_eq!(out.root_hash_blake3, hex32(&env.root_hash));
    }

    #[test]
    fn verify_rejects_empty_and_garbage() {
        let mcp: DisrobeMcp = DisrobeMcp::new();
        let empty: ErrorData = expect_err(mcp.verify(Parameters(VerifyParams {
            bytes_b64: String::new(),
        })));
        assert!(empty.message.contains("DR-MCP-0182"));
        let garbage: ErrorData = expect_err(mcp.verify(Parameters(VerifyParams {
            bytes_b64: "!!!".to_owned(),
        })));
        assert!(garbage.message.contains("DR-MCP-0181"));
    }

    #[test]
    fn provenance_lookup_hit_and_miss() {
        let mut builder: ProvenanceMapBuilder = ProvenanceMapBuilder::new("hello.py", "0.9.0");
        builder
            .push_line(
                LineProvenance::new(7, "py-decompile", ConfidenceTier::Semantic)
                    .with_source_offset(42),
            )
            .unwrap();
        let map: ProvenanceMap = builder.build();
        let map_json: String = serde_json::to_string(&map).unwrap();
        let mcp: DisrobeMcp = DisrobeMcp::new();
        let Json(hit): Json<ProvenanceLookupOut> = mcp
            .provenance_lookup(Parameters(ProvenanceLookupParams {
                map_json: map_json.clone(),
                line: 7,
            }))
            .unwrap();
        assert!(hit.found);
        assert_eq!(hit.file, "hello.py");
        assert_eq!(hit.tool_version, "0.9.0");
        let entry: LineProvenanceOut = hit.entry.unwrap();
        assert_eq!(entry.line, 7);
        assert_eq!(entry.pass, "py-decompile");
        assert_eq!(entry.confidence, "semantic");
        assert_eq!(entry.source_offset, Some(42));
        let Json(miss): Json<ProvenanceLookupOut> = mcp
            .provenance_lookup(Parameters(ProvenanceLookupParams {
                map_json,
                line: 999,
            }))
            .unwrap();
        assert!(!miss.found);
        assert!(miss.entry.is_none());
    }

    #[test]
    fn provenance_lookup_rejects_non_map_json() {
        let mcp: DisrobeMcp = DisrobeMcp::new();
        let err: ErrorData =
            expect_err(mcp.provenance_lookup(Parameters(ProvenanceLookupParams {
                map_json: r#"{"not":"a map"}"#.to_owned(),
                line: 1,
            })));
        assert!(err.message.contains("DR-MCP-0530"));
    }

    #[test]
    fn iso8601_now_ends_with_z() {
        let ts: String = iso8601_now();
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.as_bytes()[4], b'-');
        assert_eq!(ts.as_bytes()[10], b'T');
    }

    #[test]
    fn annotation_path_uses_stem() {
        let disrobe: PathBuf = PathBuf::from("/work/.disrobe");
        let target: PathBuf = PathBuf::from("/work/build/chain.json");
        let path: PathBuf = annotation_path(&disrobe, &target).unwrap();
        assert!(path.ends_with("annotations/chain.annot.json"));
    }
}
