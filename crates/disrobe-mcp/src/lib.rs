#![deny(unreachable_pub)]
#[cfg(feature = "chain")]
mod chain;
#[allow(
    clippy::redundant_pub_crate,
    reason = "parent-only visibility keeps navigation protocol types behind the private module while satisfying unreachable_pub"
)]
mod navigation;
#[cfg(feature = "wasm")]
#[allow(clippy::redundant_pub_crate)]
mod wasm;

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use disrobe_binfmt::{ByteCoverage, CoverageRegion, file_byte_coverage};
use disrobe_core::chain::{ChainPassRecovery, ChainRecoveryReport};
use disrobe_core::provenance_map::{LineProvenance, ProvenanceMap};
use disrobe_core::recovery::ConfidenceTier;
use disrobe_core::secret_scan::{
    Confidence as SecretConfidence, Finding as SecretFinding, SecretScanReport,
    redact_report as redact_secret_report, scan_report as scan_secret_report,
};
use disrobe_core::{
    BehaviorReport, IocReport, StringsOptions, StringsReport, analyze_behavior, ioc_report,
    strings_report,
};
use disrobe_llm_metadata::annotation::{ANNOTATION_SCHEMA, AnnotationFile, SymbolAnnotation};
use rmcp::ErrorData;
use rmcp::Json;
use rmcp::handler::server::wrapper::Parameters;
use serde::{Deserialize, Serialize};

const RENAMES_SCHEMA: &str = "disrobe.renames/v1";
const DEFAULT_CHAIN_DEPTH: u8 = 8;
const MAX_CHAIN_DEPTH: u8 = 64;
const MAX_IMPORTS: usize = 4096;
const MAX_IMPORT_BYTES: usize = 4096;
const MAX_INLINE_BASE64_CHARS: usize = 22 * 1024 * 1024;
const MAX_INLINE_DECODED_BYTES: usize = 16 * 1024 * 1024;
const MAX_INLINE_JSON_BYTES: usize = 4 * 1024 * 1024;
#[cfg(feature = "wasm")]
const MAX_WASM_LIFT_SOURCE_BYTES: usize = 16 * 1024 * 1024;
const MAX_PROVENANCE_LINES: usize = 262_144;
const MAX_RENAME_FIELD_BYTES: usize = 4096;
const MAX_RENAME_NOTE_BYTES: usize = 8192;
const MAX_RENAME_RECORDS: usize = 16_384;
const MAX_RENAMES_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_STRINGS_MIN_LEN: usize = 4096;
const MAX_WORKSPACE_READ_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub struct DisrobeMcp;

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

#[derive(Debug, Clone, Copy, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[schemars(crate = "rmcp::schemars")]
pub enum NativeMatchStage {
    DataReference,
    ControlFlow,
    Propagation,
    Refused,
}

impl From<NativeMatchStage> for disrobe_pass_native::NativeMatchStage {
    fn from(stage: NativeMatchStage) -> Self {
        match stage {
            NativeMatchStage::DataReference => Self::DataReference,
            NativeMatchStage::ControlFlow => Self::ControlFlow,
            NativeMatchStage::Propagation => Self::Propagation,
            NativeMatchStage::Refused => Self::Refused,
        }
    }
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub struct NativeMatchParams {
    pub a_bytes_b64: String,
    pub b_bytes_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<NativeMatchStage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
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

#[cfg(feature = "chain")]
#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub struct AutoParams {
    pub bytes_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_depth: Option<u8>,
}

#[cfg(feature = "chain")]
#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ChainPassOut {
    pub name: String,
    pub status: String,
    pub confidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format_in: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format_out: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u128>,
}

#[cfg(feature = "chain")]
#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct AutoOut {
    pub schema: String,
    pub verdict: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_format: Option<String>,
    pub detected: Vec<String>,
    pub layers: u32,
    pub passes: Vec<ChainPassOut>,
}

#[cfg(feature = "chain")]
#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub struct DecompileParams {
    pub bytes_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_depth: Option<u8>,
}

#[cfg(feature = "chain")]
#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct RecoveredSourceOut {
    pub pass: String,
    pub language: String,
    pub formatted: bool,
    pub source: String,
}

#[cfg(feature = "chain")]
#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct DecompileOut {
    pub schema: String,
    pub verdict: String,
    pub recovered: Vec<RecoveredSourceOut>,
}

#[cfg(feature = "wasm")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, rmcp::schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
#[schemars(crate = "rmcp::schemars")]
pub enum WasmLiftTarget {
    Rust,
    TypeScript,
    C,
    Wat,
}

#[cfg(feature = "wasm")]
#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub struct WasmLiftParams {
    pub bytes_b64: String,
    pub target: WasmLiftTarget,
}

#[cfg(feature = "wasm")]
#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct WasmLiftCoverageOut {
    pub total_ops: usize,
    pub translated_ops: usize,
    pub fully_recovered: bool,
    pub untranslated: Vec<String>,
}

#[cfg(feature = "wasm")]
#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct WasmLiftOut {
    pub schema: String,
    pub target: WasmLiftTarget,
    pub function_count: usize,
    pub coverage: WasmLiftCoverageOut,
    pub source: String,
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub struct IocParams {
    pub bytes_b64: String,
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub struct SecretScanParams {
    pub bytes_b64: String,
    #[serde(default)]
    pub redact: bool,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct SecretFindingOut {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    pub level: String,
    pub kind: String,
    pub offset: usize,
    pub value: String,
    pub preview: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation: Option<String>,
}

impl From<SecretFinding> for SecretFindingOut {
    fn from(finding: SecretFinding) -> Self {
        Self {
            code: finding.code,
            message: finding.message,
            uri: finding.uri,
            level: finding.level,
            kind: finding.kind.describe().to_owned(),
            offset: finding.offset,
            value: finding.value,
            preview: finding.preview,
            validation: finding
                .validation
                .map(|confidence: SecretConfidence| confidence.label().to_owned()),
        }
    }
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct SecretScanOut {
    pub schema: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    pub byte_len: usize,
    pub findings: Vec<SecretFindingOut>,
}

impl From<SecretScanReport> for SecretScanOut {
    fn from(report: SecretScanReport) -> Self {
        Self {
            schema: report.schema.to_owned(),
            uri: report.uri,
            byte_len: report.byte_len,
            findings: report
                .findings
                .into_iter()
                .map(SecretFindingOut::from)
                .collect(),
        }
    }
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub struct CoverageParams {
    pub bytes_b64: String,
}

const MAX_COVERAGE_REGIONS: usize = 512;

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct CoverageRegionOut {
    pub start: u64,
    pub end: u64,
    pub class: String,
    pub claimant: Option<String>,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct CoverageOut {
    pub format: String,
    pub file_len: u64,
    pub claimed_bytes: u64,
    pub slack_bytes: u64,
    pub unclaimed_bytes: u64,
    pub truncated_bytes: u64,
    pub coverage_ratio: f64,
    pub complete: bool,
    pub overlap_detected: bool,
    pub region_count: usize,
    pub regions_truncated: bool,
    pub regions: Vec<CoverageRegionOut>,
}

impl From<ByteCoverage> for CoverageOut {
    fn from(c: ByteCoverage) -> Self {
        let region_count: usize = c.regions.len();
        let regions: Vec<CoverageRegionOut> = c
            .regions
            .iter()
            .take(MAX_COVERAGE_REGIONS)
            .map(|region: &CoverageRegion| CoverageRegionOut {
                start: region.start,
                end: region.end,
                class: region.class.label().to_owned(),
                claimant: region.claimant.clone(),
            })
            .collect();
        Self {
            format: format!("{:?}", c.format),
            file_len: c.file_len,
            claimed_bytes: c.claimed_bytes,
            slack_bytes: c.slack_bytes,
            unclaimed_bytes: c.unclaimed_bytes,
            truncated_bytes: c.truncated_bytes,
            coverage_ratio: c.coverage_ratio,
            complete: c.complete,
            overlap_detected: c.overlap_detected,
            region_count,
            regions_truncated: region_count > MAX_COVERAGE_REGIONS,
            regions,
        }
    }
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct IndicatorOut {
    pub kind: String,
    pub value: String,
    pub offset: usize,
    pub encoding: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct IocOut {
    pub schema: String,
    pub byte_len: usize,
    pub total: usize,
    pub indicators: Vec<IndicatorOut>,
}

impl From<IocReport> for IocOut {
    fn from(r: IocReport) -> Self {
        Self {
            schema: r.schema.to_owned(),
            byte_len: r.byte_len,
            total: r.total,
            indicators: r
                .indicators
                .into_iter()
                .map(|i: disrobe_core::ioc::Indicator| IndicatorOut {
                    kind: i.kind.label().to_owned(),
                    value: i.value,
                    offset: i.offset,
                    encoding: i.encoding.label().to_owned(),
                    context: i.context,
                })
                .collect(),
        }
    }
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct EvidenceOut {
    pub signal: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attack_id: Option<String>,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct CategoryFindingOut {
    pub category: String,
    pub description: String,
    pub evidence: Vec<EvidenceOut>,
    pub attack_ids: Vec<String>,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct BehaviorOut {
    pub schema: String,
    pub byte_len: usize,
    pub categories: Vec<CategoryFindingOut>,
    pub attack_ids: Vec<String>,
}

impl From<BehaviorReport> for BehaviorOut {
    fn from(r: BehaviorReport) -> Self {
        Self {
            schema: r.schema.to_owned(),
            byte_len: r.byte_len,
            categories: r
                .categories
                .into_iter()
                .map(|c: disrobe_core::CategoryFinding| CategoryFindingOut {
                    category: c.category.label().to_owned(),
                    description: c.description.to_owned(),
                    evidence: c
                        .evidence
                        .into_iter()
                        .map(|e: disrobe_core::BehaviorEvidence| EvidenceOut {
                            signal: e.signal,
                            source: e.source.to_owned(),
                            attack_id: e.attack_id.map(str::to_owned),
                        })
                        .collect(),
                    attack_ids: c
                        .attack_ids
                        .iter()
                        .map(|s: &&str| (*s).to_owned())
                        .collect(),
                })
                .collect(),
            attack_ids: r
                .attack_ids
                .iter()
                .map(|s: &&str| (*s).to_owned())
                .collect(),
        }
    }
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ExtractedStringOut {
    pub value: String,
    pub offset: usize,
    pub tagging: String,
}

#[derive(Debug, Serialize, rmcp::schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct StringsOut {
    pub schema: String,
    pub byte_len: usize,
    pub min_len: usize,
    pub total: usize,
    pub strings: Vec<ExtractedStringOut>,
}

impl From<StringsReport> for StringsOut {
    fn from(r: StringsReport) -> Self {
        Self {
            schema: r.schema.to_owned(),
            byte_len: r.byte_len,
            min_len: r.min_len,
            total: r.total,
            strings: r
                .strings
                .into_iter()
                .map(
                    |s: disrobe_core::strings::ExtractedString| ExtractedStringOut {
                        tagging: s.tagging.label(),
                        value: s.value,
                        offset: s.offset,
                    },
                )
                .collect(),
        }
    }
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub struct BehaviorParams {
    pub bytes_b64: String,
    #[serde(default)]
    pub imports: Vec<String>,
}

#[derive(Debug, Deserialize, rmcp::schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub struct StringsParams {
    pub bytes_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_len: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decode: Option<bool>,
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

#[rmcp::tool_router(router = base_tool_router, vis = "pub")]
#[allow(clippy::unused_self)]
impl DisrobeMcp {
    #[rmcp::tool(
        name = "native_match",
        description = "Match functions across two inline base64 native images. Optional stage, function address, and row limit select a bounded disrobe.native.match/v2 report. The tool never reads disk or executes either image."
    )]
    fn native_match(
        &self,
        Parameters(p): Parameters<NativeMatchParams>,
    ) -> Result<Json<serde_json::Map<String, serde_json::Value>>, ErrorData> {
        let a: Vec<u8> = decode_inline_bytes(&p.a_bytes_b64)?;
        let b: Vec<u8> = decode_inline_bytes(&p.b_bytes_b64)?;
        let report = disrobe_pass_native::match_native_images(
            "a",
            &a,
            "b",
            &b,
            disrobe_pass_native::NativeMatchOptions {
                limit: Some(
                    p.limit
                        .unwrap_or(disrobe_pass_native::NATIVE_MATCH_DEFAULT_LIMIT),
                ),
                function: p.function,
                stage: p.stage.map(Into::into),
            },
        )
        .map_err(|error: disrobe_pass_native::NativeMatchError| {
            ErrorData::invalid_params(error.to_string(), None)
        })?;
        match serde_json::to_value(report) {
            Ok(serde_json::Value::Object(object)) => Ok(Json(object)),
            Ok(_) => Err(ErrorData::internal_error(
                "DR-MCP-0680: native match report serialization produced a non-object value",
                None,
            )),
            Err(error) => Err(ErrorData::internal_error(
                format!("DR-MCP-0680: native match report serialization failed: {error}"),
                None,
            )),
        }
    }

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
        validate_rename_params(&p)?;
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
        if file.records.len() >= MAX_RENAME_RECORDS {
            return Err(ErrorData::invalid_params(
                format!("DR-MCP-0340: renames file already has {MAX_RENAME_RECORDS} records"),
                None,
            ));
        }
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
        let root: PathBuf = workspace_root()?;
        let target: PathBuf = resolve_workspace_target(&root, Path::new(&p.target))?;
        let stem: &str = target_stem(&target)?;
        let path: PathBuf = annotation_path(&root.join(".disrobe"), stem);
        let file: AnnotationFile = build_from_target(&target, stem)?;
        file.validate().map_err(annotation_invalid)?;
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
        ensure_text_bytes(
            "map_json",
            &p.map_json,
            MAX_INLINE_JSON_BYTES,
            "DR-MCP-0531",
        )?;
        let map: ProvenanceMap = serde_json::from_str::<ProvenanceMap>(&p.map_json).map_err(
            |e: serde_json::Error| {
                ErrorData::invalid_params(
                    format!("DR-MCP-0530: not a disrobe.provenance-map/v1 doc: {e}"),
                    None,
                )
            },
        )?;
        if map.lines.len() > MAX_PROVENANCE_LINES {
            return Err(ErrorData::invalid_params(
                format!("DR-MCP-0532: map_json exceeds {MAX_PROVENANCE_LINES} line records"),
                None,
            ));
        }
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

    #[cfg(feature = "chain")]
    #[rmcp::tool(
        name = "auto",
        description = "Auto-detect and chain disrobe's Python + native-packer passes over inline base64 bytes; returns the chain verdict, detected formats, and per-pass recovery summary. Never reads disk."
    )]
    fn auto(&self, Parameters(p): Parameters<AutoParams>) -> Result<Json<AutoOut>, ErrorData> {
        let bytes: Vec<u8> = decode_inline_bytes(&p.bytes_b64)?;
        let cap: u8 = chain_depth(p.max_depth, "DR-MCP-0611")?;
        let run: chain::ChainRun = chain::run_auto(bytes, cap).map_err(|e: String| {
            ErrorData::internal_error(format!("DR-MCP-0610: auto chain failed: {e}"), None)
        })?;
        let doc: disrobe_core::chain::ChainDocument = disrobe_core::chain::ChainDocument::from_plan(
            &run.plan,
            &run.spec,
            &run.spec_raw,
            env!("CARGO_PKG_VERSION"),
            None,
        );
        let report: ChainRecoveryReport =
            ChainRecoveryReport::from_plan(&run.plan, env!("CARGO_PKG_VERSION"), None);
        let passes: Vec<ChainPassOut> = report
            .passes
            .into_iter()
            .map(|r: ChainPassRecovery| ChainPassOut {
                name: r.name,
                status: r.status.as_str().to_owned(),
                confidence: r.confidence.as_str().to_owned(),
                format_in: r.format_in,
                format_out: r.format_out,
                duration_ms: r.duration_ms,
            })
            .collect();
        Ok(Json(AutoOut {
            schema: doc.schema,
            verdict: verdict_label(&doc.verdict),
            final_format: doc.final_format,
            detected: doc.input.detected,
            layers: doc.stats.layers,
            passes,
        }))
    }

    #[cfg(feature = "chain")]
    #[rmcp::tool(
        name = "decompile",
        description = "Auto-chain inline base64 bytes and return every terminal recovered-source artifact (language-keyed text), e.g. a .pyc decompiled to Python. Never reads disk."
    )]
    fn decompile(
        &self,
        Parameters(p): Parameters<DecompileParams>,
    ) -> Result<Json<DecompileOut>, ErrorData> {
        let bytes: Vec<u8> = decode_inline_bytes(&p.bytes_b64)?;
        let cap: u8 = chain_depth(p.max_depth, "DR-MCP-0621")?;
        let run: chain::ChainRun = chain::run_auto(bytes, cap).map_err(|e: String| {
            ErrorData::internal_error(format!("DR-MCP-0620: decompile chain failed: {e}"), None)
        })?;
        let recovered: Vec<RecoveredSourceOut> = chain::recovered_sources(&run.plan)
            .into_iter()
            .map(|r: chain::RecoveredSource| RecoveredSourceOut {
                pass: r.pass,
                language: r.language,
                formatted: r.formatted,
                source: r.source,
            })
            .collect();
        let verdict: disrobe_core::chain::VerdictDoc =
            disrobe_core::chain::VerdictDoc::from(&run.plan.verdict);
        Ok(Json(DecompileOut {
            schema: "disrobe.decompile/v1".to_owned(),
            verdict: verdict_label(&verdict),
            recovered,
        }))
    }

    #[rmcp::tool(
        name = "ioc",
        description = "Extract indicators of compromise (URLs, domains, IPs, emails, paths, registry keys, wallet addresses, crypto constants) from inline base64 bytes, decoding one layer of base64/hex. Never reads disk."
    )]
    fn ioc(&self, Parameters(p): Parameters<IocParams>) -> Result<Json<IocOut>, ErrorData> {
        let bytes: Vec<u8> = decode_inline_bytes(&p.bytes_b64)?;
        Ok(Json(IocOut::from(ioc_report(&bytes, None))))
    }

    #[rmcp::tool(
        name = "secret_scan",
        description = "Detect secrets in inline base64 bytes and optionally replace matched values in the response with stable redaction tokens. Never reads disk."
    )]
    fn secret_scan(
        &self,
        Parameters(p): Parameters<SecretScanParams>,
    ) -> Result<Json<SecretScanOut>, ErrorData> {
        let bytes: Vec<u8> = decode_inline_bytes(&p.bytes_b64)?;
        let mut report: SecretScanReport = scan_secret_report(&bytes, None);
        if p.redact {
            redact_secret_report(&mut report);
        }
        Ok(Json(SecretScanOut::from(report)))
    }

    #[rmcp::tool(
        name = "behavior",
        description = "Static capability / behavior summary across network, filesystem, process-exec, registry-persistence, crypto, anti-analysis, and dynamic-code categories with MITRE ATT&CK ids, from inline base64 bytes plus optional import names. Never reads disk."
    )]
    fn behavior(
        &self,
        Parameters(p): Parameters<BehaviorParams>,
    ) -> Result<Json<BehaviorOut>, ErrorData> {
        let bytes: Vec<u8> = decode_inline_bytes(&p.bytes_b64)?;
        validate_imports(&p.imports)?;
        Ok(Json(BehaviorOut::from(analyze_behavior(
            &bytes, &p.imports,
        ))))
    }

    #[rmcp::tool(
        name = "coverage",
        description = "Account for every byte of an inline base64 PE / ELF / Mach-O image against the structures its format declares: bytes a structure claims, alignment slack, bytes nothing claims (where an appended overlay shows up), bytes a structure declares past the end of the file, and structures that overlap. Never reads disk."
    )]
    fn coverage(
        &self,
        Parameters(p): Parameters<CoverageParams>,
    ) -> Result<Json<CoverageOut>, ErrorData> {
        let bytes: Vec<u8> = decode_inline_bytes(&p.bytes_b64)?;
        let mapped: ByteCoverage = file_byte_coverage(&bytes).map_err(|e| {
            ErrorData::invalid_params(
                format!("DR-MCP-0660: cannot account for the bytes of this input: {e}"),
                None,
            )
        })?;
        Ok(Json(CoverageOut::from(mapped)))
    }

    #[rmcp::tool(
        name = "strings",
        description = "Extract printable strings (ASCII + UTF-16) from inline base64 bytes, optionally decoding base64/rot/stack-string obfuscation, tagged with their encoding. Never reads disk."
    )]
    fn strings(
        &self,
        Parameters(p): Parameters<StringsParams>,
    ) -> Result<Json<StringsOut>, ErrorData> {
        let bytes: Vec<u8> = decode_inline_bytes(&p.bytes_b64)?;
        let defaults: StringsOptions = StringsOptions::default();
        let min_len: usize = p.min_len.map_or(defaults.min_len, |value: usize| value);
        if min_len == 0 || min_len > MAX_STRINGS_MIN_LEN {
            return Err(ErrorData::invalid_params(
                format!("DR-MCP-0640: min_len must be in 1..={MAX_STRINGS_MIN_LEN}"),
                None,
            ));
        }
        let opts: StringsOptions = StringsOptions {
            min_len,
            decode: p.decode.map_or(defaults.decode, |value: bool| value),
        };
        Ok(Json(StringsOut::from(strings_report(&bytes, None, opts))))
    }

    #[rmcp::tool(
        name = "call_graph",
        description = "Page through function summaries and explicitly classified call edges from an inline Disasm- or Mir-rung .dr envelope under a hard o200k_base token budget. Never reads disk."
    )]
    fn call_graph(
        &self,
        Parameters(p): Parameters<navigation::CallGraphParams>,
    ) -> Result<navigation::Json<navigation::CallGraphOut>, ErrorData> {
        navigation::call_graph(p).map(navigation::Json::new)
    }

    #[rmcp::tool(
        name = "xrefs",
        description = "Page through cross-references to a content-bound function id from an inline Disasm- or Mir-rung .dr envelope under a hard o200k_base token budget. Never reads disk."
    )]
    fn xrefs(
        &self,
        Parameters(p): Parameters<navigation::XrefsParams>,
    ) -> Result<navigation::Json<navigation::XrefsOut>, ErrorData> {
        navigation::xrefs(p).map(navigation::Json::new)
    }

    #[rmcp::tool(
        name = "function_summary",
        description = "Return one structural summary for a content-bound function id in an inline Disasm- or Mir-rung .dr envelope under a hard o200k_base token budget. Never reads disk."
    )]
    fn function_summary(
        &self,
        Parameters(p): Parameters<navigation::FunctionSummaryParams>,
    ) -> Result<navigation::Json<navigation::FunctionSummaryResponse>, ErrorData> {
        navigation::function_summary(p).map(navigation::Json::new)
    }

    #[rmcp::tool(
        name = "neighborhood",
        description = "Page through a cycle-safe caller, callee, or bidirectional function neighborhood from content-bound entry ids under a hard o200k_base token budget. Never reads disk."
    )]
    fn neighborhood(
        &self,
        Parameters(p): Parameters<navigation::NeighborhoodParams>,
    ) -> Result<navigation::Json<navigation::NeighborhoodOut>, ErrorData> {
        navigation::neighborhood(p).map(navigation::Json::new)
    }
}

#[cfg(feature = "wasm")]
#[rmcp::tool_router(router = wasm_tool_router)]
impl DisrobeMcp {
    #[rmcp::tool(
        name = "wasm_lift",
        description = "Lift inline WebAssembly bytes to bounded Rust, TypeScript, C, or WAT source with operation coverage. Shared-memory TypeScript output includes executable wait and notify semantics. Never reads disk or executes the module."
    )]
    fn wasm_lift(
        &self,
        Parameters(p): Parameters<WasmLiftParams>,
    ) -> Result<Json<WasmLiftOut>, ErrorData> {
        let bytes: Vec<u8> = decode_inline_bytes(&p.bytes_b64)?;
        wasm::lift(&bytes, p.target, MAX_WASM_LIFT_SOURCE_BYTES)
            .map(Json)
            .map_err(|error: wasm::WasmLiftError| {
                ErrorData::invalid_params(
                    format!("DR-MCP-0670: WebAssembly lift failed: {error}"),
                    None,
                )
            })
    }
}

impl DisrobeMcp {
    pub fn tool_router() -> rmcp::handler::server::router::tool::ToolRouter<Self> {
        let router: rmcp::handler::server::router::tool::ToolRouter<Self> =
            Self::base_tool_router();
        #[cfg(feature = "wasm")]
        {
            router + Self::wasm_tool_router()
        }
        #[cfg(not(feature = "wasm"))]
        {
            router
        }
    }
}

#[rmcp::tool_handler]
impl rmcp::ServerHandler for DisrobeMcp {
    fn get_info(&self) -> rmcp::model::ServerInfo {
        let mut info: rmcp::model::ServerInfo = rmcp::model::ServerInfo::default();
        info.capabilities = rmcp::model::ServerCapabilities::builder()
            .enable_tools()
            .build();
        #[cfg(feature = "wasm")]
        let analysis_tools: &str = "auto-detect and chain (auto), decompile to source (decompile), match functions across two native images (native_match), lift WebAssembly to Rust, TypeScript, C, or WAT (wasm_lift), extract IOCs (ioc), summarize behavior and ATT&CK (behavior), and pull strings (strings)";
        #[cfg(all(feature = "chain", not(feature = "wasm")))]
        let analysis_tools: &str = "auto-detect and chain (auto), decompile to source (decompile), match functions across two native images (native_match), extract IOCs (ioc), summarize behavior and ATT&CK (behavior), and pull strings (strings)";
        #[cfg(not(feature = "chain"))]
        let analysis_tools: &str = "match functions across two native images (native_match), extract IOCs (ioc), summarize behavior and ATT&CK (behavior), and pull strings (strings)";
        info.instructions = Some(format!(
            "disrobe MCP companion: {analysis_tools}, verify .dr envelopes, look up provenance-map lines, and navigate call graphs, cross-references, function summaries, and cycle-safe neighborhoods. Analysis tools take inline base64 or inline JSON and never read a filesystem path. The workspace tools (rename, annot) read and write only inside the `.disrobe/` workspace under the current directory; annot's target must resolve within that workspace root."
        ));
        info
    }
}

impl DisrobeMcp {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

fn decode_inline_bytes(bytes_b64: &str) -> Result<Vec<u8>, ErrorData> {
    if bytes_b64.is_empty() {
        return Err(ErrorData::invalid_params(
            "DR-MCP-0182: `bytes_b64` is required & must be non-empty; this tool decodes inline bytes and does not read from disk".to_owned(),
            None,
        ));
    }
    ensure_text_bytes(
        "bytes_b64",
        bytes_b64,
        MAX_INLINE_BASE64_CHARS,
        "DR-MCP-0183",
    )?;
    let raw: &[u8] = bytes_b64.as_bytes();
    let decoded: Result<Vec<u8>, base64::DecodeError> = if raw.iter().any(u8::is_ascii_whitespace) {
        let cleaned: Vec<u8> = raw
            .iter()
            .copied()
            .filter(|b: &u8| !b.is_ascii_whitespace())
            .collect();
        BASE64_STANDARD.decode(&cleaned)
    } else {
        BASE64_STANDARD.decode(raw)
    };
    decoded
        .map_err(|e: base64::DecodeError| {
            ErrorData::invalid_params(format!("DR-MCP-0181: bytes_b64 decode: {e}"), None)
        })
        .and_then(|bytes: Vec<u8>| {
            ensure_bytes_len(
                "decoded bytes",
                bytes.len(),
                MAX_INLINE_DECODED_BYTES,
                "DR-MCP-0185",
            )?;
            Ok(bytes)
        })
}

fn ensure_bytes_len(field: &str, len: usize, limit: usize, code: &str) -> Result<(), ErrorData> {
    if len > limit {
        return Err(ErrorData::invalid_params(
            format!("{code}: `{field}` exceeds {limit} bytes"),
            None,
        ));
    }
    Ok(())
}

fn ensure_text_bytes(field: &str, value: &str, limit: usize, code: &str) -> Result<(), ErrorData> {
    ensure_bytes_len(field, value.len(), limit, code)
}

fn ensure_count(field: &str, len: usize, limit: usize, code: &str) -> Result<(), ErrorData> {
    if len > limit {
        return Err(ErrorData::invalid_params(
            format!("{code}: `{field}` exceeds {limit} entries"),
            None,
        ));
    }
    Ok(())
}

fn validate_rename_params(p: &RenameParams) -> Result<(), ErrorData> {
    ensure_text_bytes("old", &p.old, MAX_RENAME_FIELD_BYTES, "DR-MCP-0338")?;
    ensure_text_bytes("new", &p.new, MAX_RENAME_FIELD_BYTES, "DR-MCP-0338")?;
    if let Some(note) = &p.note {
        ensure_text_bytes("note", note, MAX_RENAME_NOTE_BYTES, "DR-MCP-0338")?;
    }
    Ok(())
}

fn validate_imports(imports: &[String]) -> Result<(), ErrorData> {
    ensure_count("imports", imports.len(), MAX_IMPORTS, "DR-MCP-0641")?;
    for import in imports {
        ensure_text_bytes("import", import, MAX_IMPORT_BYTES, "DR-MCP-0642")?;
    }
    Ok(())
}

fn chain_depth(value: Option<u8>, code: &str) -> Result<u8, ErrorData> {
    let cap: u8 = value.unwrap_or(DEFAULT_CHAIN_DEPTH);
    if cap == 0 || cap > MAX_CHAIN_DEPTH {
        return Err(ErrorData::invalid_params(
            format!("{code}: max_depth must be in 1..={MAX_CHAIN_DEPTH}"),
            None,
        ));
    }
    Ok(cap)
}

fn hex32(bytes: &[u8; 32]) -> String {
    const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
    let mut s: String = String::with_capacity(64);
    for byte in bytes.iter().copied() {
        let high: usize = usize::from(byte >> 4);
        let low: usize = usize::from(byte & 0x0f);
        s.push(char::from(HEX_LOWER[high]));
        s.push(char::from(HEX_LOWER[low]));
    }
    s
}

#[cfg(feature = "chain")]
fn verdict_label(v: &disrobe_core::chain::VerdictDoc) -> String {
    use disrobe_core::chain::VerdictDoc;
    match v {
        VerdictDoc::Ok => "ok",
        VerdictDoc::Complete => "complete",
        VerdictDoc::FanOut => "fan-out",
        VerdictDoc::FanOutPartial => "fan-out-partial",
        VerdictDoc::Stalled => "stalled",
        VerdictDoc::Cycle => "cycle",
        VerdictDoc::CapReached => "cap-reached",
        VerdictDoc::Extracted => "extracted",
        VerdictDoc::Error => "error",
        VerdictDoc::DryRun => "dry-run",
    }
    .to_owned()
}

fn workspace_root() -> Result<PathBuf, ErrorData> {
    let cwd: PathBuf = std::env::current_dir().map_err(|e: std::io::Error| {
        ErrorData::internal_error(format!("DR-MCP-0322: cannot read cwd: {e}"), None)
    })?;
    if !cwd.join(".disrobe").is_dir() {
        return Err(ErrorData::invalid_params(
            format!(
                "DR-MCP-0323: no `.disrobe/` workspace in {} - run `disrobe init` first",
                cwd.display()
            ),
            None,
        ));
    }
    Ok(cwd)
}

fn disrobe_dir() -> Result<PathBuf, ErrorData> {
    Ok(workspace_root()?.join(".disrobe"))
}

fn resolve_workspace_target(root: &Path, target: &Path) -> Result<PathBuf, ErrorData> {
    let joined: PathBuf = if target.is_absolute() {
        target.to_path_buf()
    } else {
        root.join(target)
    };
    let canonical_root: PathBuf = root.canonicalize().map_err(|e: std::io::Error| {
        ErrorData::internal_error(
            format!(
                "DR-MCP-0337: cannot canonicalize workspace root {}: {e}",
                root.display()
            ),
            None,
        )
    })?;
    let canonical_target: PathBuf = joined.canonicalize().map_err(|e: std::io::Error| {
        ErrorData::invalid_params(
            format!(
                "DR-MCP-0339: cannot locate target {}: {e}",
                target.display()
            ),
            None,
        )
    })?;
    if !canonical_target.starts_with(&canonical_root) {
        return Err(ErrorData::invalid_params(
            format!(
                "DR-MCP-0336: target {} resolves outside the workspace root {}",
                target.display(),
                canonical_root.display()
            ),
            None,
        ));
    }
    Ok(canonical_target)
}

fn target_stem(target: &Path) -> Result<&str, ErrorData> {
    target
        .file_stem()
        .and_then(|s: &std::ffi::OsStr| s.to_str())
        .ok_or_else(|| {
            ErrorData::invalid_params(
                format!(
                    "DR-MCP-0331: target {} has no usable file stem",
                    target.display()
                ),
                None,
            )
        })
}

fn annotation_path(disrobe: &Path, stem: &str) -> PathBuf {
    disrobe
        .join("annotations")
        .join(format!("{stem}.annot.json"))
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

fn build_from_target(target: &Path, stem: &str) -> Result<AnnotationFile, ErrorData> {
    let bytes: Vec<u8> = read_bounded_file(target, MAX_WORKSPACE_READ_BYTES, "DR-MCP-0324")?;
    let mut file: AnnotationFile = AnnotationFile::new(target.display().to_string());
    if let Ok(report) = serde_json::from_slice::<ChainRecoveryReport>(&bytes) {
        for pass in &report.passes {
            let note: String = format!(
                "status={} format_out={}",
                pass.status.as_str(),
                pass.format_out
                    .as_deref()
                    .map_or("-", |format_out: &str| format_out)
            );
            file.push(SymbolAnnotation::new(
                pass.name.clone(),
                "pass",
                note,
                pass.confidence,
            ))
            .map_err(annotation_invalid)?;
        }
        return Ok(file);
    }
    let line_count: usize = String::from_utf8_lossy(&bytes).lines().count();
    let byte_len: usize = bytes.len();
    file.push(SymbolAnnotation::new(
        stem,
        "module",
        format!("{line_count} lines, {byte_len} bytes"),
        ConfidenceTier::Skeleton,
    ))
    .map_err(annotation_invalid)?;
    Ok(file)
}

fn annotation_invalid(e: disrobe_llm_metadata::AnnotationError) -> ErrorData {
    ErrorData::invalid_params(
        format!("DR-MCP-0329: annotation validation failed: {e}"),
        None,
    )
}

fn load_renames_or_default(path: &Path) -> Result<RenamesFile, ErrorData> {
    let file: std::fs::File = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(RenamesFile::default()),
        Err(e) => {
            return Err(ErrorData::invalid_params(
                format!("DR-MCP-0330: cannot read {}: {e}", path.display()),
                None,
            ));
        }
    };
    let bytes: Vec<u8> = read_bounded_open_file(path, file, MAX_RENAMES_FILE_BYTES, "DR-MCP-0341")?;
    let file: RenamesFile =
        serde_json::from_slice::<RenamesFile>(&bytes).map_err(|e: serde_json::Error| {
            ErrorData::invalid_params(
                format!(
                    "DR-MCP-0330: {} is not a valid disrobe.renames/v1 file: {e}",
                    path.display()
                ),
                None,
            )
        })?;
    if file.records.len() > MAX_RENAME_RECORDS {
        return Err(ErrorData::invalid_params(
            format!("DR-MCP-0340: renames file exceeds {MAX_RENAME_RECORDS} records"),
            None,
        ));
    }
    validate_renames_file(&file)?;
    Ok(file)
}

fn validate_renames_file(file: &RenamesFile) -> Result<(), ErrorData> {
    if file.schema != RENAMES_SCHEMA {
        return Err(ErrorData::invalid_params(
            format!("DR-MCP-0342: renames file schema must be {RENAMES_SCHEMA}"),
            None,
        ));
    }
    for record in &file.records {
        ensure_text_bytes("old", &record.old, MAX_RENAME_FIELD_BYTES, "DR-MCP-0343")?;
        ensure_text_bytes("new", &record.new, MAX_RENAME_FIELD_BYTES, "DR-MCP-0343")?;
        if let Some(note) = &record.note {
            ensure_text_bytes("note", note, MAX_RENAME_NOTE_BYTES, "DR-MCP-0343")?;
        }
    }
    Ok(())
}

fn read_bounded_file(path: &Path, limit: u64, code: &str) -> Result<Vec<u8>, ErrorData> {
    let file: std::fs::File = std::fs::File::open(path).map_err(|e: std::io::Error| {
        ErrorData::invalid_params(
            format!("{code}: cannot read target {}: {e}", path.display()),
            None,
        )
    })?;
    read_bounded_open_file(path, file, limit, code)
}

fn read_bounded_open_file(
    path: &Path,
    file: std::fs::File,
    limit: u64,
    code: &str,
) -> Result<Vec<u8>, ErrorData> {
    let reserve: usize = file.metadata().map_or(0, |metadata: std::fs::Metadata| {
        usize::try_from(metadata.len().min(limit)).map_or(0, std::convert::identity)
    });
    let mut bytes: Vec<u8> = Vec::with_capacity(reserve);
    let mut reader: std::io::Take<std::fs::File> = file.take(limit.saturating_add(1));
    reader
        .read_to_end(&mut bytes)
        .map_err(|e: std::io::Error| {
            ErrorData::invalid_params(format!("{code}: cannot read {}: {e}", path.display()), None)
        })?;
    let len: u64 = u64::try_from(bytes.len()).map_or(u64::MAX, std::convert::identity);
    if len > limit {
        return Err(ErrorData::invalid_params(
            format!("{code}: {} exceeds {limit} bytes", path.display()),
            None,
        ));
    }
    Ok(bytes)
}

#[allow(clippy::disallowed_methods)]
fn iso8601_now() -> String {
    let now: SystemTime = SystemTime::now();
    let dur: Duration = now
        .duration_since(UNIX_EPOCH)
        .map_or(Duration::ZERO, |value: Duration| value);
    let secs: u64 = dur.as_secs();
    let nanos: u32 = dur.subsec_nanos();
    let seconds_per_day: u64 = 86_400;
    let days_since_epoch: u64 = secs / seconds_per_day;
    let time_in_day: u64 = secs % seconds_per_day;
    let hh: u64 = time_in_day / 3600;
    let mm: u64 = (time_in_day % 3600) / 60;
    let ss: u64 = time_in_day % 60;
    let days_i64: i64 = u64_to_i64(days_since_epoch);
    let (year, month, day): (i32, u32, u32) = civil_from_days(days_i64);
    format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}.{nanos:09}Z")
}

fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z: i64 = z + 719_468;
    let era: i64 = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe: u64 = i64_to_u64(z - era * 146_097);
    let yoe: u64 = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y: i64 = u64_to_i64(yoe) + era * 400;
    let doy: u64 = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp: u64 = (5 * doy + 2) / 153;
    let d: u64 = doy - (153 * mp + 2) / 5 + 1;
    let m: u64 = if mp < 10 { mp + 3 } else { mp - 9 };
    let year_full: i64 = y + i64::from(m <= 2);
    let year_out: i32 = i64_to_i32(year_full);
    (year_out, u64_to_u32(m), u64_to_u32(d))
}

fn i64_to_u64(value: i64) -> u64 {
    u64::try_from(value).map_or(0, std::convert::identity)
}

fn u64_to_i64(value: u64) -> i64 {
    i64::try_from(value).map_or(i64::MAX, std::convert::identity)
}

fn i64_to_i32(value: i64) -> i32 {
    i32::try_from(value).unwrap_or_else(|_: std::num::TryFromIntError| {
        if value.is_negative() {
            i32::MIN
        } else {
            i32::MAX
        }
    })
}

fn u64_to_u32(value: u64) -> u32 {
    u32::try_from(value).map_or(u32::MAX, std::convert::identity)
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
    fn tools_list_exposes_real_tools_with_object_schemas() {
        let router: ToolRouter<DisrobeMcp> = DisrobeMcp::tool_router();
        let tools: Vec<rmcp::model::Tool> = router.list_all();
        let names: Vec<&str> = tools
            .iter()
            .map(|t: &rmcp::model::Tool| t.name.as_ref())
            .collect();
        for expected in [
            "verify",
            "rename",
            "annot",
            "provenance_lookup",
            "ioc",
            "secret_scan",
            "behavior",
            "coverage",
            "strings",
            "call_graph",
            "xrefs",
            "function_summary",
            "neighborhood",
            "native_match",
        ] {
            assert!(names.contains(&expected), "missing tool {expected}");
        }
        #[cfg(feature = "chain")]
        for expected in ["auto", "decompile"] {
            assert!(names.contains(&expected), "missing chain tool {expected}");
        }
        #[cfg(feature = "wasm")]
        assert!(
            names.contains(&"wasm_lift"),
            "missing WebAssembly lift tool"
        );
        let expected_count: usize =
            14 + usize::from(cfg!(feature = "chain")) * 2 + usize::from(cfg!(feature = "wasm"));
        assert_eq!(tools.len(), expected_count);
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
        let native_match: &rmcp::model::Tool = tools
            .iter()
            .find(|tool: &&rmcp::model::Tool| tool.name == "native_match")
            .unwrap();
        assert!(
            native_match.input_schema["properties"]
                .get("a_bytes_b64")
                .is_some()
        );
        assert!(
            native_match.input_schema["properties"]
                .get("b_bytes_b64")
                .is_some()
        );
    }

    #[test]
    fn native_match_returns_the_shared_report_for_two_real_inputs() {
        const SAMPLE: &[u8] =
            include_bytes!("../../../corpus/native/obfuscators/guardian-rs/sample.clean.exe");
        let encoded: String = BASE64_STANDARD.encode(SAMPLE);
        let mcp: DisrobeMcp = DisrobeMcp::new();
        let Json(actual): Json<serde_json::Map<String, serde_json::Value>> = mcp
            .native_match(Parameters(NativeMatchParams {
                a_bytes_b64: encoded.clone(),
                b_bytes_b64: encoded,
                stage: None,
                function: None,
                limit: Some(5),
            }))
            .unwrap();
        let expected = disrobe_pass_native::match_native_images(
            "a",
            SAMPLE,
            "b",
            SAMPLE,
            disrobe_pass_native::NativeMatchOptions {
                limit: Some(5),
                function: None,
                stage: None,
            },
        )
        .unwrap();

        assert_eq!(
            serde_json::Value::Object(actual),
            serde_json::to_value(expected).unwrap()
        );
    }

    #[test]
    fn native_match_returns_the_exact_native_refusal_reason() {
        const SAMPLE: &[u8] =
            include_bytes!("../../../corpus/native/obfuscators/guardian-rs/sample.clean.exe");
        let encoded: String = BASE64_STANDARD.encode(SAMPLE);
        let mcp: DisrobeMcp = DisrobeMcp::new();
        let error: ErrorData = expect_err(mcp.native_match(Parameters(NativeMatchParams {
            a_bytes_b64: encoded.clone(),
            b_bytes_b64: encoded,
            stage: None,
            function: Some(u64::MAX),
            limit: None,
        })));

        assert_eq!(
            error.message,
            "DR-NATIVE-0208: no function at address 0xffffffffffffffff in either input"
        );
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
    fn inline_bytes_rejects_oversized_base64_before_decode() {
        let too_large: String = "A".repeat(MAX_INLINE_BASE64_CHARS + 1);
        let err: ErrorData = expect_err(decode_inline_bytes(&too_large));
        assert!(err.message.contains("DR-MCP-0183"));
    }

    #[test]
    fn rename_rejects_oversized_fields_before_workspace_lookup() {
        let mcp: DisrobeMcp = DisrobeMcp::new();
        let err: ErrorData = expect_err(mcp.rename(Parameters(RenameParams {
            old: "a".repeat(MAX_RENAME_FIELD_BYTES + 1),
            new: "b".to_owned(),
            note: None,
        })));
        assert!(err.message.contains("DR-MCP-0338"));
    }

    #[test]
    fn renames_loader_rejects_bad_existing_files() {
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("disrobe_mcp_renames_validation_test")
                .expect("create scratch directory");
        let base: PathBuf = scratch.path().to_path_buf();
        let target: PathBuf = base.join("renames.json");
        std::fs::write(&target, br#"{"schema":"wrong","records":[]}"#).unwrap();
        let schema_err: ErrorData = expect_err(load_renames_or_default(&target));
        assert!(schema_err.message.contains("DR-MCP-0342"));

        let oversized: String = serde_json::json!({
            "schema": RENAMES_SCHEMA,
            "records": [{
                "old": "a".repeat(MAX_RENAME_FIELD_BYTES + 1),
                "new": "b",
                "recorded_at": "2026-06-30T00:00:00.000000000Z"
            }]
        })
        .to_string();
        std::fs::write(&target, oversized.as_bytes()).unwrap();
        let field_err: ErrorData = expect_err(load_renames_or_default(&target));
        assert!(field_err.message.contains("DR-MCP-0343"));
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
    fn provenance_lookup_rejects_oversized_inline_json() {
        let mcp: DisrobeMcp = DisrobeMcp::new();
        let err: ErrorData =
            expect_err(mcp.provenance_lookup(Parameters(ProvenanceLookupParams {
                map_json: " ".repeat(MAX_INLINE_JSON_BYTES + 1),
                line: 1,
            })));
        assert!(err.message.contains("DR-MCP-0531"));
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
        let stem: &str = target_stem(&target).unwrap();
        let path: PathBuf = annotation_path(&disrobe, stem);
        assert!(path.ends_with("annotations/chain.annot.json"));
    }

    #[test]
    fn resolve_workspace_target_confines_reads_to_root() {
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("disrobe_mcp_confine_test")
                .expect("create scratch directory");
        let base: PathBuf = scratch.path().to_path_buf();
        let root: PathBuf = base.join("root");
        let outside: PathBuf = base.join("outside");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let inside_file: PathBuf = root.join("sub").join("artifact.json");
        std::fs::write(&inside_file, b"{}").unwrap();
        let secret: PathBuf = outside.join("secret.txt");
        std::fs::write(&secret, b"top-secret").unwrap();

        let ok: PathBuf = resolve_workspace_target(&root, Path::new("sub/artifact.json")).unwrap();
        assert!(ok.ends_with("artifact.json"));

        let abs_escape: ErrorData = expect_err(resolve_workspace_target(&root, &secret));
        assert!(abs_escape.message.contains("DR-MCP-0336"));

        let rel_escape: ErrorData = expect_err(resolve_workspace_target(
            &root,
            Path::new("../outside/secret.txt"),
        ));
        assert!(rel_escape.message.contains("DR-MCP-0336"));

        let missing: ErrorData =
            expect_err(resolve_workspace_target(&root, Path::new("sub/nope.json")));
        assert!(missing.message.contains("DR-MCP-0339"));
    }

    #[test]
    fn bounded_file_reader_rejects_limit_overrun() {
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create("disrobe_mcp_read_limit_test")
                .expect("create scratch directory");
        let base: PathBuf = scratch.path().to_path_buf();
        let target: PathBuf = base.join("payload.bin");
        std::fs::write(&target, b"abcd").unwrap();
        let err: ErrorData = expect_err(read_bounded_file(&target, 3, "DR-MCP-0324"));
        assert!(err.message.contains("DR-MCP-0324"));
    }

    fn b64(bytes: &[u8]) -> String {
        BASE64_STANDARD.encode(bytes)
    }

    #[test]
    fn ioc_extracts_url_and_ipv4() {
        let mcp: DisrobeMcp = DisrobeMcp::new();
        let payload: &[u8] = b"connect to http://evil.example.com/c2 then 203.0.113.7";
        let Json(out): Json<IocOut> = mcp
            .ioc(Parameters(IocParams {
                bytes_b64: b64(payload),
            }))
            .unwrap();
        assert_eq!(out.schema, disrobe_core::ioc::IOC_SCHEMA);
        assert_eq!(out.byte_len, payload.len());
        let kinds: Vec<&str> = out
            .indicators
            .iter()
            .map(|i: &IndicatorOut| i.kind.as_str())
            .collect();
        assert!(kinds.contains(&"url"), "kinds: {kinds:?}");
        assert!(kinds.contains(&"ipv4"), "kinds: {kinds:?}");
    }

    #[test]
    fn ioc_rejects_empty_and_garbage() {
        let mcp: DisrobeMcp = DisrobeMcp::new();
        let empty: ErrorData = expect_err(mcp.ioc(Parameters(IocParams {
            bytes_b64: String::new(),
        })));
        assert!(empty.message.contains("DR-MCP-0182"));
        let garbage: ErrorData = expect_err(mcp.ioc(Parameters(IocParams {
            bytes_b64: "!!!".to_owned(),
        })));
        assert!(garbage.message.contains("DR-MCP-0181"));
    }

    #[test]
    fn secret_scan_redaction_is_opt_in_and_preserves_offsets() {
        let mcp: DisrobeMcp = DisrobeMcp::new();
        let secret: &str = "AKIA3KFTG2KQ4WXYZ7AB";
        let payload: Vec<u8> = format!("prefix key={secret} suffix").into_bytes();
        let Json(plain): Json<SecretScanOut> = mcp
            .secret_scan(Parameters(SecretScanParams {
                bytes_b64: b64(&payload),
                redact: false,
            }))
            .expect("plain secret scan");
        let Json(redacted): Json<SecretScanOut> = mcp
            .secret_scan(Parameters(SecretScanParams {
                bytes_b64: b64(&payload),
                redact: true,
            }))
            .expect("redacted secret scan");

        assert!(
            plain.findings.iter().any(|finding: &SecretFindingOut| {
                finding.value == secret && finding.offset == 11
            })
        );
        assert_eq!(plain.findings.len(), redacted.findings.len());
        assert_eq!(
            plain
                .findings
                .iter()
                .map(|finding: &SecretFindingOut| finding.offset)
                .collect::<Vec<usize>>(),
            redacted
                .findings
                .iter()
                .map(|finding: &SecretFindingOut| finding.offset)
                .collect::<Vec<usize>>()
        );
        let serialized: String = serde_json::to_string(&redacted).expect("serialize result");
        assert!(!serialized.contains(secret));
        assert!(serialized.contains("[REDACTED:"));
    }

    #[test]
    fn coverage_accounts_for_every_byte_of_a_real_image() {
        let image: Vec<u8> = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../corpus/native/formats/hello.pe64.exe"),
        )
        .expect("this case accounts for a committed image, so its absence is a damaged checkout");
        let mcp: DisrobeMcp = DisrobeMcp::new();
        let Json(out): Json<CoverageOut> = mcp
            .coverage(Parameters(CoverageParams {
                bytes_b64: b64(&image),
            }))
            .unwrap();
        assert_eq!(
            out.file_len,
            u64::try_from(image.len()).expect("length fits an address")
        );
        assert!(out.claimed_bytes > 0, "a real image claims bytes");
        assert_eq!(
            out.claimed_bytes
                .saturating_add(out.unclaimed_bytes)
                .saturating_add(out.slack_bytes),
            out.file_len,
            "every byte belongs to a claimed region, an unclaimed one, or alignment slack"
        );
        assert!(!out.regions.is_empty(), "the map must carry its regions");
        assert!(
            !out.regions_truncated,
            "a small committed image must not exceed the region cap"
        );
    }

    #[test]
    fn coverage_reports_an_appended_overlay_as_bytes_nothing_claims() {
        let mut image: Vec<u8> = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../corpus/native/formats/hello.pe64.exe"),
        )
        .expect("committed image");
        let clean: u64 = u64::try_from(image.len()).expect("length fits an address");
        image.extend_from_slice(&[0xA5_u8; 4096]);

        let mcp: DisrobeMcp = DisrobeMcp::new();
        let Json(out): Json<CoverageOut> = mcp
            .coverage(Parameters(CoverageParams {
                bytes_b64: b64(&image),
            }))
            .unwrap();
        assert!(
            out.unclaimed_bytes >= 4096,
            "4096 appended bytes belong to no declared structure, got {}",
            out.unclaimed_bytes
        );
        assert!(
            !out.complete,
            "an image carrying an overlay is not complete"
        );
        assert!(
            out.regions
                .iter()
                .any(|r: &CoverageRegionOut| r.class == "unclaimed" && r.start == clean),
            "the unclaimed run must begin where the original image ended, at {clean:#x}"
        );
    }

    #[test]
    fn coverage_refuses_bytes_that_are_not_an_image() {
        let mcp: DisrobeMcp = DisrobeMcp::new();
        let err: ErrorData = expect_err(mcp.coverage(Parameters(CoverageParams {
            bytes_b64: b64(&[0x00_u8; 64]),
        })));
        assert!(
            format!("{err:?}").contains("DR-MCP-0660"),
            "the refusal must carry its typed code, got {err:?}"
        );
    }

    #[test]
    fn behavior_flags_network_from_imports() {
        let mcp: DisrobeMcp = DisrobeMcp::new();
        let Json(out): Json<BehaviorOut> = mcp
            .behavior(Parameters(BehaviorParams {
                bytes_b64: b64(b"placeholder"),
                imports: vec!["WSAStartup".to_owned(), "connect".to_owned()],
            }))
            .unwrap();
        assert_eq!(out.schema, disrobe_core::behavior::BEHAVIOR_SCHEMA);
        let cats: Vec<&str> = out
            .categories
            .iter()
            .map(|c: &CategoryFindingOut| c.category.as_str())
            .collect();
        assert!(cats.contains(&"network"), "categories: {cats:?}");
        assert!(out.attack_ids.iter().any(|a: &String| a.starts_with('T')));
    }

    #[test]
    fn behavior_rejects_import_caps() {
        let mcp: DisrobeMcp = DisrobeMcp::new();
        let too_many: Vec<String> = vec!["connect".to_owned(); MAX_IMPORTS + 1];
        let count_err: ErrorData = expect_err(mcp.behavior(Parameters(BehaviorParams {
            bytes_b64: b64(b"payload"),
            imports: too_many,
        })));
        assert!(count_err.message.contains("DR-MCP-0641"));
        let name_err: ErrorData = expect_err(mcp.behavior(Parameters(BehaviorParams {
            bytes_b64: b64(b"payload"),
            imports: vec!["x".repeat(MAX_IMPORT_BYTES + 1)],
        })));
        assert!(name_err.message.contains("DR-MCP-0642"));
    }

    #[test]
    fn strings_extracts_and_validates_min_len() {
        let mcp: DisrobeMcp = DisrobeMcp::new();
        let payload: &[u8] = b"\x00\x01tiny\x00this_is_a_long_visible_string\x00\x02";
        let Json(out): Json<StringsOut> = mcp
            .strings(Parameters(StringsParams {
                bytes_b64: b64(payload),
                min_len: Some(8),
                decode: Some(false),
            }))
            .unwrap();
        assert_eq!(out.min_len, 8);
        assert!(
            out.strings
                .iter()
                .any(|s: &ExtractedStringOut| s.value.contains("long_visible_string")),
            "strings: {:?}",
            out.strings
        );
        assert!(
            out.strings
                .iter()
                .all(|s: &ExtractedStringOut| s.value != "tiny"),
            "min_len must filter the short run"
        );
        let bad: ErrorData = expect_err(mcp.strings(Parameters(StringsParams {
            bytes_b64: b64(payload),
            min_len: Some(0),
            decode: None,
        })));
        assert!(bad.message.contains("DR-MCP-0640"));
    }

    #[cfg(feature = "chain")]
    const BINARY_OPS_PYC: &[u8] =
        include_bytes!("../../../corpus/python/decompile/legacy/compiled/binary_ops.3.11.pyc");

    #[cfg(feature = "chain")]
    #[test]
    fn auto_chains_pyc_to_python_source() {
        let mcp: DisrobeMcp = DisrobeMcp::new();
        let Json(out): Json<AutoOut> = mcp
            .auto(Parameters(AutoParams {
                bytes_b64: b64(BINARY_OPS_PYC),
                max_depth: None,
            }))
            .unwrap();
        assert_eq!(out.schema, "disrobe.chain/v1");
        assert_eq!(out.final_format.as_deref(), Some("Python"));
        assert!(out.layers >= 1);
        assert!(
            out.passes
                .iter()
                .any(|p: &ChainPassOut| p.name == "py.decompile"),
            "passes: {:?}",
            out.passes
        );
    }

    #[cfg(feature = "chain")]
    #[test]
    fn decompile_recovers_python_text() {
        let mcp: DisrobeMcp = DisrobeMcp::new();
        let Json(out): Json<DecompileOut> = mcp
            .decompile(Parameters(DecompileParams {
                bytes_b64: b64(BINARY_OPS_PYC),
                max_depth: None,
            }))
            .unwrap();
        assert_eq!(out.schema, "disrobe.decompile/v1");
        assert!(
            !out.recovered.is_empty(),
            "expected a recovered source artifact"
        );
        let py: &RecoveredSourceOut = out
            .recovered
            .iter()
            .find(|r: &&RecoveredSourceOut| r.language == "Python")
            .expect("a Python artifact");
        assert!(!py.source.is_empty());
    }

    #[cfg(feature = "chain")]
    #[test]
    fn auto_rejects_empty_and_garbage_without_touching_disk() {
        let mcp: DisrobeMcp = DisrobeMcp::new();
        let empty: ErrorData = expect_err(mcp.auto(Parameters(AutoParams {
            bytes_b64: String::new(),
            max_depth: None,
        })));
        assert!(empty.message.contains("DR-MCP-0182"));
        let garbage: ErrorData = expect_err(mcp.auto(Parameters(AutoParams {
            bytes_b64: "@@@@".to_owned(),
            max_depth: None,
        })));
        assert!(garbage.message.contains("DR-MCP-0181"));
    }

    #[cfg(feature = "chain")]
    #[test]
    fn auto_rejects_invalid_depth() {
        let mcp: DisrobeMcp = DisrobeMcp::new();
        let zero: ErrorData = expect_err(mcp.auto(Parameters(AutoParams {
            bytes_b64: b64(b"payload"),
            max_depth: Some(0),
        })));
        assert!(zero.message.contains("DR-MCP-0611"));
        let high: ErrorData = expect_err(mcp.auto(Parameters(AutoParams {
            bytes_b64: b64(b"payload"),
            max_depth: Some(MAX_CHAIN_DEPTH.saturating_add(1)),
        })));
        assert!(high.message.contains("DR-MCP-0611"));
    }
}
