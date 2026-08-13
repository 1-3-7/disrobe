#![allow(
    clippy::too_many_lines,
    clippy::struct_excessive_bools,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::cast_precision_loss,
    clippy::needless_pass_by_value,
    clippy::doc_markdown,
    clippy::too_long_first_doc_paragraph
)]

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use clap::Args;
use disrobe_llm_metadata::{
    BundleBuilder, Category, InputDescriptor, MetadataFormat, MetadataSelection, PII_CAPABILITY,
    Pack, PerPassEnvelope, PipelineStep, SelectionBuilder, ToolDescriptor, envelope_map, pii,
    serialize, write_bundle_to_path,
};
use serde_json::Value as Json;

#[derive(Args, Debug, Clone, Default)]
pub(crate) struct LlmFlags {
    #[arg(long, global = true, help = "alias for --metadata-pack-4")]
    pub(crate) llm: bool,

    #[arg(
        long = "metadata-pack-1",
        global = true,
        help = "pack-1: ast + disasm + symbols + strings"
    )]
    pub(crate) pack_1: bool,

    #[arg(
        long = "metadata-pack-2",
        global = true,
        help = "pack-2: pack-1 + cfg + types + imports + provenance"
    )]
    pub(crate) pack_2: bool,

    #[arg(
        long = "metadata-pack-3",
        global = true,
        help = "pack-3: pack-2 + dfg + signatures + constants + roundtrip + sourcemap + manifest"
    )]
    pub(crate) pack_3: bool,

    #[arg(
        long = "metadata-pack-4",
        global = true,
        help = "pack-4: pack-3 + confidence + opcode-coverage + pii-map + decryption-keys (only decryption-keys needs --i-have-authorization)"
    )]
    pub(crate) pack_4: bool,

    #[arg(
        long = "ast",
        global = true,
        help = "add the ast category to the bundle"
    )]
    pub(crate) ast: bool,
    #[arg(long = "disasm", global = true, help = "add the disassembly category")]
    pub(crate) disasm: bool,
    #[arg(
        long = "cfg",
        global = true,
        help = "add the control-flow-graph category"
    )]
    pub(crate) cfg: bool,
    #[arg(long = "dfg", global = true, help = "add the data-flow-graph category")]
    pub(crate) dfg: bool,
    #[arg(long = "symbols", global = true, help = "add the symbols category")]
    pub(crate) symbols: bool,
    #[arg(long = "strings", global = true, help = "add the strings category")]
    pub(crate) strings: bool,
    #[arg(
        long = "types",
        global = true,
        help = "add the recovered-types category"
    )]
    pub(crate) types: bool,
    #[arg(long = "imports", global = true, help = "add the imports category")]
    pub(crate) imports: bool,
    #[arg(long = "constants", global = true, help = "add the constants category")]
    pub(crate) constants: bool,
    #[arg(
        long = "signatures",
        global = true,
        help = "add the function-signatures category"
    )]
    pub(crate) signatures: bool,
    #[arg(
        long = "provenance",
        global = true,
        help = "add the provenance category"
    )]
    pub(crate) provenance: bool,
    #[arg(
        long = "roundtrip-verdict",
        global = true,
        help = "add the roundtrip-verdict category"
    )]
    pub(crate) roundtrip_verdict: bool,
    #[arg(
        long = "source-map",
        global = true,
        help = "add the source-map category"
    )]
    pub(crate) source_map: bool,
    #[arg(
        long = "manifest-cat",
        global = true,
        help = "add the manifest category"
    )]
    pub(crate) manifest_cat: bool,
    #[arg(
        long = "decryption-keys",
        global = true,
        help = "add decryption keys; requires --i-have-authorization"
    )]
    pub(crate) decryption_keys: bool,
    #[arg(
        long = "confidence",
        global = true,
        help = "add the confidence-scores category"
    )]
    pub(crate) confidence: bool,
    #[arg(
        long = "opcode-coverage",
        global = true,
        help = "add the opcode-coverage category"
    )]
    pub(crate) opcode_coverage: bool,
    #[arg(long = "pii-map", global = true, help = "add the pii-map category")]
    pub(crate) pii_map: bool,

    #[arg(long = "metadata-include", global = true, value_delimiter = ',')]
    pub(crate) metadata_include: Vec<String>,

    #[arg(long = "metadata-exclude", global = true, value_delimiter = ',')]
    pub(crate) metadata_exclude: Vec<String>,

    #[arg(long = "metadata-out", global = true, value_name = "PATH")]
    pub(crate) metadata_out: Option<PathBuf>,

    #[arg(
        long = "metadata-format",
        global = true,
        value_name = "FMT",
        default_value = "json"
    )]
    pub(crate) metadata_format: String,

    #[arg(
        long = "i-have-authorization",
        global = true,
        help = "acknowledge authorization: unlocks the decryption_keys category and the gated commercial protector transforms"
    )]
    pub(crate) i_have_authorization: bool,

    #[arg(
        long = "llm-briefs",
        global = true,
        help = "also emit AGENTS.md and SKILL.md reconstruction briefs next to the bundle"
    )]
    pub(crate) llm_briefs: bool,
}

impl LlmFlags {
    pub(crate) const fn is_active(&self) -> bool {
        self.llm
            || self.pack_1
            || self.pack_2
            || self.pack_3
            || self.pack_4
            || self.ast
            || self.disasm
            || self.cfg
            || self.dfg
            || self.symbols
            || self.strings
            || self.types
            || self.imports
            || self.constants
            || self.signatures
            || self.provenance
            || self.roundtrip_verdict
            || self.source_map
            || self.manifest_cat
            || self.decryption_keys
            || self.confidence
            || self.opcode_coverage
            || self.pii_map
            || self.llm_briefs
            || !self.metadata_include.is_empty()
    }

    pub(crate) const fn flag_categories(&self) -> [(bool, Category); 18] {
        [
            (self.ast, Category::Ast),
            (self.disasm, Category::Disasm),
            (self.cfg, Category::Cfg),
            (self.dfg, Category::Dfg),
            (self.symbols, Category::Symbols),
            (self.strings, Category::Strings),
            (self.types, Category::Types),
            (self.imports, Category::Imports),
            (self.constants, Category::Constants),
            (self.signatures, Category::Signatures),
            (self.provenance, Category::Provenance),
            (self.roundtrip_verdict, Category::RoundtripVerdict),
            (self.source_map, Category::SourceMap),
            (self.manifest_cat, Category::Manifest),
            (self.decryption_keys, Category::DecryptionKeys),
            (self.confidence, Category::Confidence),
            (self.opcode_coverage, Category::OpcodeCoverage),
            (self.pii_map, Category::PiiMap),
        ]
    }

    pub(crate) fn to_selection(&self) -> miette::Result<Option<MetadataSelection>> {
        if !self.is_active() {
            return Ok(None);
        }

        let mut builder: SelectionBuilder = SelectionBuilder::new();
        if self.pack_4 || self.llm || self.llm_briefs {
            builder = builder.pack(Pack::Pack4);
        } else if self.pack_3 {
            builder = builder.pack(Pack::Pack3);
        } else if self.pack_2 {
            builder = builder.pack(Pack::Pack2);
        } else if self.pack_1 {
            builder = builder.pack(Pack::Pack1);
        }

        for (set, cat) in self.flag_categories() {
            if set {
                builder = builder.category(cat);
            }
        }

        for raw in &self.metadata_include {
            for piece in raw.split(',') {
                let piece: &str = piece.trim();
                if piece.is_empty() {
                    continue;
                }
                let cat: Category = Category::parse(piece).map_err(|e| {
                    miette::miette!(
                        "DR-CLI-0410: unknown category in --metadata-include `{piece}`: {e}"
                    )
                })?;
                builder = builder.category(cat);
            }
        }
        for raw in &self.metadata_exclude {
            for piece in raw.split(',') {
                let piece: &str = piece.trim();
                if piece.is_empty() {
                    continue;
                }
                let cat: Category = Category::parse(piece).map_err(|e| {
                    miette::miette!(
                        "DR-CLI-0410: unknown category in --metadata-exclude `{piece}`: {e}"
                    )
                })?;
                builder = builder.exclude(cat);
            }
        }

        if self.i_have_authorization {
            builder = builder.authorize_decryption_keys();
        }

        let fmt: MetadataFormat = parse_format(&self.metadata_format)?;
        builder = builder.format(fmt);

        let selection: MetadataSelection = builder.build();

        if self.decryption_keys && !self.i_have_authorization {
            return Err(miette::miette!(
                "DR-CLI-0420: --decryption-keys requires --i-have-authorization"
            ));
        }

        Ok(Some(selection))
    }

    pub(crate) fn resolve_out_path(&self, primary_output: &Path) -> PathBuf {
        if let Some(p) = self.metadata_out.as_ref() {
            return p.clone();
        }
        let stem: String = primary_output
            .file_stem()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or("output")
            .to_owned();
        let ext: &str = match parse_format(&self.metadata_format).unwrap_or(MetadataFormat::Json) {
            MetadataFormat::Json => "json",
            MetadataFormat::Jsonl => "jsonl",
            MetadataFormat::Cbor => "cbor",
            MetadataFormat::Msgpack => "msgpack",
        };
        let parent: &Path = primary_output.parent().unwrap_or_else(|| Path::new("."));
        parent.join(format!("{stem}.disrobe.llm.{ext}"))
    }
}

fn parse_format(raw: &str) -> miette::Result<MetadataFormat> {
    match raw.to_ascii_lowercase().as_str() {
        "json" => Ok(MetadataFormat::Json),
        "jsonl" => Ok(MetadataFormat::Jsonl),
        "cbor" => Ok(MetadataFormat::Cbor),
        "msgpack" | "msg-pack" => Ok(MetadataFormat::Msgpack),
        other => Err(miette::miette!(
            "DR-CLI-0440: --metadata-format `{other}` is unsupported; valid: json | jsonl | cbor | msgpack"
        )),
    }
}

#[must_use]
pub(crate) fn blake3_hex(bytes: &[u8]) -> String {
    let hash: blake3::Hash = blake3::hash(bytes);
    hash.to_hex().to_string()
}

#[must_use]
#[allow(clippy::disallowed_methods)]
pub(crate) fn iso8601_now() -> String {
    let now: SystemTime = SystemTime::now();
    let dur: std::time::Duration = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    iso8601_from_epoch(
        dur.as_secs(),
        FractionDigits::Nanoseconds(dur.subsec_nanos()),
    )
}

#[must_use]
pub(crate) fn iso8601_millis_from_epoch(seconds: u64) -> String {
    iso8601_from_epoch(seconds, FractionDigits::Milliseconds(0))
}

#[derive(Debug, Clone, Copy)]
enum FractionDigits {
    Milliseconds(u32),
    Nanoseconds(u32),
}

fn iso8601_from_epoch(seconds: u64, fraction: FractionDigits) -> String {
    let seconds_per_day: u64 = 86_400;
    let days_since_epoch: u64 = seconds / seconds_per_day;
    let time_in_day: u64 = seconds % seconds_per_day;
    let hh: u64 = time_in_day / 3600;
    let mm: u64 = (time_in_day % 3600) / 60;
    let ss: u64 = time_in_day % 60;
    let (year, month, day): (i32, u32, u32) = civil_from_days(days_since_epoch as i64);
    let head: String = format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}");
    match fraction {
        FractionDigits::Milliseconds(value) => format!("{head}.{value:03}Z"),
        FractionDigits::Nanoseconds(value) => format!("{head}.{value:09}Z"),
    }
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

#[derive(Debug, Clone)]
pub(crate) struct LlmOutputs {
    pub(crate) bundle: PathBuf,
    pub(crate) agents_md: Option<PathBuf>,
    pub(crate) skill_md: Option<PathBuf>,
}

pub(crate) fn write_llm_bundle(
    flags: &LlmFlags,
    selection: &MetadataSelection,
    input_path: &Path,
    input_bytes: &[u8],
    primary_output: &Path,
    per_pass_envelope_maps: Vec<(PipelineStep, Json)>,
) -> miette::Result<LlmOutputs> {
    let out_path: PathBuf = flags.resolve_out_path(primary_output);
    if out_path.exists() && !crate::cli::globals::current().force {
        return Err(miette::miette!(
            "DR-CLI-0431: --metadata-out {} exists; pass --force to overwrite",
            out_path.display()
        ));
    }
    let input_size_bytes: u64 = u64::try_from(input_bytes.len()).unwrap_or(u64::MAX);
    let input: InputDescriptor = InputDescriptor {
        path: input_path.display().to_string(),
        size_bytes: input_size_bytes,
        hash_blake3: blake3_hex(input_bytes),
        magic_bytes_hex: input_bytes
            .first_chunk::<8>()
            .map(|c: &[u8; 8]| hex_lower(c)),
        detected_formats: Vec::new(),
    };
    let tool: ToolDescriptor = ToolDescriptor::default();

    let mut builder: BundleBuilder = BundleBuilder::new();
    for (step, envelope_map) in per_pass_envelope_maps {
        builder.record_pass(step, envelope_map);
    }
    if let Some((step, envelope_map)) = pii_pass_for_bytes(selection, input_bytes) {
        builder.record_pass(step, envelope_map);
    }
    let bundle: Json = builder
        .finalize(iso8601_now(), tool, selection, input)
        .map_err(|e: disrobe_llm_metadata::LlmMetadataError| {
            miette::miette!("DR-CLI-0440: build LLM bundle failed: {e}")
        })?;

    let bytes: Vec<u8> = serialize(&bundle, selection.format).map_err(
        |e: disrobe_llm_metadata::LlmMetadataError| {
            miette::miette!("DR-CLI-0440: serialize LLM bundle failed: {e}")
        },
    )?;
    write_bundle_to_path(&out_path, &bytes).map_err(
        |e: disrobe_llm_metadata::LlmMetadataError| {
            miette::miette!("DR-CLI-0430: write LLM bundle failed: {e}")
        },
    )?;

    let (agents_md, skill_md): (Option<PathBuf>, Option<PathBuf>) = if flags.llm_briefs {
        let dir: &Path = out_path.parent().unwrap_or_else(|| Path::new("."));
        let (agents, skill): (PathBuf, PathBuf) = disrobe_llm_metadata::write_briefs_to_dir(
            dir, &bundle,
        )
        .map_err(|e: disrobe_llm_metadata::LlmMetadataError| {
            miette::miette!("DR-CLI-0432: write LLM briefs failed: {e}")
        })?;
        (Some(agents), Some(skill))
    } else {
        (None, None)
    };

    Ok(LlmOutputs {
        bundle: out_path,
        agents_md,
        skill_md,
    })
}

#[inline]
fn hex_lower(bytes: &[u8]) -> String {
    let mut s: String = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _: std::fmt::Result = std::fmt::Write::write_fmt(&mut s, format_args!("{b:02x}"));
    }
    s
}

#[must_use]
pub(crate) fn make_step(
    pass: &str,
    version: &str,
    rung_in: &str,
    rung_out: &str,
    duration_ms: f64,
) -> PipelineStep {
    PipelineStep {
        pass: pass.to_owned(),
        version: version.to_owned(),
        rung_in: rung_in.to_owned(),
        rung_out: rung_out.to_owned(),
        duration_ms,
        input_hash_blake3: None,
        output_hash_blake3: None,
        capabilities_required: Vec::new(),
        capabilities_produced: Vec::new(),
        config: None,
    }
}

fn pii_truncation_note(outcome: &disrobe_llm_metadata::PiiScanOutcome) -> Option<String> {
    if !outcome.input_truncated() {
        return None;
    }
    Some(format!(
        "the scan covered only the first {} of {} input byte(s); a size cap bounds pii_map cost \
         on large inputs",
        outcome.scanned_bytes, outcome.total_bytes
    ))
}

fn pii_not_applicable_reason(outcome: &disrobe_llm_metadata::PiiScanOutcome) -> String {
    let base: String = format!(
        "pass `{}` supports `{}` but produced no data for this input",
        PII_CAPABILITY.pass,
        Category::PiiMap.label()
    );
    pii_truncation_note(outcome)
        .map_or_else(|| base.clone(), |note: String| format!("{base}; {note}"))
}

fn pii_applicable_reason(outcome: &disrobe_llm_metadata::PiiScanOutcome) -> Option<String> {
    let cap_note: Option<String> = (outcome.omitted > 0).then(|| {
        format!(
            "pii_map entry cap reached; {} occurrence(s) were found but not emitted",
            outcome.omitted
        )
    });
    let truncation_note: Option<String> = pii_truncation_note(outcome);
    match (cap_note, truncation_note) {
        (Some(cap), Some(trunc)) => Some(format!("{cap}; {trunc}")),
        (Some(cap), None) => Some(cap),
        (None, Some(trunc)) => Some(trunc),
        (None, None) => None,
    }
}

fn pii_pass_for_bytes(selection: &MetadataSelection, bytes: &[u8]) -> Option<(PipelineStep, Json)> {
    if !selection.contains(Category::PiiMap) {
        return None;
    }
    let started: std::time::Instant = std::time::Instant::now();
    let outcome: disrobe_llm_metadata::PiiScanOutcome = pii::scan(bytes);
    let duration_ms: f64 = started.elapsed().as_secs_f64() * 1000.0_f64;
    let envelope: PerPassEnvelope = if outcome.entries.is_empty() {
        PerPassEnvelope::not_applicable(
            PII_CAPABILITY.pass,
            PII_CAPABILITY.pass_version,
            pii_not_applicable_reason(&outcome),
        )
    } else {
        let reason: Option<String> = pii_applicable_reason(&outcome);
        let mut envelope: PerPassEnvelope = PerPassEnvelope::applicable(
            PII_CAPABILITY.pass,
            PII_CAPABILITY.pass_version,
            Json::Array(outcome.entries),
        );
        envelope.reason = reason;
        envelope
    };
    let mut entries: std::collections::BTreeMap<&'static str, PerPassEnvelope> =
        std::collections::BTreeMap::new();
    entries.insert(Category::PiiMap.label(), envelope);
    Some((
        make_step(
            PII_CAPABILITY.pass,
            PII_CAPABILITY.pass_version,
            "raw",
            "raw",
            duration_ms,
        ),
        envelope_map(entries),
    ))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn make_flags() -> LlmFlags {
        LlmFlags {
            metadata_format: "json".to_owned(),
            ..LlmFlags::default()
        }
    }

    #[test]
    fn no_flags_returns_none() {
        let flags: LlmFlags = make_flags();
        assert!(flags.to_selection().expect("ok").is_none());
    }

    #[test]
    fn llm_resolves_to_pack4_full_set() {
        let mut flags: LlmFlags = make_flags();
        flags.llm = true;
        flags.i_have_authorization = true;
        let sel: MetadataSelection = flags.to_selection().expect("ok").expect("some");
        let resolved: std::collections::BTreeSet<Category> = sel.resolved();
        assert!(resolved.contains(&Category::Ast));
        assert!(resolved.contains(&Category::DecryptionKeys));
        assert!(resolved.contains(&Category::PiiMap));
    }

    #[test]
    fn pack3_excludes_decryption_keys_without_auth() {
        let mut flags: LlmFlags = make_flags();
        flags.pack_3 = true;
        let sel: MetadataSelection = flags.to_selection().expect("ok").expect("some");
        let resolved: std::collections::BTreeSet<Category> = sel.resolved();
        assert!(!resolved.contains(&Category::DecryptionKeys));
        assert!(resolved.contains(&Category::Manifest));
    }

    #[test]
    fn decryption_keys_without_auth_errors() {
        let mut flags: LlmFlags = make_flags();
        flags.decryption_keys = true;
        let err: miette::Report = flags.to_selection().expect_err("must fail");
        let msg: String = format!("{err:?}");
        assert!(msg.contains("DR-CLI-0420"), "got: {msg}");
    }

    #[test]
    fn include_excludes_apply_after_packs() {
        let mut flags: LlmFlags = make_flags();
        flags.pack_3 = true;
        flags.metadata_exclude = vec!["ast,symbols".to_owned()];
        let sel: MetadataSelection = flags.to_selection().expect("ok").expect("some");
        let resolved: std::collections::BTreeSet<Category> = sel.resolved();
        assert!(!resolved.contains(&Category::Ast));
        assert!(!resolved.contains(&Category::Symbols));
        assert!(resolved.contains(&Category::Disasm));
    }

    #[test]
    fn unknown_category_in_include_errors() {
        let mut flags: LlmFlags = make_flags();
        flags.metadata_include = vec!["asti".to_owned()];
        let err: miette::Report = flags.to_selection().expect_err("must fail");
        assert!(format!("{err:?}").contains("DR-CLI-0410"));
    }

    #[test]
    fn unknown_format_errors() {
        let mut flags: LlmFlags = make_flags();
        flags.llm = true;
        flags.metadata_format = "xml".to_owned();
        let err: miette::Report = flags.to_selection().expect_err("must fail");
        assert!(format!("{err:?}").contains("DR-CLI-0440"));
    }

    #[test]
    fn iso8601_format_smoke() {
        let s: String = iso8601_now();
        assert!(s.ends_with('Z'));
        assert!(s.len() >= 20);
    }

    #[test]
    fn out_path_default_uses_stem() {
        let flags: LlmFlags = LlmFlags::default();
        let primary: PathBuf = PathBuf::from("./out/foo.py");
        let resolved: PathBuf = flags.resolve_out_path(&primary);
        assert!(resolved.to_string_lossy().contains("foo.disrobe.llm.json"));
    }

    #[test]
    fn make_step_serializes_with_required_fields() {
        let s: PipelineStep =
            make_step("disrobe-pass-py-disasm", "0.1.0", "raw", "disasm", 1.5_f64);
        let v: Json = serde_json::to_value(&s).expect("ok");
        assert_eq!(
            v.get("pass").and_then(Json::as_str),
            Some("disrobe-pass-py-disasm")
        );
        assert_eq!(v.get("rung_in").and_then(Json::as_str), Some("raw"));
    }

    fn pii_selection() -> MetadataSelection {
        SelectionBuilder::new().category(Category::PiiMap).build()
    }

    #[test]
    fn pii_pass_is_skipped_when_not_selected() {
        let selection: MetadataSelection = SelectionBuilder::new().category(Category::Ast).build();
        assert!(pii_pass_for_bytes(&selection, b"alice@example.com").is_none());
    }

    #[test]
    fn pii_pass_reports_not_applicable_when_nothing_found() {
        let selection: MetadataSelection = pii_selection();
        let (step, map): (PipelineStep, Json) =
            pii_pass_for_bytes(&selection, b"nothing sensitive here").expect("pii pass runs");
        assert_eq!(step.pass, PII_CAPABILITY.pass);
        assert_eq!(step.rung_in, "raw");
        assert_eq!(step.rung_out, "raw");
        let envelope: &Json = map.get("pii_map").expect("pii_map key");
        assert_eq!(
            envelope.get("applicable").and_then(Json::as_bool),
            Some(false)
        );
        assert!(envelope.get("value").is_none_or(Json::is_null));
        let reason: &str = envelope
            .get("reason")
            .and_then(Json::as_str)
            .expect("reason present");
        assert!(reason.contains("produced no data"), "{reason}");
    }

    #[test]
    fn pii_pass_reports_applicable_with_entries_when_found() {
        let selection: MetadataSelection = pii_selection();
        let (_step, map): (PipelineStep, Json) =
            pii_pass_for_bytes(&selection, b"contact alice@example.com now").expect("pii runs");
        let envelope: &Json = map.get("pii_map").expect("pii_map key");
        assert_eq!(
            envelope.get("applicable").and_then(Json::as_bool),
            Some(true)
        );
        let value: &Json = envelope.get("value").expect("value present");
        assert!(value.as_array().is_some_and(|a: &Vec<Json>| !a.is_empty()));
        assert!(envelope.get("reason").is_some_and(Json::is_null));
    }

    #[test]
    fn pii_pass_reason_reports_the_cap_when_reached() {
        use std::fmt::Write as _;
        let selection: MetadataSelection = pii_selection();
        let mut text: String = String::new();
        for i in 0..4300 {
            let _: std::fmt::Result = write!(text, "user{i}@example{i}.com ");
        }
        let (_step, map): (PipelineStep, Json) =
            pii_pass_for_bytes(&selection, text.as_bytes()).expect("pii runs");
        let envelope: &Json = map.get("pii_map").expect("pii_map key");
        let reason: &str = envelope
            .get("reason")
            .and_then(Json::as_str)
            .expect("cap reason present");
        assert!(reason.contains("cap"), "{reason}");
    }

    #[test]
    fn pii_pass_reason_reports_input_truncation_on_a_large_input() {
        let selection: MetadataSelection = pii_selection();
        let mut buf: Vec<u8> = b"contact alice@example.com ".to_vec();
        buf.extend(std::iter::repeat_n(b'.', 2 * 1024 * 1024));
        let (_step, map): (PipelineStep, Json) =
            pii_pass_for_bytes(&selection, &buf).expect("pii runs");
        let envelope: &Json = map.get("pii_map").expect("pii_map key");
        let reason: &str = envelope
            .get("reason")
            .and_then(Json::as_str)
            .expect("truncation reason present");
        assert!(
            reason.contains("size cap") && reason.contains("input byte"),
            "{reason}"
        );
    }
}
