#![cfg(feature = "chain")]
#![allow(clippy::needless_pass_by_value)]
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use disrobe_core::anti_analysis::{
    AntiAnalysisFinding, AntiAnalysisReport, ChainEvidence, DefeatStatus,
    Technique as AntiTechnique, scan_with_chain as scan_anti_analysis,
};
use disrobe_core::chain::metadata_keys::{self, MetadataValueError, keys};
use disrobe_core::chain::spec::PassToken;
use disrobe_core::chain::state_machine::{PassRunner, Verdict};
use disrobe_core::chain::{
    ChainConfig, ChainDocument, ChainDriver, ChainPlan, ChainRecoveryReport, ChainSpec,
    ChildArtifact, ChildHandle, DetectorPick, Node, OutputKind, PassRegistry, PassRunOutcome,
};
use disrobe_core::pass::PassContext;
use disrobe_core::{Artifact, Redactor, Rung};

use super::backend_export::{BackendExportTarget, SupplementalOutput, write_supplemental_output};
use super::output::{OutputFormat, emit};
use super::path_ops::{self, LinkKind};
use super::progress_ui::ChainProgress;

#[derive(Debug)]
struct ChainPassRunner<'p> {
    progress: &'p ChainProgress,
}

impl<'p> ChainPassRunner<'p> {
    const fn new(progress: &'p ChainProgress) -> Self {
        Self { progress }
    }
}

fn insert_refusal_metadata(
    metadata: &mut BTreeMap<String, String>,
    refusals: &[String],
) -> Result<(), String> {
    if refusals.is_empty() {
        return Ok(());
    }
    let mut encoded_bytes: usize = 2;
    let mut bounded: Vec<String> = Vec::new();
    for refusal in refusals {
        let encoded: Vec<u8> =
            serde_json::to_vec(refusal).map_err(|error: serde_json::Error| error.to_string())?;
        let separator_bytes: usize = usize::from(!bounded.is_empty());
        let Some(next_bytes): Option<usize> = encoded_bytes
            .checked_add(separator_bytes)
            .and_then(|value: usize| value.checked_add(encoded.len()))
        else {
            break;
        };
        if next_bytes > keys::CONTAINER_REFUSALS_KEY.max_bytes() {
            break;
        }
        encoded_bytes = next_bytes;
        bounded.push(refusal.clone());
    }
    let total: i64 = i64::try_from(refusals.len())
        .map_err(|_error: std::num::TryFromIntError| "container refusal count overflow")?;
    let omitted_count: usize = refusals.len().saturating_sub(bounded.len());
    let omitted: i64 = i64::try_from(omitted_count)
        .map_err(|_error: std::num::TryFromIntError| "container omitted-refusal count overflow")?;
    let value: serde_json::Value =
        serde_json::to_value(bounded).map_err(|error: serde_json::Error| error.to_string())?;
    metadata_keys::set_json(metadata, keys::CONTAINER_REFUSALS_KEY, &value)
        .map_err(|error: MetadataValueError| error.to_string())?;
    metadata_keys::set_integer(metadata, keys::CONTAINER_REFUSALS_TOTAL_KEY, total)
        .map_err(|error: MetadataValueError| error.to_string())?;
    metadata_keys::set_integer(metadata, keys::CONTAINER_REFUSALS_OMITTED_KEY, omitted)
        .map_err(|error: MetadataValueError| error.to_string())?;
    metadata_keys::set_boolean(
        metadata,
        keys::CONTAINER_REFUSALS_TRUNCATED_KEY,
        omitted_count != 0,
    )
    .map_err(|error: MetadataValueError| error.to_string())?;
    Ok(())
}

impl PassRunner for ChainPassRunner<'_> {
    fn run(
        &self,
        pick: &DetectorPick,
        bytes: Vec<u8>,
        config: &ChainConfig,
        path_hint: Option<&str>,
    ) -> Result<PassRunOutcome, String> {
        self.progress.step(pick.verdict.pass_id);
        let hash: [u8; 32] = blake3_hash(&bytes);
        let artifact: Artifact = Artifact::new(Rung::Raw, bytes, hash);
        let started: Instant = Instant::now();
        let context: PassContext<'_> = PassContext {
            path_hint,
            i_have_authorization: config.i_have_authorization,
        };
        let out_artifact: Artifact = pick
            .pass
            .run_with_context(&artifact, context)
            .map_err(|e: disrobe_core::error::CoreError| format!("{e}"))?;
        let initial_kind: OutputKind = pick.pass.output_kind(&out_artifact);
        let mut metadata: BTreeMap<String, String> = pick
            .pass
            .chain_metadata(&artifact)
            .map_err(|e: disrobe_core::error::CoreError| format!("{e}"))?;
        let refusals: Vec<String> = pick
            .pass
            .chain_refusals(&artifact)
            .map_err(|e: disrobe_core::error::CoreError| format!("{e}"))?;
        insert_refusal_metadata(&mut metadata, &refusals)?;
        let (kind, children): (OutputKind, Vec<Vec<u8>>) = if initial_kind.is_mixed() {
            let extracted: Vec<ChildArtifact> = pick
                .pass
                .extract_children_with_context(&artifact, context)
                .map_err(|e: disrobe_core::error::CoreError| format!("{e}"))?;
            extend_anti_metadata(pick.verdict.pass_id, &extracted, &mut metadata)
                .map_err(|error: MetadataValueError| error.to_string())?;
            OutputKind::mixed_from_children(extracted)
        } else {
            if pick.verdict.pass_id == "wasm.deob"
                && out_artifact.rung == Rung::Surface
                && let Ok(extracted) = pick.pass.extract_children_with_context(&artifact, context)
            {
                extend_anti_metadata(pick.verdict.pass_id, &extracted, &mut metadata)
                    .map_err(|error: MetadataValueError| error.to_string())?;
            }
            (initial_kind, Vec::new())
        };
        Ok(PassRunOutcome {
            output_bytes: out_artifact.envelope,
            kind,
            duration: started.elapsed(),
            metadata,
            children,
        })
    }
}

fn blake3_hash(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

fn metadata_value_report(error: MetadataValueError) -> miette::Report {
    miette::miette!("DR-CLI-0299: invalid chain metadata: {error}")
}

fn chain_evidence(plan: &ChainPlan) -> Result<ChainEvidence, MetadataValueError> {
    let mut executed_pass_ids: Vec<String> = Vec::new();
    let mut recovered_format_tags: Vec<String> = Vec::new();
    let mut recovered_techniques: Vec<AntiTechnique> = Vec::new();
    for node in &plan.nodes {
        let succeeded: bool = !matches!(
            node.verdict,
            Verdict::Error { .. } | Verdict::Stalled | Verdict::DryRun
        );
        if !succeeded {
            continue;
        }
        if let Some(pass_id) = node.pass_id.as_deref() {
            let owned: String = pass_id.to_string();
            if !executed_pass_ids.contains(&owned) {
                executed_pass_ids.push(owned);
            }
            for technique in recovered_techniques_for(pass_id, &node.metadata)? {
                push_unique_technique(&mut recovered_techniques, technique);
            }
        }
        if let Some(OutputKind::Bytes { format_tag, .. }) = node.output_kind.as_ref() {
            let tag: String = (*format_tag).to_string();
            if !recovered_format_tags.contains(&tag) {
                recovered_format_tags.push(tag);
            }
        }
        if node.pass_id.as_deref() == Some("native.packer-unpack")
            && let Some(OutputKind::Mixed { children }) = node.output_kind.as_ref()
            && children
                .iter()
                .any(|c: &ChildHandle| c.relative_path == "recovered-image.bin")
        {
            let tag: String = "pe".to_string();
            if !recovered_format_tags.contains(&tag) {
                recovered_format_tags.push(tag);
            }
        }
    }
    Ok(ChainEvidence {
        executed_pass_ids,
        recovered_format_tags,
        recovered_techniques,
    })
}

fn recovered_techniques_for(
    _pass_id: &str,
    metadata: &BTreeMap<String, String>,
) -> Result<Vec<AntiTechnique>, MetadataValueError> {
    let mut techniques: Vec<AntiTechnique> = Vec::new();
    let Some(labels): Option<Vec<&str>> =
        metadata_keys::get_comma_list(metadata, keys::ANTI_RECOVERED_TECHNIQUES_KEY)?
    else {
        return Ok(techniques);
    };
    for label in labels {
        if let Some(technique) = anti_technique_from_label(label) {
            push_unique_technique(&mut techniques, technique);
        }
    }
    Ok(techniques)
}

fn extend_anti_metadata(
    pass_id: &str,
    children: &[ChildArtifact],
    metadata: &mut BTreeMap<String, String>,
) -> Result<(), MetadataValueError> {
    let mut techniques: Vec<AntiTechnique> = Vec::new();
    for child in children {
        match (pass_id, child.handle.relative_path.as_str()) {
            ("wasm.deob", "wasm.recovery.json") => {
                extend_from_wasm_recovery(&child.bytes, &mut techniques);
            }
            ("native.packer-unpack", "deobf.json") => {
                extend_from_native_deobf(&child.bytes, &mut techniques);
            }
            _ => {}
        }
    }
    if !techniques.is_empty() {
        let labels: Vec<&str> = techniques
            .iter()
            .map(|technique: &AntiTechnique| technique.label())
            .collect();
        let _previous: Option<String> =
            metadata_keys::set_comma_list(metadata, keys::ANTI_RECOVERED_TECHNIQUES_KEY, &labels)?;
    }
    Ok(())
}

fn extend_from_wasm_recovery(bytes: &[u8], techniques: &mut Vec<AntiTechnique>) {
    let Ok(value): Result<serde_json::Value, serde_json::Error> = serde_json::from_slice(bytes)
    else {
        return;
    };
    if json_usize(&value, "flattened_functions_restructured") > 0 {
        push_unique_technique(techniques, AntiTechnique::ControlFlowFlattening);
    }
    if json_usize(&value, "opaque_predicates_removed") > 0
        || json_usize(&value, "collatz_predicates_removed") > 0
    {
        push_unique_technique(techniques, AntiTechnique::OpaquePredicate);
    }
    if json_usize(&value, "decrypt_stub_bytes_recovered") > 0 {
        push_unique_technique(techniques, AntiTechnique::StringEncryption);
    }
}

fn extend_from_native_deobf(bytes: &[u8], techniques: &mut Vec<AntiTechnique>) {
    let Ok(value): Result<serde_json::Value, serde_json::Error> = serde_json::from_slice(bytes)
    else {
        return;
    };
    if value
        .get("cff")
        .is_some_and(|v: &serde_json::Value| !v.is_null())
    {
        push_unique_technique(techniques, AntiTechnique::ControlFlowFlattening);
    }
    if json_array_nonempty(&value, "bogus_branches")
        || json_array_nonempty(&value, "mba_simplifications")
        || json_array_nonempty(&value, "branch_folds")
    {
        push_unique_technique(techniques, AntiTechnique::OpaquePredicate);
    }
    if value
        .get("cleaned_listing")
        .is_some_and(serde_json::Value::is_string)
    {
        push_unique_technique(techniques, AntiTechnique::AntiDisassembly);
    }
    if json_array_nonempty(&value, "stack_strings") {
        push_unique_technique(techniques, AntiTechnique::StringEncryption);
    }
}

fn json_usize(value: &serde_json::Value, key: &str) -> usize {
    value
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .and_then(|n: u64| usize::try_from(n).ok())
        .unwrap_or(0)
}

fn json_array_nonempty(value: &serde_json::Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(serde_json::Value::as_array)
        .is_some_and(|items: &Vec<serde_json::Value>| !items.is_empty())
}

fn anti_technique_from_label(label: &str) -> Option<AntiTechnique> {
    match label {
        "anti-disassembly" => Some(AntiTechnique::AntiDisassembly),
        "control-flow-flattening" => Some(AntiTechnique::ControlFlowFlattening),
        "opaque-predicate" => Some(AntiTechnique::OpaquePredicate),
        "string-encryption" => Some(AntiTechnique::StringEncryption),
        _ => None,
    }
}

fn push_unique_technique(techniques: &mut Vec<AntiTechnique>, technique: AntiTechnique) {
    if !techniques.contains(&technique) {
        techniques.push(technique);
    }
}

fn render_anti_analysis(report: &AntiAnalysisReport) {
    let detected: Vec<&AntiAnalysisFinding> = report
        .findings
        .iter()
        .filter(|f: &&AntiAnalysisFinding| f.detected)
        .collect();
    let informational: Vec<&AntiAnalysisFinding> = report
        .findings
        .iter()
        .filter(|f: &&AntiAnalysisFinding| !f.detected)
        .collect();
    if detected.is_empty() && informational.is_empty() {
        println!("anti-analysis: none detected");
        return;
    }
    if detected.is_empty() {
        println!(
            "anti-analysis: no verdict-grade techniques ({} informational signal(s)):",
            informational.len()
        );
    } else {
        println!(
            "anti-analysis ({} technique(s), {} overcome):",
            detected.len(),
            report.overcome_count()
        );
    }
    for finding in &detected {
        match &finding.defeated_by {
            DefeatStatus::OvercomeBy { mechanism } => {
                println!(
                    "  anti-analysis: {} -> overcome via {}",
                    finding.technique.label(),
                    mechanism.label()
                );
            }
            DefeatStatus::DetectedNotDefeated { reason } => {
                println!(
                    "  anti-analysis: {} -> detected, not defeated: {}",
                    finding.technique.label(),
                    reason
                );
            }
        }
    }
    for finding in &informational {
        println!(
            "  anti-analysis [informational]: {} -> weak signal surfaced for triage",
            finding.technique.label()
        );
    }
}

fn delphi_report_for(bytes: &[u8]) -> Option<disrobe_pass_native::delphi::DelphiReport> {
    disrobe_pass_native::detect_delphi(bytes).then(|| disrobe_pass_native::delphi::analyze(bytes))
}

fn render_delphi(report: Option<&disrobe_pass_native::delphi::DelphiReport>) {
    let Some(report): Option<&disrobe_pass_native::delphi::DelphiReport> = report else {
        return;
    };
    if !report.is_delphi {
        println!("delphi: a Delphi signal fired, the analysis confirmed no Delphi structure");
        render_delphi_notes(report);
        return;
    }
    println!("delphi: built with Delphi or C++Builder");
    render_delphi_version(&report.version);
    if report.classes.is_empty() {
        println!("  delphi: no class recovered from a virtual method table");
    } else {
        let unattributed: usize = report
            .classes
            .len()
            .saturating_sub(report.author_class_count + report.library_class_count);
        println!(
            "  delphi: {} class(es) recovered ({} author, {} runtime library, {} unattributed)",
            report.classes.len(),
            report.author_class_count,
            report.library_class_count,
            unattributed
        );
    }
    if !report.types.is_empty() {
        println!("  delphi: {} RTTI type record(s)", report.types.len());
    }
    println!(
        "  delphi: {} DFM form resource(s) decoded",
        report.forms.len()
    );
    render_delphi_notes(report);
}

fn render_delphi_version(version: &disrobe_pass_native::delphi::DelphiVersion) {
    match version.product.as_deref() {
        Some(product) => {
            let symbol: &str = version.ver_symbol.as_deref().unwrap_or("no VER symbol");
            println!("  delphi: version {product} ({symbol})");
        }
        None if version.conflicts.is_empty() => {
            println!("  delphi: version not named; no signal resolved a single release");
        }
        None => println!(
            "  delphi: version not named; {} version signal(s) disagree, listed below",
            version.conflicts.len()
        ),
    }
}

fn render_delphi_notes(report: &disrobe_pass_native::delphi::DelphiReport) {
    for note in &report.notes {
        println!("  delphi note: {note}");
    }
}

fn build_registry() -> PassRegistry {
    disrobe_passes::build_registry()
}

#[derive(Clone, Debug)]
pub(crate) struct ChainRunOptions {
    pub(crate) write_to_disk: bool,
    pub(crate) redact: bool,
    pub(crate) capture_stages: bool,
    pub(crate) emit_recovery: bool,
    pub(crate) backend_export: Option<BackendExportTarget>,
    pub(crate) engine_symbol_map: Option<PathBuf>,
    pub(crate) i_have_authorization: bool,
}

impl ChainRunOptions {
    fn chain_config(&self, stream_extracted: bool) -> ChainConfig {
        ChainConfig {
            capture_stage_bytes: self.capture_stages && self.write_to_disk,
            persist_children: self.write_to_disk,
            stream_extracted,
            i_have_authorization: self.i_have_authorization,
            ..ChainConfig::default()
        }
    }
}

#[cfg(feature = "jvm")]
fn direct_root_dalvik_node(plan: &ChainPlan, input_hash: [u8; 32]) -> Option<&Node> {
    plan.nodes.iter().find(|node: &&Node| {
        node.parent_id == Some(plan.root_id)
            && node.pass_id.as_deref() == Some("jvm.classify")
            && node.format_tag_in.as_deref() == Some("android-dex")
            && node.input_blake3 == input_hash
            && matches!(
                node.output_kind.as_ref(),
                Some(OutputKind::Mixed { children }) if !children.is_empty()
            )
            && matches!(node.verdict, Verdict::FanOut { count } if count > 0)
    })
}

#[cfg(feature = "flutter")]
fn direct_root_flutter_node(plan: &ChainPlan, input_hash: [u8; 32]) -> Option<&Node> {
    plan.nodes.iter().find(|node: &&Node| {
        node.parent_id == Some(plan.root_id)
            && node.pass_id.as_deref() == Some("mobile.classify")
            && node.format_tag_in.as_deref() == Some("flutter-aot")
            && node.input_blake3 == input_hash
            && matches!(
                node.output_kind.as_ref(),
                Some(OutputKind::Mixed { children }) if children.is_empty()
            )
            && matches!(node.verdict, Verdict::FanOut { count: 0 })
    })
}

#[cfg(feature = "flutter")]
fn prepare_flutter_symbol_export(
    plan: &ChainPlan,
    input: &[u8],
    input_path: &Path,
    engine_symbol_map_path: Option<&Path>,
    target: Option<BackendExportTarget>,
) -> miette::Result<Option<SupplementalOutput>> {
    let input_hash: [u8; 32] = blake3_hash(input);
    if direct_root_flutter_node(plan, input_hash).is_none() {
        if engine_symbol_map_path.is_some() {
            return Err(miette::miette!(
                "DR-CLI-0446: --engine-symbol-map requires a successful direct root Flutter AOT classification for the original input"
            ));
        }
        return Ok(None);
    }
    let Some(target): Option<BackendExportTarget> = target else {
        return Ok(None);
    };
    let layout: disrobe_pass_mobile::LibAppLayout = disrobe_pass_mobile::parse_libapp_so(input)
        .map_err(|error| miette::miette!("DR-CLI-0445: requested Flutter symbol export cannot parse the classified root libapp.so: {error}"))?;
    let engine_symbol_map: Option<super::flutter::FlutterEngineSymbolInput> =
        super::flutter::resolve_flutter_engine_symbol_map(engine_symbol_map_path, input)?;
    super::flutter::prepare_flutter_symbol_export(
        input_path,
        &layout,
        engine_symbol_map.as_ref(),
        target,
    )
    .map(Some)
}

#[cfg(not(feature = "flutter"))]
fn prepare_flutter_symbol_export(
    _plan: &ChainPlan,
    _input: &[u8],
    _input_path: &Path,
    engine_symbol_map_path: Option<&Path>,
    target: Option<BackendExportTarget>,
) -> miette::Result<Option<SupplementalOutput>> {
    if engine_symbol_map_path.is_some() {
        return Err(miette::miette!(
            "DR-CLI-0447: --engine-symbol-map requires a binary built with the `flutter` feature"
        ));
    }
    let _ = target;
    Ok(None)
}

#[cfg(feature = "jvm")]
fn prepare_dalvik_symbol_export(
    plan: &ChainPlan,
    input: &[u8],
    input_path: &Path,
    target: Option<BackendExportTarget>,
) -> miette::Result<Option<SupplementalOutput>> {
    let Some(target): Option<BackendExportTarget> = target else {
        return Ok(None);
    };
    let input_hash: [u8; 32] = blake3_hash(input);
    if direct_root_dalvik_node(plan, input_hash).is_none() {
        return Err(miette::miette!(
            "DR-CLI-0442: requested Dalvik symbol export requires a successful direct root `jvm.classify` android-dex node for the original input"
        ));
    }
    let dex: disrobe_pass_jvm::DexFile = disrobe_pass_jvm::parse_dex(input)
        .map_err(|error| miette::miette!("DR-CLI-0443: requested Dalvik symbol export cannot parse the classified root DEX: {error}"))?;
    super::jvm::render_dalvik_symbol_export(input_path, &dex, target, target.auto_path()).map(Some)
}

#[cfg(not(feature = "jvm"))]
fn prepare_dalvik_symbol_export(
    _plan: &ChainPlan,
    _input: &[u8],
    _input_path: &Path,
    target: Option<BackendExportTarget>,
) -> miette::Result<Option<SupplementalOutput>> {
    if target.is_some() {
        return Err(miette::miette!(
            "DR-CLI-0441: this binary was built without the `jvm` feature, so it cannot emit a requested Dalvik symbol export"
        ));
    }
    Ok(None)
}

pub(crate) fn run_with_disk(
    input: PathBuf,
    out: Option<PathBuf>,
    chain_arg: String,
    pin_arg: Option<String>,
    fmt: OutputFormat,
    options: ChainRunOptions,
) -> miette::Result<()> {
    let write_to_disk: bool = options.write_to_disk;
    let redact: bool = options.redact;
    let capture_stages: bool = options.capture_stages;
    let emit_recovery: bool = options.emit_recovery;
    let backend_export: Option<BackendExportTarget> = options.backend_export;
    let engine_symbol_map: Option<&Path> = options.engine_symbol_map.as_deref();
    let spec_raw: String = match pin_arg {
        None => chain_arg,
        Some(pin) => combine_chain_and_pin_owned(chain_arg, &pin)?,
    };
    let spec: ChainSpec = ChainSpec::parse(&spec_raw)
        .map_err(|e| miette::miette!("DR-CLI-0291: --chain parse error: {e}"))?;
    let luks1_probe: Option<super::luks1_input::Luks1FileProbe> = super::luks1_input::probe(&input)
        .map_err(|error: super::luks1_input::Luks1ProbeError| match error {
            super::luks1_input::Luks1ProbeError::Input(error) => miette::miette!(
                "DR-CLI-0292: chain cannot read input {}: {error}",
                input.display()
            ),
            super::luks1_input::Luks1ProbeError::Refused(error) => miette::miette!(
                "DR-CLI-0844: LUKS1 input {} was refused before payload allocation: {error}",
                input.display()
            ),
        })?;
    let bytes: Vec<u8> = luks1_probe.map_or_else(
        || {
            std::fs::read(&input).map_err(|error: std::io::Error| {
                miette::miette!(
                    "DR-CLI-0292: chain cannot read input {}: {error}",
                    input.display()
                )
            })
        },
        |probe: super::luks1_input::Luks1FileProbe| {
            super::luks1_input::read_luks1_bounded(&input, &probe)
        },
    )?;
    let registry: PassRegistry = build_registry();
    validate_explicit_passes(&spec, &registry)?;
    let progress: ChainProgress = ChainProgress::for_chain("disrobe auto");
    let runner: ChainPassRunner<'_> = ChainPassRunner::new(&progress);
    let stream_out_dir: Option<PathBuf> = if write_to_disk {
        let dir: PathBuf = out.unwrap_or_else(|| {
            let stem: &str = input
                .file_stem()
                .and_then(|s: &std::ffi::OsStr| s.to_str())
                .unwrap_or("chain");
            PathBuf::from(format!("./out/{stem}-chain"))
        });
        std::fs::create_dir_all(&dir)
            .map_err(|e| miette::miette!("DR-CLI-0293: cannot create chain out dir: {e}"))?;
        Some(dir)
    } else {
        None
    };
    let config: ChainConfig = options.chain_config(stream_out_dir.is_some());
    let driver: ChainDriver<'_, ChainPassRunner<'_>> = ChainDriver::new(&registry, &runner, config);
    let mut streamed: Vec<String> = Vec::new();
    let mut seen_paths: BTreeSet<PathBuf> = BTreeSet::new();
    let seed_for_scan: Vec<u8> = bytes.clone();
    let mut stream_error: Option<miette::Report> = None;
    let plan: ChainPlan = {
        let stream_dir: Option<&Path> = stream_out_dir.as_deref();
        let mut sink = |art: &disrobe_core::chain::ExtractedArtifact| {
            if stream_error.is_some() {
                return;
            }
            if let Some(dir) = stream_dir {
                match write_extracted_artifact(dir, art, &mut seen_paths) {
                    Ok(path) => streamed.push(path),
                    Err(error) => stream_error = Some(error),
                }
            }
        };
        driver.run_with_sink(bytes, &spec, Some(input.display().to_string()), &mut sink)
    };
    if let Some(error) = stream_error {
        return Err(error);
    }
    let supplemental_output: Option<SupplementalOutput> = if write_to_disk {
        let flutter_output: Option<SupplementalOutput> = prepare_flutter_symbol_export(
            &plan,
            &seed_for_scan,
            &input,
            engine_symbol_map,
            backend_export,
        )?;
        if flutter_output.is_some() {
            flutter_output
        } else {
            prepare_dalvik_symbol_export(&plan, &seed_for_scan, &input, backend_export)?
        }
    } else {
        None
    };
    progress.finish(&format!("{} pass(es) ran", progress.steps()));
    let evidence: ChainEvidence = chain_evidence(&plan).map_err(metadata_value_report)?;
    let anti: AntiAnalysisReport = scan_anti_analysis(
        &seed_for_scan,
        Some(&input.display().to_string()),
        &evidence,
    );
    let delphi: Option<disrobe_pass_native::delphi::DelphiReport> =
        delphi_report_for(&seed_for_scan);
    let doc: ChainDocument = ChainDocument::from_plan(
        &plan,
        &spec,
        &spec_raw,
        env!("CARGO_PKG_VERSION"),
        Some(input.display().to_string()),
    )
    .map_err(metadata_value_report)?;
    let report: ChainRecoveryReport = ChainRecoveryReport::from_plan(
        &plan,
        env!("CARGO_PKG_VERSION"),
        Some(input.display().to_string()),
    );
    let py_guidance: Option<String> = maybe_py_deob_guidance(&spec_raw, &plan, &seed_for_scan);
    let display_anti: AntiAnalysisReport = redacted_copy(&anti, redact)?;
    let display_delphi: Option<disrobe_pass_native::delphi::DelphiReport> = delphi
        .as_ref()
        .map(|report: &disrobe_pass_native::delphi::DelphiReport| redacted_copy(report, redact))
        .transpose()?;
    let display_guidance: Option<String> = py_guidance
        .map(|guidance: String| redacted_text(guidance, redact))
        .transpose()?;
    if !write_to_disk {
        let rendered = || {
            println!("chain.json (dry-run; nothing written to disk)");
            render_anti_analysis(&display_anti);
            render_delphi(display_delphi.as_ref());
            if let Some(guidance) = display_guidance.as_ref() {
                eprintln!();
                eprint!("{guidance}");
            }
        };
        if redact {
            let value: serde_json::Value = serialized_value(&doc, true)?;
            emit(fmt, &value, rendered)?;
        } else {
            emit(fmt, &doc, rendered)?;
        }
        if emit_recovery && fmt.is_machine() {
            if redact {
                let value: serde_json::Value = serialized_value(&report, true)?;
                emit(fmt, &value, || {})?;
            } else {
                emit(fmt, &report, || {})?;
            }
        }
        return Ok(());
    }
    let out_dir: PathBuf = stream_out_dir.unwrap_or_else(|| {
        let stem: &str = input
            .file_stem()
            .and_then(|s: &std::ffi::OsStr| s.to_str())
            .unwrap_or("chain");
        PathBuf::from(format!("./out/{stem}-chain"))
    });
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-CLI-0293: cannot create chain out dir: {e}"))?;
    let chain_path: PathBuf = out_dir.join("chain.json");
    let chain_bytes: Vec<u8> = serialized_report(&doc, redact)
        .map_err(|e| miette::miette!("DR-CLI-0294: chain.json serialize: {e}"))?;
    std::fs::write(&chain_path, &chain_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0295: cannot write chain.json: {e}"))?;
    let recovery_path: PathBuf = out_dir.join("recovery.json");
    let recovery_bytes: Vec<u8> = serialized_report(&report, redact)
        .map_err(|e| miette::miette!("DR-CLI-0305: recovery.json serialize: {e}"))?;
    std::fs::write(&recovery_path, &recovery_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0306: cannot write recovery.json: {e}"))?;
    let recovery_path_str: String = redacted_text(recovery_path.display().to_string(), redact)?;
    let anti_path: PathBuf = out_dir.join("anti-analysis.json");
    let anti_bytes: Vec<u8> = serialized_report(&anti, redact)
        .map_err(|e| miette::miette!("DR-CLI-0307: anti-analysis.json serialize: {e}"))?;
    std::fs::write(&anti_path, &anti_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0308: cannot write anti-analysis.json: {e}"))?;
    let anti_path_str: String = redacted_text(anti_path.display().to_string(), redact)?;
    let delphi_path_str: Option<String> = match delphi.as_ref() {
        None => None,
        Some(report) => {
            let delphi_path: PathBuf = out_dir.join("delphi.json");
            let delphi_bytes: Vec<u8> = serialized_report(report, redact)
                .map_err(|e| miette::miette!("DR-CLI-0314: delphi.json serialize: {e}"))?;
            std::fs::write(&delphi_path, &delphi_bytes)
                .map_err(|e| miette::miette!("DR-CLI-0315: cannot write delphi.json: {e}"))?;
            Some(redacted_text(delphi_path.display().to_string(), redact)?)
        }
    };
    let mut extracted_written: Vec<String> = streamed;
    extracted_written.extend(write_extracted_children(&out_dir, &plan)?);
    if redact {
        extracted_written = extracted_written
            .into_iter()
            .map(|path: String| redacted_text(path, true))
            .collect::<miette::Result<Vec<String>>>()?;
    }
    let extracted_dir_str: String =
        redacted_text(out_dir.join("extracted").display().to_string(), redact)?;
    let recovered: bool = !extracted_written.is_empty() || recovered_anything(&plan);
    let advisory: Option<String> = if recovered {
        None
    } else {
        Some(redacted_text(identify_advisory(&plan), redact)?)
    };
    let stage_summary: Option<String> = if capture_stages {
        let mirror: StageMirror = write_stage_mirror(&out_dir, &plan)?;
        Some(redacted_text(
            format!(
                "{} stage artifact(s) mirrored as out/NN-<pass>/ step dir(s) under {}; {} terminal stage(s) linked under {}",
                mirror.steps.len(),
                out_dir.display(),
                mirror.finals.len(),
                out_dir.join("final").display()
            ),
            redact,
        )?)
    } else {
        None
    };
    super::report::write_single_forensic(&doc, &report, &out_dir, redact)?;
    let forensic_path: PathBuf = out_dir.join("report.json");
    let forensic_sarif_path: PathBuf = out_dir.join("report.sarif");
    let forensic_path_str: String = redacted_text(forensic_path.display().to_string(), redact)?;
    let forensic_sarif_path_str: String =
        redacted_text(forensic_sarif_path.display().to_string(), redact)?;
    let chain_path_str: String = redacted_text(chain_path.display().to_string(), redact)?;
    let supplemental_label: Option<&str> =
        supplemental_output
            .as_ref()
            .map(|output: &SupplementalOutput| {
                if output.relative_path().starts_with("exports/flutter") {
                    "Flutter"
                } else {
                    "Dalvik"
                }
            });
    let supplemental_path_str: Option<String> = supplemental_output
        .as_ref()
        .map(|output: &SupplementalOutput| write_supplemental_output(&out_dir, output))
        .transpose()?
        .map(|path: PathBuf| redacted_text(path.display().to_string(), redact))
        .transpose()?;
    let rendered = || {
        println!("chain.json written: {chain_path_str}");
        println!("recovery.json written: {recovery_path_str}");
        println!("anti-analysis.json written: {anti_path_str}");
        println!("report.json written: {forensic_path_str}");
        println!("report.sarif written: {forensic_sarif_path_str}");
        if let (Some(label), Some(path)) = (supplemental_label, supplemental_path_str.as_ref()) {
            println!("{label} symbol export written: {path}");
        }
        if let Some(path) = delphi_path_str.as_ref() {
            println!("delphi.json written: {path}");
        }
        if !extracted_written.is_empty() {
            println!(
                "extracted {} file(s) to {extracted_dir_str}",
                extracted_written.len()
            );
            for path in extracted_written.iter().take(20) {
                println!("  - {path}");
            }
            if extracted_written.len() > 20 {
                println!("  ... and {} more", extracted_written.len() - 20);
            }
        }
        if let Some(summary) = stage_summary.as_ref() {
            println!("{summary}");
        }
        render_anti_analysis(&display_anti);
        render_delphi(display_delphi.as_ref());
        if let Some(guidance) = display_guidance.as_ref() {
            eprintln!();
            eprint!("{guidance}");
        }
        if let Some(note) = advisory.as_ref() {
            eprintln!();
            eprintln!("{note}");
        }
    };
    if redact {
        let value: serde_json::Value = serialized_value(&doc, true)?;
        emit(fmt, &value, rendered)?;
    } else {
        emit(fmt, &doc, rendered)?;
    }
    if emit_recovery && fmt.is_machine() {
        if redact {
            let value: serde_json::Value = serialized_value(&report, true)?;
            emit(fmt, &value, || {})?;
        } else {
            emit(fmt, &report, || {})?;
        }
    }
    Ok(())
}

fn maybe_py_deob_guidance(spec_raw: &str, plan: &ChainPlan, bytes: &[u8]) -> Option<String> {
    let is_auto: bool = spec_raw.starts_with("auto:") || spec_raw.starts_with("?:");
    if !is_auto {
        return None;
    }
    let a_pass_ran: bool = plan.nodes.iter().any(|n| n.pass_id.is_some());
    if a_pass_ran {
        return None;
    }
    if !disrobe_pass_py_deob::looks_obfuscated(bytes) {
        return None;
    }
    let outcome: disrobe_pass_py_deob::AutoDeobOutcome =
        disrobe_pass_py_deob::auto_deobfuscate(bytes, None);
    match outcome.kind {
        disrobe_pass_py_deob::RouteKind::Unidentified => outcome.guidance,
        _ => None,
    }
}

fn sanitize_extract_path(rel: &str) -> PathBuf {
    let mut safe: PathBuf = PathBuf::new();
    for comp in Path::new(rel).components() {
        if let Component::Normal(part) = comp {
            safe.push(part);
        }
    }
    if safe.as_os_str().is_empty() {
        safe.push("unnamed.bin");
    }
    safe
}

fn write_extracted_artifact(
    out_dir: &Path,
    art: &disrobe_core::chain::ExtractedArtifact,
    seen: &mut BTreeSet<PathBuf>,
) -> miette::Result<String> {
    let root: PathBuf = out_dir.join("extracted");
    let rel: PathBuf = sanitize_extract_path(&art.relative_path);
    let mut dest: PathBuf = root.join(&rel);
    if !seen.insert(dest.clone()) {
        let mut attempt: usize = 0;
        loop {
            let node_dir: String = if attempt == 0 {
                format!("node{}", art.node_id)
            } else {
                format!("node{}-{attempt}", art.node_id)
            };
            dest = root.join(node_dir).join(&rel);
            if seen.insert(dest.clone()) {
                break;
            }
            attempt = attempt.saturating_add(1);
        }
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0309: cannot create extract dir: {e}"))?;
    }
    std::fs::write(&dest, &art.bytes)
        .map_err(|e| miette::miette!("DR-CLI-0310: cannot write extracted file: {e}"))?;
    Ok(dest.display().to_string())
}

fn write_extracted_children(out_dir: &Path, plan: &ChainPlan) -> miette::Result<Vec<String>> {
    if plan.extracted.is_empty() {
        return Ok(Vec::new());
    }
    let mut written: Vec<String> = Vec::new();
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    for art in &plan.extracted {
        written.push(write_extracted_artifact(out_dir, art, &mut seen)?);
    }
    Ok(written)
}

fn recovered_anything(plan: &ChainPlan) -> bool {
    !plan.extracted.is_empty()
        || plan
            .nodes
            .iter()
            .any(|n: &Node| matches!(n.verdict, Verdict::Complete { .. }))
}

fn advisory_for_group(group: &str, tag: &str) -> String {
    if crate::subcommand_names().contains(group) {
        format!(
            "note: auto recovered no files from this input. It looks like `{tag}`. Confirm with `disrobe detect <file>`, then run the dedicated command (see `disrobe {group} --help`)."
        )
    } else {
        format!(
            "note: auto recovered no files from this input. It looks like `{tag}`, which auto reaches through the `{group}` pass and which no dedicated subcommand exposes. Confirm with `disrobe detect <file>`, and see `disrobe catalog` for what this build covers."
        )
    }
}

fn identify_advisory(plan: &ChainPlan) -> String {
    let best: Option<&DetectorPick> = plan
        .nodes
        .iter()
        .flat_map(|n: &Node| n.picks.iter())
        .max_by(|a: &&DetectorPick, b: &&DetectorPick| {
            a.verdict.confidence.total_cmp(&b.verdict.confidence)
        });
    best.map_or_else(
        || "note: auto recovered no files and could not identify the format. Run `disrobe detect <file>` to identify it, then the matching subcommand.".to_string(),
        |pick: &DetectorPick| {
            let group: &str = pick.verdict.pass_id.split('.').next().unwrap_or("detect");
            advisory_for_group(group, pick.verdict.format_tag)
        },
    )
}

#[derive(Debug)]
pub(crate) struct ChainOutcome {
    pub(crate) doc: ChainDocument,
    pub(crate) report: ChainRecoveryReport,
    pub(crate) anti: AntiAnalysisReport,
    pub(crate) supplemental_outputs: Vec<String>,
}

pub(crate) fn run_chain_to_dir(
    input_label: &str,
    bytes: Vec<u8>,
    out_dir: &Path,
    chain_arg: &str,
    redact: bool,
    capture_stages: bool,
    backend_export: Option<BackendExportTarget>,
    i_have_authorization: bool,
) -> miette::Result<ChainOutcome> {
    let spec: ChainSpec = ChainSpec::parse(chain_arg)
        .map_err(|e| miette::miette!("DR-CLI-0291: --chain parse error: {e}"))?;
    let registry: PassRegistry = build_registry();
    validate_explicit_passes(&spec, &registry)?;
    let progress: ChainProgress = ChainProgress::noop();
    let runner: ChainPassRunner<'_> = ChainPassRunner::new(&progress);
    let config: ChainConfig = ChainRunOptions {
        write_to_disk: true,
        redact,
        capture_stages,
        emit_recovery: false,
        backend_export,
        engine_symbol_map: None,
        i_have_authorization,
    }
    .chain_config(false);
    let driver: ChainDriver<'_, ChainPassRunner<'_>> = ChainDriver::new(&registry, &runner, config);
    let seed_for_scan: Vec<u8> = bytes.clone();
    let plan: ChainPlan = driver.run(bytes, &spec, Some(input_label.to_string()));
    let flutter_output: Option<SupplementalOutput> = prepare_flutter_symbol_export(
        &plan,
        &seed_for_scan,
        Path::new(input_label),
        None,
        backend_export,
    )?;
    let supplemental_output: Option<SupplementalOutput> = if flutter_output.is_some() {
        flutter_output
    } else {
        prepare_dalvik_symbol_export(
            &plan,
            &seed_for_scan,
            Path::new(input_label),
            backend_export,
        )?
    };
    let evidence: ChainEvidence = chain_evidence(&plan).map_err(metadata_value_report)?;
    let anti: AntiAnalysisReport = scan_anti_analysis(&seed_for_scan, Some(input_label), &evidence);
    let doc: ChainDocument = ChainDocument::from_plan(
        &plan,
        &spec,
        chain_arg,
        env!("CARGO_PKG_VERSION"),
        Some(input_label.to_string()),
    )
    .map_err(metadata_value_report)?;
    let report: ChainRecoveryReport = ChainRecoveryReport::from_plan(
        &plan,
        env!("CARGO_PKG_VERSION"),
        Some(input_label.to_string()),
    );
    std::fs::create_dir_all(out_dir)
        .map_err(|e| miette::miette!("DR-CLI-0293: cannot create chain out dir: {e}"))?;
    let chain_bytes: Vec<u8> = serialized_report(&doc, redact)
        .map_err(|e| miette::miette!("DR-CLI-0294: chain.json serialize: {e}"))?;
    std::fs::write(out_dir.join("chain.json"), &chain_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0295: cannot write chain.json: {e}"))?;
    let recovery_bytes: Vec<u8> = serialized_report(&report, redact)
        .map_err(|e| miette::miette!("DR-CLI-0305: recovery.json serialize: {e}"))?;
    std::fs::write(out_dir.join("recovery.json"), &recovery_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0306: cannot write recovery.json: {e}"))?;
    let anti_bytes: Vec<u8> = serialized_report(&anti, redact)
        .map_err(|e| miette::miette!("DR-CLI-0307: anti-analysis.json serialize: {e}"))?;
    std::fs::write(out_dir.join("anti-analysis.json"), &anti_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0308: cannot write anti-analysis.json: {e}"))?;
    let _: Vec<String> = write_extracted_children(out_dir, &plan)?;
    if capture_stages {
        let _: StageMirror = write_stage_mirror(out_dir, &plan)?;
    }
    super::report::write_single_forensic(&doc, &report, out_dir, redact)?;
    let supplemental_outputs: Vec<String> = supplemental_output
        .as_ref()
        .map(|output: &SupplementalOutput| write_supplemental_output(out_dir, output))
        .transpose()?
        .into_iter()
        .map(|path: PathBuf| path.display().to_string())
        .collect();
    Ok(ChainOutcome {
        doc,
        report,
        anti,
        supplemental_outputs,
    })
}

pub(crate) fn serialized_value<T: serde::Serialize>(
    value: &T,
    redact: bool,
) -> miette::Result<serde_json::Value> {
    let mut serialized: serde_json::Value =
        serde_json::to_value(value).map_err(|error: serde_json::Error| {
            miette::miette!("DR-CLI-0362: report serialize: {error}")
        })?;
    if redact {
        Redactor::new()
            .redact_json_value(&mut serialized)
            .map_err(|error| miette::miette!("DR-CLI-0363: report redaction: {error}"))?;
    }
    Ok(serialized)
}

pub(crate) fn redacted_copy<T>(value: &T, redact: bool) -> miette::Result<T>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    serde_json::from_value(serialized_value(value, redact)?).map_err(|error: serde_json::Error| {
        miette::miette!("DR-CLI-0364: redacted report: {error}")
    })
}

pub(crate) fn redacted_text(value: String, redact: bool) -> miette::Result<String> {
    if !redact {
        return Ok(value);
    }
    Redactor::new()
        .redact_text(&value)
        .map_err(|error| miette::miette!("DR-CLI-0365: rendered text redaction: {error}"))
}

pub(crate) fn serialized_report<T: serde::Serialize>(
    value: &T,
    redact: bool,
) -> miette::Result<Vec<u8>> {
    if !redact {
        return serde_json::to_vec_pretty(value)
            .map_err(|error: serde_json::Error| miette::miette!("{error}"));
    }
    serde_json::to_vec_pretty(&serialized_value(value, true)?)
        .map_err(|error: serde_json::Error| miette::miette!("{error}"))
}

fn stage_slug(pass_id: Option<&str>) -> String {
    let raw: &str = pass_id.unwrap_or("input");
    raw.chars()
        .map(|c: char| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

#[derive(Debug)]
struct StageMirror {
    steps: Vec<String>,
    finals: Vec<String>,
}

fn write_stage_mirror(out_dir: &Path, plan: &ChainPlan) -> miette::Result<StageMirror> {
    let final_dir: PathBuf = out_dir.join("final");
    let mut steps: Vec<String> = Vec::new();
    let mut finals: Vec<String> = Vec::new();
    let mut ordinal: u32 = 0;
    for node in &plan.nodes {
        let Some(stage_bytes): Option<&Vec<u8>> = node.output_bytes.as_ref() else {
            continue;
        };
        let Some(pass_id): Option<&str> = node.pass_id.as_deref() else {
            continue;
        };
        ordinal += 1;
        let slug: String = stage_slug(Some(pass_id));
        let stage_dir: PathBuf = out_dir.join(format!("{ordinal:02}-{slug}"));
        std::fs::create_dir_all(&stage_dir).map_err(|e| {
            miette::miette!(
                "DR-CLI-0301: cannot create stage dir {}: {e}",
                stage_dir.display()
            )
        })?;
        let stage_path: PathBuf = stage_dir.join("output.bin");
        std::fs::write(&stage_path, stage_bytes).map_err(|e| {
            miette::miette!(
                "DR-CLI-0302: cannot write stage output {}: {e}",
                stage_path.display()
            )
        })?;
        steps.push(stage_path.display().to_string());

        let is_terminal: bool = !plan
            .nodes
            .iter()
            .any(|other: &Node| other.parent_id == Some(node.id));
        if is_terminal {
            let final_target: PathBuf = final_dir.join(format!("{ordinal:02}-{slug}"));
            let kind: LinkKind = path_ops::link_final(&stage_dir, &final_target)?;
            finals.push(format!("{} ({})", final_target.display(), kind.label()));
        }
    }
    Ok(StageMirror { steps, finals })
}

fn validate_explicit_passes(spec: &ChainSpec, registry: &PassRegistry) -> miette::Result<()> {
    let tokens: &[PassToken] = match spec {
        ChainSpec::Explicit { passes } => passes.as_slice(),
        ChainSpec::PrefixThenAuto { prefix, .. } => prefix.as_slice(),
        ChainSpec::Auto { .. } | ChainSpec::PlanOnly { .. } => return Ok(()),
    };
    let mut unknown: Vec<&str> = Vec::new();
    for tok in tokens {
        if registry.get(tok.pass_id.as_str()).is_none() {
            unknown.push(tok.pass_id.as_str());
        }
    }
    if unknown.is_empty() {
        return Ok(());
    }
    let mut known: Vec<&str> = registry
        .iter_passes()
        .map(disrobe_core::chain::Pass::id)
        .collect();
    known.sort_unstable();
    Err(miette::miette!(
        "DR-CLI-0298: unknown pass id(s) {unknown:?}; known: {known:?}"
    ))
}

fn combine_chain_and_pin_owned(chain_arg: String, pin_arg: &str) -> miette::Result<String> {
    if pin_arg.is_empty() {
        return Ok(chain_arg);
    }
    if chain_arg.starts_with("auto") {
        Ok(format!("{pin_arg},*"))
    } else if chain_arg == "?" || chain_arg.starts_with("?:") {
        Err(miette::miette!(
            "DR-CLI-0296: --chain-pin cannot combine with `?` (plan-only)"
        ))
    } else {
        Err(miette::miette!(
            "DR-CLI-0297: --chain-pin requires --chain auto[:N]; got {chain_arg:?}"
        ))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use disrobe_core::chain::detection::{DetectContext, DetectVerdict};
    use disrobe_core::chain::{Detector, Pass};
    use disrobe_core::error::Result as CoreResult;
    use disrobe_core::pass::PassId;
    use std::io::Write as _;
    use std::sync::atomic::{AtomicBool, Ordering};

    static OBSERVED_AUTHORIZATION: AtomicBool = AtomicBool::new(false);

    #[test]
    fn cli_chain_registry_matches_the_shared_assembly() {
        let ids: Vec<PassId> = build_registry().iter_passes().map(Pass::id).collect();
        assert_eq!(
            ids,
            disrobe_passes::expected_pass_ids(),
            "the cli chain registry diverged from the shared assembly; a hand-edited registry here \
             would drop or add a pass relative to disrobe-passes"
        );
        assert_eq!(
            ids,
            disrobe_passes::registered_pass_ids(),
            "the cli chain registry diverged from what the shared assembly actually constructs"
        );
    }

    #[test]
    fn pass_meta_support_matches_each_catalog_ceiling() {
        use disrobe_core::chain::SupportQuality;

        let registry: PassRegistry = build_registry();
        for catalog in crate::cli::catalog_registry::registry() {
            let pass_id: &str = catalog.pass_id();
            let Some(best): Option<SupportQuality> = catalog
                .catalog()
                .iter()
                .map(|entry: &&'static dyn disrobe_core::chain::CatalogEntry| {
                    entry.support_quality()
                })
                .min()
            else {
                continue;
            };
            let pass: &'static dyn Pass = registry
                .get(pass_id)
                .expect("catalogued pass must be registered");
            assert_eq!(
                pass.meta().support,
                best,
                "pass {pass_id} meta support must equal the strongest tier in its catalog"
            );
        }
    }

    #[derive(Debug)]
    struct AuthorizationProbeDetector;

    impl Detector for AuthorizationProbeDetector {
        fn id(&self) -> PassId {
            "test.authorization-probe"
        }

        fn detect(&self, _ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
            None
        }
    }

    static AUTHORIZATION_PROBE_DETECTOR: AuthorizationProbeDetector = AuthorizationProbeDetector;

    #[derive(Debug)]
    struct AuthorizationProbePass;

    impl Pass for AuthorizationProbePass {
        fn id(&self) -> PassId {
            "test.authorization-probe"
        }

        fn detector(&self) -> &'static dyn Detector {
            &AUTHORIZATION_PROBE_DETECTOR
        }

        fn output_kind(&self, _output: &Artifact) -> OutputKind {
            OutputKind::Bytes {
                format_tag: "test.probe",
                family: "test",
            }
        }

        fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
            Ok(Artifact::new(
                Rung::Raw,
                artifact.envelope.clone(),
                artifact.root_hash,
            ))
        }

        fn run_with_context(
            &self,
            artifact: &Artifact,
            context: PassContext<'_>,
        ) -> CoreResult<Artifact> {
            OBSERVED_AUTHORIZATION.store(context.i_have_authorization, Ordering::SeqCst);
            self.run(artifact)
        }
    }

    static AUTHORIZATION_PROBE_PASS: AuthorizationProbePass = AuthorizationProbePass;

    fn options_asserting(i_have_authorization: bool) -> ChainRunOptions {
        ChainRunOptions {
            write_to_disk: true,
            redact: false,
            capture_stages: false,
            emit_recovery: false,
            backend_export: None,
            engine_symbol_map: None,
            i_have_authorization,
        }
    }

    fn authorization_seen_by_pass(i_have_authorization: bool) -> bool {
        OBSERVED_AUTHORIZATION.store(!i_have_authorization, Ordering::SeqCst);
        let progress: ChainProgress = ChainProgress::noop();
        let runner: ChainPassRunner<'_> = ChainPassRunner::new(&progress);
        let pick: DetectorPick = DetectorPick {
            pass: &AUTHORIZATION_PROBE_PASS,
            verdict: DetectVerdict::new(
                "test.authorization-probe",
                "test.probe",
                "test",
                1.0,
                1,
                Vec::new(),
                String::new(),
            ),
        };
        let config: ChainConfig = options_asserting(i_have_authorization).chain_config(false);
        let _outcome: PassRunOutcome = runner
            .run(&pick, b"probe".to_vec(), &config, None)
            .expect("probe pass runs");
        OBSERVED_AUTHORIZATION.load(Ordering::SeqCst)
    }

    #[test]
    fn chain_config_leaves_authorization_unasserted_by_default() {
        let config: ChainConfig = options_asserting(false).chain_config(false);
        assert!(!config.i_have_authorization);
    }

    #[test]
    fn chain_config_carries_an_asserted_authorization() {
        let config: ChainConfig = options_asserting(true).chain_config(false);
        assert!(config.i_have_authorization);
    }

    #[test]
    fn a_pass_observes_the_operator_authorization_it_was_given() {
        assert!(
            !authorization_seen_by_pass(false),
            "a pass must not see an assertion the operator never made"
        );
        assert!(
            authorization_seen_by_pass(true),
            "a pass must see the assertion the operator made"
        );
    }

    #[test]
    fn pin_combines_with_auto_default() {
        let s: String = combine_chain_and_pin_owned("auto".to_string(), "pyarmor").unwrap();
        assert_eq!(s, "pyarmor,*");
    }

    #[test]
    fn pin_combines_with_auto_cap() {
        let s: String = combine_chain_and_pin_owned("auto:16".to_string(), "pyarmor").unwrap();
        assert_eq!(s, "pyarmor,*");
    }

    #[test]
    fn pin_rejects_with_question_mark() {
        assert!(combine_chain_and_pin_owned("?".to_string(), "pyarmor").is_err());
    }

    #[test]
    fn pin_rejects_with_explicit_chain() {
        assert!(combine_chain_and_pin_owned("a,b,c".to_string(), "pyarmor").is_err());
    }

    #[test]
    fn validate_explicit_passes_accepts_known_ids() {
        let r: PassRegistry = build_registry();
        let s: ChainSpec = ChainSpec::parse("py.deob").unwrap();
        assert!(validate_explicit_passes(&s, &r).is_ok());
    }

    #[test]
    fn validate_explicit_passes_rejects_unknown_id() {
        let r: PassRegistry = build_registry();
        let s: ChainSpec = ChainSpec::parse("definitely.no-such-pass").unwrap();
        let err: miette::Report = validate_explicit_passes(&s, &r).unwrap_err();
        let msg: String = format!("{err}");
        assert!(
            msg.contains("DR-CLI-0298") && msg.contains("definitely.no-such-pass"),
            "got: {msg}"
        );
    }

    #[test]
    fn validate_explicit_passes_rejects_unknown_in_prefix_then_auto() {
        let r: PassRegistry = build_registry();
        let s: ChainSpec = ChainSpec::parse("definitely.bogus,*").unwrap();
        assert!(validate_explicit_passes(&s, &r).is_err());
    }

    #[test]
    fn validate_explicit_passes_skips_auto() {
        let r: PassRegistry = build_registry();
        let s: ChainSpec = ChainSpec::parse("auto:8").unwrap();
        assert!(validate_explicit_passes(&s, &r).is_ok());
    }

    use disrobe_core::scratch::ScratchDir;

    fn mirror_tmp(stem: &str) -> ScratchDir {
        let purpose: String = format!("disrobe-mirror-{stem}");
        ScratchDir::create(&purpose).expect("create scratch directory")
    }

    fn partial_arc_for_auto() -> Vec<u8> {
        const ARC_METHODS: &[u8] = include_bytes!("../../../../corpus/binfmt/arc/methods.arc");
        let parsed: disrobe_binfmt::containers::ArcArchive =
            disrobe_binfmt::containers::parse_arc(ARC_METHODS).expect("parse ARC method fixture");
        let entry: &disrobe_binfmt::containers::ArcEntry = parsed
            .entries
            .iter()
            .find(|entry: &&disrobe_binfmt::containers::ArcEntry| entry.method != 1)
            .expect("ARC member with an original-size field");
        let original_size_offset: usize = entry.data_offset - 4;
        let mut archive: Vec<u8> = ARC_METHODS.to_vec();
        archive[original_size_offset..original_size_offset + 4]
            .copy_from_slice(&(512 * 1024 * 1024 + 1_u32).to_le_bytes());
        archive
    }

    fn partial_zip_for_auto() -> Vec<u8> {
        let cursor: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(Vec::new());
        let mut writer: zip::ZipWriter<std::io::Cursor<Vec<u8>>> = zip::ZipWriter::new(cursor);
        let options: zip::write::FileOptions<()> = zip::write::FileOptions::default();
        for (name, bytes) in [
            ("first.bin", b"first".as_slice()),
            (".disrobe-user.bin", b"user-controlled".as_slice()),
            ("../refused.bin", b"refused".as_slice()),
            ("last.bin", b"last".as_slice()),
        ] {
            writer.start_file(name, options).expect("start ZIP member");
            writer.write_all(bytes).expect("write ZIP member");
        }
        writer.finish().expect("finish ZIP").into_inner()
    }

    fn duplicate_zip_for_auto() -> Vec<u8> {
        let cursor: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(Vec::new());
        let mut writer: zip::ZipWriter<std::io::Cursor<Vec<u8>>> = zip::ZipWriter::new(cursor);
        let options: zip::write::FileOptions<()> = zip::write::FileOptions::default();
        for (name, bytes) in [
            ("duplicate.bin", b"first".as_slice()),
            ("DUPLICATE.bin", b"second".as_slice()),
            ("last.bin", b"last".as_slice()),
        ] {
            writer.start_file(name, options).expect("start ZIP member");
            writer.write_all(bytes).expect("write ZIP member");
        }
        writer.finish().expect("finish ZIP").into_inner()
    }

    fn refusal_overflow_zip_for_auto() -> Vec<u8> {
        let cursor: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(Vec::new());
        let mut writer: zip::ZipWriter<std::io::Cursor<Vec<u8>>> = zip::ZipWriter::new(cursor);
        let options: zip::write::FileOptions<()> = zip::write::FileOptions::default();
        writer
            .start_file("retained.bin", options)
            .expect("start retained ZIP member");
        writer
            .write_all(b"retained")
            .expect("write retained ZIP member");
        for index in 0..1_500_u16 {
            let name: String = format!("../refused-{index:04}-{}.bin", "x".repeat(48));
            writer
                .start_file(name, options)
                .expect("start refused ZIP member");
            writer
                .write_all(b"refused")
                .expect("write refused ZIP member");
        }
        writer.finish().expect("finish ZIP").into_inner()
    }

    fn partial_tar_for_auto() -> Vec<u8> {
        let mut builder: tar::Builder<Vec<u8>> = tar::Builder::new(Vec::new());
        for (name, bytes) in [
            ("first.bin", b"first".as_slice()),
            ("../refused.bin", b"refused".as_slice()),
            ("last.bin", b"last".as_slice()),
        ] {
            let mut header: tar::Header = tar::Header::new_gnu();
            header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
            header.set_mode(0o644);
            header.set_size(u64::try_from(bytes.len()).expect("TAR member size"));
            header.set_cksum();
            builder.append(&header, bytes).expect("append TAR member");
        }
        builder.into_inner().expect("finish TAR")
    }

    fn assert_real_auto_container_parity(
        label: &str,
        extension: &str,
        kind: disrobe_binfmt::container::ContainerKind,
        archive: Vec<u8>,
        partial: bool,
    ) {
        let scratch: ScratchDir = mirror_tmp(&format!("container-parity-{label}"));
        let input: PathBuf = scratch.path().join(format!("input.{extension}"));
        let out: PathBuf = scratch.path().join("out");
        let direct_out: PathBuf = scratch.path().join("direct");
        let direct: disrobe_binfmt::ExtractionResult =
            disrobe_binfmt::extract_to(kind, &archive, &direct_out)
                .expect("direct matrix extraction");
        let expected_members: Vec<(String, [u8; 32])> = direct
            .entries
            .iter()
            .filter_map(|entry: &disrobe_binfmt::ExtractedEntry| {
                if entry.origin == disrobe_binfmt::ExtractedEntryOrigin::GeneratedSidecar {
                    return None;
                }
                let path: &Path = entry.disk_path.as_deref()?;
                let bytes: Vec<u8> = std::fs::read(path).expect("read direct member");
                Some((entry.name.clone(), blake3_hash(&bytes)))
            })
            .collect();
        assert!(!expected_members.is_empty(), "{label} materialized members");
        if partial {
            assert!(!direct.integrity_violations.is_empty(), "{label} refusals");
        }
        std::fs::write(&input, archive).expect("write container input");
        run_with_disk(
            input,
            Some(out.clone()),
            "auto:1".to_owned(),
            None,
            OutputFormat::Json,
            ChainRunOptions {
                write_to_disk: true,
                redact: false,
                capture_stages: false,
                emit_recovery: false,
                backend_export: None,
                engine_symbol_map: None,
                i_have_authorization: false,
            },
        )
        .expect("run matrix auto");
        let chain: serde_json::Value = serde_json::from_slice(
            &std::fs::read(out.join("chain.json")).expect("read chain document"),
        )
        .expect("parse chain document");
        let nodes: &[serde_json::Value] = chain["nodes"].as_array().expect("nodes");
        let node: &serde_json::Value = nodes
            .iter()
            .find(|node: &&serde_json::Value| {
                node["pass"] == "binfmt.container" && node["output_kind"]["kind"] == "mixed"
            })
            .expect("matrix container mixed node");
        let refusals: Vec<String> = node["metadata"][keys::CONTAINER_REFUSALS]
            .as_str()
            .map(|encoded: &str| serde_json::from_str(encoded).expect("refusal list"))
            .unwrap_or_default();
        assert_eq!(refusals, direct.integrity_violations, "{label} refusals");
        let children: &[serde_json::Value] = node["output_kind"]["children"]
            .as_array()
            .expect("mixed children");
        let actual_members: Vec<(String, [u8; 32])> = children
            .iter()
            .map(|child: &serde_json::Value| {
                let name: String = child["relative_path"]
                    .as_str()
                    .expect("child path")
                    .to_owned();
                let bytes: Vec<u8> = std::fs::read(out.join("extracted").join(&name))
                    .expect("read matrix auto member");
                (name, blake3_hash(&bytes))
            })
            .collect();
        assert_eq!(actual_members, expected_members, "{label} members");
    }

    #[test]
    fn real_auto_container_matrix_matches_direct_order_bytes_and_refusals() {
        use disrobe_binfmt::container::ContainerKind;
        for (label, extension, kind, archive, partial) in [
            (
                "arc",
                "arc",
                ContainerKind::Arc,
                partial_arc_for_auto(),
                true,
            ),
            (
                "rar",
                "rar",
                ContainerKind::Rar,
                include_bytes!("../../../../corpus/binfmt/rar/store-rar4.rar").to_vec(),
                false,
            ),
            (
                "arj",
                "arj",
                ContainerKind::Arj,
                include_bytes!("../../../../corpus/binfmt/arj/method0.arj").to_vec(),
                false,
            ),
            (
                "lzh",
                "pma",
                ContainerKind::Lzh,
                include_bytes!("../../../../corpus/binfmt/lzh/pmarc/generated_pm1.pma").to_vec(),
                true,
            ),
            (
                "lzh-pm2",
                "pma",
                ContainerKind::Lzh,
                include_bytes!("../../../../corpus/binfmt/lzh/pmarc/pmarc2_comment.pma").to_vec(),
                false,
            ),
            (
                "inno",
                "exe",
                ContainerKind::InnoSetup,
                include_bytes!(
                    "../../../disrobe-binfmt/tests/fixtures/innosetup/innosetup-6.3.3.exe"
                )
                .to_vec(),
                false,
            ),
            (
                "installshield",
                "cab",
                ContainerKind::InstallShield,
                include_bytes!("../../../../corpus/binfmt/installshield/wireplay-user1.cab")
                    .to_vec(),
                true,
            ),
            (
                "zip",
                "zip",
                ContainerKind::Zip,
                partial_zip_for_auto(),
                true,
            ),
            (
                "zip-duplicate",
                "zip",
                ContainerKind::Zip,
                duplicate_zip_for_auto(),
                true,
            ),
            (
                "tar",
                "tar",
                ContainerKind::Tar,
                partial_tar_for_auto(),
                true,
            ),
            (
                "dotnet",
                "exe",
                ContainerKind::DotnetSingleFile,
                include_bytes!("../../../../corpus/binfmt/dotnet-single-file/probe.v6.win-x64.exe")
                    .to_vec(),
                false,
            ),
            (
                "erofs",
                "erofs",
                ContainerKind::Erofs,
                include_bytes!(
                    "../../../disrobe-binfmt/tests/fixtures/erofs/lzma-compact-mixed.erofs"
                )
                .to_vec(),
                false,
            ),
            (
                "stuffit",
                "sit",
                ContainerKind::StuffIt,
                include_bytes!(
                    "../../../disrobe-binfmt/tests/fixtures/stuffit/stuffit45-method13.sit"
                )
                .to_vec(),
                false,
            ),
            (
                "rpm",
                "rpm",
                ContainerKind::Rpm,
                include_bytes!("../../../disrobe-binfmt/tests/fixtures/rpm/hello-v4-gzip.rpm")
                    .to_vec(),
                false,
            ),
            (
                "appimage",
                "AppImage",
                ContainerKind::AppImage,
                include_bytes!(
                    "../../../../corpus/binfmt/appimage-type1/AppImageAssistant.AppImage"
                )
                .to_vec(),
                false,
            ),
            (
                "uefi",
                "fv",
                ContainerKind::UefiFv,
                include_bytes!(
                    "../../../disrobe-binfmt/tests/fixtures/uefi_fv/edk2_brotli_guided.fv"
                )
                .to_vec(),
                false,
            ),
        ] {
            assert_real_auto_container_parity(label, extension, kind, archive, partial);
        }
    }

    #[test]
    fn real_auto_bounds_refusal_metadata_without_losing_children_or_counts() {
        let scratch: ScratchDir = mirror_tmp("container-refusal-overflow");
        let input: PathBuf = scratch.path().join("input.zip");
        let out: PathBuf = scratch.path().join("out");
        std::fs::write(&input, refusal_overflow_zip_for_auto()).expect("write overflow ZIP");
        run_with_disk(
            input,
            Some(out.clone()),
            "auto:1".to_owned(),
            None,
            OutputFormat::Json,
            ChainRunOptions {
                write_to_disk: true,
                redact: false,
                capture_stages: false,
                emit_recovery: false,
                backend_export: None,
                engine_symbol_map: None,
                i_have_authorization: false,
            },
        )
        .expect("run overflow auto");
        assert_eq!(
            std::fs::read(out.join("extracted/retained.bin")).expect("read retained child"),
            b"retained"
        );
        let chain: serde_json::Value = serde_json::from_slice(
            &std::fs::read(out.join("chain.json")).expect("read overflow chain document"),
        )
        .expect("parse overflow chain document");
        let node: &serde_json::Value = chain["nodes"]
            .as_array()
            .expect("nodes")
            .iter()
            .find(|node: &&serde_json::Value| node["pass"] == "binfmt.container")
            .expect("container node");
        let metadata: &serde_json::Value = &node["metadata"];
        let retained: Vec<String> = serde_json::from_str(
            metadata[keys::CONTAINER_REFUSALS]
                .as_str()
                .expect("bounded refusal array"),
        )
        .expect("parse bounded refusal array");
        let total: usize = metadata[keys::CONTAINER_REFUSALS_TOTAL]
            .as_str()
            .expect("total refusal count")
            .parse()
            .expect("parse total refusal count");
        let omitted: usize = metadata[keys::CONTAINER_REFUSALS_OMITTED]
            .as_str()
            .expect("omitted refusal count")
            .parse()
            .expect("parse omitted refusal count");
        assert_eq!(total, 1_500);
        assert_eq!(omitted, total - retained.len());
        assert!(omitted > 0);
        assert_eq!(
            metadata[keys::CONTAINER_REFUSALS_TRUNCATED].as_str(),
            Some("true")
        );
    }

    #[test]
    fn extracted_children_written_and_traversal_neutralized() {
        let mut plan: ChainPlan = linear_plan(vec![leaf_node(0, None, "root", b"seed")]);
        plan.extracted = vec![
            disrobe_core::chain::ExtractedArtifact {
                node_id: 1,
                relative_path: "main.dll".to_string(),
                bytes: b"MZ-main".to_vec(),
            },
            disrobe_core::chain::ExtractedArtifact {
                node_id: 1,
                relative_path: "../../escape.bin".to_string(),
                bytes: b"PWNED".to_vec(),
            },
        ];
        let dir_scratch: ScratchDir = mirror_tmp("extracted");
        let dir: PathBuf = dir_scratch.path().to_path_buf();
        let written: Vec<String> = super::write_extracted_children(&dir, &plan).expect("write");
        assert_eq!(written.len(), 2);
        assert_eq!(
            std::fs::read(dir.join("extracted").join("main.dll")).expect("main.dll"),
            b"MZ-main"
        );
        assert_eq!(
            std::fs::read(dir.join("extracted").join("escape.bin")).expect("escape.bin"),
            b"PWNED",
            "traversal components must be stripped so the file stays under extracted/"
        );
    }

    #[test]
    fn extracted_children_collision_fallback_keeps_node_paths_unique() {
        let mut plan: ChainPlan = linear_plan(vec![leaf_node(0, None, "root", b"seed")]);
        plan.extracted = vec![
            disrobe_core::chain::ExtractedArtifact {
                node_id: 9,
                relative_path: "main.dll".to_string(),
                bytes: b"primary".to_vec(),
            },
            disrobe_core::chain::ExtractedArtifact {
                node_id: 8,
                relative_path: "node1/main.dll".to_string(),
                bytes: b"occupied".to_vec(),
            },
            disrobe_core::chain::ExtractedArtifact {
                node_id: 1,
                relative_path: "main.dll".to_string(),
                bytes: b"fallback".to_vec(),
            },
        ];
        let dir_scratch: ScratchDir = mirror_tmp("collision");
        let dir: PathBuf = dir_scratch.path().to_path_buf();
        let written: Vec<String> = super::write_extracted_children(&dir, &plan).expect("write");
        assert_eq!(written.len(), 3);
        let root: PathBuf = dir.join("extracted");
        assert_eq!(
            std::fs::read(root.join("main.dll")).expect("primary"),
            b"primary"
        );
        assert_eq!(
            std::fs::read(root.join("node1").join("main.dll")).expect("occupied"),
            b"occupied"
        );
        assert_eq!(
            std::fs::read(root.join("node1-1").join("main.dll")).expect("fallback"),
            b"fallback"
        );
    }

    fn leaf_node(id: u32, parent_id: Option<u32>, pass_id: &str, bytes: &[u8]) -> Node {
        Node {
            id,
            parent_id,
            depth: u8::try_from(id).unwrap_or(0),
            branch_id: "main".to_string(),
            pass_id: Some(pass_id.to_string()),
            format_tag_in: None,
            input_blake3: [0u8; 32],
            input_size: bytes.len() as u64,
            output_kind: None,
            output_blake3: None,
            output_size: Some(bytes.len() as u64),
            output_bytes: Some(bytes.to_vec()),
            duration: None,
            picks: Vec::new(),
            artifacts: Vec::new(),
            metadata: BTreeMap::new(),
            verdict: disrobe_core::chain::state_machine::Verdict::Ok,
        }
    }

    fn linear_plan(nodes: Vec<Node>) -> ChainPlan {
        ChainPlan {
            nodes,
            root_id: 0,
            verdict: disrobe_core::chain::state_machine::Verdict::Ok,
            final_format: None,
            total: std::time::Duration::ZERO,
            detector_calls: 0,
            rejected_passes: 0,
            has_multiple_branches: true,
            extracted: Vec::new(),
        }
    }

    fn anti_child(path: &str, bytes: Vec<u8>) -> ChildArtifact {
        ChildArtifact {
            handle: ChildHandle {
                artifact_index: 0,
                relative_path: path.to_string(),
                hint: Some(disrobe_core::chain::detection::TERMINAL_HINT.to_string()),
            },
            bytes,
        }
    }

    #[test]
    fn wasm_recovery_sidecar_records_anti_analysis_techniques() {
        let report: serde_json::Value = serde_json::json!({
            "flattened_functions_restructured": 1,
            "opaque_predicates_removed": 2,
            "collatz_predicates_removed": 0,
            "decrypt_stub_bytes_recovered": 16
        });
        let child: ChildArtifact =
            anti_child("wasm.recovery.json", serde_json::to_vec(&report).unwrap());
        let mut metadata: BTreeMap<String, String> = BTreeMap::new();
        extend_anti_metadata("wasm.deob", &[child], &mut metadata).expect("metadata");
        let techniques: Vec<AntiTechnique> =
            recovered_techniques_for("wasm.deob", &metadata).expect("techniques");
        assert!(techniques.contains(&AntiTechnique::ControlFlowFlattening));
        assert!(techniques.contains(&AntiTechnique::OpaquePredicate));
        assert!(techniques.contains(&AntiTechnique::StringEncryption));
    }

    #[test]
    fn native_deobf_sidecar_records_anti_analysis_techniques() {
        let report: serde_json::Value = serde_json::json!({
            "cff": { "dispatcher": 4096 },
            "bogus_branches": [{ "address": 8192 }],
            "mba_simplifications": [],
            "branch_folds": [],
            "cleaned_listing": "entry:\n  ret\n",
            "stack_strings": [{ "value": "secret" }]
        });
        let child: ChildArtifact = anti_child("deobf.json", serde_json::to_vec(&report).unwrap());
        let mut metadata: BTreeMap<String, String> = BTreeMap::new();
        extend_anti_metadata("native.packer-unpack", &[child], &mut metadata).expect("metadata");
        let techniques: Vec<AntiTechnique> =
            recovered_techniques_for("native.packer-unpack", &metadata).expect("techniques");
        assert!(techniques.contains(&AntiTechnique::ControlFlowFlattening));
        assert!(techniques.contains(&AntiTechnique::OpaquePredicate));
        assert!(techniques.contains(&AntiTechnique::AntiDisassembly));
        assert!(techniques.contains(&AntiTechnique::StringEncryption));
    }

    #[test]
    fn chain_evidence_consumes_anti_analysis_metadata() {
        let mut node: Node = leaf_node(0, None, "wasm.deob", b"(module)");
        node.output_kind = Some(OutputKind::Source {
            language: disrobe_core::Language::Wat,
            formatted: true,
        });
        let _previous: Option<String> = metadata_keys::set_comma_list(
            &mut node.metadata,
            keys::ANTI_RECOVERED_TECHNIQUES_KEY,
            &[
                "control-flow-flattening",
                "opaque-predicate",
                "string-encryption",
            ],
        )
        .expect("metadata");
        let plan: ChainPlan = linear_plan(vec![node]);
        let evidence: ChainEvidence = chain_evidence(&plan).expect("chain evidence");
        assert!(
            evidence
                .recovered_techniques
                .contains(&AntiTechnique::ControlFlowFlattening)
        );
        assert!(
            evidence
                .recovered_techniques
                .contains(&AntiTechnique::OpaquePredicate)
        );
        assert!(
            evidence
                .recovered_techniques
                .contains(&AntiTechnique::StringEncryption)
        );
    }

    #[test]
    fn malformed_metadata_uses_a_distinct_diagnostic_code() {
        let mut node: Node = leaf_node(0, None, "wasm.deob", b"(module)");
        node.metadata
            .insert(keys::ANTI_RECOVERED_TECHNIQUES.to_string(), String::new());
        let plan: ChainPlan = linear_plan(vec![node]);
        let report: miette::Report = chain_evidence(&plan)
            .map_err(metadata_value_report)
            .expect_err("malformed metadata");
        let rendered: String = report.to_string();
        assert!(rendered.starts_with("DR-CLI-0299:"), "{rendered}");
        assert!(!rendered.contains("DR-CLI-0294"), "{rendered}");
    }

    #[test]
    fn chain_json_serializes_nonempty_registered_metadata() {
        let mut node: Node = leaf_node(0, None, "wasm.deob", b"(module)");
        let _previous: Option<String> = metadata_keys::set_comma_list(
            &mut node.metadata,
            keys::ANTI_RECOVERED_TECHNIQUES_KEY,
            &["opaque-predicate", "string-encryption"],
        )
        .expect("metadata");
        let plan: ChainPlan = linear_plan(vec![node]);
        let spec: ChainSpec = ChainSpec::Auto { cap: 8 };
        let document: ChainDocument =
            ChainDocument::from_plan(&plan, &spec, "auto:8", "0.10.5", None)
                .expect("valid chain metadata");
        let serialized: serde_json::Value = serde_json::to_value(document).expect("chain document");
        assert_eq!(
            serialized["nodes"][0]["metadata"][keys::ANTI_RECOVERED_TECHNIQUES],
            "opaque-predicate,string-encryption"
        );
        let encoded_metadata: String =
            serde_json::to_string(&serialized["nodes"][0]["metadata"]).expect("metadata JSON");
        assert_eq!(
            encoded_metadata,
            r#"{"anti.recovered_techniques":"opaque-predicate,string-encryption"}"#
        );
    }

    #[test]
    fn write_stage_mirror_links_terminal_to_stage_bytes() {
        let root_scratch: ScratchDir = mirror_tmp("linear");
        let root: PathBuf = root_scratch.path().to_path_buf();

        let terminal_bytes: &[u8] = b"\xde\xad\xbe\xefterminal-output";
        let plan: ChainPlan = linear_plan(vec![
            leaf_node(0, None, "py.deob", b"root-bytes"),
            leaf_node(1, Some(0), "py.decompile", terminal_bytes),
        ]);

        let mirror: StageMirror = write_stage_mirror(&root, &plan).expect("mirror");
        assert!(
            mirror.finals.iter().any(|w: &String| w.contains("final")),
            "expected a final/ link label in {:?}",
            mirror.finals
        );

        let terminal: &Node = plan
            .nodes
            .iter()
            .find(|n: &&Node| !plan.nodes.iter().any(|o: &Node| o.parent_id == Some(n.id)))
            .expect("a terminal");
        let final_bin: PathBuf = root
            .join("final")
            .join("02-py-decompile")
            .join("output.bin");
        let got: Vec<u8> = std::fs::read(&final_bin).expect("final output.bin readable");
        assert_eq!(
            got.as_slice(),
            terminal.output_bytes.as_deref().expect("bytes"),
            "final must resolve to terminal stage bytes"
        );

        let stage_bin: PathBuf = root.join("02-py-decompile").join("output.bin");
        let stage_got: Vec<u8> = std::fs::read(&stage_bin).expect("stage output.bin");
        assert_eq!(got, stage_got, "final and stage bytes must match");
        assert!(
            !root.join("stages").exists(),
            "flat layout must not create a stages/ wrapper"
        );
    }

    #[test]
    fn write_stage_mirror_handles_multiple_terminals() {
        let root_scratch: ScratchDir = mirror_tmp("multi");
        let root: PathBuf = root_scratch.path().to_path_buf();

        let plan: ChainPlan = linear_plan(vec![
            leaf_node(0, None, "binfmt.container", b"root"),
            leaf_node(1, Some(0), "py.deob", b"branch-a-bytes"),
            leaf_node(2, Some(0), "js.deob", b"branch-b-bytes"),
        ]);

        let _: StageMirror = write_stage_mirror(&root, &plan).expect("mirror");

        for (dir_name, expected) in [
            ("02-py-deob", b"branch-a-bytes".as_slice()),
            ("03-js-deob", b"branch-b-bytes"),
        ] {
            let bin: PathBuf = root.join("final").join(dir_name).join("output.bin");
            let got: Vec<u8> = std::fs::read(&bin).expect("terminal final output.bin readable");
            assert_eq!(
                got.as_slice(),
                expected,
                "terminal {dir_name} bytes mismatch"
            );
        }
    }

    #[test]
    fn registry_has_all_passes() {
        let r: PassRegistry = build_registry();
        assert!(r.len() >= 23);
        assert!(r.get("pyarmor.unpack").is_some());
        assert!(r.get("native.packer-unpack").is_some());
        assert!(r.get("js.deob").is_some());
        assert!(r.get("py.deob").is_some());
        assert!(r.get("binfmt.container").is_some());
        assert!(r.get("sourcedefender.decrypt").is_some());
        assert!(r.get("pyfreeze.extract").is_some());
        assert!(r.get("nuitka.extract").is_some());
        assert!(r.get("wasm.deob").is_some());
        assert!(r.get("php.peel").is_some());
        assert!(r.get("ruby.classify").is_some());
        assert!(r.get("shell.deob").is_some());
        assert!(r.get("mobile.classify").is_some());
        assert!(r.get("lua.deob").is_some());
        assert!(r.get("swift-objc.classify").is_some());
        assert!(r.get("py.disasm").is_some());
        assert!(r.get("py.decompile").is_some());
        assert!(r.get("pyinstaller.extract").is_some());
        assert!(r.get("jvm.classify").is_some());
        assert!(r.get("dotnet.classify").is_some());
        assert!(r.get("go.classify").is_some());
        assert!(r.get("beam.classify").is_some());
        assert!(r.get("as3.classify").is_some());
        assert!(r.get("scriptlang.classify").is_some());
    }

    #[test]
    fn no_advisory_names_a_subcommand_this_binary_does_not_have() {
        let names: BTreeSet<String> = crate::subcommand_names();
        assert!(
            names.len() >= 8,
            "clap reported only {} subcommand(s), so this check is reading the wrong shape and \
             would pass over an advisory naming anything: {names:?}",
            names.len()
        );
        let groups: BTreeSet<String> = build_registry()
            .iter_passes()
            .filter_map(|p: &dyn disrobe_core::chain::Pass| {
                p.id().split('.').next().map(str::to_owned)
            })
            .collect();
        assert!(
            !groups.is_empty(),
            "the registry declares no pass, so no advisory group can be checked"
        );
        let orphaned: Vec<&String> = groups
            .iter()
            .filter(|group: &&String| !names.contains(group.as_str()))
            .collect();
        assert!(
            !orphaned.is_empty(),
            "this check only means something while at least one pass group has no dedicated \
             subcommand; if every group now has one, replace it with an assertion of that"
        );
        for group in orphaned {
            assert!(
                !advisory_for_group(group, "probe-tag")
                    .contains(&format!("disrobe {group} --help")),
                "the advisory sends a user to `disrobe {group}`, which this binary does not have"
            );
        }
    }
}
