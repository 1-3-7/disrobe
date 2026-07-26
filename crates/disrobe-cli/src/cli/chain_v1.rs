#![cfg(feature = "chain")]
#![allow(clippy::needless_pass_by_value)]
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::anti_analysis::{
    AntiAnalysisFinding, AntiAnalysisReport, ChainEvidence, DefeatStatus,
    Technique as AntiTechnique, scan_with_chain as scan_anti_analysis,
};
use disrobe_core::chain::spec::PassToken;
use disrobe_core::chain::state_machine::{PassRunner, Verdict};
use disrobe_core::chain::{
    ChainConfig, ChainDocument, ChainDriver, ChainPlan, ChainRecoveryReport, ChainSpec,
    ChildArtifact, ChildHandle, DetectorPick, Node, OutputKind, PassRegistry, PassRunOutcome,
};
use disrobe_core::pass::PassContext;

use super::output::{OutputFormat, emit};
use super::path_ops::{self, LinkKind};
use super::progress_ui::ChainProgress;

use disrobe_core::chain::metadata_keys::keys::ANTI_RECOVERED_TECHNIQUES as ANTI_RECOVERED_TECHNIQUES_KEY;

#[derive(Debug)]
struct ChainPassRunner<'p> {
    progress: &'p ChainProgress,
}

impl<'p> ChainPassRunner<'p> {
    const fn new(progress: &'p ChainProgress) -> Self {
        Self { progress }
    }
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
        let mut metadata: BTreeMap<String, String> = BTreeMap::new();
        let (kind, children): (OutputKind, Vec<Vec<u8>>) = if initial_kind.is_mixed() {
            let extracted: Vec<ChildArtifact> = pick
                .pass
                .extract_children_with_context(&artifact, context)
                .map_err(|e: disrobe_core::error::CoreError| format!("{e}"))?;
            extend_anti_metadata(pick.verdict.pass_id, &extracted, &mut metadata);
            OutputKind::mixed_from_children(extracted)
        } else {
            if pick.verdict.pass_id == "wasm.deob"
                && out_artifact.rung == Rung::Surface
                && let Ok(extracted) = pick.pass.extract_children_with_context(&artifact, context)
            {
                extend_anti_metadata(pick.verdict.pass_id, &extracted, &mut metadata);
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

fn chain_evidence(plan: &ChainPlan) -> ChainEvidence {
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
            for technique in recovered_techniques_for(pass_id, &node.metadata) {
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
    ChainEvidence {
        executed_pass_ids,
        recovered_format_tags,
        recovered_techniques,
    }
}

fn recovered_techniques_for(
    _pass_id: &str,
    metadata: &BTreeMap<String, String>,
) -> Vec<AntiTechnique> {
    let mut techniques: Vec<AntiTechnique> = Vec::new();
    let Some(raw): Option<&String> = metadata.get(ANTI_RECOVERED_TECHNIQUES_KEY) else {
        return techniques;
    };
    for label in raw.split(',') {
        if let Some(technique) = anti_technique_from_label(label.trim()) {
            push_unique_technique(&mut techniques, technique);
        }
    }
    techniques
}

fn extend_anti_metadata(
    pass_id: &str,
    children: &[ChildArtifact],
    metadata: &mut BTreeMap<String, String>,
) {
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
        metadata.insert(
            ANTI_RECOVERED_TECHNIQUES_KEY.to_string(),
            techniques
                .iter()
                .map(|t: &AntiTechnique| t.label())
                .collect::<Vec<&str>>()
                .join(","),
        );
    }
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

fn build_registry() -> PassRegistry {
    let mut r: PassRegistry = PassRegistry::new();
    r.register(&disrobe_pass_pyarmor::chain_detector::PYARMOR_PASS);
    r.register(&disrobe_pass_native::chain_detector::PACKER_PASS);
    r.register(&disrobe_pass_py_deob::chain_detector::PY_DEOB_PASS);
    r.register(&disrobe_binfmt::chain_detector::CONTAINER_PASS);
    r.register(&disrobe_pass_sourcedefender::chain_detector::SOURCEDEFENDER_PASS);
    r.register(&disrobe_pass_pyfreeze::chain_detector::PYFREEZE_PASS);
    r.register(&disrobe_pass_nuitka::chain_detector::NUITKA_PASS);
    r.register(&disrobe_pass_py_disasm::chain_detector::PY_DISASM_PASS);
    r.register(&disrobe_pass_py_decompile::chain_detector::PY_DECOMPILE_PASS);
    r.register(&disrobe_pass_pyinstaller::chain_detector::PYINSTALLER_PASS);
    #[cfg(feature = "pickle")]
    r.register(&disrobe_pass_pickle::chain_detector::PICKLE_PASS);
    #[cfg(feature = "js")]
    r.register(&disrobe_pass_js_deob::chain_detector::JS_OBF_PASS);
    #[cfg(feature = "wasm")]
    r.register(&disrobe_pass_wasm_deob::chain_detector::WASM_DEOB_PASS);
    #[cfg(feature = "php")]
    r.register(&disrobe_pass_php::chain_detector::PHP_PASS);
    #[cfg(feature = "ruby")]
    r.register(&disrobe_pass_ruby::chain_detector::RUBY_PASS);
    #[cfg(feature = "shell")]
    r.register(&disrobe_pass_shell::chain_detector::SHELL_PASS);
    #[cfg(feature = "mobile")]
    r.register(&disrobe_pass_mobile::chain_detector::MOBILE_PASS);
    #[cfg(feature = "lua")]
    r.register(&disrobe_pass_lua::chain_detector::LUA_PASS);
    #[cfg(feature = "swift")]
    r.register(&disrobe_pass_swift_objc::chain_detector::SWIFT_OBJC_PASS);
    #[cfg(feature = "jvm")]
    r.register(&disrobe_pass_jvm::chain_detector::JVM_PASS);
    #[cfg(feature = "dotnet")]
    r.register(&disrobe_pass_dotnet::chain_detector::DOTNET_PASS);
    #[cfg(feature = "go")]
    r.register(&disrobe_pass_go::chain_detector::GO_PASS);
    #[cfg(feature = "beam")]
    r.register(&disrobe_pass_beam::chain_detector::BEAM_PASS);
    #[cfg(feature = "as3")]
    r.register(&disrobe_pass_as3::chain_detector::AS3_PASS);
    #[cfg(feature = "scriptlang")]
    r.register(&disrobe_pass_scriptlang::chain_detector::SCRIPTLANG_PASS);
    #[cfg(feature = "nativelang")]
    r.register(&disrobe_pass_nativelang::chain_detector::NATIVELANG_PASS);
    r
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ChainRunOptions {
    pub(crate) write_to_disk: bool,
    pub(crate) capture_stages: bool,
    pub(crate) emit_recovery: bool,
    pub(crate) i_have_authorization: bool,
}

impl ChainRunOptions {
    fn chain_config(self, stream_extracted: bool) -> ChainConfig {
        ChainConfig {
            capture_stage_bytes: self.capture_stages && self.write_to_disk,
            persist_children: self.write_to_disk,
            stream_extracted,
            i_have_authorization: self.i_have_authorization,
            ..ChainConfig::default()
        }
    }
}

pub(crate) fn run_with_disk(
    input: PathBuf,
    out: Option<PathBuf>,
    chain_arg: String,
    pin_arg: Option<String>,
    fmt: OutputFormat,
    options: ChainRunOptions,
) -> miette::Result<()> {
    let ChainRunOptions {
        write_to_disk,
        capture_stages,
        emit_recovery,
        ..
    } = options;
    let spec_raw: String = match pin_arg {
        None => chain_arg,
        Some(pin) => combine_chain_and_pin_owned(chain_arg, &pin)?,
    };
    let spec: ChainSpec = ChainSpec::parse(&spec_raw)
        .map_err(|e| miette::miette!("DR-CLI-0291: --chain parse error: {e}"))?;
    let bytes: Vec<u8> = std::fs::read(&input).map_err(|e| {
        miette::miette!(
            "DR-CLI-0292: chain cannot read input {}: {e}",
            input.display()
        )
    })?;
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
    progress.finish(&format!("{} pass(es) ran", progress.steps()));
    let anti: AntiAnalysisReport = scan_anti_analysis(
        &seed_for_scan,
        Some(&input.display().to_string()),
        &chain_evidence(&plan),
    );
    let doc: ChainDocument = ChainDocument::from_plan(
        &plan,
        &spec,
        &spec_raw,
        env!("CARGO_PKG_VERSION"),
        Some(input.display().to_string()),
    );
    let report: ChainRecoveryReport = ChainRecoveryReport::from_plan(
        &plan,
        env!("CARGO_PKG_VERSION"),
        Some(input.display().to_string()),
    );
    let py_guidance: Option<String> = maybe_py_deob_guidance(&spec_raw, &plan, &seed_for_scan);
    if !write_to_disk {
        emit(fmt, &doc, || {
            println!("chain.json (dry-run; nothing written to disk)");
            render_anti_analysis(&anti);
            if let Some(guidance) = py_guidance.as_ref() {
                eprintln!();
                eprint!("{guidance}");
            }
        })?;
        if emit_recovery && fmt.is_machine() {
            emit(fmt, &report, || {})?;
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
    let chain_bytes: Vec<u8> = serde_json::to_vec_pretty(&doc)
        .map_err(|e| miette::miette!("DR-CLI-0294: chain.json serialize: {e}"))?;
    std::fs::write(&chain_path, &chain_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0295: cannot write chain.json: {e}"))?;
    let recovery_path: PathBuf = out_dir.join("recovery.json");
    let recovery_bytes: Vec<u8> = serde_json::to_vec_pretty(&report)
        .map_err(|e| miette::miette!("DR-CLI-0305: recovery.json serialize: {e}"))?;
    std::fs::write(&recovery_path, &recovery_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0306: cannot write recovery.json: {e}"))?;
    let recovery_path_str: String = recovery_path.display().to_string();
    let anti_path: PathBuf = out_dir.join("anti-analysis.json");
    let anti_bytes: Vec<u8> = serde_json::to_vec_pretty(&anti)
        .map_err(|e| miette::miette!("DR-CLI-0307: anti-analysis.json serialize: {e}"))?;
    std::fs::write(&anti_path, &anti_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0308: cannot write anti-analysis.json: {e}"))?;
    let anti_path_str: String = anti_path.display().to_string();
    let mut extracted_written: Vec<String> = streamed;
    extracted_written.extend(write_extracted_children(&out_dir, &plan)?);
    let extracted_dir_str: String = out_dir.join("extracted").display().to_string();
    let recovered: bool = !extracted_written.is_empty() || recovered_anything(&plan);
    let advisory: Option<String> = if recovered {
        None
    } else {
        Some(identify_advisory(&plan))
    };
    let stage_summary: Option<String> = if capture_stages {
        let mirror: StageMirror = write_stage_mirror(&out_dir, &plan)?;
        Some(format!(
            "{} stage artifact(s) mirrored as out/NN-<pass>/ step dir(s) under {}; {} terminal stage(s) linked under {}",
            mirror.steps.len(),
            out_dir.display(),
            mirror.finals.len(),
            out_dir.join("final").display()
        ))
    } else {
        None
    };
    let chain_path_str: String = chain_path.display().to_string();
    emit(fmt, &doc, || {
        println!("chain.json written: {chain_path_str}");
        println!("recovery.json written: {recovery_path_str}");
        println!("anti-analysis.json written: {anti_path_str}");
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
        render_anti_analysis(&anti);
        if let Some(guidance) = py_guidance.as_ref() {
            eprintln!();
            eprint!("{guidance}");
        }
        if let Some(note) = advisory.as_ref() {
            eprintln!();
            eprintln!("{note}");
        }
    })?;
    if emit_recovery && fmt.is_machine() {
        emit(fmt, &report, || {})?;
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
            format!(
                "note: auto recovered no files from this input. It looks like `{tag}`. Confirm with `disrobe detect <file>`, then run the dedicated command (see `disrobe {group} --help`).",
                tag = pick.verdict.format_tag,
            )
        },
    )
}

#[derive(Debug)]
pub(crate) struct ChainOutcome {
    pub(crate) doc: ChainDocument,
    pub(crate) report: ChainRecoveryReport,
    pub(crate) anti: AntiAnalysisReport,
}

pub(crate) fn run_chain_to_dir(
    input_label: &str,
    bytes: Vec<u8>,
    out_dir: &Path,
    chain_arg: &str,
    capture_stages: bool,
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
        capture_stages,
        emit_recovery: false,
        i_have_authorization,
    }
    .chain_config(false);
    let driver: ChainDriver<'_, ChainPassRunner<'_>> = ChainDriver::new(&registry, &runner, config);
    let seed_for_scan: Vec<u8> = bytes.clone();
    let plan: ChainPlan = driver.run(bytes, &spec, Some(input_label.to_string()));
    let anti: AntiAnalysisReport =
        scan_anti_analysis(&seed_for_scan, Some(input_label), &chain_evidence(&plan));
    let doc: ChainDocument = ChainDocument::from_plan(
        &plan,
        &spec,
        chain_arg,
        env!("CARGO_PKG_VERSION"),
        Some(input_label.to_string()),
    );
    let report: ChainRecoveryReport = ChainRecoveryReport::from_plan(
        &plan,
        env!("CARGO_PKG_VERSION"),
        Some(input_label.to_string()),
    );
    std::fs::create_dir_all(out_dir)
        .map_err(|e| miette::miette!("DR-CLI-0293: cannot create chain out dir: {e}"))?;
    let chain_bytes: Vec<u8> = serde_json::to_vec_pretty(&doc)
        .map_err(|e| miette::miette!("DR-CLI-0294: chain.json serialize: {e}"))?;
    std::fs::write(out_dir.join("chain.json"), &chain_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0295: cannot write chain.json: {e}"))?;
    let recovery_bytes: Vec<u8> = serde_json::to_vec_pretty(&report)
        .map_err(|e| miette::miette!("DR-CLI-0305: recovery.json serialize: {e}"))?;
    std::fs::write(out_dir.join("recovery.json"), &recovery_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0306: cannot write recovery.json: {e}"))?;
    let anti_bytes: Vec<u8> = serde_json::to_vec_pretty(&anti)
        .map_err(|e| miette::miette!("DR-CLI-0307: anti-analysis.json serialize: {e}"))?;
    std::fs::write(out_dir.join("anti-analysis.json"), &anti_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0308: cannot write anti-analysis.json: {e}"))?;
    let _: Vec<String> = write_extracted_children(out_dir, &plan)?;
    if capture_stages {
        let _: StageMirror = write_stage_mirror(out_dir, &plan)?;
    }
    Ok(ChainOutcome { doc, report, anti })
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
    use std::sync::atomic::AtomicBool;

    static OBSERVED_AUTHORIZATION: AtomicBool = AtomicBool::new(false);

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
            capture_stages: false,
            emit_recovery: false,
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

    use std::sync::atomic::{AtomicU64, Ordering};

    static MIRROR_SEQ: AtomicU64 = AtomicU64::new(0);

    fn mirror_tmp(stem: &str) -> PathBuf {
        let pid: u32 = std::process::id();
        let n: u64 = MIRROR_SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("disrobe-mirror-{stem}-{pid}-{n}"))
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
        let dir: PathBuf = mirror_tmp("extracted");
        std::fs::create_dir_all(&dir).expect("mk tmp");
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
        std::fs::remove_dir_all(&dir).ok();
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
        let dir: PathBuf = mirror_tmp("collision");
        std::fs::create_dir_all(&dir).expect("mk tmp");
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
        std::fs::remove_dir_all(&dir).ok();
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
        extend_anti_metadata("wasm.deob", &[child], &mut metadata);
        let techniques: Vec<AntiTechnique> = recovered_techniques_for("wasm.deob", &metadata);
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
        extend_anti_metadata("native.packer-unpack", &[child], &mut metadata);
        let techniques: Vec<AntiTechnique> =
            recovered_techniques_for("native.packer-unpack", &metadata);
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
        node.metadata.insert(
            ANTI_RECOVERED_TECHNIQUES_KEY.to_string(),
            "control-flow-flattening,opaque-predicate,string-encryption".to_string(),
        );
        let plan: ChainPlan = linear_plan(vec![node]);
        let evidence: ChainEvidence = chain_evidence(&plan);
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
    fn write_stage_mirror_links_terminal_to_stage_bytes() {
        let root: PathBuf = mirror_tmp("linear");
        std::fs::create_dir_all(&root).expect("mk root");

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

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn write_stage_mirror_handles_multiple_terminals() {
        let root: PathBuf = mirror_tmp("multi");
        std::fs::create_dir_all(&root).expect("mk root");

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

        let _ = std::fs::remove_dir_all(&root);
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
}
