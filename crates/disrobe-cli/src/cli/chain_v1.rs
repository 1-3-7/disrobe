#![cfg(feature = "chain")]
#![allow(clippy::needless_pass_by_value)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::spec::PassToken;
use disrobe_core::chain::state_machine::PassRunner;
use disrobe_core::chain::{
    ChainConfig, ChainDocument, ChainDriver, ChainPlan, ChainRecoveryReport, ChainSpec,
    DetectorPick, Node, OutputKind, PassRegistry, PassRunOutcome,
};

use super::output::{OutputFormat, emit};
use super::path_ops::{self, LinkKind};

#[derive(Debug)]
struct ChainPassRunner;

impl PassRunner for ChainPassRunner {
    fn run(
        &self,
        pick: &DetectorPick,
        bytes: &[u8],
        _config: &ChainConfig,
    ) -> Result<PassRunOutcome, String> {
        let artifact: Artifact = Artifact::new(Rung::Raw, bytes.to_vec(), blake3_hash(bytes));
        let started: Instant = Instant::now();
        let out_artifact: Artifact = pick
            .pass
            .run(&artifact)
            .map_err(|e: disrobe_core::error::CoreError| format!("{e}"))?;
        let kind: OutputKind = pick.pass.output_kind(&out_artifact);
        Ok(PassRunOutcome {
            output_bytes: out_artifact.envelope,
            kind,
            duration: started.elapsed(),
            metadata: BTreeMap::new(),
        })
    }
}

fn blake3_hash(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
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
    r
}

pub(crate) fn run(
    input: PathBuf,
    out: Option<PathBuf>,
    chain_arg: String,
    pin_arg: Option<String>,
    fmt: OutputFormat,
    capture_stages: bool,
) -> miette::Result<()> {
    run_with_disk(
        input,
        out,
        chain_arg,
        pin_arg,
        fmt,
        true,
        capture_stages,
        false,
    )
}

pub(crate) fn run_with_disk(
    input: PathBuf,
    out: Option<PathBuf>,
    chain_arg: String,
    pin_arg: Option<String>,
    fmt: OutputFormat,
    write_to_disk: bool,
    capture_stages: bool,
    emit_recovery: bool,
) -> miette::Result<()> {
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
    let runner: ChainPassRunner = ChainPassRunner;
    let config: ChainConfig = ChainConfig {
        capture_stage_bytes: capture_stages && write_to_disk,
        ..ChainConfig::default()
    };
    let driver: ChainDriver<'_, ChainPassRunner> = ChainDriver::new(&registry, &runner, config);
    let plan: ChainPlan = driver.run(bytes, &spec, Some(input.display().to_string()));
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
    if !write_to_disk {
        emit(fmt, &doc, || {
            println!("chain.json (dry-run; nothing written to disk)");
        })?;
        if emit_recovery && fmt.is_machine() {
            emit(fmt, &report, || {})?;
        }
        return Ok(());
    }
    let out_dir: PathBuf = out.unwrap_or_else(|| {
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
    let stage_summary: Option<String> = if capture_stages {
        let written: Vec<String> = write_stage_mirror(&out_dir, &plan)?;
        Some(format!(
            "{} stage artifact(s) mirrored under {}; terminal stage(s) linked under {}",
            written.len(),
            out_dir.join("stages").display(),
            out_dir.join("final").display()
        ))
    } else {
        None
    };
    let chain_path_str: String = chain_path.display().to_string();
    emit(fmt, &doc, || {
        println!("chain.json written: {chain_path_str}");
        println!("recovery.json written: {recovery_path_str}");
        if let Some(summary) = stage_summary.as_ref() {
            println!("{summary}");
        }
    })?;
    if emit_recovery && fmt.is_machine() {
        emit(fmt, &report, || {})?;
    }
    Ok(())
}

fn stage_slug(pass_id: Option<&str>) -> String {
    let raw: &str = pass_id.unwrap_or("input");
    raw.chars()
        .map(|c: char| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

fn write_stage_mirror(out_dir: &Path, plan: &ChainPlan) -> miette::Result<Vec<String>> {
    let stages_dir: PathBuf = out_dir.join("stages");
    let final_dir: PathBuf = out_dir.join("final");
    let mut written: Vec<String> = Vec::new();
    for node in &plan.nodes {
        let Some(stage_bytes): Option<&Vec<u8>> = node.output_bytes.as_ref() else {
            continue;
        };
        let slug: String = stage_slug(node.pass_id.as_deref());
        let stage_dir: PathBuf = stages_dir.join(format!("{:02}-{slug}", node.id));
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
        written.push(stage_path.display().to_string());

        let is_terminal: bool = !plan
            .nodes
            .iter()
            .any(|other: &Node| other.parent_id == Some(node.id));
        if is_terminal {
            let final_target: PathBuf = final_dir.join(format!("{:02}-{slug}", node.id));
            let kind: LinkKind = path_ops::link_final(&stage_dir, &final_target)?;
            written.push(format!("{} ({})", final_target.display(), kind.label()));
        }
    }
    Ok(written)
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
            topology_is_tree: true,
        }
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

        let written: Vec<String> = write_stage_mirror(&root, &plan).expect("mirror");
        assert!(
            written.iter().any(|w: &String| w.contains("final")),
            "expected a final/ link label in {written:?}"
        );

        let terminal: &Node = plan
            .nodes
            .iter()
            .find(|n: &&Node| !plan.nodes.iter().any(|o: &Node| o.parent_id == Some(n.id)))
            .expect("a terminal");
        let slug: String = stage_slug(terminal.pass_id.as_deref());
        let final_bin: PathBuf = root
            .join("final")
            .join(format!("{:02}-{slug}", terminal.id))
            .join("output.bin");
        let got: Vec<u8> = std::fs::read(&final_bin).expect("final output.bin readable");
        assert_eq!(
            got.as_slice(),
            terminal.output_bytes.as_deref().expect("bytes"),
            "final must resolve to terminal stage bytes"
        );

        let stage_bin: PathBuf = root
            .join("stages")
            .join(format!("{:02}-{slug}", terminal.id))
            .join("output.bin");
        let stage_got: Vec<u8> = std::fs::read(&stage_bin).expect("stage output.bin");
        assert_eq!(got, stage_got, "final and stage bytes must match");

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

        let _: Vec<String> = write_stage_mirror(&root, &plan).expect("mirror");

        for (id, expected) in [
            (1u32, b"branch-a-bytes".as_slice()),
            (2u32, b"branch-b-bytes"),
        ] {
            let slug: String = stage_slug(Some(if id == 1 { "py.deob" } else { "js.deob" }));
            let bin: PathBuf = root
                .join("final")
                .join(format!("{id:02}-{slug}"))
                .join("output.bin");
            let got: Vec<u8> = std::fs::read(&bin).expect("terminal final output.bin readable");
            assert_eq!(got.as_slice(), expected, "terminal {id} bytes mismatch");
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
    }
}
