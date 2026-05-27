#![cfg(feature = "chain")]
#![allow(clippy::needless_pass_by_value)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Instant;

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::spec::PassToken;
use disrobe_core::chain::state_machine::PassRunner;
use disrobe_core::chain::{
    ChainConfig, ChainDocument, ChainDriver, ChainPlan, ChainSpec, DetectorPick, OutputKind,
    PassRegistry, PassRunOutcome,
};

use super::output::{OutputFormat, emit};

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
    r.register(&disrobe_pass_js_deob::chain_detector::JS_OBF_PASS);
    r.register(&disrobe_pass_py_deob::chain_detector::PY_DEOB_PASS);
    r.register(&disrobe_binfmt::chain_detector::CONTAINER_PASS);
    r.register(&disrobe_pass_sourcedefender::chain_detector::SOURCEDEFENDER_PASS);
    r.register(&disrobe_pass_pyfreeze::chain_detector::PYFREEZE_PASS);
    r.register(&disrobe_pass_nuitka::chain_detector::NUITKA_PASS);
    r.register(&disrobe_pass_wasm_deob::chain_detector::WASM_DEOB_PASS);
    r.register(&disrobe_pass_php::chain_detector::PHP_PASS);
    r.register(&disrobe_pass_ruby::chain_detector::RUBY_PASS);
    r.register(&disrobe_pass_shell::chain_detector::SHELL_PASS);
    r.register(&disrobe_pass_mobile::chain_detector::MOBILE_PASS);
    r.register(&disrobe_pass_lua::chain_detector::LUA_PASS);
    r.register(&disrobe_pass_swift_objc::chain_detector::SWIFT_OBJC_PASS);
    r.register(&disrobe_pass_py_disasm::chain_detector::PY_DISASM_PASS);
    r.register(&disrobe_pass_py_decompile::chain_detector::PY_DECOMPILE_PASS);
    r.register(&disrobe_pass_pyinstaller::chain_detector::PYINSTALLER_PASS);
    r.register(&disrobe_pass_jvm::chain_detector::JVM_PASS);
    r.register(&disrobe_pass_dotnet::chain_detector::DOTNET_PASS);
    r.register(&disrobe_pass_go::chain_detector::GO_PASS);
    r.register(&disrobe_pass_beam::chain_detector::BEAM_PASS);
    r.register(&disrobe_pass_as3::chain_detector::AS3_PASS);
    r
}

pub(crate) fn run(
    input: PathBuf,
    out: Option<PathBuf>,
    chain_arg: String,
    pin_arg: Option<String>,
    fmt: OutputFormat,
) -> miette::Result<()> {
    run_with_disk(input, out, chain_arg, pin_arg, fmt, true)
}

pub(crate) fn run_with_disk(
    input: PathBuf,
    out: Option<PathBuf>,
    chain_arg: String,
    pin_arg: Option<String>,
    fmt: OutputFormat,
    write_to_disk: bool,
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
    let driver: ChainDriver<'_, ChainPassRunner> =
        ChainDriver::new(&registry, &runner, ChainConfig::default());
    let plan: ChainPlan = driver.run(bytes, &spec, Some(input.display().to_string()));
    let doc: ChainDocument = ChainDocument::from_plan(
        &plan,
        &spec,
        &spec_raw,
        env!("CARGO_PKG_VERSION"),
        Some(input.display().to_string()),
    );
    if !write_to_disk {
        emit(fmt, &doc, || {
            println!("chain.json (dry-run; nothing written to disk)");
        })?;
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
    let chain_path_str: String = chain_path.display().to_string();
    emit(fmt, &doc, || {
        println!("chain.json written: {chain_path_str}");
    })?;
    Ok(())
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
