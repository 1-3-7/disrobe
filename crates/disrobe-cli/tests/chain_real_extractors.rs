#![cfg(feature = "chain")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::unnecessary_debug_formatting
)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Instant;

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::chain_json::VerdictDoc;
use disrobe_core::chain::state_machine::PassRunner;
use disrobe_core::chain::{
    ChainConfig, ChainDocument, ChainDriver, ChainPlan, ChainSpec, DetectorPick, OutputKind,
    PassRegistry, PassRunOutcome,
};

#[derive(Debug)]
struct RealPassRunner;

impl PassRunner for RealPassRunner {
    fn run(
        &self,
        pick: &DetectorPick,
        bytes: &[u8],
        _config: &ChainConfig,
    ) -> Result<PassRunOutcome, String> {
        let artifact: Artifact = Artifact::new(Rung::Raw, bytes.to_vec(), blake3_hash(bytes));
        let started: Instant = Instant::now();
        let out_artifact: Artifact = pick.pass.run(&artifact).map_err(|e| format!("{e}"))?;
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

fn registry_full() -> PassRegistry {
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

fn workspace_root() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn corpus(rel: &str) -> PathBuf {
    workspace_root().join("corpus").join(rel)
}

fn read_fixture(rel: &str) -> Option<Vec<u8>> {
    let path: PathBuf = corpus(rel);
    if !path.exists() {
        eprintln!("SKIP fixture missing: {path:?}");
        return None;
    }
    std::fs::read(&path).ok()
}

fn run_chain_auto(bytes: Vec<u8>, source_path: &str) -> ChainDocument {
    let registry: PassRegistry = registry_full();
    let runner: RealPassRunner = RealPassRunner;
    let driver: ChainDriver<'_, RealPassRunner> =
        ChainDriver::new(&registry, &runner, ChainConfig::default());
    let spec: ChainSpec = ChainSpec::Auto { cap: 8 };
    let plan: ChainPlan = driver.run(bytes, &spec, Some(source_path.to_owned()));
    ChainDocument::from_plan(
        &plan,
        &spec,
        "auto:8",
        "0.8.0-real",
        Some(source_path.to_owned()),
    )
}

fn pick_first_pass_node(doc: &ChainDocument) -> Option<&disrobe_core::chain::NodeDoc> {
    doc.nodes
        .iter()
        .find(|n: &&disrobe_core::chain::NodeDoc| n.pass.is_some())
}

fn assert_pass_id(doc: &ChainDocument, expected: &str) {
    let node: &disrobe_core::chain::NodeDoc = pick_first_pass_node(doc)
        .unwrap_or_else(|| panic!("no pass node in chain doc for {expected}"));
    let pass: &str = node.pass.as_deref().unwrap_or("");
    assert_eq!(pass, expected, "expected pass {expected}, got {pass}");
}

fn assert_pass_completes(doc: &ChainDocument, expected: &str) {
    let node: &disrobe_core::chain::NodeDoc = pick_first_pass_node(doc)
        .unwrap_or_else(|| panic!("no pass node in chain doc for {expected}"));
    assert_eq!(
        node.verdict,
        VerdictDoc::Complete,
        "expected complete verdict for {expected}, got {:?} (error={:?})",
        node.verdict,
        node.error,
    );
    let size: u64 = node.output_size.unwrap_or(0);
    assert!(size > 0, "expected non-empty output for {expected}");
}

#[test]
fn real_extractor_jvm_classfile() {
    let Some(bytes): Option<Vec<u8>> = read_fixture("jvm/proguard/Hello-baseline.class") else {
        return;
    };
    let doc: ChainDocument = run_chain_auto(bytes, "corpus://jvm/Hello-baseline.class");
    assert_pass_id(&doc, "jvm.classify");
    assert_pass_completes(&doc, "jvm.classify");
}

#[test]
fn real_extractor_jvm_dex() {
    let Some(bytes): Option<Vec<u8>> = read_fixture("jvm/dex/Hello.dex") else {
        return;
    };
    let doc: ChainDocument = run_chain_auto(bytes, "corpus://jvm/Hello.dex");
    assert_pass_id(&doc, "jvm.classify");
    assert_pass_completes(&doc, "jvm.classify");
}

#[test]
fn real_extractor_dotnet_pe() {
    let Some(bytes): Option<Vec<u8>> = read_fixture("dotnet/HelloApp.dll") else {
        return;
    };
    let doc: ChainDocument = run_chain_auto(bytes, "corpus://dotnet/HelloApp.dll");
    let node: &disrobe_core::chain::NodeDoc =
        pick_first_pass_node(&doc).expect("must dispatch at least one pass");
    let pass: &str = node.pass.as_deref().unwrap_or("");
    assert!(
        pass == "dotnet.classify" || pass == "native.packer-unpack",
        "expected dotnet or packer pass, got {pass}",
    );
}

#[test]
fn real_extractor_beam_module() {
    let Some(bytes): Option<Vec<u8>> = read_fixture("beam/erlang/hello.beam") else {
        return;
    };
    let doc: ChainDocument = run_chain_auto(bytes, "corpus://beam/hello.beam");
    assert_pass_id(&doc, "beam.classify");
    assert_pass_completes(&doc, "beam.classify");
}

#[test]
fn real_extractor_lua_bytecode() {
    let Some(bytes): Option<Vec<u8>> = read_fixture("lua/luac/hello.5_3.luac") else {
        return;
    };
    let doc: ChainDocument = run_chain_auto(bytes, "corpus://lua/hello.5_3.luac");
    assert_pass_id(&doc, "lua.deob");
    assert_pass_completes(&doc, "lua.deob");
}

#[test]
fn real_extractor_wasm_module() {
    let Some(bytes): Option<Vec<u8>> = read_fixture("wasm/wat/custom_page_size.wasm") else {
        return;
    };
    let doc: ChainDocument = run_chain_auto(bytes, "corpus://wasm/module.wasm");
    assert_pass_id(&doc, "wasm.deob");
    assert_pass_completes(&doc, "wasm.deob");
}

#[test]
fn real_extractor_php_source() {
    let Some(bytes): Option<Vec<u8>> = read_fixture("php/baseline/hello.php") else {
        return;
    };
    let doc: ChainDocument = run_chain_auto(bytes, "corpus://php/hello.php");
    assert_pass_id(&doc, "php.peel");
    assert_pass_completes(&doc, "php.peel");
}

#[test]
fn real_extractor_ruby_yarv_binary() {
    let Some(bytes): Option<Vec<u8>> = read_fixture("ruby/mri/yarv/hello.rb.yarvc") else {
        return;
    };
    let doc: ChainDocument = run_chain_auto(bytes, "corpus://ruby/hello.rb.yarvc");
    assert_pass_id(&doc, "ruby.classify");
    assert_pass_completes(&doc, "ruby.classify");
}

#[test]
fn real_extractor_shell_bash() {
    let Some(bytes): Option<Vec<u8>> = read_fixture("shell/bash/bashfuscator/string/hello.sh")
    else {
        return;
    };
    let doc: ChainDocument = run_chain_auto(bytes, "corpus://shell/hello.sh");
    assert_pass_id(&doc, "shell.deob");
    assert_pass_completes(&doc, "shell.deob");
}

#[test]
fn real_extractor_py_decompile_cpython_pyc() {
    let candidates: [&str; 3] = [
        "python/decompile/playground/edge_cases_2_7.pyc",
        "python/decompile/playground/__pycache__/edge_cases.cpython-314.pyc",
        "python/decompile/playground/__pycache__/edge_cases_3_10.cpython-310.pyc",
    ];
    for rel in candidates {
        let Some(bytes): Option<Vec<u8>> = read_fixture(rel) else {
            continue;
        };
        let doc: ChainDocument = run_chain_auto(bytes, &format!("corpus://{rel}"));
        let node: &disrobe_core::chain::NodeDoc =
            pick_first_pass_node(&doc).expect("must dispatch a pyc-handling pass");
        let pass: &str = node.pass.as_deref().unwrap_or("");
        assert!(
            pass == "py.decompile" || pass == "py.disasm",
            "expected py.decompile or py.disasm for {rel}, got {pass}",
        );
        return;
    }
    eprintln!("SKIP: no cpython pyc fixtures available");
}

#[derive(Debug, Default)]
struct CapturingPassRunner {
    captured: std::sync::Mutex<BTreeMap<String, Vec<u8>>>,
}

impl PassRunner for CapturingPassRunner {
    fn run(
        &self,
        pick: &DetectorPick,
        bytes: &[u8],
        _config: &ChainConfig,
    ) -> Result<PassRunOutcome, String> {
        let artifact: Artifact = Artifact::new(Rung::Raw, bytes.to_vec(), blake3_hash(bytes));
        let started: Instant = Instant::now();
        let out_artifact: Artifact = pick.pass.run(&artifact).map_err(|e| format!("{e}"))?;
        let kind: OutputKind = pick.pass.output_kind(&out_artifact);
        let mut guard: std::sync::MutexGuard<'_, BTreeMap<String, Vec<u8>>> =
            self.captured.lock().expect("mutex");
        let _: Option<Vec<u8>> =
            guard.insert(pick.pass.id().to_owned(), out_artifact.envelope.clone());
        drop(guard);
        Ok(PassRunOutcome {
            output_bytes: out_artifact.envelope,
            kind,
            duration: started.elapsed(),
            metadata: BTreeMap::new(),
        })
    }
}

#[test]
fn real_extractor_py_decompile_3_12_emits_python_source() {
    let rel: &str = "python/decompile/playground/__pycache__/edge_cases_3_12.cpython-312.pyc";
    let Some(bytes): Option<Vec<u8>> = read_fixture(rel) else {
        eprintln!("SKIP: 3.12 pyc fixture missing");
        return;
    };
    let registry: PassRegistry = registry_full();
    let runner: CapturingPassRunner = CapturingPassRunner::default();
    let driver: ChainDriver<'_, CapturingPassRunner> =
        ChainDriver::new(&registry, &runner, ChainConfig::default());
    let spec: ChainSpec = ChainSpec::Auto { cap: 8 };
    let _plan: disrobe_core::chain::ChainPlan =
        driver.run(bytes, &spec, Some(format!("corpus://{rel}")));

    let envelope: Vec<u8> = {
        let captured: std::sync::MutexGuard<'_, BTreeMap<String, Vec<u8>>> =
            runner.captured.lock().expect("mutex");
        captured.get("py.decompile").cloned().unwrap_or_else(|| {
            panic!(
                "py.decompile not dispatched for {rel}; captured passes: {:?}",
                captured.keys().collect::<Vec<&String>>()
            )
        })
    };
    let source: &str = std::str::from_utf8(&envelope)
        .unwrap_or_else(|e: std::str::Utf8Error| panic!("py.decompile output is not utf-8: {e}"));
    assert!(
        !source.trim().is_empty(),
        "py.decompile emitted empty source for {rel}",
    );
    let lower: String = source.to_lowercase();
    let has_def: bool = source.contains("def ");
    let has_class: bool = source.contains("class ");
    let has_import: bool = lower.contains("import");
    let has_marker: bool = source.contains("# Decompiled")
        || source.contains("# Python ")
        || source.contains("# disrobe py.decompile");
    assert!(
        has_def || has_class || has_import || has_marker,
        "py.decompile output does not contain any recognizable python identifier or header marker; first 400 chars: {:?}",
        source.chars().take(400).collect::<String>(),
    );
    eprintln!(
        "py.decompile 3.12 output: {} bytes, first line: {:?}",
        source.len(),
        source.lines().next().unwrap_or("")
    );
}

#[test]
fn registry_has_all_14_real_extractors() {
    let r: PassRegistry = registry_full();
    for id in [
        "jvm.classify",
        "dotnet.classify",
        "go.classify",
        "beam.classify",
        "as3.classify",
        "mobile.classify",
        "ruby.classify",
        "swift-objc.classify",
        "php.peel",
        "shell.deob",
        "lua.deob",
        "wasm.deob",
        "py.disasm",
        "py.decompile",
    ] {
        assert!(r.get(id).is_some(), "missing pass {id}");
    }
}
