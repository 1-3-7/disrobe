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
    ChainConfig, ChainDocument, ChainDriver, ChainPlan, ChainSpec, ChildArtifact, DetectorPick,
    ExtractedArtifact, OutputKind, PassRegistry, PassRunOutcome, PassToken,
};

#[derive(Debug)]
struct RealPassRunner;

impl PassRunner for RealPassRunner {
    fn run(
        &self,
        pick: &DetectorPick,
        bytes: Vec<u8>,
        _config: &ChainConfig,
        _path_hint: Option<&str>,
    ) -> Result<PassRunOutcome, String> {
        let hash: [u8; 32] = blake3_hash(&bytes);
        let artifact: Artifact = Artifact::new(Rung::Raw, bytes, hash);
        let started: Instant = Instant::now();
        let out_artifact: Artifact = pick.pass.run(&artifact).map_err(|e| format!("{e}"))?;
        let kind: OutputKind = pick.pass.output_kind(&out_artifact);
        let (kind, children): (OutputKind, Vec<Vec<u8>>) = if kind.is_mixed() {
            let extracted: Vec<ChildArtifact> = pick
                .pass
                .extract_children(&artifact)
                .map_err(|e| format!("{e}"))?;
            OutputKind::mixed_from_children(extracted)
        } else {
            (kind, Vec::new())
        };
        Ok(PassRunOutcome {
            output_bytes: out_artifact.envelope,
            kind,
            duration: started.elapsed(),
            metadata: BTreeMap::new(),
            children,
        })
    }
}

fn blake3_hash(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

fn registry_full() -> PassRegistry {
    disrobe_passes::build_registry()
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

fn assert_pass_fans_out_recovered_children(doc: &ChainDocument, expected: &str) {
    let node: &disrobe_core::chain::NodeDoc = pick_first_pass_node(doc)
        .unwrap_or_else(|| panic!("no pass node in chain doc for {expected}"));
    assert_eq!(
        node.verdict,
        VerdictDoc::FanOut,
        "expected fan-out verdict for {expected} (the pass now surfaces the recovered source plus \
         classify sidecars as children), got {:?} (error={:?})",
        node.verdict,
        node.error,
    );
    let recovered_children: usize = doc
        .nodes
        .iter()
        .filter(|n: &&disrobe_core::chain::NodeDoc| {
            n.parent_id == Some(node.id) && n.verdict == VerdictDoc::Extracted && n.input_size > 0
        })
        .count();
    assert!(
        recovered_children > 0,
        "expected {expected} to surface at least one non-empty recovered child",
    );
}

#[test]
fn real_extractor_jvm_classfile() {
    let Some(bytes): Option<Vec<u8>> = read_fixture("jvm/proguard/Hello-baseline.class") else {
        return;
    };
    let doc: ChainDocument = run_chain_auto(bytes, "corpus://jvm/Hello-baseline.class");
    assert_pass_id(&doc, "jvm.classify");
    assert_pass_fans_out_recovered_children(&doc, "jvm.classify");
}

#[test]
fn real_extractor_jvm_dex() {
    let Some(bytes): Option<Vec<u8>> = read_fixture("jvm/dex/Hello.dex") else {
        return;
    };
    let doc: ChainDocument = run_chain_auto(bytes, "corpus://jvm/Hello.dex");
    assert_pass_id(&doc, "jvm.classify");
    assert_pass_fans_out_recovered_children(&doc, "jvm.classify");
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
    assert_pass_fans_out_recovered_children(&doc, "lua.deob");
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
        bytes: Vec<u8>,
        _config: &ChainConfig,
        _path_hint: Option<&str>,
    ) -> Result<PassRunOutcome, String> {
        let hash: [u8; 32] = blake3_hash(&bytes);
        let artifact: Artifact = Artifact::new(Rung::Raw, bytes, hash);
        let started: Instant = Instant::now();
        let out_artifact: Artifact = pick.pass.run(&artifact).map_err(|e| format!("{e}"))?;
        let kind: OutputKind = pick.pass.output_kind(&out_artifact);
        let mut guard: std::sync::MutexGuard<'_, BTreeMap<String, Vec<u8>>> =
            self.captured.lock().expect("mutex");
        let _: Option<Vec<u8>> =
            guard.insert(pick.pass.id().to_owned(), out_artifact.envelope.clone());
        drop(guard);
        let (kind, children): (OutputKind, Vec<Vec<u8>>) = if kind.is_mixed() {
            let extracted: Vec<ChildArtifact> = pick
                .pass
                .extract_children(&artifact)
                .map_err(|e| format!("{e}"))?;
            OutputKind::mixed_from_children(extracted)
        } else {
            (kind, Vec::new())
        };
        Ok(PassRunOutcome {
            output_bytes: out_artifact.envelope,
            kind,
            duration: started.elapsed(),
            metadata: BTreeMap::new(),
            children,
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

fn capture_pass(bytes: Vec<u8>, source_path: &str, pass_id: &str) -> Option<Vec<u8>> {
    let registry: PassRegistry = registry_full();
    let runner: CapturingPassRunner = CapturingPassRunner::default();
    let driver: ChainDriver<'_, CapturingPassRunner> =
        ChainDriver::new(&registry, &runner, ChainConfig::default());
    let spec: ChainSpec = ChainSpec::Auto { cap: 8 };
    let _plan: disrobe_core::chain::ChainPlan =
        driver.run(bytes, &spec, Some(source_path.to_owned()));
    let captured: std::sync::MutexGuard<'_, BTreeMap<String, Vec<u8>>> =
        runner.captured.lock().expect("mutex");
    if !captured.contains_key(pass_id) {
        eprintln!(
            "pass {pass_id} not dispatched for {source_path}; captured: {:?}",
            captured.keys().collect::<Vec<&String>>()
        );
    }
    captured.get(pass_id).cloned()
}

fn utf8(envelope: &[u8], pass_id: &str) -> String {
    std::str::from_utf8(envelope)
        .unwrap_or_else(|e: std::str::Utf8Error| panic!("{pass_id} output is not utf-8: {e}"))
        .to_owned()
}

#[test]
fn real_extractor_dotnet_emits_csharp_source_not_summary() {
    let rel: &str = "dotnet/HelloApp.dll";
    let Some(bytes): Option<Vec<u8>> = read_fixture(rel) else {
        eprintln!("SKIP: dotnet fixture missing");
        return;
    };
    let Some(envelope): Option<Vec<u8>> =
        capture_pass(bytes, &format!("corpus://{rel}"), "dotnet.classify")
    else {
        eprintln!("SKIP: dotnet.classify not dispatched (packer pass may have won)");
        return;
    };
    let source: String = utf8(&envelope, "dotnet.classify");
    assert!(
        source.contains("native CIL->C#") && source.contains("// module:"),
        "dotnet chain output is not a C# decompilation; first 400: {:?}",
        source.chars().take(400).collect::<String>(),
    );
    assert!(
        !source.contains("\"pe_bitness\"") && !source.contains("\"opcode_table_size\""),
        "dotnet chain output still leaks the PassSummary analysis json",
    );
}

#[test]
fn real_extractor_jvm_dex_emits_java_source_not_summary() {
    let rel: &str = "jvm/dex/Hello.dex";
    let Some(bytes): Option<Vec<u8>> = read_fixture(rel) else {
        eprintln!("SKIP: dex fixture missing");
        return;
    };
    let envelope: Vec<u8> = capture_pass(bytes, &format!("corpus://{rel}"), "jvm.classify")
        .expect("jvm.classify must dispatch for a dex");
    let source: String = utf8(&envelope, "jvm.classify");
    assert!(
        source.contains("class ") || source.contains("interface "),
        "jvm dex chain output has no java type declaration; first 400: {:?}",
        source.chars().take(400).collect::<String>(),
    );
    assert!(
        !source.contains("\"smali_text\"") && !source.contains("\"method_body_count\""),
        "jvm dex chain output still leaks the JvmExtract summary json",
    );
}

#[test]
fn real_extractor_ruby_yarv_emits_ruby_source_not_analysis() {
    for rel in [
        "ruby/mri/yarv/greeter.rb.yarvc",
        "ruby/mri/yarv/hello.rb.yarvc",
    ] {
        let Some(bytes): Option<Vec<u8>> = read_fixture(rel) else {
            continue;
        };
        let envelope: Vec<u8> = capture_pass(bytes, &format!("corpus://{rel}"), "ruby.classify")
            .expect("ruby.classify must dispatch for a yarv binary");
        let source: String = utf8(&envelope, "ruby.classify");
        assert!(
            source.contains("yarv decompile") && source.contains("def "),
            "ruby yarv chain output is not recovered ruby; first 400: {:?}",
            source.chars().take(400).collect::<String>(),
        );
        assert!(
            !source.contains("\"flavor\"") && !source.contains("\"input_hash\""),
            "ruby yarv chain output still leaks the RubyAnalysis json for {rel}",
        );
        return;
    }
    eprintln!("SKIP: no ruby yarv fixtures available");
}

#[test]
fn real_extractor_swift_emits_swift_source_not_report() {
    let rel: &str = "mobile/macho-mac/SwiftHello.original";
    let Some(bytes): Option<Vec<u8>> = read_fixture(rel) else {
        eprintln!("SKIP: swift macho fixture missing");
        return;
    };
    let Some(envelope): Option<Vec<u8>> =
        capture_pass(bytes, &format!("corpus://{rel}"), "swift-objc.classify")
    else {
        eprintln!("SKIP: swift-objc.classify not dispatched");
        return;
    };
    let source: String = utf8(&envelope, "swift-objc.classify");
    let is_source: bool = source.contains("class ")
        || source.contains("struct ")
        || source.contains("enum ")
        || source.contains("@interface ");
    assert!(
        is_source && source.contains("class-dump (recovered reflection metadata)"),
        "swift chain output is not recovered swift/objc source; first 400: {:?}",
        source.chars().take(400).collect::<String>(),
    );
    assert!(
        !source.contains("\"container\"") && !source.contains("\"metadata_summary\""),
        "swift chain output still leaks the SwiftObjcReport json",
    );
}

#[test]
fn real_extractor_py_disasm_emits_listing_not_json() {
    for rel in [
        "python/decompile/legacy/compiled/binary_ops.3.11.pyc",
        "python/decompile/legacy/compiled/binary_slice.3.12.pyc",
    ] {
        let Some(bytes): Option<Vec<u8>> = read_fixture(rel) else {
            continue;
        };
        let Some(envelope): Option<Vec<u8>> =
            capture_pass(bytes, &format!("corpus://{rel}"), "py.disasm")
        else {
            continue;
        };
        let text: String = utf8(&envelope, "py.disasm");
        assert!(
            !text.trim_start().starts_with('{') && !text.contains("\"instruction_count\""),
            "py.disasm chain output still leaks the PyDisasmExtract json for {rel}; first 200: {:?}",
            text.chars().take(200).collect::<String>(),
        );
        assert!(
            text.contains("RESUME") || text.contains("LOAD") || text.contains("RETURN"),
            "py.disasm chain output has no recognizable cpython opcode for {rel}; first 200: {:?}",
            text.chars().take(200).collect::<String>(),
        );
        return;
    }
    eprintln!("SKIP: no cpython pyc fixtures available for py.disasm");
}

type NamedMember = (String, Vec<u8>);
type CapturedChildren = BTreeMap<String, Vec<NamedMember>>;

#[derive(Debug, Default)]
struct ChildCapturingRunner {
    children: std::sync::Mutex<CapturedChildren>,
}

impl PassRunner for ChildCapturingRunner {
    fn run(
        &self,
        pick: &DetectorPick,
        bytes: Vec<u8>,
        _config: &ChainConfig,
        _path_hint: Option<&str>,
    ) -> Result<PassRunOutcome, String> {
        let hash: [u8; 32] = blake3_hash(&bytes);
        let artifact: Artifact = Artifact::new(Rung::Raw, bytes, hash);
        let started: Instant = Instant::now();
        let out_artifact: Artifact = pick.pass.run(&artifact).map_err(|e| format!("{e}"))?;
        let kind: OutputKind = pick.pass.output_kind(&out_artifact);
        let (kind, children): (OutputKind, Vec<Vec<u8>>) = if kind.is_mixed() {
            let extracted: Vec<ChildArtifact> = pick
                .pass
                .extract_children(&artifact)
                .map_err(|e| format!("{e}"))?;
            let named: Vec<NamedMember> = extracted
                .iter()
                .map(|c: &ChildArtifact| (c.handle.relative_path.clone(), c.bytes.clone()))
                .collect();
            self.children
                .lock()
                .expect("mutex")
                .insert(pick.pass.id().to_owned(), named);
            OutputKind::mixed_from_children(extracted)
        } else {
            (kind, Vec::new())
        };
        Ok(PassRunOutcome {
            output_bytes: out_artifact.envelope,
            kind,
            duration: started.elapsed(),
            metadata: BTreeMap::new(),
            children,
        })
    }
}

fn synth_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write as _;
    let cursor: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(Vec::new());
    let mut zw: zip::ZipWriter<std::io::Cursor<Vec<u8>>> = zip::ZipWriter::new(cursor);
    let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default();
    for (name, body) in files {
        zw.start_file(*name, opts).expect("zip start");
        zw.write_all(body).expect("zip write");
    }
    zw.finish().expect("zip finish").into_inner()
}

#[test]
fn real_extractor_container_zip_carves_each_member_through_chain() {
    let members: [(&str, &[u8]); 3] = [
        ("alpha.txt", b"alpha member bytes"),
        ("pkg/beta.bin", b"beta-member-0123456789"),
        ("gamma", b""),
    ];
    let zip_bytes: Vec<u8> = synth_zip(&members);

    let registry: PassRegistry = registry_full();
    let runner: ChildCapturingRunner = ChildCapturingRunner::default();
    let driver: ChainDriver<'_, ChildCapturingRunner> =
        ChainDriver::new(&registry, &runner, ChainConfig::default());
    let spec: ChainSpec = ChainSpec::Explicit {
        passes: vec![PassToken::new("binfmt.container")],
    };
    let _plan: ChainPlan = driver.run(zip_bytes, &spec, Some("synth://members.zip".to_owned()));

    let carved: Vec<NamedMember> = {
        let captured: std::sync::MutexGuard<'_, CapturedChildren> =
            runner.children.lock().expect("mutex");
        captured
            .get("binfmt.container")
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "binfmt.container did not carve children; passes seen: {:?}",
                    captured.keys().collect::<Vec<&String>>()
                )
            })
    };
    assert_eq!(carved.len(), 3, "one child per stored zip member");
    for (name, body) in members {
        let found: &NamedMember = carved
            .iter()
            .find(|(n, _): &&NamedMember| n == name)
            .unwrap_or_else(|| panic!("member {name} not carved by the container chain"));
        assert_eq!(
            found.1, body,
            "carved bytes for {name} must match the original"
        );
    }
}

#[test]
fn real_extractor_pyfreeze_emits_manifest_not_input_unchanged() {
    let rel: &str = "python/freezers/shiv/hello.pyz";
    let Some(bytes): Option<Vec<u8>> = read_fixture(rel) else {
        eprintln!("SKIP: shiv pyz fixture missing");
        return;
    };
    let original: Vec<u8> = bytes.clone();
    let Some(envelope): Option<Vec<u8>> =
        capture_pass(bytes, &format!("corpus://{rel}"), "pyfreeze.extract")
    else {
        eprintln!("SKIP: pyfreeze.extract not dispatched (another pass may have won)");
        return;
    };
    assert_ne!(
        envelope, original,
        "pyfreeze chain output must be a manifest, not the input returned unchanged",
    );
    let text: String = utf8(&envelope, "pyfreeze.extract");
    assert!(
        !text.trim_start().starts_with('{') && text.starts_with("pyfreeze.extract"),
        "pyfreeze chain output must be the readable manifest; first 200: {:?}",
        text.chars().take(200).collect::<String>(),
    );
    assert!(
        text.contains("members=") && text.contains("bytes)"),
        "pyfreeze manifest must list the carved zip members; first 300: {:?}",
        text.chars().take(300).collect::<String>(),
    );
}

#[test]
fn real_extractor_go_emits_symbol_listing_not_json() {
    let fixture: PathBuf = {
        let mut p: PathBuf = workspace_root();
        p.push("crates");
        p.push("disrobe-pass-go");
        p.push("tests");
        p.push("fixtures");
        p.push("hello_normal.exe");
        p
    };
    let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(&fixture) else {
        eprintln!("SKIP: go fixture missing at {}", fixture.display());
        return;
    };
    let Some(envelope): Option<Vec<u8>> =
        capture_pass(bytes, "corpus://go/hello_normal.exe", "go.classify")
    else {
        eprintln!("SKIP: go.classify not dispatched");
        return;
    };
    let text: String = utf8(&envelope, "go.classify");
    assert!(
        !text.trim_start().starts_with('{') && !text.contains("\"image_kind\""),
        "go chain output must be the symbol listing, not the analysis json; first 200: {:?}",
        text.chars().take(200).collect::<String>(),
    );
    assert!(
        text.contains("func main.main") || text.contains("func runtime."),
        "go chain output has no recovered function symbols; first 400: {:?}",
        text.chars().take(400).collect::<String>(),
    );
}

#[test]
fn real_pyinstaller_auto_surfaces_native_disasm_for_bundled_pyd() {
    let Some(bytes): Option<Vec<u8>> =
        read_fixture("python/freezers/pyinstaller/gauntlet/hello.exe")
    else {
        return;
    };
    let registry: PassRegistry = registry_full();
    let runner: RealPassRunner = RealPassRunner;
    let config: ChainConfig = ChainConfig {
        persist_children: true,
        ..ChainConfig::default()
    };
    let driver: ChainDriver<'_, RealPassRunner> = ChainDriver::new(&registry, &runner, config);
    let plan: ChainPlan = driver.run(
        bytes,
        &ChainSpec::Auto { cap: 8 },
        Some("corpus://python/pyinstaller/hello.exe".to_owned()),
    );

    let asm_artifacts: Vec<&ExtractedArtifact> = plan
        .extracted
        .iter()
        .filter(|a: &&ExtractedArtifact| {
            a.relative_path.contains("native/")
                && std::path::Path::new(&a.relative_path)
                    .extension()
                    .is_some_and(|ext: &std::ffi::OsStr| ext.eq_ignore_ascii_case("asm"))
        })
        .collect();
    assert!(
        !asm_artifacts.is_empty(),
        "auto must surface native disasm for the bundled .pyd/.dll modules; got paths: {:?}",
        plan.extracted
            .iter()
            .map(|a: &ExtractedArtifact| a.relative_path.as_str())
            .collect::<Vec<&str>>(),
    );
    let has_real_x86: bool = asm_artifacts.iter().any(|a: &&ExtractedArtifact| {
        let asm: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&a.bytes);
        ["mov", "push", "call", "ret", "lea", "jmp", "pop", "test"]
            .iter()
            .any(|m: &&str| asm.contains(*m))
    });
    assert!(
        has_real_x86,
        "the auto-surfaced native disasm must contain real x86 mnemonics",
    );

    let has_recon: bool = plan.extracted.iter().any(|a: &ExtractedArtifact| {
        a.relative_path.contains("native/") && a.relative_path.ends_with(".recon.json")
    });
    assert!(
        has_recon,
        "auto must surface recon findings for the bundled native modules",
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

#[test]
fn real_extractor_dotnet_single_file_bundle_routes_its_assembly_to_the_cil_pass() {
    const REL: &str = "binfmt/dotnet-single-file/probe.v6.all-types.exe";
    let bytes: Vec<u8> = std::fs::read(corpus(REL)).unwrap_or_else(|e| {
        panic!(
            "corpus/{REL} is committed and must be readable, so a skip here would hide the \
             routing this test exists to prove: {e}"
        )
    });
    let doc: ChainDocument = run_chain_auto(bytes, "corpus://binfmt/probe.v6.all-types.exe");

    assert_pass_id(&doc, "binfmt.container");

    let container: &disrobe_core::chain::NodeDoc =
        pick_first_pass_node(&doc).expect("container node");
    assert_eq!(
        container.verdict,
        VerdictDoc::FanOut,
        "the container pass must fan the bundle out into its entries, got {:?} (error={:?})",
        container.verdict,
        container.error,
    );
    assert_eq!(
        container.format_tag_in.as_deref(),
        Some("dotnet-single-file"),
        "the bundle must be claimed as a .NET single-file container, not as a bare host binary",
    );

    let child_count: usize = doc
        .nodes
        .iter()
        .filter(|n: &&disrobe_core::chain::NodeDoc| n.parent_id == Some(container.id))
        .count();
    assert_eq!(child_count, 5, "every embedded entry becomes a child");

    let expected_managed: Vec<u8> =
        std::fs::read(corpus("binfmt/dotnet-single-file/expected/probe.dll"))
            .expect("tracked managed reference must be readable");
    let expected_native: Vec<u8> =
        std::fs::read(corpus("binfmt/dotnet-single-file/expected/libcustom.dll"))
            .expect("tracked native reference must be readable");
    let managed_hash: String = blake3::hash(&expected_managed).to_hex().to_string();
    let native_hash: String = blake3::hash(&expected_native).to_hex().to_string();
    assert!(
        doc.nodes.iter().any(|node: &disrobe_core::chain::NodeDoc| {
            node.input_blake3 == managed_hash && node.pass.as_deref() == Some("dotnet.classify")
        }),
        "the independently extracted managed assembly must reach the CIL pass through `auto`"
    );
    assert!(
        doc.nodes.iter().any(|node: &disrobe_core::chain::NodeDoc| {
            node.input_blake3 == native_hash
                && node.pass.as_deref() == Some("native.image-classify")
        }),
        "the independently extracted native member must reach the native image pass through `auto`"
    );
}
