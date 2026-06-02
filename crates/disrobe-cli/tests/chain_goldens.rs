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

use std::path::PathBuf;

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::chain_json::VerdictDoc;
use disrobe_core::chain::state_machine::PassRunner;
use disrobe_core::chain::{
    ChainConfig, ChainDocument, ChainDriver, ChainPlan, ChainSpec, DetectorPick, OutputKind,
    PassRegistry, PassRunOutcome,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

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
        let scrubbed: Vec<u8> = scrub_provenance_timing(out_artifact.envelope);
        Ok(PassRunOutcome {
            output_bytes: scrubbed,
            kind,
            duration: started.elapsed(),
            metadata: BTreeMap::new(),
        })
    }
}

fn scrub_provenance_timing(bytes: Vec<u8>) -> Vec<u8> {
    let Ok(text): Result<&str, std::str::Utf8Error> = std::str::from_utf8(&bytes) else {
        return bytes;
    };
    let needle: &str = " in ";
    let mut out: String = String::with_capacity(text.len());
    let mut cursor: usize = 0;
    while let Some(rel) = text[cursor..].find(needle) {
        let absolute: usize = cursor + rel;
        out.push_str(&text[cursor..absolute + needle.len()]);
        let tail: &str = &text[absolute + needle.len()..];
        let token_end: usize = tail.find([' ', '\n', '*', '\r']).unwrap_or(tail.len());
        let token: &str = &tail[..token_end];
        if is_duration_token(token) {
            out.push_str("0ms");
        } else {
            out.push_str(token);
        }
        cursor = absolute + needle.len() + token_end;
    }
    out.push_str(&text[cursor..]);
    out.replace("\r\n", "\n").into_bytes()
}

fn is_duration_token(token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    let lower: String = token.to_ascii_lowercase();
    let suffixes: [&str; 5] = ["ms", "s", "m", "h", "d"];
    let stripped: Option<&str> = suffixes.iter().find_map(|s: &&str| lower.strip_suffix(s));
    let Some(num): Option<&str> = stripped else {
        return lower == "5d+";
    };
    num.chars().all(|c: char| c.is_ascii_digit() || c == '.')
        && num.chars().any(|c: char| c.is_ascii_digit())
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

fn run_to_document(seed: Vec<u8>, spec: &ChainSpec, path: Option<String>) -> ChainDocument {
    let registry: PassRegistry = registry_full();
    let runner: RealPassRunner = RealPassRunner;
    let driver: ChainDriver<'_, RealPassRunner> =
        ChainDriver::new(&registry, &runner, ChainConfig::default());
    let plan: ChainPlan = driver.run(seed, spec, path.clone());
    ChainDocument::from_plan(&plan, spec, "auto:8", "0.1.0-golden", path)
}

fn scrub_timings(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if k == "total_ms" || k == "duration_ms" {
                    *v = Value::from(0u64);
                } else {
                    scrub_timings(v);
                }
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                scrub_timings(v);
            }
        }
        _ => {}
    }
}

fn scrub_errors(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if k == "error"
                    && let Value::String(s) = v
                {
                    *v = Value::String(scrub_error_text(s));
                    continue;
                }
                scrub_errors(v);
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                scrub_errors(v);
            }
        }
        _ => {}
    }
}

fn scrub_error_text(s: &str) -> String {
    let normalized: String = s.replace("\r\n", "\n").replace('\r', "");
    for marker in ["upx -d failed", "upx unpack failed", "exited with status"] {
        if let Some(idx) = normalized.find(marker) {
            return format!("{}{marker}", &normalized[..idx]);
        }
    }
    normalized
}

fn render_canonical(doc: &ChainDocument) -> String {
    let mut v: Value = serde_json::to_value(doc).expect("chain doc serializes");
    scrub_timings(&mut v);
    scrub_errors(&mut v);
    serde_json::to_string_pretty(&v).expect("canonical render")
}

fn workspace_root() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn golden_dir() -> PathBuf {
    let mut p: PathBuf = workspace_root();
    p.push("corpus");
    p.push("chain");
    p.push("goldens");
    p
}

fn synthetic_error_dir() -> PathBuf {
    golden_dir().join("synthetic_error")
}

fn golden_path(name: &str) -> PathBuf {
    golden_dir().join(format!("{name}.chain.json"))
}

fn synthetic_error_path(name: &str) -> PathBuf {
    synthetic_error_dir().join(format!("{name}.chain.json"))
}

fn corpus_fixture(rel: &[&str]) -> PathBuf {
    let mut p: PathBuf = workspace_root();
    p.push("corpus");
    for seg in rel {
        p.push(seg);
    }
    p
}

fn load_corpus(rel: &[&str]) -> Option<Vec<u8>> {
    std::fs::read(corpus_fixture(rel)).ok()
}

fn assert_golden_at(path: &PathBuf, name: &str, doc: &ChainDocument) {
    let actual: String = render_canonical(doc);
    if !path.exists() {
        std::fs::create_dir_all(path.parent().expect("dir")).expect("create goldens dir");
        std::fs::write(path, &actual).expect("seed golden");
        eprintln!("SEED golden written: {path:?}");
        return;
    }
    let raw: String = std::fs::read_to_string(path)
        .unwrap_or_else(|e: std::io::Error| panic!("read golden {path:?}: {e}"));
    let expected: String = raw.replace("\r\n", "\n");
    if expected != actual {
        let actual_path: PathBuf = path.with_extension("actual.json");
        std::fs::write(&actual_path, &actual).expect("write actual snapshot");
        let at: usize = expected
            .bytes()
            .zip(actual.bytes())
            .position(|(a, b): (u8, u8)| a != b)
            .unwrap_or_else(|| expected.len().min(actual.len()));
        let lo: usize = at.saturating_sub(60);
        eprintln!(
            "GOLDEN-DIFF {name} @byte {at} (exp_len={} act_len={}):\n  exp: {:?}\n  act: {:?}",
            expected.len(),
            actual.len(),
            expected
                .get(lo..(at + 80).min(expected.len()))
                .unwrap_or(""),
            actual.get(lo..(at + 80).min(actual.len())).unwrap_or("")
        );
        panic!("golden mismatch for {name}: expected={path:?} actual={actual_path:?}");
    }
}

fn assert_golden(name: &str, doc: &ChainDocument) {
    assert_golden_at(&golden_path(name), name, doc);
}

fn assert_synthetic_error_golden(name: &str, doc: &ChainDocument) {
    assert_golden_at(&synthetic_error_path(name), name, doc);
}

fn upx_packed_pe_fixture() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::with_capacity(2048);
    v.extend_from_slice(b"MZ");
    v.extend(std::iter::repeat_n(0u8, 58));
    v.extend_from_slice(&0x80u32.to_le_bytes());
    v.extend(std::iter::repeat_n(0u8, 64));
    v.extend_from_slice(b"PE\0\0");
    v.extend(std::iter::repeat_n(0u8, 256));
    v.extend_from_slice(b"UPX!\x0d\x09\x02\x00");
    v.extend_from_slice(b"UPX0UPX1UPX2");
    v.extend(std::iter::repeat_n(0u8, 1536));
    v
}

fn pyc_311_fixture() -> Vec<u8> {
    let magic: u16 = 3495;
    let mut v: Vec<u8> = Vec::with_capacity(16);
    v.extend_from_slice(&magic.to_le_bytes());
    v.extend_from_slice(&[0x0d, 0x0a, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]);
    v
}

fn js_obfuscator_fixture() -> Vec<u8> {
    b"// obfuscator.io output\nvar _0xabcd = function(){};\n_0xabcd();\n".to_vec()
}

fn jvm_classfile_fixture() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::with_capacity(16);
    v.extend_from_slice(&0xCAFE_BABEu32.to_be_bytes());
    v.extend_from_slice(&[0u8, 0u8, 0u8, 65u8]);
    v.extend(std::iter::repeat_n(0u8, 8));
    v
}

fn beam_fixture() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::with_capacity(32);
    v.extend_from_slice(b"FOR1");
    v.extend_from_slice(&64u32.to_be_bytes());
    v.extend_from_slice(b"BEAM");
    v.extend(std::iter::repeat_n(0u8, 16));
    v
}

fn dry_run_fixture() -> Vec<u8> {
    b"any-input-bytes-for-plan-only".to_vec()
}

#[test]
fn golden_pyc_to_python() {
    let spec: ChainSpec = ChainSpec::Auto { cap: 8 };
    let Some(seed): Option<Vec<u8>> = load_corpus(&[
        "python",
        "decompile",
        "playground",
        "__pycache__",
        "edge_cases_3_12.cpython-312.pyc",
    ]) else {
        eprintln!("skip: corpus fixture absent");
        return;
    };
    let doc: ChainDocument = run_to_document(
        seed,
        &spec,
        Some(
            "corpus://python/decompile/playground/__pycache__/edge_cases_3_12.cpython-312.pyc"
                .to_string(),
        ),
    );
    assert_golden("pyc_to_python", &doc);
}

#[test]
fn golden_js_obfuscator_to_source() {
    let spec: ChainSpec = ChainSpec::Auto { cap: 8 };
    let doc: ChainDocument = run_to_document(
        js_obfuscator_fixture(),
        &spec,
        Some("synthetic://obfuscated.js".to_string()),
    );
    assert_golden("js_obfuscator_to_source", &doc);
}

#[test]
fn golden_upx_packed_pe() {
    let spec: ChainSpec = ChainSpec::Auto { cap: 8 };
    let doc: ChainDocument = run_to_document(
        upx_packed_pe_fixture(),
        &spec,
        Some("synthetic://packed.upx.exe".to_string()),
    );
    assert_golden("upx_packed_pe", &doc);
}

#[test]
fn golden_jvm_classfile() {
    let spec: ChainSpec = ChainSpec::Auto { cap: 8 };
    let Some(seed): Option<Vec<u8>> = load_corpus(&["jvm", "proguard", "Hello-baseline.class"])
    else {
        eprintln!("skip: corpus fixture absent");
        return;
    };
    let doc: ChainDocument = run_to_document(
        seed,
        &spec,
        Some("corpus://jvm/proguard/Hello-baseline.class".to_string()),
    );
    assert_golden("jvm_classfile", &doc);
}

#[test]
fn golden_wasm_module() {
    let spec: ChainSpec = ChainSpec::Auto { cap: 8 };
    let Some(seed): Option<Vec<u8>> = load_corpus(&["wasm", "wat", "function_refs.wasm"]) else {
        eprintln!("skip: corpus fixture absent");
        return;
    };
    let doc: ChainDocument = run_to_document(
        seed,
        &spec,
        Some("corpus://wasm/wat/function_refs.wasm".to_string()),
    );
    assert_golden("wasm_module", &doc);
}

#[test]
fn golden_beam_module() {
    let spec: ChainSpec = ChainSpec::Auto { cap: 8 };
    let Some(seed): Option<Vec<u8>> = load_corpus(&["beam", "erlang", "hello.beam"]) else {
        eprintln!("skip: corpus fixture absent");
        return;
    };
    let doc: ChainDocument = run_to_document(
        seed,
        &spec,
        Some("corpus://beam/erlang/hello.beam".to_string()),
    );
    assert_golden("beam_module", &doc);
}

#[test]
fn golden_beam_edge_cases_module() {
    let spec: ChainSpec = ChainSpec::Auto { cap: 8 };
    let Some(seed): Option<Vec<u8>> = load_corpus(&["beam", "megafile", "edge_cases.beam"]) else {
        eprintln!("skip: corpus fixture absent");
        return;
    };
    let doc: ChainDocument = run_to_document(
        seed,
        &spec,
        Some("corpus://beam/megafile/edge_cases.beam".to_string()),
    );
    assert_eq!(
        doc.verdict,
        VerdictDoc::Complete,
        "edge_cases.beam (uses opcode 182 bs_match) must chain to complete; got {:?}",
        doc.verdict,
    );
    assert_golden("beam_edge_cases_module", &doc);
}

#[test]
fn synthetic_error_pyc_truncated() {
    let spec: ChainSpec = ChainSpec::Auto { cap: 8 };
    let doc: ChainDocument = run_to_document(
        pyc_311_fixture(),
        &spec,
        Some("synthetic://pyc-3.11".to_string()),
    );
    assert_eq!(
        doc.verdict,
        VerdictDoc::Error,
        "synthetic truncated pyc must error"
    );
    assert_synthetic_error_golden("pyc_to_python", &doc);
}

#[test]
fn synthetic_error_jvm_classfile_truncated() {
    let spec: ChainSpec = ChainSpec::Auto { cap: 8 };
    let doc: ChainDocument = run_to_document(
        jvm_classfile_fixture(),
        &spec,
        Some("synthetic://Hello.class".to_string()),
    );
    assert_eq!(
        doc.verdict,
        VerdictDoc::Error,
        "synthetic truncated classfile must error"
    );
    assert_synthetic_error_golden("jvm_classfile", &doc);
}

#[test]
fn synthetic_error_beam_bad_length() {
    let spec: ChainSpec = ChainSpec::Auto { cap: 8 };
    let doc: ChainDocument = run_to_document(
        beam_fixture(),
        &spec,
        Some("synthetic://module.beam".to_string()),
    );
    assert_eq!(
        doc.verdict,
        VerdictDoc::Error,
        "synthetic malformed beam must error"
    );
    assert_synthetic_error_golden("beam_module", &doc);
}

#[test]
fn golden_dry_run_plan_only() {
    let spec: ChainSpec = ChainSpec::PlanOnly { cap: 4 };
    let doc: ChainDocument = run_to_document(
        dry_run_fixture(),
        &spec,
        Some("synthetic://plan-only".to_string()),
    );
    assert_golden("dry_run_plan_only", &doc);
}

#[test]
fn golden_explicit_chain_pyarmor_pin() {
    let spec: ChainSpec = ChainSpec::parse("pyarmor.unpack,*").expect("spec parses");
    let doc: ChainDocument = run_to_document(
        pyc_311_fixture(),
        &spec,
        Some("synthetic://pyc-with-pin".to_string()),
    );
    assert_golden("explicit_chain_pyarmor_pin", &doc);
}

#[test]
fn snapshot_is_byte_identical_across_two_runs() {
    let spec: ChainSpec = ChainSpec::Auto { cap: 8 };
    let a: String = render_canonical(&run_to_document(
        pyc_311_fixture(),
        &spec,
        Some("synthetic://twice".to_string()),
    ));
    let b: String = render_canonical(&run_to_document(
        pyc_311_fixture(),
        &spec,
        Some("synthetic://twice".to_string()),
    ));
    assert_eq!(
        a, b,
        "chain.json must be byte-identical across runs once timings scrubbed"
    );
}

const _: Duration = Duration::from_secs(0);
