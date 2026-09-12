#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::uninlined_format_args,
    clippy::needless_raw_string_hashes
)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchFile;
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_js_deob::{ProtectorOptions, ProtectorOutput, arxan_deobfuscate as deob};

const NODE_TIMEOUT: Duration = Duration::from_secs(30);
const NODE_CAPTURE: usize = 1usize << 18;

const HOST_ORIGINAL: &str = r#"function accumulate(values) {
  var total = 0;
  for (var i = 0; i < values.length; i++) {
    if (values[i] % 2 === 0) { total += values[i] * 3; } else { total -= values[i]; }
  }
  return total;
}
function label(n) {
  if (n < 0) { return 'negative:' + n; }
  return 'positive:' + n;
}
console.log(accumulate([1, 2, 3, 4, 5, 6]));
console.log(label(accumulate([1, 2, 3, 4, 5, 6])));
console.log(label(-1));
console.log(typeof accumulate, typeof label);
"#;

const GUARDED_NESTED: &str = r#"/* (c) Digital.ai Application Protection * build 2024.1 */
function __guard_a1b2c3d4() {
  var k = atob('Q2hlY2tzdW1HdWFyZFRva2VuQUFBQQ==');
  if (k.length > 0) { return k.length; }
  return 0;
}
var __arxan_probe = [17, 34, 51, 68];
for (var __chk = 0; __chk < __arxan_probe.length; __chk++) {
  if (__arxan_probe[__chk] > 20) { __arxan_probe[__chk] ^= 0x42; } else { __arxan_probe[__chk] ^= 0x11; }
}
if (__arxan_integrity() !== 0xdeadbeef) {
  if (typeof console !== 'undefined') { console.log('tamper detected'); }
  throw new Error('tamper');
}
var _ARXAN_runtime_marker = __guard_a1b2c3d4();
function accumulate(values) {
  var total = 0;
  for (var i = 0; i < values.length; i++) {
    if (values[i] % 2 === 0) { total += values[i] * 3; } else { total -= values[i]; }
  }
  return total;
}
function label(n) {
  if (n < 0) { return 'negative:' + n; }
  return 'positive:' + n;
}
console.log(accumulate([1, 2, 3, 4, 5, 6]));
console.log(label(accumulate([1, 2, 3, 4, 5, 6])));
console.log(label(-1));
console.log(typeof accumulate, typeof label);
"#;

const SATISFYING_GUARD_STUB: &str = "function __arxan_integrity() { return 0xdeadbeef; }\n";

fn node_binary() -> PathBuf {
    let candidate: PathBuf = PathBuf::from("node");
    let probe: Option<CapturedOutput> = run_captured(
        candidate.as_path(),
        &["--version"],
        NODE_TIMEOUT,
        NODE_CAPTURE,
    )
    .unwrap_or_else(|err| {
        panic!(
            "node is the reference this grader is measured against and it could not be launched: \
             {err}. Install Node.js (CI provisions node 24 via actions/setup-node); this check \
             must fail rather than skip, because a skipped reference reports green while the \
             claim it backs goes unmeasured."
        )
    });
    let out: CapturedOutput = probe.unwrap_or_else(|| {
        panic!("node --version exceeded {NODE_TIMEOUT:?} without producing a version")
    });
    assert_eq!(
        out.exit_code,
        Some(0i32),
        "node --version must succeed for this grader to have a reference; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    candidate
}

fn parses_under_node(program: &str) -> Result<(), String> {
    let (scratch, mut file): (ScratchFile, std::fs::File) =
        ScratchFile::create("disrobe_arxan_check", "js").expect("scratch file");
    file.write_all(program.as_bytes()).expect("write program");
    drop(file);
    let path: PathBuf = scratch.path().to_path_buf();
    let node: PathBuf = node_binary();
    let args: [&str; 2] = ["--check", path.to_str().expect("utf-8 scratch path")];
    let captured: CapturedOutput = run_captured(node.as_path(), &args, NODE_TIMEOUT, NODE_CAPTURE)
        .expect("spawn node --check")
        .expect("node --check must finish inside the timeout");
    if captured.exit_code == Some(0i32) {
        return Ok(());
    }
    Err(String::from_utf8_lossy(&captured.stderr).into_owned())
}

fn run_under_node(program: &str) -> Result<String, String> {
    let (scratch, mut file): (ScratchFile, std::fs::File) =
        ScratchFile::create("disrobe_arxan_run", "js").expect("scratch file");
    file.write_all(program.as_bytes()).expect("write program");
    drop(file);
    let path: PathBuf = scratch.path().to_path_buf();
    let node: PathBuf = node_binary();
    let args: [&str; 1] = [path.to_str().expect("utf-8 scratch path")];
    let captured: CapturedOutput = run_captured(node.as_path(), &args, NODE_TIMEOUT, NODE_CAPTURE)
        .expect("spawn node")
        .expect("node must finish inside the timeout");
    if captured.exit_code == Some(0i32) {
        return Ok(String::from_utf8_lossy(&captured.stdout).into_owned());
    }
    Err(String::from_utf8_lossy(&captured.stderr).into_owned())
}

fn recover(protected: &str) -> ProtectorOutput {
    let opts: ProtectorOptions = ProtectorOptions {
        i_have_authorization: true,
    };
    deob(protected, &opts).expect("the guarded fixture must be recognized and peeled")
}

fn reference_stdout() -> String {
    run_under_node(HOST_ORIGINAL).expect("the pre-protection program must run under node")
}

#[test]
fn guarded_fixture_is_faithful_to_the_pre_protection_program() {
    let want: String = reference_stdout();
    let with_guard_satisfied: String = format!("{SATISFYING_GUARD_STUB}{GUARDED_NESTED}");
    let got: String = run_under_node(&with_guard_satisfied)
        .expect("the guarded fixture must run under node once its integrity callout is satisfied");
    assert_eq!(
        want, got,
        "the guarded fixture must wrap the pre-protection program without changing what it \
         prints, otherwise the recovery target is not the original program"
    );
}

#[test]
fn recovered_source_parses_under_real_node() {
    let out: ProtectorOutput = recover(GUARDED_NESTED);
    if let Err(stderr) = parses_under_node(&out.source) {
        panic!(
            "node rejected the recovered source, so the peel emitted broken JavaScript:\n\
             --node stderr--\n{stderr}\n--recovered--\n{}",
            out.source
        );
    }
}

#[test]
fn recovered_source_reproduces_the_pre_protection_stdout_under_real_node() {
    let want: String = reference_stdout();
    let out: ProtectorOutput = recover(GUARDED_NESTED);
    let got: String = run_under_node(&out.source).unwrap_or_else(|stderr| {
        panic!(
            "the recovered source must run standalone with no guard stub:\n\
             --node stderr--\n{stderr}\n--recovered--\n{}",
            out.source
        )
    });
    assert_eq!(
        want, got,
        "recovered stdout diverged from the committed pre-protection program\n--recovered--\n{}",
        out.source
    );
}

#[test]
fn recovered_source_keeps_no_guard_residue() {
    let out: ProtectorOutput = recover(GUARDED_NESTED);
    for residue in [
        "Digital.ai",
        "__guard_",
        "__chk",
        "__arxan_integrity",
        "tamper",
        "_ARXAN_runtime_marker",
    ] {
        assert!(
            !out.source.contains(residue),
            "{residue} survived the peel:\n{}",
            out.source
        );
    }
    assert!(out.stats.reversed >= 5usize, "stats={:?}", out.stats);
}

#[test]
fn the_node_differential_rejects_a_corrupted_recovery() {
    let want: String = reference_stdout();
    let out: ProtectorOutput = recover(GUARDED_NESTED);
    let corrupted: String = out
        .source
        .replacen("values[i] * 3", "values[i] * 4", 1usize);
    assert_ne!(
        corrupted, out.source,
        "the mutation must actually change the recovered source"
    );
    parses_under_node(&corrupted)
        .expect("the corrupted recovery must still parse, so the differential is behavioral");
    let got: String = run_under_node(&corrupted).expect("the corrupted recovery must still run");
    assert_ne!(
        want, got,
        "a deliberately wrong recovery produced the reference stdout, so this differential \
         cannot detect a wrong answer"
    );
}

#[test]
fn a_guard_body_holding_a_nested_block_is_not_half_removed() {
    let out: ProtectorOutput = recover(GUARDED_NESTED);
    let braces_open: usize = out.source.matches('{').count();
    let braces_close: usize = out.source.matches('}').count();
    assert_eq!(
        braces_open, braces_close,
        "the peel left unbalanced braces behind:\n{}",
        out.source
    );
}

#[test]
fn corpus_fixture_recovery_parses_and_keeps_the_real_work() {
    let fixture: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("js")
        .join("protectors")
        .join("arxan")
        .join("edge_cases_guarded.synth.js");
    let text: String = std::fs::read_to_string(&fixture)
        .unwrap_or_else(|err| panic!("missing fixture {}: {err}", fixture.display()));
    let out: ProtectorOutput = recover(&text);
    if let Err(stderr) = parses_under_node(&out.source) {
        panic!(
            "node rejected the recovered corpus fixture:\n--node stderr--\n{stderr}\n--recovered--\n{}",
            out.source
        );
    }
    assert!(out.source.contains("realWork"));
    assert!(!out.source.contains("__arxan_integrity"));
}
