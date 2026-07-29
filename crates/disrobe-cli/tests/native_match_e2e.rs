#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::indexing_slicing
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use serde_json::Value;

const CLEAN: &str = "corpus/native/obfuscators/guardian-rs/sample.clean.exe";

const VARIANT: &str = "corpus/native/obfuscators/guardian-rs/sample.virtualized.exe";

const STAGES: [&str; 3] = ["data-reference", "control-flow", "propagation"];

fn workspace_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root
}

fn cli_binary() -> PathBuf {
    let mut binary: PathBuf = workspace_root();
    binary.push("target");
    binary.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    binary.push(if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    });
    binary
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run_match(args: &[&str]) -> Run {
    let binary: PathBuf = cli_binary();
    assert!(
        binary.exists(),
        "disrobe binary missing at {}; run `cargo build -p disrobe-cli --bin disrobe` first",
        binary.display()
    );
    let mut command: Command = Command::new(&binary);
    command.arg("native").arg("match").args(args);
    let output: Output = command
        .env_remove("RUST_LOG")
        .env_remove("DISROBE_LOG")
        .output()
        .expect("spawn disrobe native match");
    let run: Run = Run {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    };
    assert!(
        !run.stderr.contains("panicked at"),
        "the command panicked: {}",
        run.stderr
    );
    run
}

fn fixture(relative: &str) -> Option<PathBuf> {
    let path: PathBuf = workspace_root().join(relative);
    if path.is_file() {
        return Some(path);
    }
    eprintln!("skipping: the committed fixture {relative} is absent from this checkout");
    None
}

fn report_of(a: &Path, b: &Path) -> Value {
    let run: Run = run_match(&[
        "--json",
        a.to_str().expect("fixture path is utf-8"),
        b.to_str().expect("fixture path is utf-8"),
    ]);
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    serde_json::from_str(&run.stdout).expect("--json must emit one JSON document on stdout")
}

fn verdicts_of<'a>(report: &'a Value, side: &str) -> &'a Vec<Value> {
    report[side]
        .as_array()
        .unwrap_or_else(|| panic!("{side} must be an array"))
}

fn kind_of(verdict: &Value) -> &str {
    verdict["verdict"]
        .as_str()
        .expect("every verdict names the stage or the refusal that produced it")
}

fn put16(image: &mut [u8], at: usize, value: u16) {
    image[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(image: &mut [u8], at: usize, value: u32) {
    image[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(image: &mut [u8], at: usize, value: u64) {
    image[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn elf64_without_code() -> Vec<u8> {
    const HEADER_BYTES: usize = 64;
    const SECTION_ENTRY_BYTES: usize = 64;
    const NAMES: &[u8] = b"\0.shstrtab\0";
    let names_at: usize = HEADER_BYTES + SECTION_ENTRY_BYTES * 2;
    let mut image: Vec<u8> = vec![0u8; names_at + NAMES.len()];
    image[..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    put16(&mut image, 16, 2);
    put16(&mut image, 18, 0x3e);
    put32(&mut image, 20, 1);
    put64(&mut image, 40, HEADER_BYTES as u64);
    put16(&mut image, 52, HEADER_BYTES as u16);
    put16(&mut image, 54, 56);
    put16(&mut image, 58, SECTION_ENTRY_BYTES as u16);
    put16(&mut image, 60, 2);
    put16(&mut image, 62, 1);
    let strings: usize = HEADER_BYTES + SECTION_ENTRY_BYTES;
    put32(&mut image, strings, 1);
    put32(&mut image, strings + 4, 3);
    put64(&mut image, strings + 24, names_at as u64);
    put64(&mut image, strings + 32, NAMES.len() as u64);
    put64(&mut image, strings + 48, 1);
    image[names_at..].copy_from_slice(NAMES);
    image
}

fn scratch() -> ScratchDir {
    ScratchDir::create("disrobe-native-match").expect("create scratch directory")
}

#[test]
fn an_image_pairs_every_function_it_can_key_with_itself() {
    let Some(clean): Option<PathBuf> = fixture(CLEAN) else {
        return;
    };
    let report: Value = report_of(&clean, &clean);
    let pairs: u64 = report["pairs"].as_u64().expect("pairs");
    assert!(pairs > 0, "an image must pair with itself: {report}");
    let functions: u64 = report["a_side"]["functions"].as_u64().expect("functions");
    assert!(
        pairs * 2 > functions,
        "an image paired only {pairs} of its {functions} functions with itself"
    );
    for verdict in verdicts_of(&report, "a_verdicts") {
        if !STAGES.contains(&kind_of(verdict)) {
            continue;
        }
        assert_eq!(
            verdict["subject"], verdict["counterpart"],
            "an image must pair a function with itself, not with a different one: {verdict}"
        );
    }
}

#[test]
fn every_pair_carries_the_evidence_of_the_stage_that_produced_it() {
    let (Some(clean), Some(variant)): (Option<PathBuf>, Option<PathBuf>) =
        (fixture(CLEAN), fixture(VARIANT))
    else {
        return;
    };
    let report: Value = report_of(&clean, &variant);
    let mut seen: Vec<&str> = Vec::new();
    for verdict in verdicts_of(&report, "a_verdicts") {
        match kind_of(verdict) {
            "data-reference" => {
                let shared: &Vec<Value> = verdict["shared_references"]
                    .as_array()
                    .expect("a data reference pair names the references it shares");
                assert!(!shared.is_empty(), "{verdict}");
                assert!(verdict["anchor_strength"].is_string(), "{verdict}");
                for reference in shared {
                    assert!(reference["kind"].is_string(), "{reference}");
                }
                seen.push("data-reference");
            }
            "control-flow" => {
                assert!(verdict["fingerprint"].is_u64(), "{verdict}");
                let mix: &Vec<Value> = verdict["instruction_mix"]
                    .as_array()
                    .expect("a control flow pair names its instruction mix");
                assert!(!mix.is_empty(), "{verdict}");
                seen.push("control-flow");
            }
            "propagation" => {
                assert!(verdict["anchor"].is_u64(), "{verdict}");
                assert!(verdict["anchor_counterpart"].is_u64(), "{verdict}");
                assert!(verdict["hops"].is_u64(), "{verdict}");
                let relation: &str = verdict["relation"].as_str().expect("relation");
                assert!(matches!(relation, "callee" | "caller"), "{verdict}");
                seen.push("propagation");
            }
            "ambiguous" | "unmatched" => {}
            other => panic!("unknown verdict {other}: {verdict}"),
        }
    }
    for stage in STAGES {
        assert!(
            seen.contains(&stage),
            "this pair must exercise the {stage} stage, saw {seen:?}"
        );
    }
}

#[test]
fn a_refusal_is_reported_with_its_candidates_rather_than_dropped() {
    let (Some(clean), Some(variant)): (Option<PathBuf>, Option<PathBuf>) =
        (fixture(CLEAN), fixture(VARIANT))
    else {
        return;
    };
    let report: Value = report_of(&clean, &variant);
    let ambiguous: u64 = report["a_side"]["ambiguous"].as_u64().expect("ambiguous");
    assert!(ambiguous > 0, "this pair must produce a refusal: {report}");

    let mut counted: u64 = 0;
    for verdict in verdicts_of(&report, "a_verdicts") {
        match kind_of(verdict) {
            "ambiguous" => {
                let candidates: &Vec<Value> = verdict["candidates"]
                    .as_array()
                    .expect("an ambiguous verdict names its candidates");
                assert!(!candidates.is_empty(), "{verdict}");
                assert!(verdict["own_side"].is_u64(), "{verdict}");
                assert!(verdict["other_side"].is_u64(), "{verdict}");
                counted += 1;
            }
            "unmatched" => {
                let cause: &str = verdict["cause"].as_str().expect("cause");
                assert!(
                    matches!(
                        cause,
                        "no-anchor" | "no-candidate" | "duplicate-function-id"
                    ),
                    "{verdict}"
                );
            }
            _ => {}
        }
    }
    assert_eq!(counted, ambiguous, "the count must match the rows");

    let run: Run = run_match(&[
        clean.to_str().expect("utf-8"),
        variant.to_str().expect("utf-8"),
    ]);
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    assert!(run.stdout.contains("refusal ambiguous"), "{}", run.stdout);
    assert!(run.stdout.contains("candidates: 0x"), "{}", run.stdout);
}

#[test]
fn text_listing_controls_bound_rows_select_verdicts_and_leave_json_complete() {
    let (Some(clean), Some(variant)): (Option<PathBuf>, Option<PathBuf>) =
        (fixture(CLEAN), fixture(VARIANT))
    else {
        return;
    };
    let report: Value = report_of(&clean, &variant);
    let default_run: Run = run_match(&[
        clean.to_str().expect("utf-8"),
        variant.to_str().expect("utf-8"),
    ]);
    assert_eq!(default_run.code, 0, "stderr: {}", default_run.stderr);
    assert!(
        default_run.stdout.contains("withheld listing rows:"),
        "{}",
        default_run.stdout
    );

    let limited_run: Run = run_match(&[
        clean.to_str().expect("utf-8"),
        variant.to_str().expect("utf-8"),
        "--limit",
        "1",
    ]);
    assert_eq!(limited_run.code, 0, "stderr: {}", limited_run.stderr);
    assert!(
        limited_run.stdout.contains("withheld listing rows:"),
        "{}",
        limited_run.stdout
    );

    let data_reference: &Value = verdicts_of(&report, "a_verdicts")
        .iter()
        .find(|verdict: &&Value| kind_of(verdict) == "data-reference")
        .expect("fixture carries a data-reference pair");
    let subject: u64 = data_reference["subject"].as_u64().expect("subject");
    let address: String = format!("0x{subject:x}");
    let function_run: Run = run_match(&[
        clean.to_str().expect("utf-8"),
        variant.to_str().expect("utf-8"),
        "--limit",
        "0",
        "--function",
        &address,
    ]);
    assert_eq!(function_run.code, 0, "stderr: {}", function_run.stderr);
    assert!(
        function_run
            .stdout
            .contains(&format!("function {address} on a:")),
        "{}",
        function_run.stdout
    );
    assert!(
        function_run.stdout.contains("data reference"),
        "{}",
        function_run.stdout
    );
    assert!(
        !function_run.stdout.contains("withheld listing rows:"),
        "{}",
        function_run.stdout
    );

    let propagation_run: Run = run_match(&[
        clean.to_str().expect("utf-8"),
        variant.to_str().expect("utf-8"),
        "--stage",
        "propagation",
        "--limit",
        "1000",
    ]);
    assert_eq!(
        propagation_run.code, 0,
        "stderr: {}",
        propagation_run.stderr
    );
    let propagation_rows: Vec<&str> = propagation_run
        .stdout
        .lines()
        .filter(|line: &&str| line.starts_with("    a 0x"))
        .collect();
    assert!(!propagation_rows.is_empty(), "{}", propagation_run.stdout);
    assert!(
        propagation_rows
            .iter()
            .all(|line: &&str| line.contains("propagation")),
        "{}",
        propagation_run.stdout
    );

    let refused_run: Run = run_match(&[
        clean.to_str().expect("utf-8"),
        variant.to_str().expect("utf-8"),
        "--stage",
        "refused",
        "--limit",
        "1000",
    ]);
    assert_eq!(refused_run.code, 0, "stderr: {}", refused_run.stderr);
    let refusal_rows: Vec<&str> = refused_run
        .stdout
        .lines()
        .filter(|line: &&str| line.starts_with("    a 0x") || line.starts_with("    b 0x"))
        .collect();
    assert!(!refusal_rows.is_empty(), "{}", refused_run.stdout);
    assert!(
        refusal_rows
            .iter()
            .all(|line: &&str| line.contains("refusal")),
        "{}",
        refused_run.stdout
    );

    let json_run: Run = run_match(&[
        "--json",
        "--limit",
        "0",
        "--stage",
        "refused",
        clean.to_str().expect("utf-8"),
        variant.to_str().expect("utf-8"),
    ]);
    assert_eq!(json_run.code, 0, "stderr: {}", json_run.stderr);
    let filtered_json: Value = serde_json::from_str(&json_run.stdout).expect("json report");
    assert_eq!(filtered_json, report, "--json must keep every verdict");
}

#[test]
fn malformed_listing_selectors_are_diagnostics_not_panics() {
    let (Some(clean), Some(variant)): (Option<PathBuf>, Option<PathBuf>) =
        (fixture(CLEAN), fixture(VARIANT))
    else {
        return;
    };
    let function_run: Run = run_match(&[
        clean.to_str().expect("utf-8"),
        variant.to_str().expect("utf-8"),
        "--function",
        "not-an-address",
    ]);
    assert_ne!(function_run.code, 0, "stdout: {}", function_run.stdout);
    assert!(
        function_run.stderr.contains("invalid value"),
        "{}",
        function_run.stderr
    );
    assert!(
        !function_run.stderr.contains("panicked at"),
        "{}",
        function_run.stderr
    );

    let absent_run: Run = run_match(&[
        clean.to_str().expect("utf-8"),
        variant.to_str().expect("utf-8"),
        "--function",
        "0xffffffffffffffff",
    ]);
    assert_ne!(absent_run.code, 0, "stdout: {}", absent_run.stdout);
    assert!(
        absent_run.stderr.contains("DR-NATIVE-0208"),
        "{}",
        absent_run.stderr
    );
    assert!(
        !absent_run.stderr.contains("panicked at"),
        "{}",
        absent_run.stderr
    );

    let stage_run: Run = run_match(&[
        clean.to_str().expect("utf-8"),
        variant.to_str().expect("utf-8"),
        "--stage",
        "unknown-stage",
    ]);
    assert_ne!(stage_run.code, 0, "stdout: {}", stage_run.stdout);
    assert!(
        stage_run.stderr.contains("invalid value"),
        "{}",
        stage_run.stderr
    );
    assert!(
        !stage_run.stderr.contains("panicked at"),
        "{}",
        stage_run.stderr
    );
}

#[test]
fn the_counts_account_for_every_function_on_both_sides() {
    let (Some(clean), Some(variant)): (Option<PathBuf>, Option<PathBuf>) =
        (fixture(CLEAN), fixture(VARIANT))
    else {
        return;
    };
    let report: Value = report_of(&clean, &variant);
    let pairs: u64 = report["pairs"].as_u64().expect("pairs");
    let staged: u64 = STAGES
        .iter()
        .map(|stage: &&str| {
            report["by_stage"][stage.replace('-', "_")]
                .as_u64()
                .unwrap_or_else(|| panic!("by_stage misses {stage}"))
        })
        .sum();
    assert_eq!(pairs, staged, "the stage counts must add up to the pairs");

    for (side, rows) in [("a_side", "a_verdicts"), ("b_side", "b_verdicts")] {
        let refused: u64 = report[side]["refused"].as_u64().expect("refused");
        let functions: u64 = report[side]["functions"].as_u64().expect("functions");
        let without_evidence: u64 = report[side]["without_evidence"]
            .as_u64()
            .expect("without_evidence");
        assert!(without_evidence <= functions, "{side}");
        let subjects: u64 = verdicts_of(&report, rows).len() as u64;
        assert_eq!(
            pairs + refused,
            subjects,
            "{side} must account for every subject it reports"
        );
    }
}

#[test]
fn the_report_is_written_when_an_out_path_is_given() {
    let (Some(clean), Some(variant)): (Option<PathBuf>, Option<PathBuf>) =
        (fixture(CLEAN), fixture(VARIANT))
    else {
        return;
    };
    let dir: ScratchDir = scratch();
    let out: PathBuf = dir.path().join("nested").join("match.json");
    let run: Run = run_match(&[
        clean.to_str().expect("utf-8"),
        variant.to_str().expect("utf-8"),
        "--out",
        out.to_str().expect("utf-8"),
    ]);
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    assert!(run.stdout.contains("wrote:"), "{}", run.stdout);
    let written: String = std::fs::read_to_string(&out).expect("the report must be on disk");
    let report: Value = serde_json::from_str(&written).expect("the written report must be json");
    assert_eq!(report["schema"], "disrobe.native.match/v1");
}

#[test]
fn a_file_that_is_not_an_object_file_is_refused_with_a_diagnostic() {
    let Some(clean): Option<PathBuf> = fixture(CLEAN) else {
        return;
    };
    let dir: ScratchDir = scratch();
    let plain: PathBuf = dir.path().join("plain.txt");
    std::fs::write(&plain, b"this is not an object file, just plain text\n").expect("write");
    let run: Run = run_match(&[
        plain.to_str().expect("utf-8"),
        clean.to_str().expect("utf-8"),
    ]);
    assert_ne!(run.code, 0, "stdout: {}", run.stdout);
    assert!(run.stderr.contains("DR-NATIVE-0202"), "{}", run.stderr);
}

#[test]
fn a_truncated_image_is_refused_with_a_diagnostic() {
    let Some(clean): Option<PathBuf> = fixture(CLEAN) else {
        return;
    };
    let dir: ScratchDir = scratch();
    let whole: Vec<u8> = std::fs::read(&clean).expect("read the fixture");
    let cut: PathBuf = dir.path().join("truncated.exe");
    std::fs::write(&cut, &whole[..whole.len() / 32]).expect("write");
    let run: Run = run_match(&[clean.to_str().expect("utf-8"), cut.to_str().expect("utf-8")]);
    assert_ne!(run.code, 0, "stdout: {}", run.stdout);
    assert!(run.stderr.contains("DR-NATIVE-0203"), "{}", run.stderr);
}

#[test]
fn an_image_that_parses_but_carries_no_function_is_refused_with_a_diagnostic() {
    let Some(clean): Option<PathBuf> = fixture(CLEAN) else {
        return;
    };
    let dir: ScratchDir = scratch();
    let bare: PathBuf = dir.path().join("no-code.elf");
    std::fs::write(&bare, elf64_without_code()).expect("write");
    let run: Run = run_match(&[
        bare.to_str().expect("utf-8"),
        clean.to_str().expect("utf-8"),
    ]);
    assert_ne!(run.code, 0, "stdout: {}", run.stdout);
    assert!(run.stderr.contains("DR-NATIVE-020"), "{}", run.stderr);
    assert!(
        run.stderr.contains("executable section"),
        "the diagnostic must say what the image lacks: {}",
        run.stderr
    );
}

#[test]
fn a_missing_input_is_refused_with_a_diagnostic() {
    let Some(clean): Option<PathBuf> = fixture(CLEAN) else {
        return;
    };
    let dir: ScratchDir = scratch();
    let absent: PathBuf = dir.path().join("absent.exe");
    let run: Run = run_match(&[
        absent.to_str().expect("utf-8"),
        clean.to_str().expect("utf-8"),
    ]);
    assert_ne!(run.code, 0, "stdout: {}", run.stdout);
    assert!(run.stderr.contains("DR-NATIVE-0200"), "{}", run.stderr);
}
