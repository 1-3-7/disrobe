#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use common::{Run, run_disrobe, temp_dir};

fn write(path: &std::path::Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("mkdir");
    }
    std::fs::write(path, bytes).expect("write fixture");
}

fn run_auto_into(input: &std::path::Path, out: &std::path::Path) {
    let r: Run = run_disrobe(&[
        "auto",
        input.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "auto setup must succeed; stderr={}", r.stderr);
}

#[test]
fn report_text_on_completed_single_run() {
    let work_scratch: disrobe_core::scratch::ScratchDir = temp_dir("report-single");
    let work: PathBuf = work_scratch.path().to_path_buf();
    let input: PathBuf = work.join("sample.bin");
    write(&input, &(0u8..96).collect::<Vec<u8>>());
    let out: PathBuf = work.join("run");
    run_auto_into(&input, &out);

    let r: Run = run_disrobe(&["report", out.to_str().unwrap(), "--format", "text"]);
    assert_eq!(r.code, 0, "report must succeed; stderr={}", r.stderr);
    assert!(r.stdout.contains("disrobe report"), "got: {}", r.stdout);
    assert!(
        r.stdout.contains("blake3:"),
        "missing identity; got: {}",
        r.stdout
    );
    assert!(
        r.stdout.contains("stages:"),
        "missing stages; got: {}",
        r.stdout
    );
    assert!(
        !r.stdout.contains("chain.json written"),
        "reporting an existing dir must not re-run auto; got: {}",
        r.stdout
    );
}

#[test]
fn report_json_is_machine_readable() {
    let work_scratch: disrobe_core::scratch::ScratchDir = temp_dir("report-json");
    let work: PathBuf = work_scratch.path().to_path_buf();
    let input: PathBuf = work.join("sample.bin");
    write(&input, &(0u8..96).collect::<Vec<u8>>());
    let out: PathBuf = work.join("run");
    run_auto_into(&input, &out);

    let r: Run = run_disrobe(&["report", out.to_str().unwrap(), "--format", "json"]);
    assert_eq!(r.code, 0, "stderr={}", r.stderr);
    let parsed: serde_json::Value =
        serde_json::from_str(&r.stdout).expect("report --format json must be valid json");
    assert_eq!(parsed["report_kind"], serde_json::json!("single"));
    assert!(parsed["input"]["blake3"].is_string());
    assert!(parsed["stages"].is_array());
}

#[test]
fn report_markdown_is_shareable() {
    let work_scratch: disrobe_core::scratch::ScratchDir = temp_dir("report-md");
    let work: PathBuf = work_scratch.path().to_path_buf();
    let input: PathBuf = work.join("sample.bin");
    write(&input, &(0u8..96).collect::<Vec<u8>>());
    let out: PathBuf = work.join("run");
    run_auto_into(&input, &out);

    let r: Run = run_disrobe(&["report", out.to_str().unwrap(), "--format", "markdown"]);
    assert_eq!(r.code, 0, "stderr={}", r.stderr);
    assert!(
        r.stdout.starts_with("# disrobe report"),
        "got: {}",
        r.stdout
    );
    assert!(r.stdout.contains("| field | value |"), "got: {}", r.stdout);
    assert!(r.stdout.contains("## Stages"), "got: {}", r.stdout);
}

#[test]
fn report_runs_auto_on_raw_input() {
    let work_scratch: disrobe_core::scratch::ScratchDir = temp_dir("report-raw");
    let work: PathBuf = work_scratch.path().to_path_buf();
    let input: PathBuf = work.join("raw.bin");
    write(&input, &(0u8..64).collect::<Vec<u8>>());

    let r: Run = run_disrobe(&["report", input.to_str().unwrap(), "--format", "json"]);
    assert_eq!(
        r.code, 0,
        "report on a raw input must run auto first; stderr={}",
        r.stderr
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&r.stdout).expect("raw-input report must still emit valid json only");
    assert_eq!(parsed["report_kind"], serde_json::json!("single"));
    assert_eq!(parsed["input"]["size"], serde_json::json!(64));
}

#[test]
fn report_on_batch_dir_aggregates_manifest() {
    let work_scratch: disrobe_core::scratch::ScratchDir = temp_dir("report-batch");
    let work: PathBuf = work_scratch.path().to_path_buf();
    write(&work.join("samples/a.bin"), &[1u8; 32]);
    write(&work.join("samples/b.bin"), &[2u8; 32]);
    let batch_out: PathBuf = work.join("batch-out");
    let r0: Run = run_disrobe(&[
        "auto",
        work.join("samples").to_str().unwrap(),
        "--out",
        batch_out.to_str().unwrap(),
    ]);
    assert_eq!(r0.code, 0, "batch setup; stderr={}", r0.stderr);

    let r: Run = run_disrobe(&["report", batch_out.to_str().unwrap(), "--format", "json"]);
    assert_eq!(r.code, 0, "stderr={}", r.stderr);
    let parsed: serde_json::Value =
        serde_json::from_str(&r.stdout).expect("batch report must be valid json");
    assert_eq!(parsed["report_kind"], serde_json::json!("batch"));
    assert_eq!(parsed["processed"], serde_json::json!(2));
    assert!(parsed["files"].as_array().is_some_and(|a| a.len() == 2));
}

#[test]
fn report_missing_target_fails() {
    let work_scratch: disrobe_core::scratch::ScratchDir = temp_dir("report-missing");
    let work: PathBuf = work_scratch.path().to_path_buf();
    let missing: PathBuf = work.join("not-here");
    let r: Run = run_disrobe(&["report", missing.to_str().unwrap()]);
    assert_ne!(r.code, 0, "missing target must fail");
    assert!(
        r.stderr.contains("DR-CLI-0350"),
        "expected DR-CLI-0350; stderr={}",
        r.stderr
    );
}

#[test]
fn report_global_json_flag_forces_json() {
    let work_scratch: disrobe_core::scratch::ScratchDir = temp_dir("report-global-json");
    let work: PathBuf = work_scratch.path().to_path_buf();
    let input: PathBuf = work.join("sample.bin");
    write(&input, &(0u8..48).collect::<Vec<u8>>());
    let out: PathBuf = work.join("run");
    run_auto_into(&input, &out);

    let r: Run = run_disrobe(&["--json", "report", out.to_str().unwrap()]);
    assert_eq!(r.code, 0, "stderr={}", r.stderr);
    let parsed: serde_json::Value = serde_json::from_str(&r.stdout)
        .expect("global --json must force json even at default text format");
    assert_eq!(parsed["report_kind"], serde_json::json!("single"));
}
