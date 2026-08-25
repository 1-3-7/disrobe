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
    let sarif_path: PathBuf = batch_out.join("report.sarif");
    assert!(
        sarif_path.is_file(),
        "batch auto must write a standards report beside manifest.json: {}",
        sarif_path.display()
    );
    let sarif: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&sarif_path).expect("read batch automatic standards report"),
    )
    .expect("batch automatic standards report must be JSON");
    assert_eq!(sarif["version"], serde_json::json!("2.1.0"));
    assert_eq!(sarif["runs"][0]["properties"]["stix"]["available"], false);
    assert!(sarif["runs"][0]["properties"]["stix"]["reason"].is_string());
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

#[test]
fn report_redaction_covers_every_shareable_format_and_stays_opt_in() {
    let work_scratch: disrobe_core::scratch::ScratchDir = temp_dir("report-redact");
    let work: PathBuf = work_scratch.path().to_path_buf();
    let secret: &str = "AKIA3KFTG2KQ4WXYZ7AB";
    let input: PathBuf = work.join(format!("sample-{secret}.bin"));
    write(&input, format!("embedded={secret}\n").as_bytes());
    let out: PathBuf = work.join("run");
    run_auto_into(&input, &out);

    let plain: Run = run_disrobe(&[
        "report",
        out.to_str().expect("report path"),
        "--format",
        "json",
    ]);
    assert_eq!(plain.code, 0, "stderr={}", plain.stderr);
    assert!(
        plain.stdout.contains(secret),
        "default output must retain the secret"
    );

    for format in ["text", "json", "markdown", "html", "sarif"] {
        let redacted: Run = run_disrobe(&[
            "report",
            out.to_str().expect("report path"),
            "--format",
            format,
            "--redact",
        ]);
        assert_eq!(
            redacted.code, 0,
            "format={format} stderr={}",
            redacted.stderr
        );
        assert!(!redacted.stdout.contains(secret), "format={format}");
        assert!(redacted.stdout.contains("[REDACTED:"), "format={format}");
        if matches!(format, "json" | "sarif") {
            serde_json::from_str::<serde_json::Value>(&redacted.stdout).unwrap_or_else(
                |error: serde_json::Error| panic!("format={format} invalid JSON: {error}"),
            );
        }
    }
}

#[test]
fn auto_redaction_scrubs_machine_output_and_written_reports() {
    let work_scratch: disrobe_core::scratch::ScratchDir = temp_dir("auto-redact");
    let work: PathBuf = work_scratch.path().to_path_buf();
    let secret: &str = "AKIA3KFTG2KQ4WXYZ7AB";
    let input: PathBuf = work.join(format!("sample-{secret}.bin"));
    write(&input, format!("embedded={secret}\n").as_bytes());
    let plain_out: PathBuf = work.join("plain");
    let plain: Run = run_disrobe(&[
        "--json",
        "auto",
        input.to_str().expect("input path"),
        "--out",
        plain_out.to_str().expect("plain output path"),
    ]);
    assert_eq!(plain.code, 0, "stderr={}", plain.stderr);
    assert!(
        plain.stdout.contains(secret),
        "default output must retain the secret"
    );

    let redacted_out: PathBuf = work.join("redacted");
    let redacted: Run = run_disrobe(&[
        "--json",
        "auto",
        input.to_str().expect("input path"),
        "--out",
        redacted_out.to_str().expect("redacted output path"),
        "--redact",
    ]);
    assert_eq!(redacted.code, 0, "stderr={}", redacted.stderr);
    assert!(!redacted.stdout.contains(secret));
    assert!(redacted.stdout.contains("[REDACTED:"));
    serde_json::from_str::<serde_json::Value>(&redacted.stdout).expect("redacted auto JSON");

    for name in [
        "chain.json",
        "recovery.json",
        "anti-analysis.json",
        "report.json",
    ] {
        let bytes: Vec<u8> = std::fs::read(redacted_out.join(name)).expect("read auto report");
        let text: String = String::from_utf8(bytes).expect("auto report UTF-8");
        assert!(!text.contains(secret), "{name} leaked the secret");
        serde_json::from_str::<serde_json::Value>(&text)
            .unwrap_or_else(|error: serde_json::Error| panic!("{name} invalid JSON: {error}"));
    }
}

#[test]
fn auto_redaction_scrubs_single_text_and_parallel_batch_text() {
    let work_scratch: disrobe_core::scratch::ScratchDir = temp_dir("auto-redact-text");
    let work: PathBuf = work_scratch.path().to_path_buf();
    let secret: &str = "AKIA3KFTG2KQ4WXYZ7AB";
    let single: PathBuf = work.join(format!("single-{secret}.bin"));
    let original: Vec<u8> = format!("embedded={secret}\n").into_bytes();
    write(&single, &original);
    let single_out: PathBuf = work.join(format!("single-out-{secret}"));

    let single_run: Run = run_disrobe(&[
        "auto",
        single.to_str().expect("single input"),
        "--out",
        single_out.to_str().expect("single output"),
        "--redact",
    ]);
    assert_eq!(single_run.code, 0, "stderr={}", single_run.stderr);
    assert!(
        !single_run.stdout.contains(secret),
        "single text leaked: {}",
        single_run.stdout
    );
    assert_eq!(std::fs::read(&single).expect("read single input"), original);

    let batch: PathBuf = work.join("batch");
    write(&batch.join(format!("first-{secret}.bin")), &original);
    write(&batch.join(format!("second-{secret}.bin")), &original);
    let batch_out: PathBuf = work.join(format!("batch-out-{secret}"));
    let batch_run: Run = run_disrobe(&[
        "auto",
        batch.to_str().expect("batch input"),
        "--out",
        batch_out.to_str().expect("batch output"),
        "--jobs",
        "4",
        "--redact",
    ]);
    assert_eq!(batch_run.code, 0, "stderr={}", batch_run.stderr);
    assert!(
        !batch_run.stdout.contains(secret),
        "batch text leaked: {}",
        batch_run.stdout
    );
    let manifest: String =
        std::fs::read_to_string(batch_out.join("manifest.json")).expect("read manifest");
    assert!(
        !manifest.contains(secret),
        "batch manifest leaked: {manifest}"
    );
    assert_eq!(
        std::fs::read(batch.join(format!("first-{secret}.bin"))).expect("read first input"),
        original
    );
}

#[test]
fn auto_json_emit_recovery_redacts_both_documents() {
    let work_scratch: disrobe_core::scratch::ScratchDir = temp_dir("auto-redact-recovery");
    let work: PathBuf = work_scratch.path().to_path_buf();
    let secret: &str = "AKIA3KFTG2KQ4WXYZ7AB";
    let input: PathBuf = work.join(format!("emit-{secret}.bin"));
    write(&input, format!("embedded={secret}\n").as_bytes());
    let out: PathBuf = work.join("run");

    let run: Run = run_disrobe(&[
        "--json",
        "auto",
        input.to_str().expect("input path"),
        "--out",
        out.to_str().expect("output path"),
        "--emit",
        "recovery",
        "--redact",
    ]);

    assert_eq!(run.code, 0, "stderr={}", run.stderr);
    assert!(
        !run.stdout.contains(secret),
        "emitted recovery leaked: {}",
        run.stdout
    );
    assert_eq!(
        run.stdout.matches("\n{").count(),
        1,
        "expected chain and recovery JSON"
    );
}

#[test]
fn report_raw_target_redacts_the_generated_run_files() {
    let work_scratch: disrobe_core::scratch::ScratchDir = temp_dir("report-raw-redact");
    let work: PathBuf = work_scratch.path().to_path_buf();
    let secret: &str = "AKIA3KFTG2KQ4WXYZ7AB";
    let input: PathBuf = work.join(format!("raw-{secret}.bin"));
    write(&input, format!("embedded={secret}\n").as_bytes());
    let base: PathBuf = work.join("runs");

    let run: Run = run_disrobe(&[
        "report",
        input.to_str().expect("input path"),
        "--out",
        base.to_str().expect("run base"),
        "--format",
        "json",
        "--redact",
    ]);
    assert_eq!(run.code, 0, "stderr={}", run.stderr);
    assert!(
        !run.stdout.contains(secret),
        "report output leaked: {}",
        run.stdout
    );

    let generated: PathBuf = base.join(format!("raw-{secret}-auto"));
    for name in [
        "chain.json",
        "recovery.json",
        "anti-analysis.json",
        "report.json",
    ] {
        let text: String =
            std::fs::read_to_string(generated.join(name)).expect("read generated report");
        assert!(!text.contains(secret), "{name} leaked: {text}");
        serde_json::from_str::<serde_json::Value>(&text)
            .unwrap_or_else(|error: serde_json::Error| panic!("{name} invalid JSON: {error}"));
    }
}
