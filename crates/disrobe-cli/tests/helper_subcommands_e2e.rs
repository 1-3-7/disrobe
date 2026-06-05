#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn cli_binary() -> PathBuf {
    let mut p: PathBuf = env_target_dir();
    p.push(if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    });
    p
}

fn env_target_dir() -> PathBuf {
    let exe: PathBuf = std::env::current_exe().expect("current exe");
    let mut dir: PathBuf = exe.parent().expect("exe dir").to_path_buf();
    while dir.file_name().and_then(|s| s.to_str()) != Some("debug")
        && dir.file_name().and_then(|s| s.to_str()) != Some("release")
    {
        if !dir.pop() {
            break;
        }
    }
    dir
}

fn temp_dir(stem: &str) -> PathBuf {
    let pid: u32 = std::process::id();
    let seq: u64 = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let p: PathBuf =
        std::env::temp_dir().join(format!("disrobe-helper-e2e-{stem}-{pid}-{seq}.dir"));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("create temp dir");
    p
}

#[derive(Debug)]
struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run_disrobe_in(work: &Path, args: &[&str]) -> Run {
    let bin: PathBuf = cli_binary();
    assert!(
        bin.exists(),
        "disrobe binary not built at {} - run `cargo build -p disrobe-cli` before tests",
        bin.display()
    );
    let output: std::process::Output = Command::new(&bin)
        .args(args)
        .current_dir(work)
        .env_remove("RUST_LOG")
        .env_remove("DISROBE_LOG")
        .output()
        .expect("spawn disrobe");
    Run {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

const RECOVERY_FIXTURE: &str = r#"{
  "schema": "disrobe.recovery/v1",
  "tool_version": "0.10.0",
  "input": { "path": "in.pyc", "blake3": "aa", "size": 4 },
  "passes": [
    {
      "name": "pyarmor.unpack",
      "status": "recovered",
      "confidence": "semantic",
      "duration_ms": 7,
      "format_in": "pyarmor",
      "format_out": "Python"
    }
  ],
  "histogram": { "exact": 0, "semantic": 1, "partial": 0, "skeleton": 0 },
  "total_ms": 7,
  "verdict": "complete"
}"#;

fn read_json(path: &Path) -> serde_json::Value {
    let text: String = std::fs::read_to_string(path).expect("read json file");
    serde_json::from_str::<serde_json::Value>(&text).expect("parse json file")
}

#[test]
fn rename_appends_not_overwrites() {
    let work: PathBuf = temp_dir("rename-append");
    let init: Run = run_disrobe_in(&work, &["init"]);
    assert_eq!(init.code, 0, "init stderr: {}", init.stderr);

    let first: Run = run_disrobe_in(&work, &["rename", "oldName", "newName"]);
    assert_eq!(first.code, 0, "rename stderr: {}", first.stderr);

    let renames: PathBuf = work.join(".disrobe").join("notes").join("renames.json");
    assert!(
        renames.is_file(),
        "renames.json missing at {}",
        renames.display()
    );
    let parsed: serde_json::Value = read_json(&renames);
    assert_eq!(parsed["schema"], "disrobe.renames/v1");
    let records: &Vec<serde_json::Value> = parsed["records"].as_array().expect("records array");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["old"], "oldName");
    assert_eq!(records[0]["new"], "newName");

    let second: Run = run_disrobe_in(&work, &["rename", "a", "b"]);
    assert_eq!(second.code, 0, "rename2 stderr: {}", second.stderr);
    let parsed2: serde_json::Value = read_json(&renames);
    assert_eq!(parsed2["records"].as_array().expect("records").len(), 2);
}

#[test]
fn rename_without_init_fails() {
    let work: PathBuf = temp_dir("rename-noinit");
    let run: Run = run_disrobe_in(&work, &["rename", "x", "y"]);
    assert_ne!(run.code, 0, "expected failure, got 0");
    assert!(
        run.stderr.contains("DR-CLI-0332"),
        "expected DR-CLI-0332, stderr: {}",
        run.stderr
    );
}

#[test]
fn annot_regenerate_then_refresh() {
    let work: PathBuf = temp_dir("annot-cycle");
    let init: Run = run_disrobe_in(&work, &["init"]);
    assert_eq!(init.code, 0, "init stderr: {}", init.stderr);

    let target: PathBuf = work.join("recovery.json");
    std::fs::write(&target, RECOVERY_FIXTURE).expect("write recovery fixture");

    let regen: Run = run_disrobe_in(&work, &["annot", "regenerate", "recovery.json"]);
    assert_eq!(regen.code, 0, "regenerate stderr: {}", regen.stderr);

    let annot: PathBuf = work
        .join(".disrobe")
        .join("annotations")
        .join("recovery.annot.json");
    assert!(
        annot.is_file(),
        "annotation file missing at {}",
        annot.display()
    );
    let parsed: serde_json::Value = read_json(&annot);
    assert_eq!(parsed["schema"], "disrobe.annotations/v1");
    let annotations: &Vec<serde_json::Value> =
        parsed["annotations"].as_array().expect("annotations array");
    assert!(!annotations.is_empty(), "expected >= 1 derived symbol");
    assert_eq!(annotations[0]["symbol"], "pyarmor.unpack");

    let refresh: Run = run_disrobe_in(&work, &["annot", "refresh", "recovery.json"]);
    assert_eq!(refresh.code, 0, "refresh stderr: {}", refresh.stderr);
    let parsed2: serde_json::Value = read_json(&annot);
    for a in parsed2["annotations"].as_array().expect("annotations") {
        let note: &str = a["note"].as_str().expect("note string");
        assert!(
            note.matches('\n').count() < 2,
            "note exceeds 2 lines: {note:?}"
        );
    }
}

#[test]
fn annot_without_init_fails() {
    let work: PathBuf = temp_dir("annot-noinit");
    let run: Run = run_disrobe_in(&work, &["annot", "refresh", "foo.py"]);
    assert_ne!(run.code, 0, "expected failure, got 0");
    assert!(
        run.stderr.contains("DR-CLI-0323"),
        "expected DR-CLI-0323, stderr: {}",
        run.stderr
    );
}

#[test]
fn context_summarizes_recovery() {
    let work: PathBuf = temp_dir("context-ok");
    let out: PathBuf = work.join("out");
    std::fs::create_dir_all(&out).expect("create out dir");
    std::fs::write(out.join("recovery.json"), RECOVERY_FIXTURE).expect("write recovery");

    let run: Run = run_disrobe_in(&work, &["context", "--out", "out"]);
    assert_eq!(run.code, 0, "context stderr: {}", run.stderr);
    assert!(
        run.stdout.contains("pyarmor.unpack"),
        "expected pass name in stdout: {}",
        run.stdout
    );
    assert!(
        run.stdout.contains("semantic=1"),
        "expected tier counts in stdout: {}",
        run.stdout
    );
}

#[test]
fn context_missing_recovery_fails() {
    let work: PathBuf = temp_dir("context-missing");
    let out: PathBuf = work.join("empty");
    std::fs::create_dir_all(&out).expect("create empty dir");
    let run: Run = run_disrobe_in(&work, &["context", "--out", "empty"]);
    assert_ne!(run.code, 0, "expected failure, got 0");
    assert!(
        run.stderr.contains("DR-CLI-0320"),
        "expected DR-CLI-0320, stderr: {}",
        run.stderr
    );
}

#[test]
fn context_json_emits_valid_object() {
    let work: PathBuf = temp_dir("context-json");
    let out: PathBuf = work.join("out");
    std::fs::create_dir_all(&out).expect("create out dir");
    std::fs::write(out.join("recovery.json"), RECOVERY_FIXTURE).expect("write recovery");

    let run: Run = run_disrobe_in(&work, &["--json", "context", "--out", "out"]);
    assert_eq!(run.code, 0, "context json stderr: {}", run.stderr);
    let value: serde_json::Value = serde_json::from_str(&run.stdout).expect("parse context json");
    assert!(
        value["passes"].is_array(),
        "passes not an array: {}",
        run.stdout
    );
    assert!(
        value["histogram"].is_object(),
        "histogram not an object: {}",
        run.stdout
    );
}

#[test]
fn rename_json_emits_valid_object() {
    let work: PathBuf = temp_dir("rename-json");
    let init: Run = run_disrobe_in(&work, &["init"]);
    assert_eq!(init.code, 0, "init stderr: {}", init.stderr);

    let run: Run = run_disrobe_in(&work, &["--json", "rename", "a", "b"]);
    assert_eq!(run.code, 0, "rename json stderr: {}", run.stderr);
    let value: serde_json::Value = serde_json::from_str(&run.stdout).expect("parse rename json");
    assert_eq!(value["record_count"], 1);
}
