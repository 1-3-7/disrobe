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

fn read_manifest(out: &std::path::Path) -> serde_json::Value {
    let text: String =
        std::fs::read_to_string(out.join("manifest.json")).expect("manifest.json must exist");
    serde_json::from_str(&text).expect("manifest.json must be valid json")
}

#[test]
fn auto_directory_writes_manifest_and_per_file_dirs() {
    let root_scratch: disrobe_core::scratch::ScratchDir = temp_dir("batch-basic");
    let root: PathBuf = root_scratch.path().to_path_buf();
    write(&root.join("a.txt"), b"the quick brown fox");
    write(&root.join("nested/b.bin"), &[0u8; 48]);
    let out_scratch: disrobe_core::scratch::ScratchDir = temp_dir("batch-basic-out");
    let out: PathBuf = out_scratch.path().to_path_buf();

    let r: Run = run_disrobe(&[
        "auto",
        root.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "batch auto must exit 0; stderr={}", r.stderr);

    let manifest: serde_json::Value = read_manifest(&out);
    assert_eq!(manifest["schema"], "disrobe.batch.manifest/v1");
    assert_eq!(manifest["summary"]["processed"], serde_json::json!(2));
    let entries: &Vec<serde_json::Value> = manifest["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 2);
    for e in entries {
        assert!(e["relative"].is_string());
        assert!(e["size"].is_number());
        assert!(e["duration_ms"].is_number());
    }
}

#[test]
fn auto_directory_exclude_glob_drops_files() {
    let root_scratch: disrobe_core::scratch::ScratchDir = temp_dir("batch-exclude");
    let root: PathBuf = root_scratch.path().to_path_buf();
    write(&root.join("keep.bin"), &[1u8; 16]);
    write(&root.join("drop.log"), b"log line");
    write(&root.join("also.log"), b"log line two");
    let out_scratch: disrobe_core::scratch::ScratchDir = temp_dir("batch-exclude-out");
    let out: PathBuf = out_scratch.path().to_path_buf();

    let r: Run = run_disrobe(&[
        "auto",
        root.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--exclude",
        "*.log",
    ]);
    assert_eq!(r.code, 0, "stderr={}", r.stderr);
    let manifest: serde_json::Value = read_manifest(&out);
    assert_eq!(
        manifest["summary"]["processed"],
        serde_json::json!(1),
        "only keep.bin should survive the exclude"
    );
}

#[test]
fn auto_directory_include_glob_restricts_files() {
    let root_scratch: disrobe_core::scratch::ScratchDir = temp_dir("batch-include");
    let root: PathBuf = root_scratch.path().to_path_buf();
    write(&root.join("x.pyc"), b"\x00\x00\x00\x00fake pyc");
    write(&root.join("y.txt"), b"text");
    write(&root.join("deep/z.pyc"), b"\x00\x00\x00\x00another");
    let out_scratch: disrobe_core::scratch::ScratchDir = temp_dir("batch-include-out");
    let out: PathBuf = out_scratch.path().to_path_buf();

    let r: Run = run_disrobe(&[
        "auto",
        root.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--include",
        "*.pyc",
    ]);
    assert_eq!(r.code, 0, "stderr={}", r.stderr);
    let manifest: serde_json::Value = read_manifest(&out);
    assert_eq!(
        manifest["summary"]["processed"],
        serde_json::json!(2),
        "both .pyc files (root + nested) should be included, .txt dropped"
    );
}

#[test]
fn auto_directory_max_depth_limits_recursion() {
    let root_scratch: disrobe_core::scratch::ScratchDir = temp_dir("batch-depth");
    let root: PathBuf = root_scratch.path().to_path_buf();
    write(&root.join("top.bin"), &[1u8; 8]);
    write(&root.join("a/mid.bin"), &[2u8; 8]);
    write(&root.join("a/b/low.bin"), &[3u8; 8]);
    let out_scratch: disrobe_core::scratch::ScratchDir = temp_dir("batch-depth-out");
    let out: PathBuf = out_scratch.path().to_path_buf();

    let r: Run = run_disrobe(&[
        "auto",
        root.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--batch-max-depth",
        "1",
    ]);
    assert_eq!(r.code, 0, "stderr={}", r.stderr);
    let manifest: serde_json::Value = read_manifest(&out);
    assert_eq!(
        manifest["summary"]["processed"],
        serde_json::json!(2),
        "depth 1 keeps top.bin and a/mid.bin but not a/b/low.bin"
    );
}

#[test]
fn auto_directory_json_output_is_machine_readable() {
    let root_scratch: disrobe_core::scratch::ScratchDir = temp_dir("batch-json");
    let root: PathBuf = root_scratch.path().to_path_buf();
    write(&root.join("only.txt"), b"content");
    let out_scratch: disrobe_core::scratch::ScratchDir = temp_dir("batch-json-out");
    let out: PathBuf = out_scratch.path().to_path_buf();

    let r: Run = run_disrobe(&[
        "--json",
        "auto",
        root.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "stderr={}", r.stderr);
    let parsed: serde_json::Value =
        serde_json::from_str(&r.stdout).expect("--json batch must emit valid json to stdout");
    assert_eq!(parsed["schema"], "disrobe.batch.manifest/v1");
    assert_eq!(parsed["summary"]["processed"], serde_json::json!(1));
}

#[test]
fn auto_single_file_behavior_unchanged() {
    let root_scratch: disrobe_core::scratch::ScratchDir = temp_dir("batch-singlefile");
    let root: PathBuf = root_scratch.path().to_path_buf();
    let file: PathBuf = root.join("solo.bin");
    write(&file, &[0u8; 16]);
    let out_scratch: disrobe_core::scratch::ScratchDir = temp_dir("batch-singlefile-out");
    let out: PathBuf = out_scratch.path().to_path_buf();

    let r: Run = run_disrobe(&[
        "auto",
        file.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(
        r.code, 0,
        "single-file auto must still work; stderr={}",
        r.stderr
    );
    assert!(
        out.join("chain.json").is_file(),
        "single-file auto must still write chain.json, not a batch manifest"
    );
    assert!(
        !out.join("manifest.json").exists(),
        "single-file auto must NOT write a batch manifest"
    );
}
