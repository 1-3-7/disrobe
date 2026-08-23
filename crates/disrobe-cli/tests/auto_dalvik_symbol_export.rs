#![cfg(all(feature = "chain", feature = "jvm"))]
#![allow(
    clippy::disallowed_methods,
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used
)]

mod common;

use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::{Run, cli_binary, temp_dir};
use zip::write::{FileOptions, ZipWriter};

fn workspace_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root
}

fn fixture_path() -> PathBuf {
    workspace_root().join("corpus/jvm/dex/EdgeCases.dex")
}

fn run_auto(input: &Path, out: &Path, format: &str, tail: &[&str]) -> Run {
    let mut command: Command = Command::new(cli_binary());
    command
        .arg("auto")
        .arg(input)
        .arg("--out")
        .arg(out)
        .arg("--format")
        .arg(format)
        .args(tail);
    let output: Output = command.output().expect("run disrobe auto");
    Run {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn pack_apk(dex_bytes: &[u8]) -> Vec<u8> {
    let cursor: Cursor<Vec<u8>> = Cursor::new(Vec::with_capacity(dex_bytes.len() + 128));
    let mut writer: ZipWriter<Cursor<Vec<u8>>> = ZipWriter::new(cursor);
    let options: FileOptions<'_, ()> =
        FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    writer
        .start_file("classes.dex", options)
        .expect("start classes.dex");
    writer.write_all(dex_bytes).expect("write classes.dex");
    writer
        .start_file("AndroidManifest.xml", options)
        .expect("start AndroidManifest.xml");
    writer
        .write_all(b"<manifest package=\"com.disrobe.edgecases\"/>")
        .expect("write AndroidManifest.xml");
    writer.finish().expect("finish apk").into_inner()
}

fn collect_sidecars(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut pending: Vec<PathBuf> = vec![root.to_path_buf()];
    let mut sidecars: Vec<(String, Vec<u8>)> = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).expect("read batch output directory") {
            let path: PathBuf = entry.expect("read batch output entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.ends_with("exports/dalvik/symbols.json") {
                let relative: String = path
                    .strip_prefix(root)
                    .expect("sidecar below batch root")
                    .to_string_lossy()
                    .replace('\\', "/");
                let bytes: Vec<u8> = std::fs::read(&path).expect("read batch sidecar");
                sidecars.push((relative, bytes));
            }
        }
    }
    sidecars.sort_by(|left: &(String, Vec<u8>), right: &(String, Vec<u8>)| left.0.cmp(&right.0));
    sidecars
}

#[test]
fn auto_writes_reserved_dalvik_export_without_changing_chain_artifacts() {
    let fixture: PathBuf = fixture_path();
    assert!(
        fixture.is_file(),
        "tracked fixture missing: {}",
        fixture.display()
    );
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("auto-dalvik-symbol-export");
    let out: PathBuf = scratch.path().join("out");
    let run: Run = run_auto(&fixture, &out, "json", &[]);
    assert_eq!(run.code, 0, "auto export failed: {}", run.stderr);

    let sidecar: PathBuf = out.join("exports/dalvik/symbols.json");
    let first: Vec<u8> = std::fs::read(&sidecar)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", sidecar.display()));
    let map: serde_json::Value = serde_json::from_slice(&first).expect("parse Dalvik sidecar");
    assert_eq!(map["schema"], "disrobe.symbol-map/v2");
    assert!(
        map["symbols"]
            .as_array()
            .is_some_and(|symbols: &Vec<serde_json::Value>| {
                symbols.iter().any(|symbol: &serde_json::Value| {
                    symbol["key"] == "dalvik-method"
                        && symbol["owner"] == "LEdgeCases;"
                        && symbol["original_name"] == "gcd"
                        && symbol["descriptor"] == "(II)I"
                })
            })
    );

    let chain: String = std::fs::read_to_string(out.join("chain.json")).expect("read chain.json");
    let recovery: String =
        std::fs::read_to_string(out.join("recovery.json")).expect("read recovery.json");
    assert!(!chain.contains("exports/dalvik"));
    assert!(!recovery.contains("exports/dalvik"));
    let chain_doc: serde_json::Value = serde_json::from_str(&chain).expect("parse chain.json");
    let root_dex: &serde_json::Value = chain_doc["nodes"]
        .as_array()
        .and_then(|nodes: &Vec<serde_json::Value>| {
            nodes.iter().find(|node: &&serde_json::Value| {
                node["pass"] == "jvm.classify" && node["format_tag_in"] == "android-dex"
            })
        })
        .expect("root jvm.classify node");
    assert_eq!(
        root_dex["output_kind"]["children"].as_array().map(Vec::len),
        Some(2)
    );
    assert_eq!(
        chain_doc["nodes"].as_array().map(Vec::len),
        Some(4),
        "supplemental export changed the chain population"
    );
    let recovery_doc: serde_json::Value =
        serde_json::from_str(&recovery).expect("parse recovery.json");
    assert_eq!(
        recovery_doc["passes"].as_array().map(Vec::len),
        Some(3),
        "supplemental export changed the recovery-pass population"
    );
    assert!(run.stdout.contains("Dalvik symbol export written:"));

    let repeat_out: PathBuf = scratch.path().join("repeat");
    let repeat: Run = run_auto(&fixture, &repeat_out, "json", &[]);
    assert_eq!(
        repeat.code, 0,
        "repeat auto export failed: {}",
        repeat.stderr
    );
    let second: Vec<u8> = std::fs::read(repeat_out.join("exports/dalvik/symbols.json"))
        .expect("read repeated sidecar");
    assert_eq!(first, second, "repeated auto export changed bytes");
}

#[test]
fn auto_dry_run_does_not_parse_render_or_write_dalvik_export() {
    let fixture: PathBuf = fixture_path();
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("auto-dalvik-dry-run");
    let out: PathBuf = scratch.path().join("must-not-exist");
    let run: Run = run_auto(&fixture, &out, "ghidra", &["--dry-run"]);
    assert_eq!(run.code, 0, "dry-run failed: {}", run.stderr);
    assert!(!out.exists(), "dry-run created {}", out.display());
    assert!(run.stdout.contains("dry-run; nothing written to disk"));
    assert!(!run.stdout.contains("Dalvik symbol export written:"));
    assert!(!run.stdout.contains("symbols.ghidra.java"));
}

#[test]
fn auto_refuses_wrong_nested_and_unwritable_dalvik_export_provenance() {
    let fixture: PathBuf = fixture_path();
    let dex_bytes: Vec<u8> = std::fs::read(&fixture).expect("read tracked DEX fixture");
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("auto-dalvik-provenance");

    let wrong: PathBuf = scratch.path().join("wrong.bin");
    std::fs::write(&wrong, b"not a dex").expect("write wrong input");
    let wrong_out: PathBuf = scratch.path().join("wrong-out");
    let wrong_run: Run = run_auto(&wrong, &wrong_out, "json", &[]);
    assert_ne!(wrong_run.code, 0, "wrong input unexpectedly exported");
    assert!(wrong_run.stderr.contains("requested Dalvik symbol export"));
    assert!(!wrong_out.join("exports/dalvik/symbols.json").exists());

    let apk: PathBuf = scratch.path().join("nested.apk");
    std::fs::write(&apk, pack_apk(&dex_bytes)).expect("write nested APK");
    let nested_out: PathBuf = scratch.path().join("nested-out");
    let nested_run: Run = run_auto(&apk, &nested_out, "json", &[]);
    assert_ne!(
        nested_run.code, 0,
        "nested DEX unexpectedly used APK root bytes"
    );
    assert!(
        nested_run.stderr.contains("DR-CLI-0442"),
        "unexpected nested provenance failure: {}",
        nested_run.stderr
    );
    assert!(!nested_out.join("exports/dalvik/symbols.json").exists());

    let unwritable_out: PathBuf = scratch.path().join("unwritable-out");
    std::fs::create_dir_all(&unwritable_out).expect("create unwritable test output");
    std::fs::write(unwritable_out.join("exports"), b"path collision")
        .expect("create exports path collision");
    let unwritable_run: Run = run_auto(&fixture, &unwritable_out, "ida", &[]);
    assert_ne!(
        unwritable_run.code, 0,
        "write failure unexpectedly succeeded"
    );
    assert!(
        unwritable_run
            .stderr
            .contains("cannot create Dalvik symbol export directory")
    );
}

#[test]
fn auto_batch_dalvik_exports_are_byte_identical_at_jobs_one_and_four() {
    let fixture: PathBuf = fixture_path();
    let bytes: Vec<u8> = std::fs::read(&fixture).expect("read tracked DEX fixture");
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("auto-dalvik-batch");
    let input: PathBuf = scratch.path().join("input");
    std::fs::create_dir_all(input.join("nested")).expect("create batch input");
    std::fs::write(input.join("first.dex"), &bytes).expect("write first DEX");
    std::fs::write(input.join("nested/second.dex"), &bytes).expect("write second DEX");

    let serial_out: PathBuf = scratch.path().join("serial");
    let serial: Run = run_auto(&input, &serial_out, "json", &["--jobs", "1"]);
    assert_eq!(serial.code, 0, "serial batch failed: {}", serial.stderr);
    let parallel_out: PathBuf = scratch.path().join("parallel");
    let parallel: Run = run_auto(&input, &parallel_out, "json", &["--jobs", "4"]);
    assert_eq!(
        parallel.code, 0,
        "parallel batch failed: {}",
        parallel.stderr
    );

    let serial_sidecars: Vec<(String, Vec<u8>)> = collect_sidecars(&serial_out);
    let parallel_sidecars: Vec<(String, Vec<u8>)> = collect_sidecars(&parallel_out);
    assert_eq!(serial_sidecars.len(), 2);
    assert_eq!(serial_sidecars, parallel_sidecars);

    for manifest_path in [
        serial_out.join("manifest.json"),
        parallel_out.join("manifest.json"),
    ] {
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&manifest_path).expect("read batch manifest"))
                .expect("parse batch manifest");
        assert!(
            manifest["entries"]
                .as_array()
                .is_some_and(|entries: &Vec<serde_json::Value>| entries.iter().all(
                    |entry: &serde_json::Value| {
                        entry["supplemental_outputs"]
                            .as_array()
                            .is_some_and(|paths: &Vec<serde_json::Value>| paths.len() == 1)
                    }
                ))
        );
    }
}

#[test]
fn auto_batch_keeps_colliding_relative_slugs_in_distinct_output_directories() {
    let fixture: PathBuf = fixture_path();
    let bytes: Vec<u8> = std::fs::read(&fixture).expect("read tracked DEX fixture");
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("auto-dalvik-slug-collision");
    let input: PathBuf = scratch.path().join("input");
    std::fs::create_dir_all(input.join("a")).expect("create colliding batch input");
    std::fs::write(input.join("a/b.dex"), &bytes).expect("write nested DEX");
    std::fs::write(input.join("a-b.dex"), &bytes).expect("write flat DEX");

    let out: PathBuf = scratch.path().join("out");
    let run: Run = run_auto(&input, &out, "json", &["--jobs", "4"]);
    assert_eq!(run.code, 0, "colliding batch failed: {}", run.stderr);
    let sidecars: Vec<(String, Vec<u8>)> = collect_sidecars(&out);
    assert_eq!(sidecars.len(), 2, "colliding slugs overwrote a sidecar");
    assert_ne!(sidecars[0].0, sidecars[1].0);

    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out.join("manifest.json")).expect("read collision manifest"),
    )
    .expect("parse collision manifest");
    let supplemental_paths: Vec<&str> = manifest["entries"]
        .as_array()
        .expect("collision manifest entries")
        .iter()
        .map(|entry: &serde_json::Value| {
            entry["supplemental_outputs"][0]
                .as_str()
                .expect("supplemental path")
        })
        .collect();
    assert_ne!(supplemental_paths[0], supplemental_paths[1]);
}
