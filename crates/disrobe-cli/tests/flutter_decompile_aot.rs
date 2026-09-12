#![cfg(feature = "flutter")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;

mod common;

use common::{Run, run_disrobe, temp_dir, write_bytes};

const FLUTTER_AOT_FIXTURE: &str = "mobile/flutter/disrobe_sample/libapp_arm64.so";
const NON_FLUTTER_ELF_FIXTURE: &str = "binfmt/elf-dynamic/sample.elf";

fn corpus_path(relative: &str) -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root.join("corpus").join(relative)
}

fn dart_snapshot() -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&0xdcdc_f5f5u32.to_le_bytes());
    bytes.extend_from_slice(&0x800u64.to_le_bytes());
    bytes.extend_from_slice(&3u64.to_le_bytes());
    bytes.extend_from_slice(b"abcdef0123456789abcdef0123456789");
    bytes.extend_from_slice(b"product no-causal_async_stacks");
    bytes.push(0u8);
    for value in 0..64u32 {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(b"\x00LibraryPrivate@MyApp\x00MaterialApp\x00");
    bytes
}

#[test]
fn flutter_decompile_emits_aot_report_and_recovered_dart() {
    let fixture: PathBuf = corpus_path(FLUTTER_AOT_FIXTURE);
    assert!(
        fixture.is_file(),
        "missing fixture at {}",
        fixture.display()
    );
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("flutter-decompile-aot");
    let report_path: PathBuf = scratch.path().join("libapp.report.json");
    let source_path: PathBuf = report_path.with_extension("recovered.dart");
    let second_report_path: PathBuf = scratch.path().join("libapp.second.json");
    let second_source_path: PathBuf = second_report_path.with_extension("recovered.dart");
    let fixture_arg: String = fixture.to_string_lossy().into_owned();
    let report_arg: String = report_path.to_string_lossy().into_owned();
    let second_report_arg: String = second_report_path.to_string_lossy().into_owned();
    let run: Run = run_disrobe(&[
        "flutter",
        "decompile",
        &fixture_arg,
        "--out",
        &report_arg,
        "--emit",
        "source,report",
    ]);
    assert_eq!(run.code, 0, "command failed: {}", run.stderr);
    let report_bytes: Vec<u8> = std::fs::read(&report_path).expect("read AOT report");
    let report: serde_json::Value =
        serde_json::from_slice(&report_bytes).expect("parse AOT report");
    assert!(
        report["function_count"]
            .as_u64()
            .is_some_and(|count| count > 0),
        "the report must contain lifted functions"
    );
    assert!(
        report["structured_function_count"]
            .as_u64()
            .is_some_and(|count| count > 0),
        "the committed sample must contain structured bodies"
    );
    let source: String = std::fs::read_to_string(&source_path).expect("read recovered Dart");
    assert!(
        source.contains("fibonacciStep("),
        "the recovered source must contain the independently graded sample function:\n{source}"
    );
    assert!(
        !source.contains("not implemented for the flutter pass"),
        "the source output must not be a placeholder"
    );
    let second: Run = run_disrobe(&[
        "flutter",
        "decompile",
        &fixture_arg,
        "--out",
        &second_report_arg,
        "--emit",
        "source,report",
    ]);
    assert_eq!(second.code, 0, "second command failed: {}", second.stderr);
    assert_eq!(
        report_bytes,
        std::fs::read(&second_report_path).expect("read second AOT report"),
        "repeated AOT report output must be byte-identical"
    );
    assert_eq!(
        source,
        std::fs::read_to_string(&second_source_path).expect("read second recovered Dart"),
        "repeated recovered Dart output must be byte-identical"
    );
}

#[test]
fn unsupported_aot_emit_is_rejected_before_output_creation() {
    let fixture: PathBuf = corpus_path(FLUTTER_AOT_FIXTURE);
    assert!(
        fixture.is_file(),
        "missing fixture at {}",
        fixture.display()
    );
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("flutter-decompile-emit-reject");
    let absent_dir: PathBuf = scratch.path().join("must-not-exist");
    let report_path: PathBuf = absent_dir.join("libapp.report.json");
    let fixture_arg: String = fixture.to_string_lossy().into_owned();
    let report_arg: String = report_path.to_string_lossy().into_owned();
    let run: Run = run_disrobe(&[
        "flutter",
        "decompile",
        &fixture_arg,
        "--out",
        &report_arg,
        "--emit",
        "disasm",
    ]);
    assert_ne!(run.code, 0, "unsupported emit unexpectedly succeeded");
    assert!(
        run.stderr.contains("DR-CLI-0766"),
        "the error must name the unsupported Flutter AOT emit kind: {}",
        run.stderr
    );
    assert!(
        !absent_dir.exists(),
        "emit validation must occur before output directory creation"
    );
}

#[test]
fn non_flutter_elf_is_rejected_before_output_creation() {
    let fixture: PathBuf = corpus_path(NON_FLUTTER_ELF_FIXTURE);
    assert!(
        fixture.is_file(),
        "missing fixture at {}",
        fixture.display()
    );
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("flutter-decompile-non-flutter-elf");
    let absent_dir: PathBuf = scratch.path().join("must-not-exist");
    let report_path: PathBuf = absent_dir.join("sample.report.json");
    let source_path: PathBuf = report_path.with_extension("recovered.dart");
    let fixture_arg: String = fixture.to_string_lossy().into_owned();
    let report_arg: String = report_path.to_string_lossy().into_owned();
    let run: Run = run_disrobe(&[
        "flutter",
        "decompile",
        &fixture_arg,
        "--out",
        &report_arg,
        "--emit",
        "source,report",
    ]);
    assert_ne!(run.code, 0, "non-Flutter ELF unexpectedly succeeded");
    assert!(
        run.stderr.contains("DR-CLI-0767"),
        "the error must identify missing Flutter AOT evidence: {}",
        run.stderr
    );
    assert!(!report_path.exists(), "a report must not be created");
    assert!(!source_path.exists(), "recovered Dart must not be created");
    assert!(
        !absent_dir.exists(),
        "Flutter AOT validation must occur before output directory creation"
    );
}

#[test]
fn raw_snapshot_metadata_report_remains_reachable() {
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("flutter-decompile-snapshot");
    let input_path: PathBuf = scratch.path().join("isolate.snapshot");
    let report_path: PathBuf = scratch.path().join("snapshot.report.json");
    write_bytes(&input_path, &dart_snapshot());
    let input_arg: String = input_path.to_string_lossy().into_owned();
    let report_arg: String = report_path.to_string_lossy().into_owned();
    let run: Run = run_disrobe(&["flutter", "decompile", &input_arg, "--out", &report_arg]);
    assert_eq!(run.code, 0, "raw snapshot command failed: {}", run.stderr);
    let report_bytes: Vec<u8> = std::fs::read(&report_path).expect("read snapshot report");
    let report: serde_json::Value =
        serde_json::from_slice(&report_bytes).expect("parse snapshot report");
    assert!(
        report["readable_strings"]
            .as_array()
            .is_some_and(|strings| strings.iter().any(|value| {
                value
                    .as_str()
                    .is_some_and(|text| text.contains("MaterialApp"))
            })),
        "the raw snapshot scanner must retain its metadata output"
    );
}
