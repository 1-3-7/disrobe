#![cfg(all(feature = "chain", feature = "flutter"))]
#![allow(
    clippy::disallowed_methods,
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used
)]

use std::path::{Path, PathBuf};

mod common;

use common::{Run, run_disrobe, temp_dir};

const FLUTTER_AOT_FIXTURE: &str = "mobile/flutter/disrobe_sample/libapp_arm64.so";

fn fixture_path() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root.join("corpus").join(FLUTTER_AOT_FIXTURE)
}

fn run_auto(input: &Path, out: &Path, format: &str, extra: &[&str]) -> Run {
    let input_arg: String = input.to_string_lossy().into_owned();
    let out_arg: String = out.to_string_lossy().into_owned();
    let mut args: Vec<&str> = vec!["auto", &input_arg, "--out", &out_arg, "--format", format];
    args.extend_from_slice(extra);
    run_disrobe(&args)
}

#[test]
fn auto_exports_flutter_symbols_from_the_direct_root_aot_image() {
    let fixture: PathBuf = fixture_path();
    assert!(
        fixture.exists(),
        "missing tracked Flutter fixture {}",
        fixture.display()
    );

    for (format, filename) in [
        ("ghidra", "symbols.ghidra.java"),
        ("ida", "symbols.ida.py"),
        ("json", "symbols.json"),
    ] {
        let scratch: disrobe_core::scratch::ScratchDir = temp_dir("auto-flutter-symbol-export");
        let out: PathBuf = scratch.path().join(format);
        let run: Run = run_auto(&fixture, &out, format, &[]);
        assert_eq!(run.code, 0, "{format} export failed: {}", run.stderr);
        assert!(run.stdout.contains("Flutter symbol export written:"));

        let sidecar: PathBuf = out.join("exports").join("flutter").join(filename);
        let first: Vec<u8> = std::fs::read(&sidecar)
            .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", sidecar.display()));
        let text: String = String::from_utf8(first.clone())
            .unwrap_or_else(|error: std::string::FromUtf8Error| panic!("utf-8 sidecar: {error}"));
        assert!(text.contains("fibonacciStep"), "{format}: {text}");

        let repeat_out: PathBuf = scratch.path().join(format!("{format}-repeat"));
        let repeat: Run = run_auto(&fixture, &repeat_out, format, &[]);
        assert_eq!(
            repeat.code, 0,
            "repeated {format} export failed: {}",
            repeat.stderr
        );
        let second: Vec<u8> =
            std::fs::read(repeat_out.join("exports").join("flutter").join(filename))
                .unwrap_or_else(|error: std::io::Error| {
                    panic!("read repeated {filename}: {error}")
                });
        assert_eq!(first, second, "{format} output changed between runs");
    }
}

#[test]
fn auto_dry_run_does_not_write_flutter_symbol_exports() {
    let fixture: PathBuf = fixture_path();
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("auto-flutter-symbol-export-dry-run");
    let out: PathBuf = scratch.path().join("must-not-exist");
    let run: Run = run_auto(&fixture, &out, "ghidra", &["--dry-run"]);

    assert_eq!(run.code, 0, "dry-run failed: {}", run.stderr);
    assert!(!out.exists(), "dry-run created {}", out.display());
    assert!(!run.stdout.contains("Flutter symbol export written:"));
}
