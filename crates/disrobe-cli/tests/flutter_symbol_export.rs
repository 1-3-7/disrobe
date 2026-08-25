#![cfg(feature = "flutter")]
#![allow(
    clippy::disallowed_methods,
    clippy::expect_used,
    clippy::panic,
    clippy::unnecessary_debug_formatting
)]

use std::path::PathBuf;
use std::process::{Command, Output};

mod common;

use common::{Run, run_disrobe, temp_dir};

const FLUTTER_AOT_FIXTURE: &str = "mobile/flutter/disrobe_sample/libapp_arm64.so";

fn workspace_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root
}

fn run_flutter_export(format: &str) -> (disrobe_core::scratch::ScratchDir, Run) {
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("flutter-symbol-export");
    let output: PathBuf = scratch.path().join("layout.json");
    let fixture: PathBuf = workspace_root().join("corpus").join(FLUTTER_AOT_FIXTURE);
    assert!(
        fixture.exists(),
        "the committed Flutter AOT fixture is missing at {}; this case cannot grade an absent input",
        fixture.display()
    );
    let fixture_arg: String = fixture.to_string_lossy().into_owned();
    let output_arg: String = output.to_string_lossy().into_owned();
    let run: Run = run_disrobe(&[
        "flutter",
        "dump",
        &fixture_arg,
        "--out",
        &output_arg,
        "--format",
        format,
    ]);
    (scratch, run)
}

#[test]
fn flutter_dump_without_export_keeps_the_layout_only_contract() {
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("flutter-layout-only");
    let output: PathBuf = scratch.path().join("layout.json");
    let fixture: PathBuf = workspace_root().join("corpus").join(FLUTTER_AOT_FIXTURE);
    let fixture_arg: String = fixture.to_string_lossy().into_owned();
    let output_arg: String = output.to_string_lossy().into_owned();
    let run: Run = run_disrobe(&["flutter", "dump", &fixture_arg, "--out", &output_arg]);
    assert_eq!(run.code, 0, "flutter layout dump failed: {}", run.stderr);
    let layout_text: String = std::fs::read_to_string(&output)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", output.display()));
    let layout: serde_json::Value =
        serde_json::from_str(&layout_text).expect("parse Flutter layout JSON");
    assert!(layout["function_symbols"].is_array());
    for sidecar in ["layout.symbols.json", "layout.ghidra.java", "layout.ida.py"] {
        assert!(
            !scratch.path().join(sidecar).exists(),
            "unexpected {sidecar}"
        );
    }
}

#[test]
fn flutter_dump_emits_shared_symbol_formats_from_real_libapp() {
    for (format, file_name) in [
        ("json", "layout.symbols.json"),
        ("ghidra", "layout.ghidra.java"),
        ("ida", "layout.ida.py"),
    ] {
        let (scratch, run): (disrobe_core::scratch::ScratchDir, Run) = run_flutter_export(format);
        assert_eq!(
            run.code, 0,
            "flutter {format} export failed: {}",
            run.stderr
        );
        let sidecar: PathBuf = scratch.path().join(file_name);
        let text: String = std::fs::read_to_string(&sidecar)
            .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", sidecar.display()));
        let (repeat_scratch, repeat_run): (disrobe_core::scratch::ScratchDir, Run) =
            run_flutter_export(format);
        assert_eq!(
            repeat_run.code, 0,
            "repeated flutter {format} export failed: {}",
            repeat_run.stderr
        );
        let repeat_sidecar: PathBuf = repeat_scratch.path().join(file_name);
        let repeat_bytes: Vec<u8> =
            std::fs::read(&repeat_sidecar).unwrap_or_else(|error: std::io::Error| {
                panic!("read {}: {error}", repeat_sidecar.display())
            });
        assert_eq!(text.as_bytes(), repeat_bytes, "{format} output changed");
        assert!(text.contains("fibonacciStep"), "{format}: {text}");
        match format {
            "json" => {
                let map: serde_json::Value =
                    serde_json::from_str(&text).expect("parse symbol map JSON");
                assert_eq!(map["schema"], "disrobe.symbol-map/v2");
                assert_eq!(map["format"], "elf-flutter-aot");
                assert!(
                    map["symbol_count"]
                        .as_u64()
                        .is_some_and(|count: u64| count > 0)
                );
                let fibonacci: &serde_json::Value = map["symbols"]
                    .as_array()
                    .and_then(|symbols: &Vec<serde_json::Value>| {
                        symbols.iter().find(|symbol: &&serde_json::Value| {
                            symbol["name"].as_str() == Some("fibonacciStep")
                        })
                    })
                    .expect("the export must retain the fixture's independently known symbol");
                assert_eq!(fibonacci["address"], 0x12_ef80_u64);
                assert_eq!(fibonacci["class"], "function");
                assert_eq!(fibonacci["origin"], "symbol-table");
            }
            "ghidra" => {
                assert!(text.contains("public class DisrobeApplySymbols"));
                assert_eq!(text.matches('{').count(), text.matches('}').count());
            }
            "ida" => {
                let compile: Output = Command::new("python")
                    .arg("-m")
                    .arg("py_compile")
                    .arg(&sidecar)
                    .output()
                    .expect("compile IDAPython sidecar");
                assert!(
                    compile.status.success(),
                    "IDAPython sidecar failed to compile: {}",
                    String::from_utf8_lossy(&compile.stderr)
                );
            }
            _ => unreachable!(),
        }
    }
}
