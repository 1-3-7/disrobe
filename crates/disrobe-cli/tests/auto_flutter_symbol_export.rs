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

fn dex_fixture_path() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root.join("corpus/jvm/dex/EdgeCases.dex")
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

#[test]
fn auto_applies_a_build_id_matched_external_engine_map_deterministically() {
    let fixture: PathBuf = fixture_path();
    let bytes: Vec<u8> = std::fs::read(&fixture).expect("read Flutter fixture");
    let layout: disrobe_pass_mobile::flutter::LibAppLayout =
        disrobe_pass_mobile::parse_libapp_so(&bytes).expect("parse Flutter image");
    let local_symbol: &disrobe_pass_mobile::flutter::DartFunctionSymbol = layout
        .function_symbols
        .first()
        .expect("tracked Flutter function symbol");
    let address: u64 = local_symbol.address;
    let local_name: &str = &local_symbol.name;
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("auto-flutter-engine-symbol-map");
    let map_path: PathBuf = scratch.path().join("engine-symbols.json");
    let map: serde_json::Value = serde_json::json!({
        "format": "disrobe.flutter.engine-symbol-map",
        "version": 1,
        "identity": {
            "kind": "elf-build-id",
            "value": "b71885094a73117bf90d3cfa05824129"
        },
        "symbols": [{ "address": address, "name": "FlutterEngineExternal" }]
    });
    std::fs::write(
        &map_path,
        serde_json::to_vec_pretty(&map).expect("serialize engine map"),
    )
    .expect("write engine map");
    let map_arg: String = map_path.to_string_lossy().into_owned();

    let first_out: PathBuf = scratch.path().join("first");
    let first: Run = run_auto(
        &fixture,
        &first_out,
        "json",
        &["--engine-symbol-map", &map_arg],
    );
    assert_eq!(first.code, 0, "auto map failed: {}", first.stderr);
    let first_bytes: Vec<u8> =
        std::fs::read(first_out.join("exports/flutter/symbols.json")).expect("read first map");
    let first_json: serde_json::Value =
        serde_json::from_slice(&first_bytes).expect("parse first map");
    assert_eq!(
        first_json["provenance"][0]["identity"],
        "b71885094a73117bf90d3cfa05824129"
    );
    assert_eq!(
        first_json["provenance"][0]["source"],
        map_path.display().to_string()
    );
    assert!(
        first_json["symbols"]
            .as_array()
            .is_some_and(|symbols| symbols.iter().any(|symbol| {
                symbol["name"] == "FlutterEngineExternal" && symbol["origin"] == "compiler-runtime"
            }))
    );
    let symbols_at_address: Vec<&serde_json::Value> = first_json["symbols"]
        .as_array()
        .expect("symbol array")
        .iter()
        .filter(|symbol: &&serde_json::Value| symbol["address"] == address)
        .collect();
    assert_eq!(symbols_at_address.len(), 1);
    assert_eq!(symbols_at_address[0]["name"], "FlutterEngineExternal");
    assert_ne!(symbols_at_address[0]["name"], local_name);

    let second_out: PathBuf = scratch.path().join("second");
    let second: Run = run_auto(
        &fixture,
        &second_out,
        "json",
        &["--engine-symbol-map", &map_arg],
    );
    assert_eq!(second.code, 0, "repeat auto map failed: {}", second.stderr);
    assert_eq!(
        first_bytes,
        std::fs::read(second_out.join("exports/flutter/symbols.json")).expect("read repeated map")
    );
}

#[test]
fn flutter_dump_applies_only_a_build_id_matched_external_engine_map() {
    let fixture: PathBuf = fixture_path();
    let bytes: Vec<u8> = std::fs::read(&fixture).expect("read Flutter fixture");
    let native: disrobe_binfmt::NativeFile =
        disrobe_binfmt::parse_native(&bytes).expect("parse Flutter image");
    let address: u64 = native
        .segments
        .iter()
        .find(|segment| segment.size != 0)
        .expect("bounded Flutter segment")
        .address;
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("flutter-engine-symbol-map");
    let map_path: PathBuf = scratch.path().join("engine-symbols.json");
    let out_path: PathBuf = scratch.path().join("layout.json");
    let map: serde_json::Value = serde_json::json!({
        "format": "disrobe.flutter.engine-symbol-map",
        "version": 1,
        "identity": {
            "kind": "elf-build-id",
            "value": "b71885094a73117bf90d3cfa05824129"
        },
        "symbols": [{ "address": address, "name": "FlutterEngineExternal" }]
    });
    std::fs::write(
        &map_path,
        serde_json::to_vec_pretty(&map).expect("serialize engine map"),
    )
    .expect("write engine map");
    let input_arg: String = fixture.to_string_lossy().into_owned();
    let out_arg: String = out_path.to_string_lossy().into_owned();
    let map_arg: String = map_path.to_string_lossy().into_owned();

    let run: Run = run_disrobe(&[
        "flutter",
        "dump",
        &input_arg,
        "--out",
        &out_arg,
        "--format",
        "json",
        "--engine-symbol-map",
        &map_arg,
    ]);

    assert_eq!(run.code, 0, "flutter dump failed: {}", run.stderr);
    let sidecar: String = std::fs::read_to_string(out_path.with_extension("symbols.json"))
        .expect("read Flutter symbol sidecar");
    assert!(sidecar.contains("FlutterEngineExternal"), "{sidecar}");
    assert!(sidecar.contains("compiler-runtime"), "{sidecar}");
}

#[test]
fn flutter_dump_refuses_a_mismatched_external_engine_map() {
    let fixture: PathBuf = fixture_path();
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("flutter-engine-symbol-map-mismatch");
    let map_path: PathBuf = scratch.path().join("engine-symbols.json");
    let out_path: PathBuf = scratch.path().join("layout.json");
    let map: serde_json::Value = serde_json::json!({
        "format": "disrobe.flutter.engine-symbol-map",
        "version": 1,
        "identity": {
            "kind": "elf-build-id",
            "value": "00000000000000000000000000000000"
        },
        "symbols": []
    });
    std::fs::write(
        &map_path,
        serde_json::to_vec_pretty(&map).expect("serialize engine map"),
    )
    .expect("write engine map");
    let input_arg: String = fixture.to_string_lossy().into_owned();
    let out_arg: String = out_path.to_string_lossy().into_owned();
    let map_arg: String = map_path.to_string_lossy().into_owned();

    let run: Run = run_disrobe(&[
        "flutter",
        "dump",
        &input_arg,
        "--out",
        &out_arg,
        "--format",
        "json",
        "--engine-symbol-map",
        &map_arg,
    ]);

    assert_ne!(run.code, 0, "mismatched map unexpectedly succeeded");
    assert!(run.stderr.contains("DR-MOB-0060"), "{}", run.stderr);
    assert!(
        run.stderr.contains("00000000000000000000000000000000"),
        "{}",
        run.stderr
    );
    assert!(
        run.stderr.contains("b71885094a73117bf90d3cfa05824129"),
        "{}",
        run.stderr
    );
    assert!(!out_path.exists(), "mismatched map wrote partial output");

    let auto_out: PathBuf = scratch.path().join("auto-out");
    let auto: Run = run_auto(
        &fixture,
        &auto_out,
        "json",
        &["--engine-symbol-map", &map_arg],
    );
    assert_ne!(auto.code, 0, "auto accepted mismatched map");
    assert!(auto.stderr.contains("DR-MOB-0060"), "{}", auto.stderr);
    assert!(
        auto.stderr.contains("00000000000000000000000000000000"),
        "{}",
        auto.stderr
    );
    assert!(
        auto.stderr.contains("b71885094a73117bf90d3cfa05824129"),
        "{}",
        auto.stderr
    );
    assert!(
        !auto_out.join("exports/flutter/symbols.json").exists(),
        "mismatched auto map wrote a Flutter symbol export"
    );
}

#[test]
fn auto_refuses_an_engine_map_for_a_non_flutter_root() {
    let fixture: PathBuf = dex_fixture_path();
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("auto-non-flutter-engine-map");
    let map_path: PathBuf = scratch.path().join("engine-symbols.json");
    std::fs::write(
        &map_path,
        br#"{"format":"disrobe.flutter.engine-symbol-map","version":1,"identity":{"kind":"elf-build-id","value":"00000000000000000000000000000000"},"symbols":[]}"#,
    )
    .expect("write engine map");
    let map_arg: String = map_path.to_string_lossy().into_owned();
    let out: PathBuf = scratch.path().join("out");

    let run: Run = run_auto(&fixture, &out, "json", &["--engine-symbol-map", &map_arg]);

    assert_ne!(run.code, 0, "non-Flutter map unexpectedly succeeded");
    assert!(run.stderr.contains("DR-CLI-0446"), "{}", run.stderr);
    assert!(!out.join("exports/flutter/symbols.json").exists());
}
