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
        let run: Run = run_auto(&fixture, &out, format, &["--no-cache"]);
        assert_eq!(run.code, 0, "{format} export failed: {}", run.stderr);
        assert!(run.stdout.contains("Flutter symbol export written:"));

        let sidecar: PathBuf = out.join("exports").join("flutter").join(filename);
        let first: Vec<u8> = std::fs::read(&sidecar)
            .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", sidecar.display()));
        let text: String = String::from_utf8(first.clone())
            .unwrap_or_else(|error: std::string::FromUtf8Error| panic!("utf-8 sidecar: {error}"));
        assert!(text.contains("fibonacciStep"), "{format}: {text}");

        let repeat_out: PathBuf = scratch.path().join(format!("{format}-repeat"));
        let repeat: Run = run_auto(&fixture, &repeat_out, format, &["--no-cache"]);
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
fn auto_reads_a_relative_engine_map_from_config_and_command_line_wins() {
    let fixture: PathBuf = fixture_path();
    let bytes: Vec<u8> = std::fs::read(&fixture).expect("read Flutter fixture");
    let layout: disrobe_pass_mobile::flutter::LibAppLayout =
        disrobe_pass_mobile::parse_libapp_so(&bytes).expect("parse Flutter image");
    let address: u64 = layout
        .function_symbols
        .first()
        .expect("tracked Flutter function symbol")
        .address;
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("auto-flutter-config-engine-map");
    let maps: PathBuf = scratch.path().join("maps");
    std::fs::create_dir_all(&maps).expect("create map directory");
    let config_map: PathBuf = maps.join("config.json");
    let flag_map: PathBuf = maps.join("flag.json");
    for (path, name) in [(&config_map, "FromConfig"), (&flag_map, "FromFlag")] {
        let map: serde_json::Value = serde_json::json!({
            "format": "disrobe.flutter.engine-symbol-map",
            "version": 1,
            "identity": {
                "kind": "elf-build-id",
                "value": "b71885094a73117bf90d3cfa05824129"
            },
            "symbols": [{ "address": address, "name": name }]
        });
        std::fs::write(
            path,
            serde_json::to_vec_pretty(&map).expect("serialize engine map"),
        )
        .expect("write engine map");
    }
    let config: PathBuf = scratch.path().join("disrobe.toml");
    std::fs::write(
        &config,
        "[execution]\nengine_symbol_map = \"maps/config.json\"\n",
    )
    .expect("write config");
    let config_arg: String = config.to_string_lossy().into_owned();
    let fixture_arg: String = fixture.to_string_lossy().into_owned();
    let config_out: PathBuf = scratch.path().join("config-out");
    let config_out_arg: String = config_out.to_string_lossy().into_owned();

    let from_config: Run = run_disrobe(&[
        "--config",
        &config_arg,
        "auto",
        &fixture_arg,
        "--out",
        &config_out_arg,
        "--format",
        "json",
    ]);
    assert_eq!(
        from_config.code, 0,
        "config map failed: {}",
        from_config.stderr
    );
    let config_export: String =
        std::fs::read_to_string(config_out.join("exports/flutter/symbols.json"))
            .expect("read config export");
    assert!(config_export.contains("FromConfig"), "{config_export}");
    let config_json: serde_json::Value =
        serde_json::from_str(&config_export).expect("parse config export");
    let config_source: PathBuf = PathBuf::from(
        config_json["provenance"][0]["source"]
            .as_str()
            .expect("config map source"),
    );
    assert_eq!(
        config_source
            .canonicalize()
            .expect("canonicalize config source"),
        config_map.canonicalize().expect("canonicalize config map")
    );

    let flag_out: PathBuf = scratch.path().join("flag-out");
    let flag_out_arg: String = flag_out.to_string_lossy().into_owned();
    let flag_arg: String = flag_map.to_string_lossy().into_owned();
    let from_flag: Run = run_disrobe(&[
        "--config",
        &config_arg,
        "auto",
        &fixture_arg,
        "--out",
        &flag_out_arg,
        "--format",
        "json",
        "--engine-symbol-map",
        &flag_arg,
    ]);
    assert_eq!(
        from_flag.code, 0,
        "explicit map failed: {}",
        from_flag.stderr
    );
    let flag_export: String =
        std::fs::read_to_string(flag_out.join("exports/flutter/symbols.json"))
            .expect("read explicit-map export");
    assert!(flag_export.contains("FromFlag"), "{flag_export}");
    assert!(!flag_export.contains("FromConfig"), "{flag_export}");
    let flag_json: serde_json::Value =
        serde_json::from_str(&flag_export).expect("parse flag export");
    let flag_source: PathBuf = PathBuf::from(
        flag_json["provenance"][0]["source"]
            .as_str()
            .expect("explicit map source"),
    );
    assert_eq!(
        flag_source
            .canonicalize()
            .expect("canonicalize explicit source"),
        flag_map.canonicalize().expect("canonicalize explicit map")
    );
}

#[test]
fn auto_config_map_rejects_malformed_and_mismatched_maps_before_export() {
    let fixture: PathBuf = fixture_path();
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("auto-flutter-config-map-errors");
    let fixture_arg: String = fixture.to_string_lossy().into_owned();

    for (name, contents, error_code) in [
        ("malformed", b"not json".as_slice(), "DR-MOB-005"),
        (
            "mismatched",
            br#"{"format":"disrobe.flutter.engine-symbol-map","version":1,"identity":{"kind":"elf-build-id","value":"00000000000000000000000000000000"},"symbols":[]}"#,
            "DR-MOB-0060",
        ),
    ] {
        let case_dir: PathBuf = scratch.path().join(name);
        std::fs::create_dir_all(&case_dir).expect("create case directory");
        let map: PathBuf = case_dir.join("map.json");
        std::fs::write(&map, contents).expect("write invalid map");
        let config: PathBuf = case_dir.join("disrobe.toml");
        std::fs::write(&config, "[execution]\nengine_symbol_map = \"map.json\"\n")
            .expect("write config");
        let config_arg: String = config.to_string_lossy().into_owned();
        let out: PathBuf = case_dir.join("out");
        let out_arg: String = out.to_string_lossy().into_owned();
        let run: Run = run_disrobe(&[
            "--config",
            &config_arg,
            "auto",
            &fixture_arg,
            "--out",
            &out_arg,
            "--format",
            "json",
        ]);
        assert_ne!(run.code, 0, "{name} map unexpectedly succeeded");
        assert!(run.stderr.contains(error_code), "{name}: {}", run.stderr);
        assert!(
            !out.join("exports/flutter/symbols.json").exists(),
            "{name} config map wrote a Flutter symbol export"
        );
    }
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

#[test]
fn flutter_engine_map_cache_reuses_only_the_matching_build_and_honors_no_cache() {
    let fixture: PathBuf = fixture_path();
    let bytes: Vec<u8> = std::fs::read(&fixture).expect("read Flutter fixture");
    let layout: disrobe_pass_mobile::flutter::LibAppLayout =
        disrobe_pass_mobile::parse_libapp_so(&bytes).expect("parse Flutter image");
    let address: u64 = layout
        .function_symbols
        .first()
        .expect("tracked Flutter function symbol")
        .address;
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("flutter-engine-map-cache");
    let map_path: PathBuf = scratch.path().join("engine-symbols.json");
    let cache_dir: PathBuf = scratch.path().join("cache");
    let config: PathBuf = scratch.path().join("disrobe.toml");
    let map: serde_json::Value = serde_json::json!({
        "format": "disrobe.flutter.engine-symbol-map",
        "version": 1,
        "identity": {
            "kind": "elf-build-id",
            "value": "b71885094a73117bf90d3cfa05824129"
        },
        "symbols": [{ "address": address, "name": "CachedFlutterEngine" }]
    });
    std::fs::write(&map_path, serde_json::to_vec(&map).expect("serialize map")).expect("write map");
    std::fs::write(
        &config,
        format!(
            "[execution]\ncache_dir = {:?}\n",
            cache_dir.display().to_string()
        ),
    )
    .expect("write config");
    let fixture_arg: String = fixture.to_string_lossy().into_owned();
    let map_arg: String = map_path.to_string_lossy().into_owned();
    let config_arg: String = config.to_string_lossy().into_owned();

    let seeded_out: PathBuf = scratch.path().join("seeded");
    let seeded_out_arg: String = seeded_out.to_string_lossy().into_owned();
    let seeded: Run = run_disrobe(&[
        "--config",
        &config_arg,
        "auto",
        &fixture_arg,
        "--out",
        &seeded_out_arg,
        "--format",
        "json",
        "--engine-symbol-map",
        &map_arg,
    ]);
    assert_eq!(seeded.code, 0, "seed cache failed: {}", seeded.stderr);

    let cached_out: PathBuf = scratch.path().join("cached");
    let cached_out_arg: String = cached_out.to_string_lossy().into_owned();
    let cached: Run = run_disrobe(&[
        "--config",
        &config_arg,
        "auto",
        &fixture_arg,
        "--out",
        &cached_out_arg,
        "--format",
        "json",
    ]);
    assert_eq!(cached.code, 0, "cached auto failed: {}", cached.stderr);
    let cached_json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(cached_out.join("exports/flutter/symbols.json"))
            .expect("read cached export"),
    )
    .expect("parse cached export");
    assert_eq!(cached_json["provenance"][0]["source"], "cache");
    assert!(cached_json["symbols"].as_array().is_some_and(|symbols| {
        symbols
            .iter()
            .any(|symbol| symbol["name"] == "CachedFlutterEngine")
    }));

    let direct_out: PathBuf = scratch.path().join("direct.json");
    let direct_out_arg: String = direct_out.to_string_lossy().into_owned();
    let direct: Run = run_disrobe(&[
        "--config",
        &config_arg,
        "flutter",
        "dump",
        &fixture_arg,
        "--out",
        &direct_out_arg,
        "--format",
        "json",
    ]);
    assert_eq!(direct.code, 0, "cached dump failed: {}", direct.stderr);
    let direct_json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(direct_out.with_extension("symbols.json")).expect("read direct export"),
    )
    .expect("parse direct export");
    assert_eq!(direct_json["provenance"], cached_json["provenance"]);

    let no_cache_out: PathBuf = scratch.path().join("no-cache");
    let no_cache_out_arg: String = no_cache_out.to_string_lossy().into_owned();
    let no_cache: Run = run_disrobe(&[
        "--config",
        &config_arg,
        "--no-cache",
        "auto",
        &fixture_arg,
        "--out",
        &no_cache_out_arg,
        "--format",
        "json",
    ]);
    assert_eq!(
        no_cache.code, 0,
        "no-cache auto failed: {}",
        no_cache.stderr
    );
    let no_cache_json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(no_cache_out.join("exports/flutter/symbols.json"))
            .expect("read no-cache export"),
    )
    .expect("parse no-cache export");
    assert!(no_cache_json["provenance"].is_null());
    assert!(no_cache_json["symbols"].as_array().is_some_and(|symbols| {
        !symbols
            .iter()
            .any(|symbol| symbol["name"] == "CachedFlutterEngine")
    }));

    let altered_input: PathBuf = scratch.path().join("other-build.so");
    let mut altered_bytes: Vec<u8> = bytes.clone();
    let old_build_id: &[u8] = b"\xb7\x18\x85\x09\x4a\x73\x11\x7b\xf9\x0d\x3c\xfa\x05\x82\x41\x29";
    let build_id_offset: usize = altered_bytes
        .windows(old_build_id.len())
        .position(|window: &[u8]| window == old_build_id)
        .expect("find tracked build ID");
    altered_bytes[build_id_offset..build_id_offset + old_build_id.len()]
        .copy_from_slice(&[0x11; 16]);
    std::fs::write(&altered_input, altered_bytes).expect("write altered build");
    let altered_input_arg: String = altered_input.to_string_lossy().into_owned();
    let altered_out: PathBuf = scratch.path().join("altered");
    let altered_out_arg: String = altered_out.to_string_lossy().into_owned();
    let altered: Run = run_disrobe(&[
        "--config",
        &config_arg,
        "auto",
        &altered_input_arg,
        "--out",
        &altered_out_arg,
        "--format",
        "json",
    ]);
    assert_eq!(altered.code, 0, "other build failed: {}", altered.stderr);
    let altered_json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(altered_out.join("exports/flutter/symbols.json"))
            .expect("read other-build export"),
    )
    .expect("parse other-build export");
    assert!(altered_json["provenance"].is_null());

    let no_write_cache: PathBuf = scratch.path().join("no-write-cache");
    let no_write_config: PathBuf = scratch.path().join("no-write.toml");
    std::fs::write(
        &no_write_config,
        format!(
            "[execution]\ncache_dir = {:?}\n",
            no_write_cache.display().to_string()
        ),
    )
    .expect("write no-cache config");
    let no_write_config_arg: String = no_write_config.to_string_lossy().into_owned();
    let no_write_out: PathBuf = scratch.path().join("no-write");
    let no_write_out_arg: String = no_write_out.to_string_lossy().into_owned();
    let no_write: Run = run_disrobe(&[
        "--config",
        &no_write_config_arg,
        "--no-cache",
        "auto",
        &fixture_arg,
        "--out",
        &no_write_out_arg,
        "--format",
        "json",
        "--engine-symbol-map",
        &map_arg,
    ]);
    assert_eq!(
        no_write.code, 0,
        "no-cache seed failed: {}",
        no_write.stderr
    );
    assert!(!no_write_cache.exists());

    let identity: disrobe_pass_mobile::FlutterEngineIdentity =
        disrobe_pass_mobile::flutter_engine_identity_for_elf(&bytes).expect("read build identity");
    let cache = disrobe_pass_mobile::FlutterEngineSymbolCache::new(
        cache_dir.join("flutter-engine-symbols"),
    );
    cache
        .store(
            &identity,
            &[disrobe_pass_mobile::FlutterEngineSymbol {
                address: u64::MAX,
                name: "OutsideLoadedImage".to_owned(),
            }],
        )
        .expect("seed invalid cached symbol");
    let invalid_out: PathBuf = scratch.path().join("invalid-cache");
    let invalid_out_arg: String = invalid_out.to_string_lossy().into_owned();
    let invalid: Run = run_disrobe(&[
        "--config",
        &config_arg,
        "auto",
        &fixture_arg,
        "--out",
        &invalid_out_arg,
        "--format",
        "json",
    ]);
    assert_eq!(invalid.code, 0, "invalid cache failed: {}", invalid.stderr);
    let invalid_json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(invalid_out.join("exports/flutter/symbols.json"))
            .expect("read invalid-cache export"),
    )
    .expect("parse invalid-cache export");
    assert!(invalid_json["provenance"].is_null());
}
