#![cfg(all(feature = "chain", feature = "flutter"))]
#![allow(clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

mod common;

use common::{Run, run_disrobe, temp_dir};

const FLUTTER_AOT_FIXTURE: &str = "mobile/flutter/disrobe_sample/libapp_arm64.so";

fn fixture_bytes() -> Vec<u8> {
    let root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    std::fs::read(root.join("corpus").join(FLUTTER_AOT_FIXTURE)).expect("read Flutter fixture")
}

fn without_build_id(mut bytes: Vec<u8>) -> Vec<u8> {
    let program_headers: usize = usize::try_from(u64::from_le_bytes(
        bytes[32..40].try_into().expect("ELF program header offset"),
    ))
    .expect("program header offset fits usize");
    let entry_size: usize = usize::from(u16::from_le_bytes(
        bytes[54..56].try_into().expect("ELF program header size"),
    ));
    let count: usize = usize::from(u16::from_le_bytes(
        bytes[56..58].try_into().expect("ELF program header count"),
    ));
    for index in 0..count {
        let offset: usize = program_headers + index * entry_size;
        if u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("segment type")) == 4 {
            bytes[offset..offset + 4].copy_from_slice(&0_u32.to_le_bytes());
            return bytes;
        }
    }
    panic!("fixture contains a GNU build-ID note segment");
}

fn run_auto(input: &Path, out: &Path, map: &Path) -> Run {
    let input_arg: String = input.to_string_lossy().into_owned();
    let out_arg: String = out.to_string_lossy().into_owned();
    let map_arg: String = map.to_string_lossy().into_owned();
    run_disrobe(&[
        "auto",
        &input_arg,
        "--out",
        &out_arg,
        "--format",
        "json",
        "--engine-symbol-map",
        &map_arg,
        "--no-cache",
    ])
}

#[test]
fn flutter_dump_and_auto_apply_an_exact_fallback_identity_map_with_fallback_provenance() {
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("flutter-engine-fallback-identity");
    let input: PathBuf = scratch.path().join("libapp-no-build-id.so");
    let bytes: Vec<u8> = without_build_id(fixture_bytes());
    std::fs::write(&input, &bytes).expect("write build-id-less Flutter image");
    let identity =
        disrobe_pass_mobile::flutter_engine_identity_for_elf(&bytes).expect("fallback identity");
    assert_eq!(
        identity.kind,
        disrobe_pass_mobile::FlutterEngineSymbolMapIdentityKind::ElfExecutableTextBlake3
    );
    let layout: disrobe_pass_mobile::LibAppLayout =
        disrobe_pass_mobile::parse_libapp_so(&bytes).expect("parse Flutter image");
    let address: u64 = layout
        .function_symbols
        .first()
        .expect("tracked Flutter symbol")
        .address;
    let map_path: PathBuf = scratch.path().join("engine-symbols.json");
    let map: serde_json::Value = serde_json::json!({
        "format": "disrobe.flutter.engine-symbol-map",
        "version": 1,
        "identity": identity,
        "symbols": [{ "address": address, "name": "FallbackEngineName" }]
    });
    std::fs::write(&map_path, serde_json::to_vec(&map).expect("serialize map")).expect("write map");

    let input_arg: String = input.to_string_lossy().into_owned();
    let direct_out: PathBuf = scratch.path().join("direct.json");
    let direct_out_arg: String = direct_out.to_string_lossy().into_owned();
    let map_arg: String = map_path.to_string_lossy().into_owned();
    let direct: Run = run_disrobe(&[
        "flutter",
        "dump",
        &input_arg,
        "--out",
        &direct_out_arg,
        "--format",
        "json",
        "--engine-symbol-map",
        &map_arg,
        "--no-cache",
    ]);
    assert_eq!(direct.code, 0, "flutter dump failed: {}", direct.stderr);
    let direct_json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(direct_out.with_extension("symbols.json")).expect("read direct export"),
    )
    .expect("parse direct export");
    assert_eq!(
        direct_json["provenance"][0]["kind"],
        "fallback-elf-executable-text-blake3"
    );
    assert!(direct_json["symbols"].as_array().is_some_and(|symbols| {
        symbols
            .iter()
            .any(|symbol| symbol["name"] == "FallbackEngineName")
    }));

    let auto_out: PathBuf = scratch.path().join("auto");
    let automatic: Run = run_auto(&input, &auto_out, &map_path);
    assert_eq!(automatic.code, 0, "auto failed: {}", automatic.stderr);
    let auto_json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(auto_out.join("exports/flutter/symbols.json")).expect("read auto export"),
    )
    .expect("parse auto export");
    assert_eq!(
        auto_json["provenance"][0]["kind"],
        "fallback-elf-executable-text-blake3"
    );
    assert!(auto_json["symbols"].as_array().is_some_and(|symbols| {
        symbols
            .iter()
            .any(|symbol| symbol["name"] == "FallbackEngineName")
    }));
}
