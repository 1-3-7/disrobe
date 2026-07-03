#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::path::PathBuf;

use disrobe_pass_lua::hercules;
use disrobe_pass_lua::obfuscator::{
    DeobfOptions, LuaObfuscatorKind, ObfuscatorDetection, PeelResult,
};

fn corpus_path(rel: &str) -> PathBuf {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    let mut p: PathBuf = PathBuf::from(manifest_dir);
    p.push("..");
    p.push("..");
    p.push("corpus");
    p.push("lua");
    p.push("hercules");
    p.push("gauntlet");
    for seg in rel.split('/') {
        p.push(seg);
    }
    p
}

fn load(name: &str) -> Vec<u8> {
    let path: PathBuf = corpus_path(name);
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("fixture {name} missing at {}: {e}", path.display()))
}

#[test]
fn obfuscated_fixture_is_tracked_and_large() {
    let bytes: Vec<u8> = load("gauntlet_obfuscated.lua");
    assert!(
        bytes.len() > 100_000,
        "real Hercules output must be a large self-decrypting blob, got {} bytes",
        bytes.len()
    );
}

#[test]
fn clean_fixture_carries_known_semantics() {
    let bytes: Vec<u8> = load("gauntlet_clean.lua");
    let text: String = String::from_utf8(bytes).expect("clean source is utf8");
    assert!(text.contains("hello from disrobe gauntlet"));
    assert!(text.contains("classify"));
}

#[test]
fn detects_real_hercules_output() {
    let bytes: Vec<u8> = load("gauntlet_obfuscated.lua");
    let det: ObfuscatorDetection =
        hercules::detect(&bytes).expect("must detect Hercules on real output");
    assert_eq!(det.kind, LuaObfuscatorKind::Hercules);
    assert!(
        det.confidence >= 90,
        "watermark + loader must yield high confidence, got {}",
        det.confidence
    );
    assert!(
        det.markers
            .iter()
            .any(|m: &String| m.contains("Hercules") || m.contains("hercules")),
        "must report the watermark marker, got {:?}",
        det.markers
    );
    assert!(
        det.markers.iter().any(|m: &String| m.contains("loader")),
        "must report the hex-subtract loader marker, got {:?}",
        det.markers
    );
}

#[test]
fn peel_decrypts_outer_loader_to_lua_bytecode() {
    let bytes: Vec<u8> = load("gauntlet_obfuscated.lua");
    let out: PeelResult =
        hercules::peel(&bytes, &DeobfOptions::default()).expect("peel must run on real output");

    assert!(
        out.passes_run
            .iter()
            .any(|p: &String| p.contains("hex-subtract-loader-decode")),
        "must run the hex-subtract loader decode, passes={:?}",
        out.passes_run
    );
    assert!(
        out.passes_run
            .iter()
            .any(|p: &String| p.contains("embedded-bytecode-constant-extract")),
        "loader must decrypt to a parseable Lua bytecode chunk, passes={:?}",
        out.passes_run
    );
}

#[test]
fn peel_extracts_embedded_next_layer_constant() {
    let bytes: Vec<u8> = load("gauntlet_obfuscated.lua");
    let out: PeelResult = hercules::peel(&bytes, &DeobfOptions::default()).expect("peel");

    let inner: &str = out
        .recovered_strings
        .iter()
        .map(String::as_str)
        .max_by_key(|s: &&str| s.len())
        .expect("must recover the embedded bytecode-chunk string constant");

    assert!(
        inner.len() > 1000,
        "extracted embedded constant must be a substantial next-layer blob, got {} bytes",
        inner.len()
    );
}

#[test]
fn peel_is_honest_about_the_vm_wall() {
    let bytes: Vec<u8> = load("gauntlet_obfuscated.lua");
    let out: PeelResult = hercules::peel(&bytes, &DeobfOptions::default()).expect("peel");

    assert!(
        !out.fully_recovered,
        "StringToExpressions + VMGenerator inner layer is not lifted; fully_recovered must be false"
    );
    assert!(
        out.residual_markers
            .iter()
            .any(|m: &String| m.contains("VM") || m.contains("StringToExpressions")),
        "must document the remaining VM layer, got {:?}",
        out.residual_markers
    );
}

#[test]
fn detection_does_not_fire_on_clean_source() {
    let bytes: Vec<u8> = load("gauntlet_clean.lua");
    assert!(
        hercules::detect(&bytes).is_none(),
        "clean known.lua must not be misdetected as Hercules"
    );
}
