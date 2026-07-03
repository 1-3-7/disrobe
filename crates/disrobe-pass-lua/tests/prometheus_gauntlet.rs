#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::path::PathBuf;

use disrobe_pass_lua::obfuscator::{
    DeobfOptions, LuaObfuscatorKind, ObfuscatorDetection, PeelResult,
};
use disrobe_pass_lua::prometheus;

fn corpus_path(rel: &str) -> PathBuf {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    let mut p: PathBuf = PathBuf::from(manifest_dir);
    p.push("..");
    p.push("..");
    p.push("corpus");
    p.push("lua");
    p.push("prometheus");
    p.push("gauntlet");
    for seg in rel.split('/') {
        p.push(seg);
    }
    p
}

fn load_fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = corpus_path(name);
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("fixture {name} missing at {}: {e}", path.display()))
}

#[test]
fn gauntlet_weak_file_is_tracked_and_non_empty() {
    let bytes: Vec<u8> = load_fixture("gauntlet_weak_obfuscated.lua");
    assert!(
        bytes.len() > 4096,
        "obfuscated fixture must be >4 KB, got {} bytes",
        bytes.len()
    );
}

#[test]
fn gauntlet_clean_file_is_tracked_and_non_empty() {
    let bytes: Vec<u8> = load_fixture("gauntlet_clean.lua");
    assert!(
        bytes.len() > 512,
        "clean source fixture must be >512 bytes, got {} bytes",
        bytes.len()
    );
}

#[test]
fn prometheus_detects_gauntlet_weak_obfuscated() {
    let bytes: Vec<u8> = load_fixture("gauntlet_weak_obfuscated.lua");
    let det: ObfuscatorDetection =
        prometheus::detect(&bytes).expect("must detect Prometheus on gauntlet fixture");
    assert_eq!(det.kind, LuaObfuscatorKind::Prometheus);
    assert!(
        det.confidence >= 50,
        "confidence must be >=50, got {}",
        det.confidence
    );
    assert!(
        !det.markers.is_empty(),
        "detection must report at least one structural marker"
    );
}

#[test]
fn prometheus_gauntlet_weak_peel_recovers_base85_string_pool() {
    let bytes: Vec<u8> = load_fixture("gauntlet_weak_obfuscated.lua");
    let opts: DeobfOptions = DeobfOptions::default();
    let out: PeelResult =
        prometheus::peel(&bytes, &opts).expect("peel must succeed on gauntlet fixture");

    assert!(
        out.passes_run
            .iter()
            .any(|p: &String| p == "prometheus-base85-variant-string-decode"),
        "gauntlet fixture must trigger the base85 string decoder; passes={:?}",
        out.passes_run
    );

    let pool: &[String] = &out.recovered_strings;

    let lua_intrinsics: &[&str] = &[
        "setmetatable",
        "tostring",
        "math",
        "table",
        "ipairs",
        "sqrt",
        "concat",
    ];
    let recovered_intrinsics: usize = lua_intrinsics
        .iter()
        .filter(|kw: &&&str| pool.iter().any(|s: &String| s == **kw))
        .count();
    assert!(
        recovered_intrinsics >= 5,
        "must recover >=5 Lua intrinsics from constant pool; got {recovered_intrinsics}/{} of {:?}, pool={pool:?}",
        lua_intrinsics.len(),
        lua_intrinsics
    );

    let source_symbols: &[&str] = &[
        "hello from gauntlet",
        "Vector",
        "magnitude",
        "ok",
        "fail",
        "zero",
    ];
    let recovered_source: usize = source_symbols
        .iter()
        .filter(|kw: &&&str| pool.iter().any(|s: &String| s == **kw))
        .count();
    assert!(
        recovered_source >= 4,
        "must recover >=4 original program symbols/strings; got {recovered_source}/{} of {:?}, pool={pool:?}",
        source_symbols.len(),
        source_symbols
    );
}

#[test]
fn prometheus_gauntlet_weak_peel_undo_rotation() {
    let bytes: Vec<u8> = load_fixture("gauntlet_weak_obfuscated.lua");
    let opts: DeobfOptions = DeobfOptions::default();
    let out: PeelResult =
        prometheus::peel(&bytes, &opts).expect("peel must succeed on gauntlet fixture");

    assert!(
        out.passes_run
            .iter()
            .any(|p: &String| p == "prometheus-constant-array-rotation-undo"),
        "gauntlet fixture must trigger the rotation-undo pass; passes={:?}",
        out.passes_run
    );
}

#[test]
fn prometheus_gauntlet_weak_peel_is_honest_about_residual() {
    let bytes: Vec<u8> = load_fixture("gauntlet_weak_obfuscated.lua");
    let opts: DeobfOptions = DeobfOptions::default();
    let out: PeelResult =
        prometheus::peel(&bytes, &opts).expect("peel must succeed on gauntlet fixture");

    assert!(
        !out.fully_recovered,
        "Vmify opcode/CFG layer is not lifted; fully_recovered must be false"
    );
    assert!(
        !out.residual_markers.is_empty(),
        "residual_markers must document the Vmify layer that remains"
    );
    assert!(
        out.residual_markers
            .iter()
            .any(|m: &String| m.contains("Vmify") || m.contains("vm")),
        "at least one residual marker must mention the VM/Vmify layer; got={:?}",
        out.residual_markers
    );
}

#[test]
fn prometheus_gauntlet_weak_output_is_valid_utf8_lua() {
    let bytes: Vec<u8> = load_fixture("gauntlet_weak_obfuscated.lua");
    let opts: DeobfOptions = DeobfOptions::default();
    let out: PeelResult =
        prometheus::peel(&bytes, &opts).expect("peel must succeed on gauntlet fixture");

    let text: &str =
        std::str::from_utf8(&out.deobfuscated).expect("deobfuscated output must be valid UTF-8");
    assert!(
        text.contains("PROMETHEUS_STRINGS"),
        "output must contain the recovered string pool table; got prefix={:?}",
        &text[..text.len().min(120)]
    );
    assert!(
        text.contains("hello from gauntlet"),
        "the greeting constant must appear in the recovered pool"
    );
}
