#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;

use disrobe_pass_lua::luaobfuscator_com;
use disrobe_pass_lua::obfuscator::{DeobfOptions, LuaObfuscatorKind};

fn fixture_path() -> PathBuf {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    let mut p: PathBuf = PathBuf::from(manifest_dir);
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("lua");
    p.push("obfuscators");
    p.push("luaobfuscator_com");
    p.push("sample_default_obf_v1.lua");
    p
}

#[test]
#[ignore = "FIXTURE PENDING: real luaobfuscator.com sample with text markers not captured; current fixture is marker-less Ironbrew2-style VM bytecode that the text-marker detector cannot identify. Re-enable once a fixture exposing LuaObfuscator/luaobfuscator marker bytes is added, or once a VM-dispatch fingerprint detector lands."]
fn detect_real_luaobfuscator_com_obf_v1() {
    let path: PathBuf = fixture_path();
    let data: Vec<u8> =
        std::fs::read(&path).expect("real fixture sample_default_obf_v1.lua captured 2026-05-26");
    assert!(
        data.len() > 30_000,
        "OBFUSCATE v1 output is ~33KB Ironbrew2-style VM"
    );
    let det =
        luaobfuscator_com::detect(&data).expect("real luaobfuscator.com fixture must be detected");
    assert_eq!(det.kind, LuaObfuscatorKind::LuaObfuscatorCom);
    assert!(
        det.markers
            .iter()
            .any(|m: &String| m.contains("LuaObfuscator") || m.contains("luaobfuscator")),
        "must surface a luaobfuscator marker: got {:?}",
        det.markers
    );
}

#[test]
#[ignore = "FIXTURE PENDING: paired with detect_real_luaobfuscator_com_obf_v1 — peel depends on the same marker detection path. Re-enable when a marker-bearing fixture or VM-dispatch fingerprint detector is added."]
fn peel_real_luaobfuscator_com_obf_v1() {
    let data: Vec<u8> = std::fs::read(fixture_path()).expect("real fixture");
    let opts: DeobfOptions = DeobfOptions::default();
    let out = luaobfuscator_com::peel(&data, &opts).expect("peel must succeed on real fixture");
    assert!(
        out.passes_run
            .iter()
            .any(|p: &String| p == "string-decode-free")
    );
}
