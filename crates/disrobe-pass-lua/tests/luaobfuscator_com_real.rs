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

fn load_fixture() -> Option<Vec<u8>> {
    std::fs::read(fixture_path()).ok()
}

#[test]
fn detect_real_luaobfuscator_com_obf_v1() {
    let Some(data): Option<Vec<u8>> = load_fixture() else {
        eprintln!("skip: luaobfuscator_com/sample_default_obf_v1.lua fixture absent");
        return;
    };
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
fn peel_real_luaobfuscator_com_obf_v1() {
    let Some(data): Option<Vec<u8>> = load_fixture() else {
        eprintln!("skip: luaobfuscator_com/sample_default_obf_v1.lua fixture absent");
        return;
    };
    let opts: DeobfOptions = DeobfOptions::default();
    let out = luaobfuscator_com::peel(&data, &opts).expect("peel must succeed on real fixture");
    assert!(
        !out.fully_recovered,
        "luaobfuscator.com vm string-layer decode requires key recovery; must report honestly"
    );
    assert!(
        out.residual_markers
            .iter()
            .any(|m: &String| m.contains("vm")),
        "must document the vm wall, got {:?}",
        out.residual_markers
    );
}
