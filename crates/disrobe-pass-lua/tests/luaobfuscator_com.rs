#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_lua::luaobfuscator_com;
use disrobe_pass_lua::obfuscator::{DeobfOptions, LuaObfuscatorKind};

#[test]
fn detect_luaobfuscator_com() {
    let det = luaobfuscator_com::detect(b"-- luaobfuscator.com\nLOC_FREE_TIER=1").expect("detect");
    assert_eq!(det.kind, LuaObfuscatorKind::LuaObfuscatorCom);
}

#[test]
fn peel_luaobfuscator_com() {
    let opts: DeobfOptions = DeobfOptions::default();
    let out = luaobfuscator_com::peel(b"luaobfuscator_com\n", &opts).expect("peel");
    assert!(!out.fully_recovered);
    assert!(!out.residual_markers.is_empty());
    assert!(
        out.residual_markers
            .iter()
            .all(|marker: &String| !marker.contains("VMPAYLOAD")),
        "luaobfuscator.com residuals must not mention synthetic vm payloads: {:?}",
        out.residual_markers
    );
}
