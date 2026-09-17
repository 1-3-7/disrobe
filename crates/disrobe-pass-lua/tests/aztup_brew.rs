#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_lua::aztup_brew;
use disrobe_pass_lua::obfuscator::{DeobfOptions, LuaObfuscatorKind};

#[test]
fn detect_aztup_brew() {
    let det = aztup_brew::detect(b"-- aztup_brew\nAztupBrew=1").expect("detect");
    assert_eq!(det.kind, LuaObfuscatorKind::AztupBrew);
}

#[test]
fn peel_aztup_brew() {
    let opts: DeobfOptions = DeobfOptions::default();
    let out = aztup_brew::peel(b"AztupBrew\n", &opts).expect("peel");
    assert!(!out.fully_recovered);
    assert!(!out.residual_markers.is_empty());
}
