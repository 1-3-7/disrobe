#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_lua::obfuscator::{DeobfOptions, LuaObfuscatorKind};
use disrobe_pass_lua::psu;

#[test]
fn detect_psu_4_0_a() {
    let det = psu::detect(b"-- PSU 4.0\nversion=4.0.A").expect("detect");
    assert_eq!(det.kind, LuaObfuscatorKind::Psu);
    assert_eq!(det.variant.as_deref(), Some("4.0.A"));
}

#[test]
fn detect_psu_4_5_a() {
    let det = psu::detect(b"-- PSU 4.5\nrelease=4.5.A").expect("detect");
    assert_eq!(det.variant.as_deref(), Some("4.5.A"));
}

#[test]
fn peel_psu() {
    let opts: DeobfOptions = DeobfOptions::default();
    let out = psu::peel(b"PSU4 PSU_VM_KEY", &opts).expect("peel");
    assert!(!out.fully_recovered);
    assert!(!out.residual_markers.is_empty());
}
