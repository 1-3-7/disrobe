#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_lua::boronide;
use disrobe_pass_lua::obfuscator::{DeobfOptions, LuaObfuscatorKind};

#[test]
fn detect_boronide_v05() {
    let det = boronide::detect(b"-- Boronide v0.5\nBORONIDE_VM").expect("detect");
    assert_eq!(det.kind, LuaObfuscatorKind::Boronide);
    assert_eq!(det.variant.as_deref(), Some("v0.5"));
}

#[test]
fn peel_boronide() {
    let opts: DeobfOptions = DeobfOptions::default();
    let out = boronide::peel(b"BORONIDE_VERSION=v0.6", &opts).expect("peel");
    assert!(!out.fully_recovered);
    assert!(!out.residual_markers.is_empty());
}
