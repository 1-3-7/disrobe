#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_lua::moonsec_v1;
use disrobe_pass_lua::obfuscator::{DeobfOptions, LuaObfuscatorKind};

#[test]
fn detect_moonsec_v1() {
    let det = moonsec_v1::detect(b"-- MoonSec v1\nprint(1)").expect("detect");
    assert_eq!(det.kind, LuaObfuscatorKind::MoonSecV1);
}

#[test]
fn peel_moonsec_v1_without_authorization() {
    let opts: DeobfOptions = DeobfOptions::default();
    let out = moonsec_v1::peel(b"-- MoonSec v1\n", &opts).expect("peel");
    assert!(!out.fully_recovered);
    assert!(!out.residual_markers.is_empty());
}
