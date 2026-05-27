#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_lua::moonsec_v2;
use disrobe_pass_lua::obfuscator::{DeobfOptions, LuaObfuscatorKind};

#[test]
fn detect_moonsec_v2() {
    let det = moonsec_v2::detect(b"-- MoonSec v2\nMS_V2_KEY=42").expect("detect");
    assert_eq!(det.kind, LuaObfuscatorKind::MoonSecV2);
    assert!(det.confidence >= 80);
}

#[test]
fn peel_moonsec_v2_unauthenticated() {
    let opts: DeobfOptions = DeobfOptions::default();
    let out = moonsec_v2::peel(b"-- MoonSec v2\n", &opts).expect("peel");
    assert!(
        out.passes_run
            .iter()
            .any(|p: &String| p == "xor-pool-decode")
    );
}
