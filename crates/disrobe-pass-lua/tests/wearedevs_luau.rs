#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_lua::obfuscator::{DeobfOptions, LuaObfuscatorKind};
use disrobe_pass_lua::wearedevs;

#[test]
fn detect_wearedevs() {
    let det = wearedevs::detect(b"-- WeAreDevs\nWRD_OBFUSCATOR=true").expect("detect");
    assert_eq!(det.kind, LuaObfuscatorKind::WeAreDevs);
}

#[test]
fn peel_wearedevs() {
    let opts: DeobfOptions = DeobfOptions::default();
    let out = wearedevs::peel(b"wearedevs_luau", &opts).expect("peel");
    assert!(
        out.passes_run
            .iter()
            .any(|p: &String| p == "luau-string-decode")
    );
}
