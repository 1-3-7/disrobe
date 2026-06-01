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
        !out.fully_recovered,
        "a bare marker with no alphabet table cannot be decoded; must report honestly"
    );
    assert!(
        out.recovered_strings.is_empty(),
        "no string pool present in this synthetic sample"
    );
    assert!(!out.residual_markers.is_empty());
}
