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

#[test]
fn peel_moonsec_v1_recovers_string_char_pool() {
    let opts: DeobfOptions = DeobfOptions::default();
    let src: &[u8] =
        b"-- MoonSec v1\nlocal a=string.char(72,116,116,112,83,101,114,118,105,99,101)\
local b=string.char(0x47,0x61,0x6d,0x65)\nreturn a,b";
    let out = moonsec_v1::peel(src, &opts).expect("peel");
    assert!(
        out.recovered_strings.contains(&"HttpService".to_owned()),
        "expected HttpService, got: {:?}",
        out.recovered_strings
    );
    assert!(out.recovered_strings.contains(&"Game".to_owned()));
    assert!(
        !out.fully_recovered,
        "vm/cff layer remains; must not claim full recovery"
    );
    let body: String = String::from_utf8_lossy(&out.deobfuscated).into_owned();
    assert!(body.contains("\"HttpService\""));
}
