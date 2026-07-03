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
    assert!(!out.fully_recovered);
    assert!(!out.residual_markers.is_empty());
}

#[test]
fn peel_moonsec_v2_recovers_fixed_xor_pool() {
    let opts: DeobfOptions = DeobfOptions::default();
    let key: u8 = 0x5A;
    let plain: &[u8] = b"GetService";
    let encoded: String = plain
        .iter()
        .map(|b: &u8| (b ^ key).to_string())
        .collect::<Vec<String>>()
        .join(",");
    let src: String =
        format!("-- MoonSec v2\nMS_V2_KEY=0x5A\nlocal s=string.char({encoded})\nreturn s");
    let out = moonsec_v2::peel(src.as_bytes(), &opts).expect("peel");
    assert!(
        out.recovered_strings.contains(&"GetService".to_owned()),
        "expected GetService via fixed-key xor, got: {:?}",
        out.recovered_strings
    );
    assert!(out.passes_run.iter().any(|p: &String| p.contains("fixed")));
    assert!(!out.fully_recovered);
}

#[test]
fn peel_moonsec_v2_recovers_multi_string_fixed_pool() {
    let opts: DeobfOptions = DeobfOptions::default();
    let key: u8 = 0x33;
    let encode = |plain: &[u8]| -> String {
        plain
            .iter()
            .map(|b: &u8| (b ^ key).to_string())
            .collect::<Vec<String>>()
            .join(",")
    };
    let src: String = format!(
        "-- MoonSec v2\nxor_key=0x33\nlocal a=string.char({})\nlocal b=string.char({})\nreturn a,b",
        encode(b"FireServer"),
        encode(b"InvokeServer")
    );
    let out = moonsec_v2::peel(src.as_bytes(), &opts).expect("peel");
    assert!(
        out.recovered_strings.contains(&"FireServer".to_owned())
            && out.recovered_strings.contains(&"InvokeServer".to_owned()),
        "expected both API strings via fixed xor, got: {:?}",
        out.recovered_strings
    );
    assert!(!out.fully_recovered);
}
