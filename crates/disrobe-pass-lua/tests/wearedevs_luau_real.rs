#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;

use disrobe_pass_lua::obfuscator::{DeobfOptions, LuaObfuscatorKind};
use disrobe_pass_lua::wearedevs;

fn fixture_path() -> PathBuf {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    let mut p: PathBuf = PathBuf::from(manifest_dir);
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("lua");
    p.push("obfuscators");
    p.push("wearedevs");
    p.push("real_sample.lua");
    p
}

fn load_fixture() -> Option<Vec<u8>> {
    std::fs::read(fixture_path()).ok()
}

#[test]
fn detect_real_wearedevs_obfuscator_net() {
    let Some(data): Option<Vec<u8>> = load_fixture() else {
        eprintln!("skip: wearedevs/real_sample.lua fixture absent");
        return;
    };
    assert!(data.len() > 10_000, "wearedevs/Prometheus output is ~20KB");
    let det = wearedevs::detect(&data).expect("real wearedevs fixture must be detected");
    assert_eq!(det.kind, LuaObfuscatorKind::WeAreDevs);
    assert!(
        det.markers.iter().any(|m: &String| m.contains("wearedevs")),
        "must surface a wearedevs marker: got {:?}",
        det.markers
    );
}

#[test]
fn peel_real_wearedevs_obfuscator_net() {
    let Some(data): Option<Vec<u8>> = load_fixture() else {
        eprintln!("skip: wearedevs/real_sample.lua fixture absent");
        return;
    };
    let opts: DeobfOptions = DeobfOptions::default();
    let out = wearedevs::peel(&data, &opts).expect("peel must succeed on real fixture");
    assert!(
        out.passes_run
            .iter()
            .any(|p: &String| p == "base64-variant-string-decode"),
        "real fixture must trigger the base64-variant decoder, got passes={:?} residual={:?}",
        out.passes_run,
        out.residual_markers
    );
    assert!(
        !out.recovered_strings.is_empty(),
        "must recover the string pool from the real wearedevs sample"
    );
    let joined: String = out.recovered_strings.join("\u{1}");
    assert!(
        joined
            .chars()
            .filter(|c: &char| c.is_ascii_graphic() || *c == ' ')
            .count()
            > joined.len() / 2,
        "decoded strings should be mostly printable, indicating a correct alphabet decode"
    );
}

const VM_ENCODED_INTRINSICS: &[&str] = &[
    "string",
    "table",
    "math",
    "setmetatable",
    "error",
    "pcall",
    "unpack",
    "tonumber",
    "tostring",
    "floor",
    "concat",
    "gmatch",
    "gsub",
    "byte",
    "char",
    "remove",
    "random",
    "len",
];

#[test]
fn peel_real_wearedevs_recovers_lua_identifiers() {
    let Some(data): Option<Vec<u8>> = load_fixture() else {
        eprintln!("skip: wearedevs/real_sample.lua fixture absent");
        return;
    };
    let opts: DeobfOptions = DeobfOptions::default();
    let out = wearedevs::peel(&data, &opts).expect("peel");
    let pool: Vec<String> = out.recovered_strings;
    let recovered_intrinsics: usize = VM_ENCODED_INTRINSICS
        .iter()
        .filter(|kw: &&&str| pool.iter().any(|s: &String| s == *kw))
        .count();
    assert!(
        recovered_intrinsics >= 12,
        "expected the WeAreDevs VM intrinsic symbol table; recovered {recovered_intrinsics}/18 of {VM_ENCODED_INTRINSICS:?}, pool={pool:?}"
    );
    let has_metamethods: bool = ["__index", "__metatable", "__len", "__gc"]
        .iter()
        .any(|mm: &&str| pool.iter().any(|s: &String| s == *mm));
    assert!(
        has_metamethods,
        "expected recovered metamethod names, pool={pool:?}"
    );
    assert!(
        pool.iter().any(|s: &String| s == "Tamper Detected!"),
        "expected the anti-tamper string literal the VM dispatch guards on, pool={pool:?}"
    );
}
