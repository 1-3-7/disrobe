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

fn load_fixture() -> Vec<u8> {
    let path: PathBuf = fixture_path();
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("missing committed fixture {}: {e}", path.display()))
}

#[test]
fn detect_real_wearedevs_obfuscator_net() {
    let data: Vec<u8> = load_fixture();
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
    let data: Vec<u8> = load_fixture();
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

#[test]
fn peel_real_wearedevs_lifts_dispatch_cfg() {
    let data: Vec<u8> = load_fixture();
    let opts: DeobfOptions = DeobfOptions::default();
    let out = wearedevs::peel(&data, &opts).expect("peel must succeed on real fixture");
    assert!(
        out.passes_run
            .iter()
            .any(|p: &String| p == "wearedevs-dispatch-lift"),
        "real fixture must lift the WeAreDevs dispatch, got passes={:?} residual={:?}",
        out.passes_run,
        out.residual_markers
    );
    let rendered: String =
        String::from_utf8(out.deobfuscated).expect("lifted WeAreDevs output is utf8");
    assert!(
        rendered.contains("local DISPATCH_CFG = {"),
        "expected structured WeAreDevs dispatch table, got {rendered}"
    );
    let guard_count: usize = rendered.matches("when = \"W <").count();
    assert!(
        guard_count >= 80,
        "expected the real WeAreDevs dispatch guards, recovered {guard_count}"
    );
    assert!(
        out.residual_markers
            .iter()
            .any(|m: &String| m.contains("structured dispatch guards")),
        "residual marker must explain the remaining data-dependent jumps: {:?}",
        out.residual_markers
    );

    let direct_edges: usize = rendered.matches("goto = ").count();
    let branch_edges: usize = rendered.matches("branch = {").count();
    let table_jumps: usize = rendered.matches("runtime_table_jump = {").count();
    assert!(
        direct_edges >= 40,
        "expected the constant next-state jumps de-flattened into concrete edges, got {direct_edges}"
    );
    assert!(
        branch_edges >= 24,
        "expected the two-target conditional jumps resolved to constant targets, got {branch_edges}"
    );
    assert_eq!(
        table_jumps, 14,
        "expected exactly the 14 runtime W=v[p(k)] table-lookup jumps flagged unresolvable"
    );
    let resolved: usize = direct_edges + branch_edges;
    assert!(
        resolved >= 65,
        "expected the majority of the {guard_count} dispatch blocks resolved to concrete control flow, got {resolved}"
    );
    assert!(
        rendered.contains("v_key = pool["),
        "runtime table jumps must name the decoded string-pool label slot they read: {rendered}"
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
    let data: Vec<u8> = load_fixture();
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
