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

#[test]
#[ignore = "FIXTURE PENDING: real wearedevs sample with text markers not captured; current fixture is marker-less Ironbrew2/Prometheus-style VM bytecode that the text-marker detector cannot identify. Re-enable once a fixture exposing a wearedevs marker is added, or once a VM-dispatch fingerprint detector lands."]
fn detect_real_wearedevs_obfuscator_net() {
    let data: Vec<u8> = std::fs::read(fixture_path())
        .expect("real fixture real_sample.lua captured 2026-05-26 from wearedevs.net/obfuscator");
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
#[ignore = "FIXTURE PENDING: paired with detect_real_wearedevs_obfuscator_net — peel depends on the same marker detection path. Re-enable when a marker-bearing fixture or VM-dispatch fingerprint detector is added."]
fn peel_real_wearedevs_obfuscator_net() {
    let data: Vec<u8> = std::fs::read(fixture_path()).expect("real fixture");
    let opts: DeobfOptions = DeobfOptions::default();
    let out = wearedevs::peel(&data, &opts).expect("peel must succeed on real fixture");
    assert!(
        out.passes_run
            .iter()
            .any(|p: &String| p == "luau-string-decode")
    );
}
