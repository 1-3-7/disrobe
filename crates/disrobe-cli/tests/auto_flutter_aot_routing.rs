#![cfg(all(feature = "chain", feature = "mobile"))]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stderr,
    clippy::panic,
    clippy::unnecessary_debug_formatting
)]

use std::path::{Path, PathBuf};

mod common;

use common::{Run, run_disrobe, temp_dir};

const FLUTTER_AOT_FIXTURE: &str = "mobile/flutter/disrobe_sample/libapp_arm64.so";

fn corpus_path(rel: &str) -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root.join("corpus").join(rel)
}

fn read_json(out_dir: &Path, name: &str) -> serde_json::Value {
    let path: PathBuf = out_dir.join(name);
    let text: String = std::fs::read_to_string(&path).unwrap_or_else(|e: std::io::Error| {
        panic!("cannot read {name} at {}: {e}", path.display())
    });
    serde_json::from_str(&text)
        .unwrap_or_else(|e: serde_json::Error| panic!("{name} must be valid JSON: {e}"))
}

fn field<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(serde_json::Value::as_str)
}

fn mobile_classify_node(chain: &serde_json::Value) -> &serde_json::Value {
    chain
        .get("nodes")
        .and_then(serde_json::Value::as_array)
        .expect("chain.json must list nodes")
        .iter()
        .find(|n: &&serde_json::Value| field(n, "pass") == Some("mobile.classify"))
        .expect("the chain must route a Flutter AOT image through mobile.classify")
}

fn mobile_classify_pass(recovery: &serde_json::Value) -> &serde_json::Value {
    recovery
        .get("passes")
        .and_then(serde_json::Value::as_array)
        .expect("recovery.json must list passes")
        .iter()
        .find(|p: &&serde_json::Value| field(p, "name") == Some("mobile.classify"))
        .expect("mobile.classify must appear in the recovery passes")
}

#[test]
fn auto_chain_routes_a_flutter_aot_image_to_mobile_classify() {
    let fixture: PathBuf = corpus_path(FLUTTER_AOT_FIXTURE);
    assert!(
        fixture.exists(),
        "the committed Flutter AOT fixture is missing at {}; it is tracked in git, so an absent \
         file means an incomplete checkout rather than an optional dependency, and routing must \
         never be reported as passing when it was compared against nothing",
        fixture.display()
    );

    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("flutter-aot-routing");
    let out: PathBuf = scratch.path().to_path_buf();
    let fixture_arg: String = fixture.to_string_lossy().into_owned();
    let out_arg: String = out.to_string_lossy().into_owned();
    let run: Run = run_disrobe(&[
        "chain",
        &fixture_arg,
        "--out",
        &out_arg,
        "--chain",
        "auto:8",
    ]);
    assert_eq!(run.code, 0, "chain exited {}: {}", run.code, run.stderr);

    let chain: serde_json::Value = read_json(&out, "chain.json");
    let detected: Vec<&str> = chain
        .get("input")
        .and_then(|i: &serde_json::Value| i.get("detected"))
        .and_then(serde_json::Value::as_array)
        .expect("chain.json must record what the input was detected as")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert!(
        detected.contains(&"flutter-aot"),
        "the Dart AOT image must be detected as flutter-aot, got {detected:?}"
    );

    let node: &serde_json::Value = mobile_classify_node(&chain);
    assert_eq!(
        field(node, "format_tag_in"),
        Some("flutter-aot"),
        "the mobile.classify node must carry the flutter-aot input tag"
    );

    let recovery: serde_json::Value = read_json(&out, "recovery.json");
    let pass: &serde_json::Value = mobile_classify_pass(&recovery);
    assert_eq!(
        field(pass, "format_in"),
        Some("flutter-aot"),
        "mobile.classify must report the flutter-aot input format"
    );
    assert_eq!(
        field(pass, "status"),
        Some("advanced"),
        "mobile.classify must advance the chain on a Dart AOT image"
    );

    eprintln!(
        "flutter AOT chain routing: input detected flutter-aot -> mobile.classify (status advanced). \
         Recovery fidelity is graded in disrobe-pass-mobile against the committed .dart and .dill, \
         not here."
    );
}
