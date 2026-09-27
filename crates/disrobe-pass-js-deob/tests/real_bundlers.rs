#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs;
use std::path::PathBuf;

use std::collections::BTreeSet;

use disrobe_pass_js_deob::{
    BundlerDetection, BundlerKind, ExtractedModule, UnbundleGraphResult, ViteManifest,
    detect_browserify, detect_bun, detect_esbuild, detect_parcel, detect_rollup, detect_systemjs,
    detect_turbopack, detect_vite, detect_webpack5, parse_vite_manifest, unbundle_with_graph,
};

fn corpus_path(rel: &str) -> PathBuf {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .join("..")
        .join("..")
        .join("corpus")
        .join("js")
        .join(rel)
}

fn load(rel: &str) -> String {
    let p: PathBuf = corpus_path(rel);
    fs::read_to_string(&p).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "tracked corpus fixture {} is required: {error}",
            p.display()
        )
    })
}

#[test]
fn real_webpack5_bundle_detects() {
    let src: String = load("webpack5/bundle.js");
    let det: BundlerDetection = detect_webpack5(&src);
    assert!(det.matched, "real webpack5 bundle must match: {det:?}");
    assert_eq!(det.kind, BundlerKind::Webpack5);
}

#[test]
fn real_rollup_bundle_detects() {
    let src: String = load("rollup/bundle.js");
    let det: BundlerDetection = detect_rollup(&src);
    assert!(det.matched, "real rollup bundle must match: {det:?}");
    assert_eq!(det.kind, BundlerKind::Rollup);
}

#[test]
fn real_vite_manifest_parses() {
    let json: String = load("vite/manifest.json");
    let manifest: ViteManifest = parse_vite_manifest(&json).expect("vite manifest parse");
    let raw: serde_json::Value = serde_json::from_str(&json).expect("manifest is json");
    let raw_entries: &serde_json::Map<String, serde_json::Value> =
        raw.as_object().expect("vite manifest is a json object");
    let parsed_keys: BTreeSet<&str> = manifest.keys().map(String::as_str).collect();
    let raw_keys: BTreeSet<&str> = raw_entries.keys().map(String::as_str).collect();
    assert_eq!(parsed_keys, raw_keys, "every manifest entry must parse");
    for (key, entry) in &manifest {
        assert_eq!(
            Some(entry.file.as_str()),
            raw_entries[key]
                .get("file")
                .and_then(serde_json::Value::as_str),
            "{key}: parsed chunk file must equal the manifest's own file field"
        );
    }
}

#[test]
fn real_vite_chunk_detects() {
    let src: String = load("vite/assets/index-DQvCGGXF.js");
    let det: BundlerDetection = detect_vite(&src);
    assert!(det.matched, "real vite chunk must match: {det:?}");
    assert_eq!(det.kind, BundlerKind::Vite);
}

#[test]
fn real_esbuild_bundle_detects() {
    let src: String = load("esbuild/bundle.js");
    let det: BundlerDetection = detect_esbuild(&src);
    assert!(det.matched, "real esbuild bundle must match: {det:?}");
    assert_eq!(det.kind, BundlerKind::Esbuild);
}

#[test]
fn real_bun_bundle_detects() {
    let src: String = load("bun/bundle.js");
    let det: BundlerDetection = detect_bun(&src);
    assert!(det.matched, "real bun bundle must match: {det:?}");
    assert_eq!(det.kind, BundlerKind::Bun);
}

#[test]
fn real_parcel_bundle_detects() {
    let src: String = load("parcel/bundle.js");
    let det: BundlerDetection = detect_parcel(&src);
    assert!(det.matched, "real parcel bundle must match: {det:?}");
    assert_eq!(det.kind, BundlerKind::Parcel);
}

#[test]
fn real_browserify_bundle_detects() {
    let src: String = load("browserify/bundle.js");
    let det: BundlerDetection = detect_browserify(&src);
    assert!(det.matched, "real browserify bundle must match: {det:?}");
    assert_eq!(det.kind, BundlerKind::Browserify);
}

#[test]
fn real_systemjs_bundle_detects() {
    let src: String = load("systemjs/bundle.js");
    let det: BundlerDetection = detect_systemjs(&src);
    assert!(det.matched, "real systemjs bundle must match: {det:?}");
    assert_eq!(det.kind, BundlerKind::SystemJs);
}

#[test]
fn real_turbopack_runtime_detects() {
    let src: String = load("turbopack/runtime.js");
    let det: BundlerDetection = detect_turbopack(&src);
    assert!(det.matched, "real turbopack runtime must match: {det:?}");
    assert_eq!(det.kind, BundlerKind::Turbopack);
}

#[test]
fn real_unbundle_graph_recovers_exact_module_ids_and_names_detect_only_bundlers() {
    let expectations: [(&str, BundlerKind, &[&str]); 8] = [
        (
            "webpack5/bundle.js",
            BundlerKind::Webpack5,
            &["./src/util.js", "./src/math.js", "./src/index.js"],
        ),
        (
            "browserify/bundle.js",
            BundlerKind::Browserify,
            &["1", "2", "3"],
        ),
        ("systemjs/bundle.js", BundlerKind::SystemJs, &["module-0"]),
        ("rollup/bundle.js", BundlerKind::Rollup, &[]),
        ("esbuild/bundle.js", BundlerKind::Esbuild, &[]),
        ("parcel/bundle.js", BundlerKind::Parcel, &[]),
        ("bun/bundle.js", BundlerKind::Bun, &[]),
        ("turbopack/runtime.js", BundlerKind::Turbopack, &[]),
    ];
    for (rel, kind, expected_ids) in expectations {
        let src: String = load(rel);
        let result: UnbundleGraphResult = unbundle_with_graph(kind, &src)
            .unwrap_or_else(|error| panic!("{rel}: unbundle_with_graph failed: {error}"));
        assert!(result.detection.matched, "{rel}: {:?}", result.detection);
        let ids: Vec<&str> = result
            .modules
            .iter()
            .map(|module: &ExtractedModule| module.id.as_str())
            .collect();
        assert_eq!(
            ids, expected_ids,
            "{rel}: recovered module ids; an empty row marks a bundler whose unbundle is detect-only on this fixture"
        );
        let mapped: BTreeSet<&str> = result
            .graph
            .module_to_chunk
            .keys()
            .map(String::as_str)
            .collect();
        let expected_set: BTreeSet<&str> = expected_ids.iter().copied().collect();
        assert_eq!(
            mapped, expected_set,
            "{rel}: every recovered module must map to a chunk"
        );
    }
}
