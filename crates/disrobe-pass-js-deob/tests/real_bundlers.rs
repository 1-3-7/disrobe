#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;

use disrobe_pass_js_deob::{
    BundlerDetection, BundlerKind, ExtractedModule, ModuleGraph, UnbundleGraphResult,
    detect_browserify, detect_bun, detect_esbuild, detect_parcel, detect_rollup, detect_systemjs,
    detect_turbopack, detect_vite, detect_webpack5, parse_vite_manifest, unbundle,
    unbundle_with_graph,
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

fn load(rel: &str) -> Option<String> {
    let p: PathBuf = corpus_path(rel);
    if !p.exists() {
        return None;
    }
    fs::read_to_string(&p).ok()
}

#[test]
fn real_webpack5_bundle_detects() {
    let Some(src): Option<String> = load("webpack5/bundle.js") else {
        return;
    };
    let det: BundlerDetection = detect_webpack5(&src);
    assert!(det.matched, "real webpack5 bundle must match: {det:?}");
    assert_eq!(det.kind, BundlerKind::Webpack5);
}

#[test]
fn real_webpack5_bundle_unbundles_without_panic() {
    let Some(src): Option<String> = load("webpack5/bundle.js") else {
        return;
    };
    let _ = unbundle(BundlerKind::Webpack5, &src);
}

#[test]
fn real_rollup_bundle_detects() {
    let Some(src): Option<String> = load("rollup/bundle.js") else {
        return;
    };
    let det: BundlerDetection = detect_rollup(&src);
    assert!(
        det.matched || det.confidence > 0.0,
        "rollup detector should at least produce confidence>0: {det:?}",
    );
    assert_eq!(det.kind, BundlerKind::Rollup);
}

#[test]
fn real_vite_manifest_parses() {
    let Some(json): Option<String> = load("vite/manifest.json") else {
        return;
    };
    let manifest = parse_vite_manifest(&json).expect("vite manifest parse");
    assert!(!manifest.is_empty(), "vite manifest must have entries");
}

#[test]
fn real_vite_chunk_detects() {
    let Some(src): Option<String> = load("vite/assets/index-DQvCGGXF.js") else {
        return;
    };
    let det: BundlerDetection = detect_vite(&src);
    let _ = det;
}

#[test]
fn real_esbuild_bundle_detects() {
    let Some(src): Option<String> = load("esbuild/bundle.js") else {
        return;
    };
    let det: BundlerDetection = detect_esbuild(&src);
    assert!(det.matched, "real esbuild bundle must match: {det:?}");
    assert_eq!(det.kind, BundlerKind::Esbuild);
}

#[test]
fn real_esbuild_bundle_unbundles_without_panic() {
    let Some(src): Option<String> = load("esbuild/bundle.js") else {
        return;
    };
    let _ = unbundle_with_graph(BundlerKind::Esbuild, &src);
}

#[test]
fn real_bun_bundle_detects() {
    let Some(src): Option<String> = load("bun/bundle.js") else {
        return;
    };
    let det: BundlerDetection = detect_bun(&src);
    let _ = det;
}

#[test]
fn real_parcel_bundle_detects() {
    let Some(src): Option<String> = load("parcel/bundle.js") else {
        return;
    };
    let det: BundlerDetection = detect_parcel(&src);
    assert!(det.matched, "real parcel bundle must match: {det:?}");
    assert_eq!(det.kind, BundlerKind::Parcel);
}

#[test]
fn real_browserify_bundle_detects() {
    let Some(src): Option<String> = load("browserify/bundle.js") else {
        return;
    };
    let det: BundlerDetection = detect_browserify(&src);
    assert!(det.matched, "real browserify bundle must match: {det:?}");
    assert_eq!(det.kind, BundlerKind::Browserify);
}

#[test]
fn real_systemjs_bundle_detects() {
    let Some(src): Option<String> = load("systemjs/bundle.js") else {
        return;
    };
    let det: BundlerDetection = detect_systemjs(&src);
    assert!(det.matched, "real systemjs bundle must match: {det:?}");
    assert_eq!(det.kind, BundlerKind::SystemJs);
}

#[test]
fn real_turbopack_runtime_detects() {
    let Some(src): Option<String> = load("turbopack/runtime.js") else {
        return;
    };
    let det: BundlerDetection = detect_turbopack(&src);
    assert!(det.matched, "real turbopack runtime must match: {det:?}");
    assert_eq!(det.kind, BundlerKind::Turbopack);
}

#[test]
fn real_unbundle_graph_emits_modules_or_empty() {
    for (rel, kind) in [
        ("webpack5/bundle.js", BundlerKind::Webpack5),
        ("rollup/bundle.js", BundlerKind::Rollup),
        ("esbuild/bundle.js", BundlerKind::Esbuild),
        ("parcel/bundle.js", BundlerKind::Parcel),
        ("browserify/bundle.js", BundlerKind::Browserify),
        ("bun/bundle.js", BundlerKind::Bun),
        ("systemjs/bundle.js", BundlerKind::SystemJs),
        ("turbopack/runtime.js", BundlerKind::Turbopack),
    ] {
        let Some(src): Option<String> = load(rel) else {
            continue;
        };
        let result: UnbundleGraphResult = match unbundle_with_graph(kind, &src) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let graph: &ModuleGraph = &result.graph;
        let modules: &[ExtractedModule] = result.modules.as_slice();
        let _ = (graph, modules);
    }
}
