#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_js_deob::{
    BundlerKind, ChunkNode, ModuleGraph, UnbundleGraphResult, detect_browserify,
    unbundle_with_graph,
};

const BROWSERIFY_LEGACY: &str = include_str!("../corpus/bundlers/browserify/legacy/bundle.js");

#[test]
fn browserify_detect_legacy_umd() {
    let det: disrobe_pass_js_deob::BundlerDetection = detect_browserify(BROWSERIFY_LEGACY);
    assert!(det.matched, "{det:?}");
}

#[test]
fn browserify_unbundle_extracts_modules() {
    let result: UnbundleGraphResult =
        unbundle_with_graph(BundlerKind::Browserify, BROWSERIFY_LEGACY).expect("unbundle");
    let graph: &ModuleGraph = &result.graph;
    let chunk: &ChunkNode = graph
        .chunks
        .get("browserify-bundle")
        .expect("browserify-bundle");
    assert!(chunk.modules.iter().any(|m: &String| m == "1"));
    assert!(chunk.modules.iter().any(|m: &String| m == "2"));
    assert!(graph.sourcemap_urls.contains_key("browserify-bundle"));
}
