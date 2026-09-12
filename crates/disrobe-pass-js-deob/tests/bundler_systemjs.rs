#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_js_deob::{
    BundlerKind, ChunkNode, ModuleGraph, UnbundleGraphResult, detect_systemjs, unbundle_with_graph,
};

const SYSTEMJS_REGISTER: &str = include_str!("../corpus/bundlers/systemjs/register/bundle.js");
const AMD_DEFINE: &str = include_str!("../corpus/bundlers/amd/define/bundle.js");

#[test]
fn systemjs_detect_via_register_call() {
    let det: disrobe_pass_js_deob::BundlerDetection = detect_systemjs(SYSTEMJS_REGISTER);
    assert!(det.matched, "{det:?}");
}

#[test]
fn systemjs_extracts_named_register_modules() {
    let result: UnbundleGraphResult =
        unbundle_with_graph(BundlerKind::SystemJs, SYSTEMJS_REGISTER).expect("unbundle");
    let graph: &ModuleGraph = &result.graph;
    let chunk: &ChunkNode = graph.chunks.get("systemjs-root").expect("systemjs-root");
    assert!(chunk.modules.iter().any(|m: &String| m == "app/main"));
    assert!(chunk.modules.iter().any(|m: &String| m == "app/util"));
}

#[test]
fn amd_define_detected_as_systemjs_family() {
    let det: disrobe_pass_js_deob::BundlerDetection = detect_systemjs(AMD_DEFINE);
    assert!(det.matched, "{det:?}");
    let result: UnbundleGraphResult =
        unbundle_with_graph(BundlerKind::SystemJs, AMD_DEFINE).expect("unbundle");
    let graph: &ModuleGraph = &result.graph;
    let chunk: &ChunkNode = graph.chunks.get("systemjs-root").expect("systemjs-root");
    assert!(
        chunk.modules.iter().any(|m: &String| m == "my/lib/core"),
        "{:?}",
        chunk.modules
    );
}
