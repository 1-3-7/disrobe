#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_js_deob::{
    BundlerKind, ChunkNode, ModuleGraph, UnbundleGraphResult, unbundle_with_graph,
};

const TURBOPACK_FULL: &str = include_str!("../corpus/bundlers/turbopack/full-graph/bundle.js");

#[test]
fn turbopack_full_graph_with_dynamic_chunks() {
    let result: UnbundleGraphResult =
        unbundle_with_graph(BundlerKind::Turbopack, TURBOPACK_FULL).expect("unbundle");
    let graph: &ModuleGraph = &result.graph;
    let root: &ChunkNode = graph.chunks.get("turbopack-root").expect("root");
    assert!(root.modules.iter().any(|m: &String| m == "./app/page.tsx"));
    assert!(
        root.modules
            .iter()
            .any(|m: &String| m == "./components/button.tsx")
    );
    assert!(
        root.dynamic_imports
            .iter()
            .any(|d: &String| d == "./chunks/lazy.js"),
        "{:?}",
        root.dynamic_imports
    );
}
