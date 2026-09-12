#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_js_deob::{
    BundlerKind, ChunkNode, ModuleGraph, UnbundleGraphResult, unbundle_with_graph,
};

const ESBUILD_FULL: &str = include_str!("../corpus/bundlers/esbuild/full-graph/bundle.js");

#[test]
fn esbuild_full_graph_extracts_commonjs_modules() {
    let result: UnbundleGraphResult =
        unbundle_with_graph(BundlerKind::Esbuild, ESBUILD_FULL).expect("unbundle");
    let graph: &ModuleGraph = &result.graph;
    let chunk: &ChunkNode = graph.chunks.get("esbuild").expect("esbuild chunk");
    for expected in ["./src/util.js", "./src/lib.js", "./src/index.js"] {
        assert!(
            chunk.modules.iter().any(|m: &String| m == expected),
            "missing {expected}: {:?}",
            chunk.modules
        );
    }
}
