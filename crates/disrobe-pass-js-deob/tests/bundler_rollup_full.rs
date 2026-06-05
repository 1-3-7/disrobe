#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_js_deob::{
    BundlerKind, ChunkNode, ModuleGraph, UnbundleGraphResult, unbundle_with_graph,
};

const ROLLUP_FULL: &str = include_str!("../corpus/bundlers/rollup/full-graph/bundle.js");

#[test]
fn rollup_full_graph_recovers_named_exports() {
    let result: UnbundleGraphResult =
        unbundle_with_graph(BundlerKind::Rollup, ROLLUP_FULL).expect("unbundle");
    let graph: &ModuleGraph = &result.graph;
    let main: &ChunkNode = graph.chunks.get("main").expect("main chunk");
    for expected in ["VERSION", "greet", "Widget"] {
        assert!(
            main.modules.iter().any(|m: &String| m == expected),
            "missing {expected}: {:?}",
            main.modules
        );
    }
}
