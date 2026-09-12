#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_js_deob::{
    BundlerKind, ChunkNode, ExtractedModule, ModuleGraph, UnbundleGraphResult, unbundle_with_graph,
};

const BUN_FULL: &str = include_str!("../corpus/bundlers/bun/full-graph/bundle.js");

#[test]
fn bun_full_graph_with_require_resolution() {
    let result: UnbundleGraphResult =
        unbundle_with_graph(BundlerKind::Bun, BUN_FULL).expect("unbundle");
    let graph: &ModuleGraph = &result.graph;
    let bundle: &ChunkNode = graph.chunks.get("bun-bundle").expect("bun-bundle");
    for expected in ["./src/a.ts", "./src/b.ts", "./src/c.ts"] {
        assert!(
            bundle.modules.iter().any(|m: &String| m == expected),
            "missing {expected}: {:?}",
            bundle.modules
        );
    }
    let b_module: &ExtractedModule = result
        .modules
        .iter()
        .find(|m: &&ExtractedModule| m.id == "./src/b.ts")
        .expect("b module");
    assert!(
        b_module.source.contains("./src/a.ts"),
        "expected require to a.ts in: {}",
        b_module.source
    );
}
