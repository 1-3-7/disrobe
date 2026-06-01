#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_js_deob::{
    BundlerKind, ChunkNode, ExtractedModule, ModuleGraph, UnbundleGraphResult, unbundle_with_graph,
};

const WEBPACK5_FULL: &str = include_str!("../corpus/bundlers/webpack5/full-graph/bundle.js");

#[test]
fn webpack5_full_graph_resolves_require_paths_and_chunk_pushes() {
    let result: UnbundleGraphResult =
        unbundle_with_graph(BundlerKind::Webpack5, WEBPACK5_FULL).expect("unbundle");
    let graph: &ModuleGraph = &result.graph;
    assert_eq!(graph.entry.as_deref(), Some("main"));
    let main_chunk: &ChunkNode = graph.chunks.get("main").expect("main chunk");
    for expected in ["./src/index.js", "./src/util.js"] {
        assert!(
            main_chunk.modules.iter().any(|m: &String| m == expected),
            "missing {expected} in main: {:?}",
            main_chunk.modules
        );
    }
    let index_module: &ExtractedModule = result
        .modules
        .iter()
        .find(|m: &&ExtractedModule| m.id == "./src/index.js")
        .expect("index module");
    assert!(
        index_module.source.contains("./src/util.js"),
        "require rewrite failed: {}",
        index_module.source
    );
    assert!(
        main_chunk
            .dynamic_imports
            .iter()
            .any(|d: &String| d.contains("lazy-chunk")),
        "{:?}",
        main_chunk.dynamic_imports
    );
    assert!(graph.sourcemap_urls.contains_key("main"));
}
