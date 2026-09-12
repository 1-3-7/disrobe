#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_js_deob::{
    BundlerKind, ChunkNode, ModuleGraph, UnbundleGraphResult, detect_rolldown, unbundle_with_graph,
};

const ROLLDOWN_SIMPLE: &str = include_str!("../corpus/bundlers/rolldown/simple/bundle.js");

#[test]
fn rolldown_detect_marks_signature() {
    let det: disrobe_pass_js_deob::BundlerDetection = detect_rolldown(ROLLDOWN_SIMPLE);
    assert!(det.matched, "{det:?}");
    assert!(det.markers.iter().any(|m: &String| m.contains("rolldown")));
}

#[test]
fn rolldown_graph_extracts_module_table_and_dynamic_imports() {
    let result: UnbundleGraphResult =
        unbundle_with_graph(BundlerKind::Rolldown, ROLLDOWN_SIMPLE).expect("unbundle");
    let graph: &ModuleGraph = &result.graph;
    assert_eq!(graph.entry.as_deref(), Some("rolldown-root"));
    let root: &ChunkNode = graph.chunks.get("rolldown-root").expect("root chunk");
    let module_ids_joined: String = root.modules.join(",");
    for expected in ["./src/a.ts", "./src/b.ts", "./src/entry.ts"] {
        assert!(
            module_ids_joined.contains(expected),
            "missing {expected} in {module_ids_joined}"
        );
    }
    assert!(
        root.dynamic_imports
            .iter()
            .any(|d: &String| d.contains("lazy-abc")),
        "{:?}",
        root.dynamic_imports
    );
}
