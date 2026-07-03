#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_js_deob::{
    BundlerKind, ChunkNode, ModuleGraph, UnbundleGraphResult, detect_parcel, unbundle_with_graph,
};

const PARCEL_SIMPLE: &str = include_str!("../corpus/bundlers/parcel/simple/bundle.js");

#[test]
fn parcel_2_detects_via_parcel_require() {
    let det: disrobe_pass_js_deob::BundlerDetection = detect_parcel(PARCEL_SIMPLE);
    assert!(det.matched, "{det:?}");
}

#[test]
fn parcel_2_unbundle_extracts_registered_modules_and_imports() {
    let result: UnbundleGraphResult =
        unbundle_with_graph(BundlerKind::Parcel, PARCEL_SIMPLE).expect("unbundle");
    let graph: &ModuleGraph = &result.graph;
    let root: &ChunkNode = graph.chunks.get("parcel-root").expect("parcel-root");
    for expected in ["aaaaa", "bbbbb", "ccccc"] {
        assert!(
            root.modules.iter().any(|m: &String| m == expected),
            "missing module {expected}: {:?}",
            root.modules
        );
    }
    for expected in ["aaaaa", "bbbbb"] {
        assert!(
            root.imports.iter().any(|i: &String| i == expected),
            "missing import {expected}: {:?}",
            root.imports
        );
    }
}
