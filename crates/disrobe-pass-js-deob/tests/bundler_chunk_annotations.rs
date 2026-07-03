#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::fs;
use std::path::PathBuf;

use disrobe_pass_js_deob::{
    BundlerKind, ChunkKind, ModuleGraph, UnbundleGraphResult, parse_vite_manifest,
    unbundle_with_graph, vite_manifest_to_graph,
};

fn corpus(rel: &str) -> Option<String> {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let p: PathBuf = manifest
        .join("..")
        .join("..")
        .join("corpus")
        .join("js")
        .join(rel);
    fs::read_to_string(p).ok()
}

#[test]
fn webpack5_magic_comment_annotates_dynamic_chunk() {
    let src: &str = r#"
        var __webpack_modules__ = { "./src/index.js": function(m,e,r){
            var p = __webpack_require__.e("panel").then(__webpack_require__.bind(__webpack_require__, "./src/panel.js"));
        } };
        var lazy = import(/* webpackChunkName: "panel", webpackPrefetch: true */ "./src/panel.js");
        (self.webpackChunkapp = self.webpackChunkapp || []).push([["panel"],{ "./src/panel.js": function(m,e,r){m.exports='p';} }]);
    "#;
    let result: UnbundleGraphResult =
        unbundle_with_graph(BundlerKind::Webpack5, src).expect("unbundle");
    let annotation = result
        .graph
        .chunk_annotations
        .values()
        .find(|a| a.chunk_name.as_deref() == Some("panel"))
        .expect("panel annotation present");
    assert!(annotation.prefetch, "prefetch flag must be recovered");
    assert!(matches!(annotation.kind, ChunkKind::Async));
}

#[test]
fn real_vite_manifest_infers_entry_and_dynamic_kinds() {
    let Some(raw): Option<String> = corpus("vite/manifest.json") else {
        return;
    };
    let manifest = parse_vite_manifest(&raw).expect("parse real vite manifest");
    let graph: ModuleGraph = vite_manifest_to_graph(&manifest);

    let entry_kind = graph
        .chunk_annotations
        .get("index.html")
        .map(|a| a.kind)
        .expect("index.html annotation");
    assert_eq!(entry_kind, ChunkKind::Entry, "index.html must be an entry");

    let lazy_kind = graph
        .chunk_annotations
        .get("src/lazy.js")
        .map(|a| a.kind)
        .expect("src/lazy.js annotation");
    assert_eq!(
        lazy_kind,
        ChunkKind::DynamicEntry,
        "src/lazy.js must be a dynamic entry"
    );
    assert_eq!(graph.entry.as_deref(), Some("index.html"));
}
