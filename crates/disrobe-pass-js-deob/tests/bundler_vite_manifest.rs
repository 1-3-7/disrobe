#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_js_deob::{
    ChunkNode, ModuleGraph, ViteManifest, parse_vite_manifest, vite_manifest_to_graph,
};

const VITE_MANIFEST: &str = include_str!("../corpus/bundlers/vite/manifest/manifest.json");

#[test]
fn vite_manifest_reconstructs_full_graph_with_entry_and_dynamic_imports() {
    let manifest: ViteManifest = parse_vite_manifest(VITE_MANIFEST).expect("parse manifest");
    let graph: ModuleGraph = vite_manifest_to_graph(&manifest);
    assert_eq!(graph.entry.as_deref(), Some("src/main.ts"));
    let main: &ChunkNode = graph.chunks.get("src/main.ts").expect("main chunk");
    assert!(
        main.imports
            .iter()
            .any(|i: &String| i == "_shared-CAFEBABE.js")
    );
    assert!(
        main.dynamic_imports
            .iter()
            .any(|d: &String| d == "src/pages/lazy.tsx")
    );
    assert!(graph.chunks.contains_key("src/pages/lazy.tsx"));
    assert!(graph.chunks.contains_key("_shared-CAFEBABE.js"));
}
