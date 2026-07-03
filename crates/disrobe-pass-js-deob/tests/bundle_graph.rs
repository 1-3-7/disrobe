#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::path::PathBuf;

use disrobe_pass_js_deob::{
    BundlerKind, ModuleGraph, UnbundleGraphResult, unbundle_with_graph, write_graph,
};

const WEBPACK4_MULTICHUNK: &str =
    include_str!("../../../corpus/src/javascript/webpack4-multichunk.js");
const WEBPACK5_SPLITCHUNKS: &str =
    include_str!("../../../corpus/src/javascript/webpack5-splitchunks.js");
const VITE_MULTICHUNK: &str = include_str!("../../../corpus/src/javascript/vite-multichunk.js");
const TURBOPACK_SAMPLE: &str = include_str!("../../../corpus/src/javascript/turbopack-sample.js");
const BUN_SAMPLE: &str = include_str!("../../../corpus/src/javascript/bun-sample.js");

fn unique_dir(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static C: AtomicU64 = AtomicU64::new(0);
    let seq: u64 = C.fetch_add(1, Ordering::Relaxed);
    let p: PathBuf = std::env::temp_dir().join(format!(
        "disrobe-bundle-graph-{label}-{}-{seq}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&p);
    p
}

#[test]
fn webpack4_chunk_graph_recovers_dynamic_chunks() {
    let result: UnbundleGraphResult =
        unbundle_with_graph(BundlerKind::Webpack4, WEBPACK4_MULTICHUNK).expect("unbundle");
    let graph: &ModuleGraph = &result.graph;
    assert_eq!(graph.entry.as_deref(), Some("main"));
    assert!(graph.chunks.contains_key("main"));
    let main: &disrobe_pass_js_deob::ChunkNode = graph.chunks.get("main").expect("main chunk");
    assert!(
        main.dynamic_imports
            .iter()
            .any(|d: &String| d == "1" || d == "2"),
        "expected dynamic imports 1 and 2: {:?}",
        main.dynamic_imports
    );
    assert!(graph.sourcemap_urls.contains_key("main"));
}

#[test]
fn webpack5_split_chunks_produces_graph_with_main_and_vendor() {
    let result: UnbundleGraphResult =
        unbundle_with_graph(BundlerKind::Webpack5, WEBPACK5_SPLITCHUNKS).expect("unbundle");
    let graph: &ModuleGraph = &result.graph;
    assert_eq!(graph.entry.as_deref(), Some("main"));
    assert!(
        graph.chunks.len() >= 2,
        "{:?}",
        graph.chunks.keys().collect::<Vec<_>>()
    );
    let main: &disrobe_pass_js_deob::ChunkNode = graph.chunks.get("main").expect("main chunk");
    assert!(
        main.dynamic_imports.iter().any(|d: &String| d == "vendor"),
        "expected vendor in dynamic imports: {:?}",
        main.dynamic_imports
    );
}

#[test]
fn vite_module_graph_collects_dynamic_imports() {
    let result: UnbundleGraphResult =
        unbundle_with_graph(BundlerKind::Vite, VITE_MULTICHUNK).expect("unbundle");
    let graph: &ModuleGraph = &result.graph;
    assert_eq!(graph.entry.as_deref(), Some("vite-entry"));
    let entry: &disrobe_pass_js_deob::ChunkNode =
        graph.chunks.get("vite-entry").expect("vite entry chunk");
    let dyn_imports_joined: String = entry.dynamic_imports.join(",");
    assert!(
        dyn_imports_joined.contains("./widgets/chart.tsx")
            || dyn_imports_joined.contains("./pages/home.tsx")
            || dyn_imports_joined.contains("glob:"),
        "missing expected dynamic imports: {dyn_imports_joined}"
    );
}

#[test]
fn turbopack_module_graph_has_root_with_modules() {
    let result: UnbundleGraphResult =
        unbundle_with_graph(BundlerKind::Turbopack, TURBOPACK_SAMPLE).expect("unbundle");
    let graph: &ModuleGraph = &result.graph;
    let root: &disrobe_pass_js_deob::ChunkNode = graph.chunks.get("turbopack-root").expect("root");
    assert!(
        root.modules.iter().any(|m: &String| m == "./app/page.tsx"),
        "expected ./app/page.tsx in root modules: {:?}",
        root.modules
    );
    assert!(
        root.imports.iter().any(|i: &String| i == "./app/page.tsx"),
        "expected ./app/page.tsx in imports (from __turbopack_require__): {:?}",
        root.imports
    );
}

#[test]
fn bun_module_graph_collects_resolve_sync_imports() {
    let result: UnbundleGraphResult =
        unbundle_with_graph(BundlerKind::Bun, BUN_SAMPLE).expect("unbundle");
    let graph: &ModuleGraph = &result.graph;
    let bundle: &disrobe_pass_js_deob::ChunkNode =
        graph.chunks.get("bun-bundle").expect("bun-bundle chunk");
    assert!(
        bundle.imports.iter().any(|i: &String| i == "./a.ts"),
        "expected ./a.ts in imports: {:?}",
        bundle.imports
    );
    assert!(
        bundle.modules.iter().any(|m: &String| m == "./a.ts"),
        "expected ./a.ts in modules: {:?}",
        bundle.modules
    );
}

#[test]
fn write_graph_emits_files_and_json() {
    let dir: PathBuf = unique_dir("write");
    let result: UnbundleGraphResult =
        unbundle_with_graph(BundlerKind::Webpack5, WEBPACK5_SPLITCHUNKS).expect("unbundle");
    let written: std::collections::BTreeMap<String, PathBuf> =
        write_graph(&dir, &result).expect("write");
    assert!(written.contains_key("__graph__"));
    let graph_path: &PathBuf = written.get("__graph__").expect("graph");
    let raw: String = std::fs::read_to_string(graph_path).expect("read");
    assert!(raw.contains("\"main\""));
    let _ = std::fs::remove_dir_all(&dir);
}
