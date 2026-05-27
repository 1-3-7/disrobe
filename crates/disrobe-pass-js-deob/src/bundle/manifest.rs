use std::collections::BTreeMap;

use serde::Deserialize;

use super::graph::{ChunkNode, ModuleGraph};
use crate::error::{Error, Result};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ViteManifestEntry {
    pub file: String,
    #[serde(default)]
    pub src: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub is_entry: bool,
    #[serde(default)]
    pub is_dynamic_entry: bool,
    #[serde(default)]
    pub imports: Vec<String>,
    #[serde(default)]
    pub dynamic_imports: Vec<String>,
    #[serde(default)]
    pub css: Vec<String>,
    #[serde(default)]
    pub assets: Vec<String>,
}

pub type ViteManifest = BTreeMap<String, ViteManifestEntry>;

pub fn parse_vite_manifest(raw: &str) -> Result<ViteManifest> {
    serde_json::from_str(raw).map_err(|e: serde_json::Error| Error::OxcParse(e.to_string()))
}

pub fn vite_manifest_to_graph(manifest: &ViteManifest) -> ModuleGraph {
    let mut graph: ModuleGraph = ModuleGraph::new();
    for (key, entry) in manifest {
        let mut node: ChunkNode = ChunkNode {
            id: key.clone(),
            file: Some(entry.file.clone()),
            imports: entry.imports.clone(),
            dynamic_imports: entry.dynamic_imports.clone(),
            modules: entry
                .src
                .as_ref()
                .map_or_else(Vec::new, |s: &String| vec![s.clone()]),
        };
        node.modules.sort();
        if entry.is_entry && graph.entry.is_none() {
            graph.entry = Some(key.clone());
        }
        graph.upsert_chunk(node);
        if let Some(src) = entry.src.as_ref() {
            graph.link_module_to_chunk(src, key);
        }
    }
    graph
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const MANIFEST: &str = r#"{
        "src/main.ts": {
            "file": "assets/main-abc.js",
            "src": "src/main.ts",
            "isEntry": true,
            "imports": ["_shared-xyz.js"],
            "dynamicImports": ["src/lazy.ts"]
        },
        "src/lazy.ts": {
            "file": "assets/lazy-def.js",
            "src": "src/lazy.ts",
            "isDynamicEntry": true,
            "imports": []
        },
        "_shared-xyz.js": {
            "file": "assets/shared-xyz.js",
            "imports": []
        }
    }"#;

    #[test]
    fn parses_real_vite_manifest_shape() {
        let m: ViteManifest = parse_vite_manifest(MANIFEST).expect("parse");
        assert_eq!(m.len(), 3);
        let main: &ViteManifestEntry = m.get("src/main.ts").expect("main");
        assert!(main.is_entry);
        assert_eq!(main.imports, vec!["_shared-xyz.js"]);
    }

    #[test]
    fn graph_marks_entry_and_links_modules() {
        let m: ViteManifest = parse_vite_manifest(MANIFEST).expect("parse");
        let g: ModuleGraph = vite_manifest_to_graph(&m);
        assert_eq!(g.entry.as_deref(), Some("src/main.ts"));
        assert_eq!(
            g.chunks.get("src/main.ts").expect("main").imports,
            vec!["_shared-xyz.js"]
        );
    }
}
