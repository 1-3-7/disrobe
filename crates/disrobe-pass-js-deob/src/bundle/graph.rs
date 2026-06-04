use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::ExtractedModule;
use crate::error::Result;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub enum ChunkKind {
    #[default]
    Unknown,
    Entry,
    DynamicEntry,
    Shared,
    Async,
}

impl ChunkKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Entry => "entry",
            Self::DynamicEntry => "dynamic-entry",
            Self::Shared => "shared",
            Self::Async => "async",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ChunkAnnotation {
    pub kind: ChunkKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunk_name: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub prefetch: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub preload: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ChunkNode {
    pub id: String,
    pub file: Option<String>,
    pub imports: Vec<String>,
    pub dynamic_imports: Vec<String>,
    pub modules: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ModuleGraph {
    pub entry: Option<String>,
    pub chunks: BTreeMap<String, ChunkNode>,
    pub module_to_chunk: BTreeMap<String, String>,
    pub sourcemap_urls: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub chunk_annotations: BTreeMap<String, ChunkAnnotation>,
}

impl ModuleGraph {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_entry(&mut self, entry: impl Into<String>) -> &mut Self {
        self.entry = Some(entry.into());
        self
    }

    pub fn upsert_chunk(&mut self, chunk: ChunkNode) {
        let id: String = chunk.id.clone();
        self.chunks.entry(id).or_insert(chunk);
    }

    pub fn link_module_to_chunk(&mut self, module_id: &str, chunk_id: &str) {
        self.module_to_chunk
            .insert(module_id.to_owned(), chunk_id.to_owned());
        if let Some(chunk) = self.chunks.get_mut(chunk_id)
            && !chunk.modules.iter().any(|m: &String| m == module_id)
        {
            chunk.modules.push(module_id.to_owned());
        }
    }

    pub fn annotate_chunk(&mut self, chunk_id: impl Into<String>, annotation: ChunkAnnotation) {
        self.chunk_annotations.insert(chunk_id.into(), annotation);
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct UnbundleGraphResult {
    pub kind: super::BundlerKind,
    pub detection: super::BundlerDetection,
    pub modules: Vec<ExtractedModule>,
    pub graph: ModuleGraph,
}

pub fn write_graph(
    out_dir: &Path,
    result: &UnbundleGraphResult,
) -> Result<BTreeMap<String, PathBuf>> {
    std::fs::create_dir_all(out_dir)?;
    let modules_dir: PathBuf = out_dir.join("modules");
    std::fs::create_dir_all(&modules_dir)?;
    let mut written: BTreeMap<String, PathBuf> = BTreeMap::new();

    for module in &result.modules {
        let id_sanitized: String = super::sanitize_id(&module.id);
        let extension: &str = pick_extension(&module.id);
        let filename: String = module.chunk_id.as_ref().map_or_else(
            || format!("{id_sanitized}.{extension}"),
            |chunk: &String| format!("{}-{id_sanitized}.{extension}", super::sanitize_id(chunk)),
        );
        let path: PathBuf = modules_dir.join(&filename);
        std::fs::write(&path, module.source.as_bytes())?;
        written.insert(module.id.clone(), path);
    }

    let graph_path: PathBuf = out_dir.join("graph.json");
    let serialized: String = serde_json::to_string_pretty(&result.graph)
        .map_err(|err| crate::error::Error::OxcParse(err.to_string()))?;
    std::fs::write(&graph_path, serialized.as_bytes())?;
    written.insert("__graph__".to_owned(), graph_path);

    Ok(written)
}

fn pick_extension(module_id: &str) -> &'static str {
    let lower: String = module_id.to_ascii_lowercase();
    let lower_str: &str = lower.as_str();
    if std::path::Path::new(lower_str)
        .extension()
        .and_then(|e: &std::ffi::OsStr| e.to_str())
        == Some("mjs")
    {
        "mjs"
    } else if std::path::Path::new(lower_str)
        .extension()
        .and_then(|e: &std::ffi::OsStr| e.to_str())
        == Some("cjs")
    {
        "cjs"
    } else if matches!(
        std::path::Path::new(lower_str)
            .extension()
            .and_then(|e: &std::ffi::OsStr| e.to_str()),
        Some("ts" | "tsx")
    ) {
        "ts"
    } else if std::path::Path::new(lower_str)
        .extension()
        .and_then(|e: &std::ffi::OsStr| e.to_str())
        == Some("jsx")
    {
        "jsx"
    } else {
        "js"
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::case_sensitive_file_extension_comparisons)]
mod tests {
    use super::*;
    use crate::bundle::{BundlerDetection, BundlerKind};

    fn unique_temp(prefix: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let seq: u64 = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path: PathBuf = std::env::temp_dir().join(format!(
            "disrobe-jsdeob-{prefix}-{}-{seq}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        path
    }

    #[test]
    fn write_graph_emits_per_chunk_files_and_graph_json() {
        let dir: PathBuf = unique_temp("graph");
        let mut graph: ModuleGraph = ModuleGraph::new();
        graph.with_entry("entry");
        graph.upsert_chunk(ChunkNode {
            id: "entry".to_owned(),
            file: Some("entry.js".to_owned()),
            imports: vec!["chunk-a".to_owned()],
            dynamic_imports: vec![],
            modules: vec!["./a.ts".to_owned()],
        });
        graph.link_module_to_chunk("./a.ts", "entry");
        let result: UnbundleGraphResult = UnbundleGraphResult {
            kind: BundlerKind::Vite,
            detection: BundlerDetection {
                kind: BundlerKind::Vite,
                matched: true,
                confidence: 0.9,
                markers: vec!["__vitePreload".to_owned()],
            },
            modules: vec![ExtractedModule {
                id: "./a.ts".to_owned(),
                chunk_id: Some("entry".to_owned()),
                source: "export const x: number = 1;".to_owned(),
            }],
            graph,
        };
        let written: BTreeMap<String, PathBuf> = write_graph(&dir, &result).expect("write");
        let graph_path: &PathBuf = written.get("__graph__").expect("graph path");
        let raw: String = std::fs::read_to_string(graph_path).expect("read graph");
        assert!(raw.contains("\"entry\""));
        assert!(raw.contains("\"./a.ts\""));
        let module_path: &PathBuf = written.get("./a.ts").expect("module path");
        let body: String = std::fs::read_to_string(module_path).expect("read body");
        assert!(body.contains("export const x"));
        assert!(
            module_path
                .file_name()
                .and_then(|n: &std::ffi::OsStr| n.to_str())
                .is_some_and(|n: &str| n.ends_with(".ts"))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
