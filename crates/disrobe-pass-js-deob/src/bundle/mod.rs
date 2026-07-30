mod amd;
mod browserify;
mod bun;
mod esbuild;
mod graph;
mod manifest;
mod parcel;
mod require_rewrite;
mod rolldown;
mod rollup;
mod scan;
mod sourcemap;
mod sourcemap_recover;
mod sourcemap_synth;
mod systemjs;
mod turbopack;
mod vite;
mod webpack4;
mod webpack5;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::{Error, Result};

pub use amd::detect as detect_amd;
pub use browserify::detect as detect_browserify;
pub use bun::detect as detect_bun;
pub use esbuild::detect as detect_esbuild;
pub use graph::{
    ChunkAnnotation, ChunkKind, ChunkNode, ModuleGraph, UnbundleGraphResult, write_graph,
};
pub use manifest::{ViteManifest, ViteManifestEntry, parse_vite_manifest, vite_manifest_to_graph};
pub use parcel::detect as detect_parcel;
pub use require_rewrite::{build_id_to_path_map, rewrite_modules, rewrite_requires};
pub use rolldown::detect as detect_rolldown;
pub use rollup::detect as detect_rollup;
pub use sourcemap::{SourceMapInfo, find as find_source_map};
pub use sourcemap_recover::{
    DeployedRecovery, MergedTreeRecovery, NoMapFallback, OriginalPosition, PositionResolver,
    RecoverOptions, RecoveredFile, RecoveryReport, SourceCoverage, SourceMap, SourceMapLocation,
    SourceTreeRecovery, decode_data_url_json, merge_reports, parse as parse_source_map_v3,
    recover as recover_source_map, recover_deployed_source,
    recover_from_inline_data_url as recover_source_map_inline,
    recover_from_json as recover_source_map_json, recover_source_tree_from_chunks,
    recover_source_tree_from_js,
};
pub use sourcemap_synth::{
    DecodedInlineMap, DecodedMappings, MappingSegment, RecoveredSourceMap, SourceMapEmit,
    SynthesizedSourceMap, decode_inline_data_url, decode_mappings, decode_vlq,
    emit as emit_source_maps, encode_mappings, parse_source_map, serialize as serialize_source_map,
    synthesize_from_modules,
};
pub use systemjs::detect as detect_systemjs;
pub use turbopack::detect as detect_turbopack;
pub use vite::detect as detect_vite;
pub use webpack4::detect as detect_webpack4;
pub use webpack5::detect as detect_webpack5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum BundlerKind {
    Webpack4,
    Webpack5,
    Vite,
    Rollup,
    Rolldown,
    Esbuild,
    Turbopack,
    Bun,
    Browserify,
    Parcel,
    SystemJs,
    Amd,
}

impl BundlerKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Amd => "amd",
            Self::Webpack4 => "webpack4",
            Self::Webpack5 => "webpack5",
            Self::Vite => "vite",
            Self::Rollup => "rollup",
            Self::Rolldown => "rolldown",
            Self::Esbuild => "esbuild",
            Self::Turbopack => "turbopack",
            Self::Bun => "bun",
            Self::Browserify => "browserify",
            Self::Parcel => "parcel",
            Self::SystemJs => "systemjs",
        }
    }

    pub const ALL: &'static [Self] = &[
        Self::Webpack5,
        Self::Webpack4,
        Self::Turbopack,
        Self::Vite,
        Self::Rolldown,
        Self::Bun,
        Self::Esbuild,
        Self::Rollup,
        Self::Browserify,
        Self::Parcel,
        Self::SystemJs,
        Self::Amd,
    ];

    pub const PUBLISHED_FAMILY_ALIASES: usize = 1;
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]
mod published_count_tests {
    use super::BundlerKind;

    #[test]
    fn published_js_bundler_count_matches_this_enum() {
        const BAR: &str = "JS bundlers";
        let manifest: &str = env!("CARGO_MANIFEST_DIR");
        let data: std::path::PathBuf = std::path::Path::new(manifest)
            .join("..")
            .join("..")
            .join("xtask")
            .join("data")
            .join("recovery.json");
        let raw: String = std::fs::read_to_string(&data)
            .unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", data.display()));
        let parsed: serde_json::Value = serde_json::from_str(&raw)
            .unwrap_or_else(|e: serde_json::Error| panic!("parse {}: {e}", data.display()));

        let mut published: Option<f64> = None;
        for group in parsed["groups"].as_array().expect("groups array") {
            for bar in group["bars"].as_array().unwrap_or(&Vec::new()) {
                if bar["label"].as_str() == Some(BAR) {
                    published = bar["value"].as_f64();
                }
            }
        }
        let published: f64 = published.expect("recovery.json must carry a JS bundlers bar");
        let expected: usize = BundlerKind::ALL.len() - BundlerKind::PUBLISHED_FAMILY_ALIASES;

        assert!(
            (published - expected as f64).abs() < f64::EPSILON,
            "xtask/data/recovery.json publishes {published} JS bundlers and the README and catalog \
             render that number, but this enum carries {} variants of which \
             {} is an alias of another published family, giving {expected}",
            BundlerKind::ALL.len(),
            BundlerKind::PUBLISHED_FAMILY_ALIASES
        );
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BundlerDetection {
    pub kind: BundlerKind,
    pub matched: bool,
    pub confidence: f32,
    pub markers: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtractedModule {
    pub id: String,
    pub chunk_id: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UnbundleResult {
    pub kind: BundlerKind,
    pub detection: BundlerDetection,
    pub modules: Vec<ExtractedModule>,
}

fn detect_kind(kind: BundlerKind, source: &str) -> BundlerDetection {
    match kind {
        BundlerKind::Amd => amd::detect(source),
        BundlerKind::Webpack4 => webpack4::detect(source),
        BundlerKind::Webpack5 => webpack5::detect(source),
        BundlerKind::Vite => vite::detect(source),
        BundlerKind::Rollup => rollup::detect(source),
        BundlerKind::Rolldown => rolldown::detect(source),
        BundlerKind::Esbuild => esbuild::detect(source),
        BundlerKind::Turbopack => turbopack::detect(source),
        BundlerKind::Bun => bun::detect(source),
        BundlerKind::Browserify => browserify::detect(source),
        BundlerKind::Parcel => parcel::detect(source),
        BundlerKind::SystemJs => systemjs::detect(source),
    }
}

fn extract_kind(kind: BundlerKind, source: &str) -> Vec<ExtractedModule> {
    match kind {
        BundlerKind::Amd => amd::extract(source),
        BundlerKind::Webpack4 => webpack4::extract(source),
        BundlerKind::Webpack5 => webpack5::extract(source),
        BundlerKind::Vite => vite::extract(source),
        BundlerKind::Rollup => rollup::extract(source),
        BundlerKind::Rolldown => rolldown::extract(source),
        BundlerKind::Esbuild => esbuild::extract(source),
        BundlerKind::Turbopack => turbopack::extract(source),
        BundlerKind::Bun => bun::extract(source),
        BundlerKind::Browserify => browserify::extract(source),
        BundlerKind::Parcel => parcel::extract(source),
        BundlerKind::SystemJs => systemjs::extract(source),
    }
}

fn graph_kind(kind: BundlerKind, source: &str, modules: &[ExtractedModule]) -> ModuleGraph {
    match kind {
        BundlerKind::Amd => amd::build_graph(source, modules),
        BundlerKind::Webpack4 => webpack4::build_graph(source, modules),
        BundlerKind::Webpack5 => webpack5::build_graph(source, modules),
        BundlerKind::Vite => vite::build_graph(source, modules),
        BundlerKind::Rollup => rollup_graph_from_modules(modules),
        BundlerKind::Rolldown => rolldown::build_graph(source, modules),
        BundlerKind::Esbuild => generic_graph_from_modules("esbuild", modules),
        BundlerKind::Turbopack => turbopack::build_graph(source, modules),
        BundlerKind::Bun => bun::build_graph(source, modules),
        BundlerKind::Browserify => browserify::build_graph(source, modules),
        BundlerKind::Parcel => parcel::build_graph(source, modules),
        BundlerKind::SystemJs => systemjs::build_graph(source, modules),
    }
}

pub fn unbundle(kind: BundlerKind, source: &str) -> Result<UnbundleResult> {
    let detection: BundlerDetection = detect_kind(kind, source);
    let mut modules: Vec<ExtractedModule> = extract_kind(kind, source);
    if matches!(
        kind,
        BundlerKind::Webpack4
            | BundlerKind::Webpack5
            | BundlerKind::Esbuild
            | BundlerKind::Turbopack
            | BundlerKind::Bun
            | BundlerKind::Browserify
            | BundlerKind::Parcel
            | BundlerKind::Rolldown
    ) {
        require_rewrite::rewrite_modules(&mut modules);
    }
    if !detection.matched && modules.is_empty() {
        return Err(Error::NoFamilyMatched);
    }
    Ok(UnbundleResult {
        kind,
        detection,
        modules,
    })
}

pub fn auto_unbundle(source: &str) -> Result<UnbundleResult> {
    let mut best: Option<(BundlerKind, BundlerDetection)> = None;
    for &kind in BundlerKind::ALL {
        let det: BundlerDetection = detect_kind(kind, source);
        if det.matched {
            let take: bool = best
                .as_ref()
                .is_none_or(|(_, prev)| det.confidence > prev.confidence);
            if take {
                best = Some((kind, det));
            }
        }
    }
    let Some((kind, _)): Option<(BundlerKind, BundlerDetection)> = best else {
        return Err(Error::NoFamilyMatched);
    };
    unbundle(kind, source)
}

pub fn write_modules(out_dir: &Path, result: &UnbundleResult) -> Result<BTreeMap<String, PathBuf>> {
    let mut written: BTreeMap<String, PathBuf> = BTreeMap::new();
    let modules_dir: PathBuf = out_dir.join("modules");
    std::fs::create_dir_all(&modules_dir)?;
    for module in &result.modules {
        let id_sanitized: String = sanitize_id(&module.id);
        let filename: String = module.chunk_id.as_ref().map_or_else(
            || format!("{id_sanitized}.js"),
            |chunk: &String| format!("{}-{id_sanitized}.js", sanitize_id(chunk)),
        );
        let path: PathBuf = modules_dir.join(&filename);
        std::fs::write(&path, module.source.as_bytes())?;
        written.insert(module.id.clone(), path);
    }
    Ok(written)
}

pub fn write_recovered_sources(
    out_dir: &Path,
    report: &RecoveryReport,
) -> Result<BTreeMap<String, PathBuf>> {
    let mut written: BTreeMap<String, PathBuf> = BTreeMap::new();
    std::fs::create_dir_all(out_dir)?;
    let canonical_root: PathBuf = out_dir
        .canonicalize()
        .unwrap_or_else(|_| out_dir.to_owned());
    for file in &report.files {
        let dest: PathBuf = safe_join(out_dir, &file.relative_path)?;
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let resolved_parent: PathBuf = dest
            .parent()
            .and_then(|p: &Path| p.canonicalize().ok())
            .unwrap_or_else(|| canonical_root.clone());
        if !resolved_parent.starts_with(&canonical_root) {
            return Err(Error::OxcParse(format!(
                "refusing to write {} outside the output directory",
                file.relative_path,
            )));
        }
        std::fs::write(&dest, &file.bytes)?;
        written.insert(file.relative_path.clone(), dest);
    }
    Ok(written)
}

fn safe_join(out_dir: &Path, relative: &str) -> Result<PathBuf> {
    let rel: PathBuf = PathBuf::from(relative);
    let all_normal: bool = rel
        .components()
        .all(|c: std::path::Component<'_>| matches!(c, std::path::Component::Normal(_)));
    if !all_normal || rel.as_os_str().is_empty() {
        return Err(Error::OxcParse(format!(
            "refusing path with traversal/absolute component: {relative}",
        )));
    }
    Ok(out_dir.join(rel))
}

pub fn unbundle_with_graph(kind: BundlerKind, source: &str) -> Result<UnbundleGraphResult> {
    let plain: UnbundleResult = unbundle(kind, source)?;
    let graph_built: ModuleGraph = graph_kind(kind, source, &plain.modules);
    Ok(UnbundleGraphResult {
        kind,
        detection: plain.detection,
        modules: plain.modules,
        graph: graph_built,
    })
}

pub fn unbundle_with_sourcemaps(
    kind: BundlerKind,
    source: &str,
) -> Result<(UnbundleGraphResult, SourceMapEmit)> {
    let graph_result: UnbundleGraphResult = unbundle_with_graph(kind, source)?;
    let mut chunk_modules: BTreeMap<String, Vec<ExtractedModule>> = BTreeMap::new();
    for m in &graph_result.modules {
        let chunk: String = m.chunk_id.clone().unwrap_or_else(|| {
            graph_result
                .graph
                .entry
                .clone()
                .unwrap_or_else(|| "main".to_owned())
        });
        chunk_modules.entry(chunk).or_default().push(m.clone());
    }
    let emit: SourceMapEmit = emit_source_maps(&chunk_modules, &graph_result.graph.sourcemap_urls);
    Ok((graph_result, emit))
}

pub fn write_sourcemaps(out_dir: &Path, emit: &SourceMapEmit) -> Result<BTreeMap<String, PathBuf>> {
    let maps_dir: PathBuf = out_dir.join("sourcemaps");
    std::fs::create_dir_all(&maps_dir)?;
    let mut written: BTreeMap<String, PathBuf> = BTreeMap::new();
    for (chunk_id, map) in &emit.per_chunk {
        let filename: String = format!("{}.synth.map.json", sanitize_id(chunk_id));
        let path: PathBuf = maps_dir.join(&filename);
        let serialized: String = serialize_source_map(map)?;
        std::fs::write(&path, serialized.as_bytes())?;
        written.insert(chunk_id.clone(), path);
    }
    for (chunk_id, decoded) in &emit.embedded {
        let filename: String = format!("{}.embedded.map.json", sanitize_id(chunk_id));
        let path: PathBuf = maps_dir.join(&filename);
        std::fs::write(&path, decoded.raw_json.as_bytes())?;
        written.insert(format!("embedded:{chunk_id}"), path);
    }
    Ok(written)
}

fn rollup_graph_from_modules(modules: &[ExtractedModule]) -> ModuleGraph {
    let mut graph: ModuleGraph = ModuleGraph::new();
    graph.with_entry("main");
    let mut chunk: ChunkNode = ChunkNode {
        id: "main".to_owned(),
        file: Some("main.js".to_owned()),
        ..ChunkNode::default()
    };
    for m in modules {
        chunk.modules.push(m.id.clone());
    }
    graph.upsert_chunk(chunk);
    for m in modules {
        graph.link_module_to_chunk(&m.id, "main");
    }
    graph
}

fn generic_graph_from_modules(label: &str, modules: &[ExtractedModule]) -> ModuleGraph {
    let mut graph: ModuleGraph = ModuleGraph::new();
    graph.with_entry(label);
    let mut chunk: ChunkNode = ChunkNode {
        id: label.to_owned(),
        file: Some(format!("{label}.js")),
        ..ChunkNode::default()
    };
    for m in modules {
        chunk.modules.push(m.id.clone());
    }
    graph.upsert_chunk(chunk);
    for m in modules {
        graph.link_module_to_chunk(&m.id, label);
    }
    graph
}

fn sanitize_id(raw: &str) -> String {
    let mut out: String = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if matches!(ch, 'A'..='Z' | 'a'..='z' | '0'..='9' | '_' | '-' | '.') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "anonymous".to_owned()
    } else {
        out
    }
}
