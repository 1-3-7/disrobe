use regex::Regex;

use super::graph::{ChunkNode, ModuleGraph};
use super::scan::find_top_level_object_entries;
use super::{BundlerDetection, BundlerKind, ExtractedModule};

#[must_use]
pub fn detect(source: &str) -> BundlerDetection {
    let head: &str = crate::scan_utils::head(source, 256 * 1024);
    let mut markers: Vec<String> = Vec::new();
    let mut score: f32 = 0.0;

    let has_turbopack_require: bool =
        head.contains("__turbopack_require__") || head.contains("__turbopack_esm__");
    let has_turbopack_modules: bool =
        head.contains("__turbopack_modules__") || head.contains("__turbopack_load__");
    let has_module_children: bool = head.contains("module.children");
    let has_turbopack_helpers: bool = head.contains("__turbopack_export_value__")
        || head.contains("__turbopack_export_namespace__");
    let has_next_marker: bool = head.contains("(self.__next_f");
    let has_global_turbopack: bool =
        head.contains("globalThis.TURBOPACK") || head.contains("globalThis[\"TURBOPACK\"]");
    let has_turbopack_asset_suffix: bool = head.contains("TURBOPACK_ASSET_SUFFIX");
    let has_next_static_chunks: bool = head.contains("static/chunks/");

    if has_turbopack_require {
        markers.push("__turbopack_require__".to_owned());
        score += 0.4;
    }
    if has_turbopack_modules {
        markers.push("__turbopack_modules__".to_owned());
        score += 0.3;
    }
    if has_module_children {
        markers.push("module.children".to_owned());
        score += 0.1;
    }
    if has_turbopack_helpers {
        markers.push("__turbopack_export_*".to_owned());
        score += 0.2;
    }
    if has_next_marker {
        markers.push("next-flight-marker".to_owned());
        score += 0.05;
    }
    if has_global_turbopack {
        markers.push("globalThis.TURBOPACK".to_owned());
        score += 0.4;
    }
    if has_turbopack_asset_suffix {
        markers.push("TURBOPACK_ASSET_SUFFIX".to_owned());
        score += 0.2;
    }
    if has_next_static_chunks {
        markers.push("next-static-chunks".to_owned());
        score += 0.1;
    }

    let matched: bool = score >= 0.5;
    BundlerDetection {
        kind: BundlerKind::Turbopack,
        matched,
        confidence: score.clamp(0.0, 0.95),
        markers,
    }
}

pub(super) fn extract(source: &str) -> Vec<ExtractedModule> {
    let mut modules: Vec<ExtractedModule> = Vec::new();
    extract_module_table(source, &mut modules);
    modules
}

pub(super) fn build_graph(source: &str, modules: &[ExtractedModule]) -> ModuleGraph {
    let mut graph: ModuleGraph = ModuleGraph::new();
    graph.with_entry("turbopack-root");
    let dynamic_chunks: Vec<String> = collect_lazy_chunks(source);
    let required_modules: Vec<String> = collect_required_modules(source);

    let dynamic_chunks_for_root: Vec<String> = dynamic_chunks.clone();
    let mut root: ChunkNode = ChunkNode {
        id: "turbopack-root".to_owned(),
        file: Some("turbopack-runtime.js".to_owned()),
        imports: required_modules,
        dynamic_imports: dynamic_chunks_for_root,
        modules: modules
            .iter()
            .map(|m: &ExtractedModule| m.id.clone())
            .collect(),
    };
    root.modules.sort();
    root.modules.dedup();
    graph.upsert_chunk(root);
    for m in modules {
        graph.link_module_to_chunk(&m.id, "turbopack-root");
    }
    for chunk_id in dynamic_chunks {
        let child_id: String = format!("chunk-{}", super::sanitize_id(&chunk_id));
        graph.upsert_chunk(ChunkNode {
            id: child_id.clone(),
            file: Some(chunk_id.clone()),
            imports: vec!["turbopack-root".to_owned()],
            dynamic_imports: Vec::new(),
            modules: Vec::new(),
        });
        graph.link_module_to_chunk(&chunk_id, &child_id);
    }
    if let Some(info) = super::sourcemap::find(source) {
        graph
            .sourcemap_urls
            .insert("turbopack-root".to_owned(), info.url);
    }
    graph
}

fn collect_lazy_chunks(source: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r#"__turbopack_load__\s*\(\s*["']([^"']+)["']"#)
    else {
        return out;
    };
    for cap in re.captures_iter(source) {
        let Some(id): Option<&str> = cap.get(1).map(|m: regex::Match<'_>| m.as_str()) else {
            continue;
        };
        if seen.insert(id.to_owned()) {
            out.push(id.to_owned());
        }
    }
    out
}

fn collect_required_modules(source: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r#"__turbopack_require__\s*\(\s*["']([^"']+)["']"#)
    else {
        return out;
    };
    for cap in re.captures_iter(source) {
        let Some(id): Option<&str> = cap.get(1).map(|m: regex::Match<'_>| m.as_str()) else {
            continue;
        };
        if seen.insert(id.to_owned()) {
            out.push(id.to_owned());
        }
    }
    out
}

fn extract_module_table(source: &str, modules: &mut Vec<ExtractedModule>) {
    let Ok(re): Result<Regex, regex::Error> = Regex::new(
        r"__turbopack_modules__\s*=\s*\{|__turbopack_load__\s*\(\s*\{|\{\s*[a-zA-Z_0-9]+\s*:\s*\(\s*__turbopack",
    ) else {
        return;
    };
    let bytes: &[u8] = source.as_bytes();
    for mat in re.find_iter(source) {
        let mut i: usize = mat.start();
        while i < bytes.len() && bytes[i] != b'{' {
            i += 1;
        }
        if i >= bytes.len() {
            continue;
        }
        let Some(entries): Option<Vec<super::scan::ObjectEntry>> =
            find_top_level_object_entries(source, i)
        else {
            continue;
        };
        for entry in entries {
            let value_text: &str = &source[entry.value_span.0..entry.value_span.1];
            modules.push(ExtractedModule {
                id: entry.key,
                chunk_id: Some("turbopack".to_owned()),
                source: value_text.trim().to_owned(),
            });
        }
        if !modules.is_empty() {
            return;
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_turbopack_runtime() {
        let src: &str = "var __turbopack_require__ = function(){}; var __turbopack_modules__ = {}; var __turbopack_export_value__ = function(){};";
        let det: BundlerDetection = detect(src);
        assert!(det.matched);
    }

    #[test]
    fn extracts_turbopack_module_table() {
        let src: &str = "__turbopack_modules__ = { \"./src/a.tsx\": function(m){m.exports='a';}, \"./src/b.tsx\": function(m){m.exports='b';} };";
        let mods: Vec<ExtractedModule> = extract(src);
        assert_eq!(mods.len(), 2);
        assert!(mods.iter().any(|m| m.id == "./src/a.tsx"));
    }
}
