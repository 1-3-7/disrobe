use regex::Regex;

use super::graph::{ChunkNode, ModuleGraph};
use super::scan::find_top_level_object_entries;
use super::{BundlerDetection, BundlerKind, ExtractedModule};

pub fn detect(source: &str) -> BundlerDetection {
    let head: &str = &source[..source.len().min(256 * 1024)];
    let mut markers: Vec<String> = Vec::new();
    let mut score: f32 = 0.0;

    let has_require_r: bool = head.contains("__webpack_require__.r");
    let has_require_d: bool = head.contains("__webpack_require__.d");
    let has_module_cache: bool = head.contains("__webpack_module_cache__");
    let has_module_table: bool = head.contains("__webpack_modules__");
    let has_require_fn: bool = head.contains("function __webpack_require__")
        || head.contains("__webpack_require__ =")
        || head.contains("__webpack_require__(");
    let has_chunk_loader: bool =
        head.contains("self.webpackChunk") || head.contains("globalThis.webpackChunk");
    let has_bare_chunk_marker: bool = head.contains("webpackChunk");
    let has_bootstrap_banner: bool =
        head.contains("// webpackBootstrap") || head.contains("webpackBootstrap");

    if has_require_r {
        markers.push("__webpack_require__.r".to_owned());
        score += 0.3;
    }
    if has_require_d {
        markers.push("__webpack_require__.d".to_owned());
        score += 0.2;
    }
    if has_module_cache {
        markers.push("__webpack_module_cache__".to_owned());
        score += 0.25;
    }
    if has_module_table {
        markers.push("__webpack_modules__".to_owned());
        score += 0.25;
    }
    if has_require_fn {
        markers.push("__webpack_require__-fn".to_owned());
        score += 0.2;
    }
    if has_chunk_loader {
        markers.push("self.webpackChunk".to_owned());
        score += 0.25;
    } else if has_bare_chunk_marker {
        markers.push("webpackChunk".to_owned());
        score += 0.15;
    }
    if has_bootstrap_banner {
        markers.push("webpackBootstrap".to_owned());
        score += 0.2;
    }

    let matched: bool = score >= 0.5;
    BundlerDetection {
        kind: BundlerKind::Webpack5,
        matched,
        confidence: score.clamp(0.0, 0.97),
        markers,
    }
}

pub(super) fn extract(source: &str) -> Vec<ExtractedModule> {
    let mut modules: Vec<ExtractedModule> = Vec::new();
    extract_module_table(source, &mut modules);
    extract_chunk_push(source, &mut modules);
    modules
}

pub(super) fn build_graph(source: &str, modules: &[ExtractedModule]) -> ModuleGraph {
    let mut graph: ModuleGraph = ModuleGraph::new();
    graph.with_entry("main");
    let chunk_module_map: std::collections::BTreeMap<String, Vec<String>> =
        group_modules_by_chunk(modules);
    let parent_to_children: std::collections::BTreeMap<String, Vec<String>> =
        collect_require_e_calls(source);
    let push_chunks: Vec<String> = collect_chunk_push_ids(source);

    for (chunk_id, mod_ids) in &chunk_module_map {
        let mut node: ChunkNode = ChunkNode {
            id: chunk_id.clone(),
            file: Some(format!("{}.js", super::sanitize_id(chunk_id))),
            imports: Vec::new(),
            dynamic_imports: parent_to_children
                .get(chunk_id)
                .cloned()
                .unwrap_or_default(),
            modules: mod_ids.clone(),
        };
        node.modules.sort();
        graph.upsert_chunk(node);
        for module_id in mod_ids {
            graph.link_module_to_chunk(module_id, chunk_id);
        }
    }
    for child_id in push_chunks
        .iter()
        .chain(parent_to_children.values().flatten())
    {
        if !graph.chunks.contains_key(child_id) {
            graph.upsert_chunk(ChunkNode {
                id: child_id.clone(),
                file: Some(format!("{}.js", super::sanitize_id(child_id))),
                imports: vec!["main".to_owned()],
                dynamic_imports: Vec::new(),
                modules: Vec::new(),
            });
        }
    }
    for (parent, children) in &parent_to_children {
        for child in children {
            if let Some(chunk) = graph.chunks.get_mut(child)
                && !chunk.imports.iter().any(|p: &String| p == parent)
            {
                chunk.imports.push(parent.clone());
            }
        }
    }
    if let Some(info) = super::sourcemap::find(source) {
        graph.sourcemap_urls.insert("main".to_owned(), info.url);
    }
    graph
}

fn group_modules_by_chunk(
    modules: &[ExtractedModule],
) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut out: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for m in modules {
        let chunk: String = m.chunk_id.clone().unwrap_or_else(|| "main".to_owned());
        out.entry(chunk).or_default().push(m.id.clone());
    }
    out
}

fn collect_require_e_calls(source: &str) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut out: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r"__webpack_require__\.[et]\s*\(\s*([0-9]+|\x22[^\x22]+\x22|'[^']+')\s*\)")
    else {
        return out;
    };
    let mut all: Vec<String> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for cap in re.captures_iter(source) {
        let Some(raw): Option<&str> = cap.get(1).map(|m: regex::Match<'_>| m.as_str()) else {
            continue;
        };
        let trimmed: String = raw.trim_matches(['"', '\'']).to_owned();
        if seen.insert(trimmed.clone()) {
            all.push(trimmed);
        }
    }
    if !all.is_empty() {
        out.insert("main".to_owned(), all);
    }
    out
}

fn collect_chunk_push_ids(source: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let Ok(re): Result<Regex, regex::Error> = Regex::new(
        r"webpackChunk[A-Za-z_0-9$]*\s*\|\|\s*\[\]\)\.push\s*\(\s*\[\s*\[\s*([0-9]+|\x22[^\x22]+\x22|'[^']+')",
    ) else {
        return out;
    };
    for cap in re.captures_iter(source) {
        let Some(raw): Option<&str> = cap.get(1).map(|m: regex::Match<'_>| m.as_str()) else {
            continue;
        };
        let trimmed: String = raw.trim_matches(['"', '\'']).to_owned();
        if seen.insert(trimmed.clone()) {
            out.push(trimmed);
        }
    }
    out
}

fn extract_module_table(source: &str, modules: &mut Vec<ExtractedModule>) {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r"(?:var|let|const)\s+__webpack_modules__\s*=\s*\{")
    else {
        return;
    };
    let Some(mat): Option<regex::Match<'_>> = re.find(source) else {
        return;
    };
    let object_open: usize = mat.end() - 1;
    let Some(entries): Option<Vec<super::scan::ObjectEntry>> =
        find_top_level_object_entries(source, object_open)
    else {
        return;
    };
    for entry in entries {
        let value_text: &str = &source[entry.value_span.0..entry.value_span.1];
        modules.push(ExtractedModule {
            id: entry.key,
            chunk_id: Some("main".to_owned()),
            source: value_text.trim().to_owned(),
        });
    }
}

fn extract_chunk_push(source: &str, modules: &mut Vec<ExtractedModule>) {
    let Ok(re): Result<Regex, regex::Error> = Regex::new(
        r"(?:self|globalThis|window)\.webpackChunk[A-Za-z_0-9$]*\s*=\s*(?:self|globalThis|window)\.webpackChunk[A-Za-z_0-9$]*\s*\|\|\s*\[\]\s*\)?\s*\.\s*push\s*\(\s*\[",
    ) else {
        return;
    };
    let bytes: &[u8] = source.as_bytes();
    for mat in re.find_iter(source) {
        let array_open: usize = mat.end() - 1;
        let Some(array_close): Option<usize> =
            super::scan::find_bracket_close(bytes, array_open + 1)
        else {
            continue;
        };
        let inner: &str = &source[array_open + 1..array_close];
        let chunk_id: String = parse_chunk_id(inner);
        let Some(obj_rel): Option<usize> = inner.find('{') else {
            continue;
        };
        let object_open_abs: usize = array_open + 1 + obj_rel;
        let Some(entries): Option<Vec<super::scan::ObjectEntry>> =
            find_top_level_object_entries(source, object_open_abs)
        else {
            continue;
        };
        for entry in entries {
            let value_text: &str = &source[entry.value_span.0..entry.value_span.1];
            modules.push(ExtractedModule {
                id: entry.key,
                chunk_id: Some(chunk_id.clone()),
                source: value_text.trim().to_owned(),
            });
        }
    }
}

fn parse_chunk_id(inner: &str) -> String {
    let bytes: &[u8] = inner.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n' | b'[') {
        i += 1;
    }
    let Some(end_rel): Option<usize> = inner.get(i..).and_then(|s| s.find(',')) else {
        return "0".to_owned();
    };
    inner.get(i..i + end_rel).map_or_else(
        || "0".to_owned(),
        |s| {
            s.trim()
                .trim_matches(['[', ']', '"', '\''])
                .trim()
                .to_owned()
        },
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_webpack5_via_runtime_helpers() {
        let src: &str = "var __webpack_modules__ = {}; var __webpack_module_cache__ = {}; var __webpack_require__ = function(){}; __webpack_require__.r = function(e){}; __webpack_require__.d = function(){}; (self.webpackChunkapp = self.webpackChunkapp || []).push([[0],{}]);";
        let det: BundlerDetection = detect(src);
        assert!(det.matched, "expected webpack5 detection: {det:?}");
    }

    #[test]
    fn extracts_module_table() {
        let src: &str = "var __webpack_modules__ = { \"./src/a.js\": function(m,e,r){m.exports='a';}, \"./src/b.js\": function(m,e,r){m.exports='b';} };";
        let mods: Vec<ExtractedModule> = extract(src);
        assert_eq!(mods.len(), 2);
        assert!(mods.iter().any(|m| m.id == "./src/a.js"));
        assert!(mods.iter().any(|m| m.id == "./src/b.js"));
    }
}
