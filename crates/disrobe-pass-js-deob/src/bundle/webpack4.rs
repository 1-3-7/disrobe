use regex::Regex;

use super::graph::{ChunkNode, ModuleGraph};
use super::scan::{find_bracket_close, find_paren_close, find_top_level_object_entries};
use super::{BundlerDetection, BundlerKind, ExtractedModule};

#[must_use]
pub fn detect(source: &str) -> BundlerDetection {
    let head: &str = crate::scan_utils::head(source, 256 * 1024);
    let mut markers: Vec<String> = Vec::new();
    let mut score: f32 = 0.0;

    let has_require_n: bool = head.contains("__webpack_require__");
    let has_iife_array_module: bool = looks_like_webpack4_iife(head);
    let has_chunk_push: bool =
        head.contains("webpackJsonp") || head.contains("window.webpackJsonp");
    let has_module_exports: bool = head.contains("module.exports");

    if has_require_n {
        markers.push("__webpack_require__".to_owned());
        score += 0.4;
    }
    if has_iife_array_module {
        markers.push("webpack4-iife-array-module-table".to_owned());
        score += 0.35;
    }
    if has_chunk_push {
        markers.push("webpackJsonp-push".to_owned());
        score += 0.25;
    }
    if has_module_exports {
        markers.push("module.exports".to_owned());
        score += 0.05;
    }
    let webpack5_only: bool =
        head.contains("__webpack_require__.r") || head.contains("__webpack_require__.d");
    if webpack5_only {
        score -= 0.4;
    }

    let matched: bool = score >= 0.5;
    BundlerDetection {
        kind: BundlerKind::Webpack4,
        matched,
        confidence: score.clamp(0.0, 0.97),
        markers,
    }
}

pub(super) fn extract(source: &str) -> Vec<ExtractedModule> {
    let mut modules: Vec<ExtractedModule> = Vec::new();
    extract_iife_array(source, &mut modules);
    extract_jsonp_chunks(source, &mut modules);
    modules
}

pub(super) fn build_graph(source: &str, modules: &[ExtractedModule]) -> ModuleGraph {
    let mut graph: ModuleGraph = ModuleGraph::new();
    graph.with_entry("main");
    let chunk_module_map: std::collections::BTreeMap<String, Vec<String>> =
        group_modules_by_chunk(modules);
    let parent_to_children: std::collections::BTreeMap<String, Vec<String>> =
        collect_require_e_chunks(source);

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
    for child_id in parent_to_children.values().flatten() {
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

fn collect_require_e_chunks(source: &str) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut out: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r"__webpack_require__\.e\s*\(\s*([0-9]+|\x22[^\x22]+\x22|'[^']+')\s*\)")
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

fn looks_like_webpack4_iife(text: &str) -> bool {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r"\(function\s*\(\s*modules\s*\)\s*\{[\s\S]{0,2000}__webpack_require__")
    else {
        return false;
    };
    re.is_match(text)
}

fn extract_iife_array(source: &str, modules: &mut Vec<ExtractedModule>) {
    let bytes: &[u8] = source.as_bytes();
    let Ok(re): Result<Regex, regex::Error> = Regex::new(r"\}\s*\)\s*\(\s*\[") else {
        return;
    };
    for mat in re.find_iter(source) {
        let array_open: usize = mat.end() - 1;
        let Some(array_close): Option<usize> = find_bracket_close(bytes, array_open + 1) else {
            continue;
        };
        let array_body: &str = &source[array_open + 1..array_close];
        if !array_body.contains("function") {
            continue;
        }
        let entries: Vec<(usize, usize)> = split_array_function_entries(source, array_open + 1);
        for (idx, (start, end)) in entries.iter().enumerate() {
            let body_text: &str = &source[*start..*end];
            modules.push(ExtractedModule {
                id: format!("{idx}"),
                chunk_id: Some("main".to_owned()),
                source: body_text.trim().to_owned(),
            });
        }
        if !modules.is_empty() {
            return;
        }
    }
}

fn split_array_function_entries(source: &str, array_open: usize) -> Vec<(usize, usize)> {
    let bytes: &[u8] = source.as_bytes();
    let mut entries: Vec<(usize, usize)> = Vec::new();
    let mut i: usize = array_open;
    let mut bracket: i32 = 0;
    let mut paren: i32 = 0;
    let mut brace: i32 = 0;
    let mut start: Option<usize> = None;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'[' => bracket += 1,
            b']' => {
                if bracket == 0 {
                    if let Some(s) = start {
                        entries.push((s, i));
                    }
                    return entries;
                }
                bracket -= 1;
            }
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'{' => brace += 1,
            b'}' => brace -= 1,
            b',' if bracket == 0 && paren == 0 && brace == 0 => {
                if let Some(s) = start {
                    entries.push((s, i));
                    start = None;
                }
            }
            b' ' | b'\t' | b'\r' | b'\n' => {}
            b'\'' | b'"' | b'`' => {
                if start.is_none() {
                    start = Some(i);
                }
                let q: u8 = b;
                let mut j: usize = i + 1;
                while j < bytes.len() {
                    if bytes[j] == b'\\' {
                        j += 2;
                        continue;
                    }
                    if bytes[j] == q {
                        break;
                    }
                    j += 1;
                }
                i = j;
            }
            _ => {
                if start.is_none() {
                    start = Some(i);
                }
            }
        }
        i += 1;
    }
    entries
}

fn extract_jsonp_chunks(source: &str, modules: &mut Vec<ExtractedModule>) {
    let Ok(re): Result<Regex, regex::Error> = Regex::new(
        r"webpackJsonp(?:\s*=\s*window\.webpackJsonp\s*\|\|\s*\[\])?\s*\.\s*push\s*\(\s*\[",
    ) else {
        return;
    };
    let bytes: &[u8] = source.as_bytes();
    for mat in re.find_iter(source) {
        let array_open: usize = mat.end() - 1;
        let Some(array_close): Option<usize> = find_bracket_close(bytes, array_open + 1) else {
            continue;
        };
        let inner: &str = &source[array_open + 1..array_close];
        let chunk_id: String = parse_chunk_id(inner);
        let Some(module_obj_rel): Option<usize> = inner.find('{') else {
            continue;
        };
        let object_open_abs: usize = array_open + 1 + module_obj_rel;
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
        let mut peek: usize = array_close + 1;
        while peek < bytes.len() && matches!(bytes[peek], b' ' | b'\t' | b'\r' | b'\n') {
            peek += 1;
        }
        if peek < bytes.len() && bytes[peek] == b')' {
            let Some(_): Option<usize> = find_paren_close(bytes, mat.end()) else {
                continue;
            };
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
        |s| s.trim().trim_matches(['[', ']']).trim().to_owned(),
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_webpack4_iife_signature() {
        let src: &str = "(function (modules) { /* runtime */ var __webpack_require__ = function (mod) { return modules[mod]; }; return __webpack_require__(0); })([function(m,e,r){module.exports='a';},function(m,e,r){module.exports='b';}]);";
        let det: BundlerDetection = detect(src);
        assert!(det.matched, "expected webpack4 detection: {det:?}");
    }

    #[test]
    fn extracts_iife_array_modules() {
        let src: &str = "(function (modules) { var __webpack_require__ = function (i) { return modules[i]; }; return __webpack_require__(0); })([function(module, exports, __webpack_require__) { module.exports = 'first'; },function(module, exports, __webpack_require__) { module.exports = 'second'; }]);";
        let mods: Vec<ExtractedModule> = extract(src);
        assert_eq!(mods.len(), 2);
        assert!(mods[0].source.contains("first"));
        assert!(mods[1].source.contains("second"));
    }

    #[test]
    fn does_not_match_webpack5() {
        let src: &str = "var __webpack_require__ = function(){}; __webpack_require__.r = function(){}; __webpack_require__.d = function(){};";
        let det: BundlerDetection = detect(src);
        assert!(!det.matched, "webpack5 should not trigger webpack4 detect");
    }
}
