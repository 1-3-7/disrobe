use regex::Regex;

use super::graph::{ChunkNode, ModuleGraph};
use super::scan::find_top_level_object_entries;
use super::{BundlerDetection, BundlerKind, ExtractedModule};

#[must_use]
pub fn detect(source: &str) -> BundlerDetection {
    let head: &str = crate::scan_utils::head(source, 256 * 1024);
    let mut markers: Vec<String> = Vec::new();
    let mut score: f32 = 0.0;

    let has_rolldown_runtime: bool =
        head.contains("__rolldown_runtime__") || head.contains("__ROLLDOWN__");
    let has_rolldown_banner: bool = head.contains("/* rolldown ") || head.contains("// rolldown");
    let has_rolldown_modules: bool =
        head.contains("__rolldown_modules__") || head.contains("__rolldownRegister");
    let has_es_module_flag: bool = head.contains("Object.defineProperty(exports, \"__esModule\"")
        || head.contains("Object.defineProperty(exports, '__esModule'");
    let has_oxc_marker: bool = head.contains("oxc-") && head.contains("rolldown");

    if has_rolldown_runtime {
        markers.push("__rolldown_runtime__".to_owned());
        score += 0.4;
    }
    if has_rolldown_banner {
        markers.push("rolldown-banner".to_owned());
        score += 0.3;
    }
    if has_rolldown_modules {
        markers.push("__rolldown_modules__".to_owned());
        score += 0.35;
    }
    if has_es_module_flag {
        markers.push("__esModule-defineProperty".to_owned());
        score += 0.1;
    }
    if has_oxc_marker {
        markers.push("oxc-rolldown".to_owned());
        score += 0.15;
    }

    if head.contains("__webpack_require__") {
        score -= 0.3;
    }
    if head.contains("__turbopack_") {
        score -= 0.3;
    }

    let matched: bool = score >= 0.4;
    BundlerDetection {
        kind: BundlerKind::Rolldown,
        matched,
        confidence: score.clamp(0.0, 0.94),
        markers,
    }
}

pub(super) fn extract(source: &str) -> Vec<ExtractedModule> {
    let mut modules: Vec<ExtractedModule> = Vec::new();
    extract_module_table(source, &mut modules);
    if modules.is_empty() {
        extract_named_export_functions(source, &mut modules);
    }
    modules
}

pub(super) fn build_graph(source: &str, modules: &[ExtractedModule]) -> ModuleGraph {
    let mut graph: ModuleGraph = ModuleGraph::new();
    graph.with_entry("rolldown-root");
    let dynamic_chunks: Vec<String> = collect_dynamic_imports(source);
    let mut root: ChunkNode = ChunkNode {
        id: "rolldown-root".to_owned(),
        file: Some("rolldown.js".to_owned()),
        imports: Vec::new(),
        dynamic_imports: dynamic_chunks.clone(),
        modules: modules
            .iter()
            .map(|m: &ExtractedModule| m.id.clone())
            .collect(),
    };
    root.modules.sort();
    root.modules.dedup();
    graph.upsert_chunk(root);
    for m in modules {
        graph.link_module_to_chunk(&m.id, "rolldown-root");
    }
    for dyn_id in dynamic_chunks {
        let child_id: String = format!("chunk-{}", super::sanitize_id(&dyn_id));
        graph.upsert_chunk(ChunkNode {
            id: child_id.clone(),
            file: Some(dyn_id.clone()),
            imports: vec!["rolldown-root".to_owned()],
            dynamic_imports: Vec::new(),
            modules: Vec::new(),
        });
        graph.link_module_to_chunk(&dyn_id, &child_id);
    }
    if let Some(info) = super::sourcemap::find(source) {
        graph
            .sourcemap_urls
            .insert("rolldown-root".to_owned(), info.url);
    }
    graph
}

fn collect_dynamic_imports(source: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let Ok(re): Result<Regex, regex::Error> = Regex::new(r#"import\s*\(\s*["']([^"']+)["']\s*\)"#)
    else {
        return out;
    };
    for cap in re.captures_iter(source) {
        let Some(path): Option<&str> = cap.get(1).map(|m: regex::Match<'_>| m.as_str()) else {
            continue;
        };
        if seen.insert(path.to_owned()) {
            out.push(path.to_owned());
        }
    }
    out
}

fn extract_module_table(source: &str, modules: &mut Vec<ExtractedModule>) {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r"(?:__rolldown_modules__|__rolldownRegister)\s*(?:=|\()\s*\{")
    else {
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
                chunk_id: Some("rolldown".to_owned()),
                source: value_text.trim().to_owned(),
            });
        }
        if !modules.is_empty() {
            return;
        }
    }
}

fn extract_named_export_functions(source: &str, modules: &mut Vec<ExtractedModule>) {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r"export\s+(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(")
    else {
        return;
    };
    let bytes: &[u8] = source.as_bytes();
    for caps in re.captures_iter(source) {
        let Some(name): Option<&str> = caps.get(1).map(|m: regex::Match<'_>| m.as_str()) else {
            continue;
        };
        let Some(full): Option<regex::Match<'_>> = caps.get(0) else {
            continue;
        };
        let paren_open: usize = full.end() - 1;
        let Some(paren_close): Option<usize> = super::scan::find_paren_close(bytes, paren_open + 1)
        else {
            continue;
        };
        let mut body_open: usize = paren_close + 1;
        while body_open < bytes.len() && matches!(bytes[body_open], b' ' | b'\t' | b'\r' | b'\n') {
            body_open += 1;
        }
        if bytes.get(body_open) != Some(&b'{') {
            continue;
        }
        let Some(body_close): Option<usize> = super::scan::find_brace_close(bytes, body_open + 1)
        else {
            continue;
        };
        modules.push(ExtractedModule {
            id: name.to_owned(),
            chunk_id: None,
            source: source[full.start()..=body_close].trim().to_owned(),
        });
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_rolldown_via_runtime_marker() {
        let src: &str =
            "/* rolldown 1.0 */\nvar __rolldown_runtime__ = {}; var __rolldown_modules__ = {};";
        let det: BundlerDetection = detect(src);
        assert!(det.matched, "{det:?}");
    }

    #[test]
    fn extracts_module_table() {
        let src: &str = "__rolldown_modules__ = { \"./a.ts\": function(m){m.exports='a';}, \"./b.ts\": function(m){m.exports='b';} };";
        let mods: Vec<ExtractedModule> = extract(src);
        assert_eq!(mods.len(), 2);
        assert!(mods.iter().any(|m: &ExtractedModule| m.id == "./a.ts"));
    }
}
