use regex::Regex;

use super::graph::{ChunkNode, ModuleGraph};
use super::scan::find_top_level_object_entries;
use super::{BundlerDetection, BundlerKind, ExtractedModule};

pub fn detect(source: &str) -> BundlerDetection {
    let head: &str = &source[..source.len().min(256 * 1024)];
    let mut markers: Vec<String> = Vec::new();
    let mut score: f32 = 0.0;

    let has_bun_runtime: bool = head.contains("__bun_register") || head.contains("@bun/runtime");
    let has_bun_build_marker: bool = head.contains("// bun build") || head.contains("Bun.build");
    let has_bun_require_helper: bool =
        head.contains("var __require = ") && head.contains("Bun.resolveSync");
    let has_bun_jsx_runtime: bool = head.contains("from \"react/jsx-runtime\"")
        && head.contains("// @bun")
        && head.contains("// node_modules");
    let has_at_bun_pragma: bool = head.starts_with("// @bun") || head.contains("\n// @bun");
    let has_bun_module_object: bool =
        head.contains("Bun.embeddedFiles") || head.contains("$bun_runtime");

    if has_bun_runtime {
        markers.push("__bun_register".to_owned());
        score += 0.4;
    }
    if has_bun_build_marker {
        markers.push("bun-build-banner".to_owned());
        score += 0.3;
    }
    if has_bun_require_helper {
        markers.push("Bun.resolveSync".to_owned());
        score += 0.25;
    }
    if has_bun_jsx_runtime {
        markers.push("bun-jsx-runtime".to_owned());
        score += 0.2;
    }
    if has_at_bun_pragma {
        markers.push("at-bun-pragma".to_owned());
        score += 0.25;
    }
    if has_bun_module_object {
        markers.push("bun-embedded-files".to_owned());
        score += 0.15;
    }

    let matched: bool = score >= 0.45;
    BundlerDetection {
        kind: BundlerKind::Bun,
        matched,
        confidence: score.clamp(0.0, 0.94),
        markers,
    }
}

pub(super) fn extract(source: &str) -> Vec<ExtractedModule> {
    let mut modules: Vec<ExtractedModule> = Vec::new();
    extract_bun_register_table(source, &mut modules);
    extract_export_functions(source, &mut modules);
    modules
}

pub(super) fn build_graph(source: &str, modules: &[ExtractedModule]) -> ModuleGraph {
    let mut graph: ModuleGraph = ModuleGraph::new();
    graph.with_entry("bun-bundle");
    let resolved: Vec<String> = collect_resolve_sync_calls(source);
    let mut entry: ChunkNode = ChunkNode {
        id: "bun-bundle".to_owned(),
        file: Some("bundle.js".to_owned()),
        imports: resolved,
        dynamic_imports: Vec::new(),
        modules: modules
            .iter()
            .map(|m: &ExtractedModule| m.id.clone())
            .collect(),
    };
    entry.modules.sort();
    entry.modules.dedup();
    graph.upsert_chunk(entry);
    for m in modules {
        graph.link_module_to_chunk(&m.id, "bun-bundle");
    }
    if let Some(info) = super::sourcemap::find(source) {
        graph
            .sourcemap_urls
            .insert("bun-bundle".to_owned(), info.url);
    }
    graph
}

fn collect_resolve_sync_calls(source: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r#"(?:Bun\.resolveSync|__require)\s*\(\s*["']([^"']+)["']"#)
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

fn extract_bun_register_table(source: &str, modules: &mut Vec<ExtractedModule>) {
    let Ok(re): Result<Regex, regex::Error> = Regex::new(r"__bun_register\s*\(\s*\{") else {
        return;
    };
    let bytes: &[u8] = source.as_bytes();
    for mat in re.find_iter(source) {
        let object_open: usize = mat.end() - 1;
        let Some(entries): Option<Vec<super::scan::ObjectEntry>> =
            find_top_level_object_entries(source, object_open)
        else {
            continue;
        };
        for entry in entries {
            let value_text: &str = &source[entry.value_span.0..entry.value_span.1];
            modules.push(ExtractedModule {
                id: entry.key,
                chunk_id: Some("bun".to_owned()),
                source: value_text.trim().to_owned(),
            });
        }
        if !modules.is_empty() {
            return;
        }
    }
    let _ = bytes;
}

fn extract_export_functions(source: &str, modules: &mut Vec<ExtractedModule>) {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r"export\s+(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(")
    else {
        return;
    };
    let bytes: &[u8] = source.as_bytes();
    for caps in re.captures_iter(source) {
        let Some(name): Option<&str> = caps.get(1).map(|m| m.as_str()) else {
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
    fn detects_bun_via_at_bun_pragma_and_helper() {
        let src: &str = "// @bun\nvar __require = function(p){ return Bun.resolveSync(p); };";
        let det: BundlerDetection = detect(src);
        assert!(det.matched);
    }

    #[test]
    fn extracts_bun_register_table() {
        let src: &str = "__bun_register({ \"./a.ts\": function(m){m.exports='a';}, \"./b.ts\": function(m){m.exports='b';} });";
        let mods: Vec<ExtractedModule> = extract(src);
        assert_eq!(mods.len(), 2);
        assert!(mods.iter().any(|m| m.id == "./a.ts"));
    }
}
