use regex::Regex;

use super::graph::{ChunkNode, ModuleGraph};
use super::{BundlerDetection, BundlerKind, ExtractedModule};

#[must_use]
pub fn detect(source: &str) -> BundlerDetection {
    let head: &str = crate::scan_utils::head(source, 256 * 1024);
    let mut markers: Vec<String> = Vec::new();
    let mut score: f32 = 0.0;

    let has_vite_preload: bool = head.contains("__vitePreload") || head.contains("vitePreload");
    let has_import_meta_glob: bool = head.contains("import.meta.glob");
    let has_import_meta_env: bool = head.contains("import.meta.env");
    let has_vite_legacy: bool =
        head.contains("__VITE_PRELOAD__") || head.contains("__vite_legacy_");
    let has_define_block: bool = head.contains("__DEFINES__") || head.contains("__vite_define__");

    if has_vite_preload {
        markers.push("__vitePreload".to_owned());
        score += 0.4;
    }
    if has_import_meta_glob {
        markers.push("import.meta.glob".to_owned());
        score += 0.45;
    }
    if has_import_meta_env {
        markers.push("import.meta.env".to_owned());
        score += 0.2;
    }
    if has_vite_legacy {
        markers.push("vite-legacy-marker".to_owned());
        score += 0.2;
    }
    if has_define_block {
        markers.push("vite-defines".to_owned());
        score += 0.1;
    }

    let matched: bool = score >= 0.4;
    BundlerDetection {
        kind: BundlerKind::Vite,
        matched,
        confidence: score.clamp(0.0, 0.95),
        markers,
    }
}

pub(super) fn extract(source: &str) -> Vec<ExtractedModule> {
    let mut modules: Vec<ExtractedModule> = Vec::new();
    extract_named_export_functions(source, &mut modules);
    extract_import_statements(source, &mut modules);
    modules
}

pub(super) fn build_graph(source: &str, modules: &[ExtractedModule]) -> ModuleGraph {
    let mut graph: ModuleGraph = ModuleGraph::new();
    graph.with_entry("vite-entry");
    let entry_chunk: ChunkNode = ChunkNode {
        id: "vite-entry".to_owned(),
        file: Some("entry.mjs".to_owned()),
        imports: Vec::new(),
        dynamic_imports: collect_dynamic_chunks(source),
        modules: modules
            .iter()
            .filter(|m: &&ExtractedModule| !m.id.starts_with("import:"))
            .map(|m: &ExtractedModule| m.id.clone())
            .collect(),
    };
    let dynamic_ids: Vec<String> = entry_chunk.dynamic_imports.clone();
    let static_imports: Vec<String> = modules
        .iter()
        .filter_map(|m: &ExtractedModule| m.id.strip_prefix("import:").map(str::to_owned))
        .collect();
    let mut entry_with_imports: ChunkNode = entry_chunk;
    entry_with_imports.imports = static_imports;
    graph.upsert_chunk(entry_with_imports);
    for module_id in modules
        .iter()
        .filter(|m: &&ExtractedModule| !m.id.starts_with("import:"))
        .map(|m: &ExtractedModule| m.id.as_str())
    {
        graph.link_module_to_chunk(module_id, "vite-entry");
    }
    for dyn_id in &dynamic_ids {
        let child_id: String = format!("chunk-{}", super::sanitize_id(dyn_id));
        graph.upsert_chunk(ChunkNode {
            id: child_id.clone(),
            file: Some(dyn_id.clone()),
            imports: vec!["vite-entry".to_owned()],
            dynamic_imports: Vec::new(),
            modules: Vec::new(),
        });
        graph.link_module_to_chunk(dyn_id, &child_id);
    }
    if let Some(info) = super::sourcemap::find(source) {
        graph
            .sourcemap_urls
            .insert("vite-entry".to_owned(), info.url);
    }
    graph
}

fn collect_dynamic_chunks(source: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let Ok(import_re): Result<Regex, regex::Error> =
        Regex::new(r#"import\s*\(\s*["']([^"']+)["']\s*\)"#)
    else {
        return out;
    };
    for cap in import_re.captures_iter(source) {
        let Some(path): Option<&str> = cap.get(1).map(|m: regex::Match<'_>| m.as_str()) else {
            continue;
        };
        if seen.insert(path.to_owned()) {
            out.push(path.to_owned());
        }
    }
    let Ok(preload_re): Result<Regex, regex::Error> =
        Regex::new(r#"__vitePreload\s*\([^)]*?["']([^"']+)["']"#)
    else {
        return out;
    };
    for cap in preload_re.captures_iter(source) {
        let Some(path): Option<&str> = cap.get(1).map(|m: regex::Match<'_>| m.as_str()) else {
            continue;
        };
        if seen.insert(path.to_owned()) {
            out.push(path.to_owned());
        }
    }
    let Ok(glob_re): Result<Regex, regex::Error> =
        Regex::new(r#"import\.meta\.glob\s*\(\s*["']([^"']+)["']"#)
    else {
        return out;
    };
    for cap in glob_re.captures_iter(source) {
        let Some(pattern): Option<&str> = cap.get(1).map(|m: regex::Match<'_>| m.as_str()) else {
            continue;
        };
        let synthesized: String = format!("glob:{pattern}");
        if seen.insert(synthesized.clone()) {
            out.push(synthesized);
        }
    }
    out
}

fn extract_named_export_functions(source: &str, modules: &mut Vec<ExtractedModule>) {
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
        let snippet: &str = &source[full.start()..=body_close];
        modules.push(ExtractedModule {
            id: name.to_owned(),
            chunk_id: None,
            source: snippet.trim().to_owned(),
        });
    }
}

fn extract_import_statements(source: &str, modules: &mut Vec<ExtractedModule>) {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r#"import\s+(?:[^;]+)\s+from\s+["']([^"']+)["']\s*;?"#)
    else {
        return;
    };
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for caps in re.captures_iter(source) {
        let Some(path): Option<&str> = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        if !seen.insert(path.to_owned()) {
            continue;
        }
        let Some(full): Option<regex::Match<'_>> = caps.get(0) else {
            continue;
        };
        modules.push(ExtractedModule {
            id: format!("import:{path}"),
            chunk_id: None,
            source: full.as_str().to_owned(),
        });
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_vite_via_preload_helper() {
        let src: &str = "const __vitePreload = (b,c) => b(); export const main = () => __vitePreload(()=>import('./chunk.js'));";
        let det: BundlerDetection = detect(src);
        assert!(det.matched);
    }

    #[test]
    fn detects_vite_via_import_meta_glob() {
        let src: &str = "const mods = import.meta.glob('./*.ts'); export default mods;";
        let det: BundlerDetection = detect(src);
        assert!(det.matched);
    }

    #[test]
    fn extracts_named_export_functions() {
        let src: &str =
            "export function foo() { return 1; }\nexport async function bar() { return 2; }";
        let mods: Vec<ExtractedModule> = extract(src);
        assert!(mods.iter().any(|m| m.id == "foo"));
        assert!(mods.iter().any(|m| m.id == "bar"));
    }
}
