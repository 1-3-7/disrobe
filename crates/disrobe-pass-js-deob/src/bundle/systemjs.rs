use regex::Regex;

use super::graph::{ChunkNode, ModuleGraph};
use super::scan::{find_brace_close, find_bracket_close, find_paren_close};
use super::{BundlerDetection, BundlerKind, ExtractedModule};

#[must_use]
pub fn detect(source: &str) -> BundlerDetection {
    let head: &str = crate::scan_utils::head(source, 256 * 1024);
    let mut markers: Vec<String> = Vec::new();
    let mut score: f32 = 0.0;

    let has_system_register: bool = head.contains("System.register(");
    let has_amd_define: bool = Regex::new(r"\bdefine\s*\(\s*\[")
        .is_ok_and(|re: Regex| re.is_match(head))
        || Regex::new(r#"\bdefine\s*\(\s*["']"#).is_ok_and(|re: Regex| re.is_match(head));
    let has_requirejs_require: bool =
        head.contains("requirejs(") || head.contains("require.config");
    let has_systemjs_loader: bool = head.contains("System.import") || head.contains("SystemJS");
    let has_define_amd: bool = head.contains("define.amd");

    if has_system_register {
        markers.push("System.register".to_owned());
        score += 0.45;
    }
    if has_amd_define {
        markers.push("define(deps,fn)".to_owned());
        score += 0.4;
    }
    if has_requirejs_require {
        markers.push("requirejs-runtime".to_owned());
        score += 0.2;
    }
    if has_systemjs_loader {
        markers.push("SystemJS-loader".to_owned());
        score += 0.15;
    }
    if has_define_amd {
        markers.push("define.amd".to_owned());
        score += 0.1;
    }

    if head.contains("__webpack_require__") {
        score -= 0.3;
    }
    if head.contains("__turbopack_") {
        score -= 0.3;
    }

    let matched: bool = score >= 0.4;
    BundlerDetection {
        kind: BundlerKind::SystemJs,
        matched,
        confidence: score.clamp(0.0, 0.94),
        markers,
    }
}

pub(super) fn extract(source: &str) -> Vec<ExtractedModule> {
    let mut modules: Vec<ExtractedModule> = Vec::new();
    extract_system_register(source, &mut modules);
    extract_amd_define(source, &mut modules);
    modules
}

pub(super) fn build_graph(source: &str, modules: &[ExtractedModule]) -> ModuleGraph {
    let mut graph: ModuleGraph = ModuleGraph::new();
    graph.with_entry("systemjs-root");
    let mut entry: ChunkNode = ChunkNode {
        id: "systemjs-root".to_owned(),
        file: Some("systemjs.js".to_owned()),
        imports: Vec::new(),
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
        graph.link_module_to_chunk(&m.id, "systemjs-root");
    }
    if let Some(info) = super::sourcemap::find(source) {
        graph
            .sourcemap_urls
            .insert("systemjs-root".to_owned(), info.url);
    }
    graph
}

fn extract_system_register(source: &str, modules: &mut Vec<ExtractedModule>) {
    let bytes: &[u8] = source.as_bytes();
    let Ok(re): Result<Regex, regex::Error> = Regex::new(r"System\.register\s*\(") else {
        return;
    };
    let mut idx: usize = 0;
    for mat in re.find_iter(source) {
        let paren_open: usize = mat.end() - 1;
        let Some(paren_close): Option<usize> = find_paren_close(bytes, paren_open + 1) else {
            continue;
        };
        let mut i: usize = paren_open + 1;
        while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n') {
            i += 1;
        }
        let (id, after_id): (String, usize) =
            if bytes.get(i) == Some(&b'"') || bytes.get(i) == Some(&b'\'') {
                let q: u8 = bytes[i];
                let Some(end): Option<usize> = super::scan::skip_string(bytes, i, q) else {
                    continue;
                };
                (source[i + 1..end - 1].to_owned(), end)
            } else {
                (format!("module-{idx}"), i)
            };
        idx += 1;
        let mut j: usize = after_id;
        while j < bytes.len() && matches!(bytes[j], b' ' | b'\t' | b'\r' | b'\n' | b',') {
            j += 1;
        }
        if bytes.get(j) != Some(&b'[') {
            continue;
        }
        let array_open: usize = j;
        let Some(array_close): Option<usize> = find_bracket_close(bytes, array_open + 1) else {
            continue;
        };
        let snippet: &str = &source[paren_open + 1..paren_close];
        let _ = array_close;
        modules.push(ExtractedModule {
            id,
            chunk_id: Some("systemjs".to_owned()),
            source: snippet.trim().to_owned(),
        });
    }
}

fn extract_amd_define(source: &str, modules: &mut Vec<ExtractedModule>) {
    let bytes: &[u8] = source.as_bytes();
    let Ok(re): Result<Regex, regex::Error> = Regex::new(r"\bdefine\s*\(") else {
        return;
    };
    let mut idx: usize = 0;
    for mat in re.find_iter(source) {
        if mat.start() > 0 {
            let prev: u8 = bytes[mat.start() - 1];
            if matches!(prev, b'.' | b'_' | b'$') || prev.is_ascii_alphanumeric() {
                continue;
            }
        }
        let paren_open: usize = mat.end() - 1;
        let Some(paren_close): Option<usize> = find_paren_close(bytes, paren_open + 1) else {
            continue;
        };
        let inner: &str = &source[paren_open + 1..paren_close];
        let mut i: usize = paren_open + 1;
        while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n') {
            i += 1;
        }
        let (id, _after_id): (String, usize) =
            if bytes.get(i) == Some(&b'"') || bytes.get(i) == Some(&b'\'') {
                let q: u8 = bytes[i];
                let Some(end): Option<usize> = super::scan::skip_string(bytes, i, q) else {
                    continue;
                };
                (source[i + 1..end - 1].to_owned(), end)
            } else {
                (format!("define-{idx}"), i)
            };
        idx += 1;
        if !inner.contains("function") {
            continue;
        }
        let func_start_rel: Option<usize> = inner.find("function");
        let Some(func_start_rel): Option<usize> = func_start_rel else {
            continue;
        };
        let func_start_abs: usize = paren_open + 1 + func_start_rel;
        let func_paren_open_rel: Option<usize> = source[func_start_abs..].find('(');
        let Some(func_paren_open_rel): Option<usize> = func_paren_open_rel else {
            continue;
        };
        let func_paren_open: usize = func_start_abs + func_paren_open_rel;
        let Some(func_paren_close): Option<usize> = find_paren_close(bytes, func_paren_open + 1)
        else {
            continue;
        };
        let mut body_open: usize = func_paren_close + 1;
        while body_open < bytes.len() && matches!(bytes[body_open], b' ' | b'\t' | b'\r' | b'\n') {
            body_open += 1;
        }
        if bytes.get(body_open) != Some(&b'{') {
            continue;
        }
        let Some(body_close): Option<usize> = find_brace_close(bytes, body_open + 1) else {
            continue;
        };
        let body_text: &str = &source[body_open + 1..body_close];
        modules.push(ExtractedModule {
            id,
            chunk_id: Some("amd".to_owned()),
            source: body_text.trim().to_owned(),
        });
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_systemjs_via_register() {
        let src: &str = "System.register([\"./dep\"], function (exports) { return { setters: [], execute: function () {} }; });";
        let det: BundlerDetection = detect(src);
        assert!(det.matched, "{det:?}");
    }

    #[test]
    fn detects_amd_define() {
        let src: &str = "define([\"jquery\"], function ($) { return { name: 'lib' }; });";
        let det: BundlerDetection = detect(src);
        assert!(det.matched, "{det:?}");
    }

    #[test]
    fn extracts_system_register_with_name() {
        let src: &str = "System.register(\"app/main\", [\"./util\"], function (e) { return { execute: function(){} }; });";
        let mods: Vec<ExtractedModule> = extract(src);
        assert!(mods.iter().any(|m: &ExtractedModule| m.id == "app/main"));
    }

    #[test]
    fn extracts_named_amd_define() {
        let src: &str = "define(\"my/module\", [\"dep\"], function (d) { return d.x; });";
        let mods: Vec<ExtractedModule> = extract(src);
        assert!(mods.iter().any(|m: &ExtractedModule| m.id == "my/module"));
    }
}
