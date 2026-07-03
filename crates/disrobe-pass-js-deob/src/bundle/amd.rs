use regex::Regex;

use super::graph::{ChunkNode, ModuleGraph};
use super::scan::{find_bracket_close, find_paren_close, skip_string};
use super::{BundlerDetection, BundlerKind, ExtractedModule};

const AMD_RESERVED_DEPS: &[&str] = &["require", "exports", "module"];

#[must_use]
pub fn detect(source: &str) -> BundlerDetection {
    let head: &str = crate::scan_utils::head(source, 256 * 1024);
    let mut markers: Vec<String> = Vec::new();
    let mut score: f32 = 0.0;

    let define_calls: usize = count_define_calls(head);
    let has_define_amd: bool = head.contains("define.amd") || head.contains("define[\"amd\"]");
    let has_require_config: bool =
        head.contains("require.config") || head.contains("requirejs.config");

    if define_calls > 0 {
        markers.push(format!("define-call x{define_calls}"));
        score += 0.45 + (f32::from(u8::try_from(define_calls.min(4)).unwrap_or(4)) * 0.05);
    }
    if has_define_amd {
        markers.push("define.amd".to_owned());
        score += 0.2;
    }
    if has_require_config {
        markers.push("require.config".to_owned());
        score += 0.1;
    }

    if head.contains("__webpack_require__") {
        score -= 0.4;
    }

    let matched: bool = define_calls > 0 && score >= 0.45;
    BundlerDetection {
        kind: BundlerKind::Amd,
        matched,
        confidence: score.clamp(0.0, 0.95),
        markers,
    }
}

pub(super) fn extract(source: &str) -> Vec<ExtractedModule> {
    let calls: Vec<DefineCall> = parse_define_calls(source);
    let mut modules: Vec<ExtractedModule> = Vec::with_capacity(calls.len());
    for (idx, call) in calls.into_iter().enumerate() {
        let id: String = call.name.clone().unwrap_or_else(|| format!("module-{idx}"));
        let chunk_id: String = if call.deps.is_empty() {
            "deps:".to_owned()
        } else {
            format!("deps:{}", call.deps.join(","))
        };
        modules.push(ExtractedModule {
            id,
            chunk_id: Some(chunk_id),
            source: call.factory,
        });
    }
    modules
}

pub(super) fn build_graph(source: &str, modules: &[ExtractedModule]) -> ModuleGraph {
    let mut graph: ModuleGraph = ModuleGraph::new();
    graph.with_entry("amd");
    for m in modules {
        let deps: Vec<String> = parse_deps_chunk(m.chunk_id.as_deref());
        let resolved: Vec<String> = deps
            .into_iter()
            .filter(|d: &String| !AMD_RESERVED_DEPS.contains(&d.as_str()))
            .collect();
        let node: ChunkNode = ChunkNode {
            id: m.id.clone(),
            file: Some(format!("{}.js", super::sanitize_id(&m.id))),
            imports: resolved,
            dynamic_imports: Vec::new(),
            modules: vec![m.id.clone()],
        };
        graph.upsert_chunk(node);
        graph.link_module_to_chunk(&m.id, &m.id);
    }
    if let Some(info) = super::sourcemap::find(source)
        && let Some(first) = modules.first()
    {
        graph.sourcemap_urls.insert(first.id.clone(), info.url);
    }
    graph
}

fn parse_deps_chunk(chunk_id: Option<&str>) -> Vec<String> {
    let Some(raw): Option<&str> = chunk_id else {
        return Vec::new();
    };
    let Some(list): Option<&str> = raw.strip_prefix("deps:") else {
        return Vec::new();
    };
    if list.is_empty() {
        return Vec::new();
    }
    list.split(',')
        .map(|s: &str| s.trim().to_owned())
        .filter(|s: &String| !s.is_empty())
        .collect()
}

#[derive(Debug)]
struct DefineCall {
    name: Option<String>,
    deps: Vec<String>,
    factory: String,
}

fn count_define_calls(source: &str) -> usize {
    let Ok(re): Result<Regex, regex::Error> = Regex::new(r"(?:^|[^.\w$])define\s*\(") else {
        return 0;
    };
    re.find_iter(source).count()
}

fn parse_define_calls(source: &str) -> Vec<DefineCall> {
    let bytes: &[u8] = source.as_bytes();
    let Ok(re): Result<Regex, regex::Error> = Regex::new(r"(?:^|[^.\w$])define\s*\(") else {
        return Vec::new();
    };
    let mut out: Vec<DefineCall> = Vec::new();
    for mat in re.find_iter(source) {
        let paren_open: usize = mat.end() - 1;
        let Some(paren_close): Option<usize> = find_paren_close(bytes, paren_open + 1) else {
            continue;
        };
        if let Some(call) = parse_define_args(source, paren_open + 1, paren_close) {
            out.push(call);
        }
    }
    out
}

fn parse_define_args(source: &str, start: usize, end: usize) -> Option<DefineCall> {
    let bytes: &[u8] = source.as_bytes();
    let mut i: usize = skip_ws(bytes, start);
    let mut name: Option<String> = None;
    if matches!(bytes.get(i), Some(&(b'"' | b'\''))) {
        let quote: u8 = bytes[i];
        let str_end: usize = skip_string(bytes, i, quote)?;
        name = Some(source.get(i + 1..str_end - 1)?.to_owned());
        i = skip_ws(bytes, str_end);
        if bytes.get(i) != Some(&b',') {
            return None;
        }
        i = skip_ws(bytes, i + 1);
    }

    let mut deps: Vec<String> = Vec::new();
    if bytes.get(i) == Some(&b'[') {
        let arr_close: usize = find_bracket_close(bytes, i + 1)?;
        deps = parse_dep_array(source, i + 1, arr_close);
        i = skip_ws(bytes, arr_close + 1);
        if bytes.get(i) != Some(&b',') {
            return None;
        }
        i = skip_ws(bytes, i + 1);
    }

    let factory_start: usize = i;
    if deps.is_empty()
        && let Some(injected) = extract_cjs_factory(source, factory_start, end)
    {
        deps = injected;
    }
    let factory_text: &str = source.get(factory_start..end)?.trim();
    Some(DefineCall {
        name,
        deps,
        factory: factory_text.to_owned(),
    })
}

fn extract_cjs_factory(source: &str, factory_start: usize, end: usize) -> Option<Vec<String>> {
    let bytes: &[u8] = source.as_bytes();
    let rest: &str = source.get(factory_start..end)?;
    let header_re: Regex =
        Regex::new(r"^function\s*[A-Za-z_$][A-Za-z0-9_$]*\s*\(|^function\s*\(").ok()?;
    if !header_re.is_match(rest) {
        return None;
    }
    let paren_open: usize = factory_start + rest.find('(')?;
    let paren_close: usize = find_paren_close(bytes, paren_open + 1)?;
    let params_raw: &str = source.get(paren_open + 1..paren_close)?;
    let params: Vec<String> = params_raw
        .split(',')
        .map(|s: &str| s.trim().to_owned())
        .filter(|s: &String| !s.is_empty())
        .collect();
    let is_cjs: bool = matches!(params.first().map(String::as_str), Some("require" | "r"));
    if is_cjs { Some(params) } else { None }
}

fn parse_dep_array(source: &str, start: usize, end: usize) -> Vec<String> {
    let bytes: &[u8] = source.as_bytes();
    let mut deps: Vec<String> = Vec::new();
    let mut i: usize = start;
    while i < end {
        i = skip_ws_and_commas(bytes, i, end);
        if i >= end {
            break;
        }
        if matches!(bytes.get(i), Some(&(b'"' | b'\''))) {
            let quote: u8 = bytes[i];
            let Some(str_end): Option<usize> = skip_string(bytes, i, quote) else {
                break;
            };
            if let Some(dep) = source.get(i + 1..str_end - 1) {
                deps.push(dep.to_owned());
            }
            i = str_end;
        } else {
            break;
        }
    }
    deps
}

fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    i
}

fn skip_ws_and_commas(bytes: &[u8], start: usize, hard_end: usize) -> usize {
    let mut i: usize = start;
    while i < hard_end && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n' | b',') {
        i += 1;
    }
    i
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_anonymous_define() {
        let src: &str = "define([\"dep1\", \"dep2\"], function(a, b) { return a + b; });";
        let det: BundlerDetection = detect(src);
        assert!(det.matched, "{det:?}");
    }

    #[test]
    fn does_not_match_non_amd() {
        let src: &str = "function predefine() { return 1; } var x = redefine(2);";
        let det: BundlerDetection = detect(src);
        assert!(!det.matched, "{det:?}");
    }

    #[test]
    fn does_not_match_webpack() {
        let src: &str = "var __webpack_require__ = 1; define([\"x\"], function(x){ return x; });";
        let det: BundlerDetection = detect(src);
        assert!(!det.matched, "webpack should suppress amd: {det:?}");
    }

    #[test]
    fn splits_dependency_array_form() {
        let src: &str = "define([\"dep1\", \"dep2\"], function(a, b) { return a + b; });";
        let mods: Vec<ExtractedModule> = extract(src);
        assert_eq!(mods.len(), 1);
        assert_eq!(mods[0].chunk_id.as_deref(), Some("deps:dep1,dep2"));
        assert!(mods[0].source.starts_with("function"));
    }

    #[test]
    fn splits_named_define() {
        let src: &str = "define(\"my/mod\", [\"a\", \"b\"], function(a, b){ return a; });";
        let mods: Vec<ExtractedModule> = extract(src);
        assert_eq!(mods.len(), 1);
        assert_eq!(mods[0].id, "my/mod");
        assert_eq!(mods[0].chunk_id.as_deref(), Some("deps:a,b"));
    }

    #[test]
    fn splits_cjs_wrapper_define() {
        let src: &str = "define(function(require, exports, module){ var x = require(\"x\"); module.exports = x; });";
        let mods: Vec<ExtractedModule> = extract(src);
        assert_eq!(mods.len(), 1);
        assert_eq!(
            mods[0].chunk_id.as_deref(),
            Some("deps:require,exports,module")
        );
    }

    #[test]
    fn splits_multiple_defines() {
        let src: &str = "define(\"a\", [\"b\"], function(b){return b;});\ndefine(\"b\", [], function(){return 2;});";
        let mods: Vec<ExtractedModule> = extract(src);
        assert_eq!(mods.len(), 2);
        assert_eq!(mods[0].id, "a");
        assert_eq!(mods[1].id, "b");
    }

    #[test]
    fn graph_resolves_deps_excluding_reserved() {
        let src: &str = "define(\"a\", [\"b\", \"require\"], function(b, require){return b;});\ndefine(\"b\", [], function(){return 2;});";
        let mods: Vec<ExtractedModule> = extract(src);
        let graph: ModuleGraph = build_graph(src, &mods);
        let chunk_a: &ChunkNode = graph.chunks.get("a").expect("chunk a");
        assert_eq!(chunk_a.imports, vec!["b".to_owned()]);
        assert!(graph.chunks.contains_key("b"));
    }

    #[test]
    fn leaves_non_amd_input_with_no_modules() {
        let src: &str = "var x = 1; function f(){ return predefine(x); }";
        let mods: Vec<ExtractedModule> = extract(src);
        assert!(mods.is_empty(), "got: {mods:?}");
    }
}
