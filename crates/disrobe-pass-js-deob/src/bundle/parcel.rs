use regex::Regex;

use super::graph::{ChunkNode, ModuleGraph};
use super::scan::{find_brace_close, find_paren_close};
use super::{BundlerDetection, BundlerKind, ExtractedModule};

#[must_use]
pub fn detect(source: &str) -> BundlerDetection {
    let head: &str = crate::scan_utils::head(source, 256 * 1024);
    let mut markers: Vec<String> = Vec::new();
    let mut score: f32 = 0.0;

    let has_parcel_require: bool = head.contains("parcelRequire");
    let has_parcel_register: bool = head.contains("parcelRegister") || head.contains(".register(");
    let has_parcel_helper: bool = head.contains("globalObject")
        && head.contains("parcelRequire")
        && head.contains("\"function\"");
    let has_parcel_banner: bool =
        head.contains("// modules are defined as an array") || head.contains("Parcel");

    if has_parcel_require {
        markers.push("parcelRequire".to_owned());
        score += 0.45;
    }
    if has_parcel_register {
        markers.push("parcelRegister".to_owned());
        score += 0.15;
    }
    if has_parcel_helper {
        markers.push("parcel-runtime-helper".to_owned());
        score += 0.2;
    }
    if has_parcel_banner {
        markers.push("parcel-banner".to_owned());
        score += 0.15;
    }

    if head.contains("__webpack_require__") {
        score -= 0.3;
    }

    let matched: bool = score >= 0.45;
    BundlerDetection {
        kind: BundlerKind::Parcel,
        matched,
        confidence: score.clamp(0.0, 0.93),
        markers,
    }
}

pub(super) fn extract(source: &str) -> Vec<ExtractedModule> {
    let mut modules: Vec<ExtractedModule> = Vec::new();
    extract_register_calls(source, &mut modules);
    modules
}

pub(super) fn build_graph(source: &str, modules: &[ExtractedModule]) -> ModuleGraph {
    let mut graph: ModuleGraph = ModuleGraph::new();
    graph.with_entry("parcel-root");
    let resolved: Vec<String> = collect_parcel_require_calls(source);
    let mut entry: ChunkNode = ChunkNode {
        id: "parcel-root".to_owned(),
        file: Some("parcel.js".to_owned()),
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
        graph.link_module_to_chunk(&m.id, "parcel-root");
    }
    if let Some(info) = super::sourcemap::find(source) {
        graph
            .sourcemap_urls
            .insert("parcel-root".to_owned(), info.url);
    }
    graph
}

fn collect_parcel_require_calls(source: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r#"parcelRequire(?:\.register)?\s*\(\s*["']([^"']+)["']"#)
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

fn extract_register_calls(source: &str, modules: &mut Vec<ExtractedModule>) {
    let bytes: &[u8] = source.as_bytes();
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r#"parcelRequire(?:\.register)?\s*\(\s*["']([^"']+)["']\s*,\s*function\s*\("#)
    else {
        return;
    };
    for caps in re.captures_iter(source) {
        let Some(id): Option<&str> = caps.get(1).map(|m: regex::Match<'_>| m.as_str()) else {
            continue;
        };
        let Some(full): Option<regex::Match<'_>> = caps.get(0) else {
            continue;
        };
        let paren_open: usize = full.end() - 1;
        let Some(paren_close): Option<usize> = find_paren_close(bytes, paren_open + 1) else {
            continue;
        };
        let mut body_open: usize = paren_close + 1;
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
            id: id.to_owned(),
            chunk_id: Some("parcel".to_owned()),
            source: body_text.trim().to_owned(),
        });
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_parcel_via_parcel_require() {
        let src: &str =
            "var parcelRequire = function(){}; parcelRequire.register(\"abc\", function(){});";
        let det: BundlerDetection = detect(src);
        assert!(det.matched, "{det:?}");
    }

    #[test]
    fn extracts_register_call_modules() {
        let src: &str = "parcelRequire.register(\"abc\", function(module, exports){ module.exports='a'; });\nparcelRequire.register(\"def\", function(module, exports){ module.exports='b'; });";
        let mods: Vec<ExtractedModule> = extract(src);
        assert_eq!(mods.len(), 2);
        assert!(mods.iter().any(|m: &ExtractedModule| m.id == "abc"));
        assert!(mods.iter().any(|m: &ExtractedModule| m.id == "def"));
    }
}
