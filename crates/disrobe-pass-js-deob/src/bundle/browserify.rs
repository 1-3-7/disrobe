use regex::Regex;

use super::graph::{ChunkNode, ModuleGraph};
use super::scan::{find_brace_close, find_bracket_close, find_paren_close, skip_string};
use super::{BundlerDetection, BundlerKind, ExtractedModule};

#[must_use]
pub fn detect(source: &str) -> BundlerDetection {
    let head: &str = crate::scan_utils::head(source, 256 * 1024);
    let mut markers: Vec<String> = Vec::new();
    let mut score: f32 = 0.0;

    let umd_re_text: &str =
        r"\(function\s*\(\s*[a-zA-Z_$]\s*,\s*[a-zA-Z_$]\s*,\s*[a-zA-Z_$]\s*\)\s*\{";
    let call_re_text: &str = r"\[[a-zA-Z_$]\]\s*\[\s*0\s*\]\s*\.\s*call";
    let has_umd_signature: bool = Regex::new(umd_re_text).is_ok_and(|re: Regex| re.is_match(head));
    let has_pack_call: bool = Regex::new(call_re_text).is_ok_and(|re: Regex| re.is_match(head));
    let has_browserify_helper: bool = head.contains("Cannot find module")
        && head.contains("function")
        && head.contains("'function'==typeof require")
        || head.contains("\"function\"==typeof require");
    let has_browserify_banner: bool =
        head.contains("// browser-pack") || head.contains("browser-pack");

    if has_umd_signature {
        markers.push("browserify-umd-wrapper".to_owned());
        score += 0.25;
    }
    if has_pack_call {
        markers.push("browserify-pack-call".to_owned());
        score += 0.3;
    }
    if has_browserify_helper {
        markers.push("browserify-helper-shape".to_owned());
        score += 0.25;
    }
    if has_browserify_banner {
        markers.push("browser-pack-banner".to_owned());
        score += 0.25;
    }

    if head.contains("__webpack_require__") {
        score -= 0.4;
    }

    let matched: bool = score >= 0.45;
    BundlerDetection {
        kind: BundlerKind::Browserify,
        matched,
        confidence: score.clamp(0.0, 0.92),
        markers,
    }
}

pub(super) fn extract(source: &str) -> Vec<ExtractedModule> {
    let mut modules: Vec<ExtractedModule> = Vec::new();
    extract_browser_pack(source, &mut modules);
    modules
}

pub(super) fn build_graph(source: &str, modules: &[ExtractedModule]) -> ModuleGraph {
    let mut graph: ModuleGraph = ModuleGraph::new();
    graph.with_entry("browserify-bundle");
    let mut entry: ChunkNode = ChunkNode {
        id: "browserify-bundle".to_owned(),
        file: Some("bundle.js".to_owned()),
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
        graph.link_module_to_chunk(&m.id, "browserify-bundle");
    }
    if let Some(info) = super::sourcemap::find(source) {
        graph
            .sourcemap_urls
            .insert("browserify-bundle".to_owned(), info.url);
    }
    graph
}

fn extract_browser_pack(source: &str, modules: &mut Vec<ExtractedModule>) {
    let bytes: &[u8] = source.as_bytes();
    let Ok(open_re): Result<Regex, regex::Error> =
        Regex::new(r"\}\s*\)\s*\(\s*\{|\}\s*\)\s*\(\s*\[")
    else {
        return;
    };
    for mat in open_re.find_iter(source) {
        let open_byte: usize = mat.end() - 1;
        let modules_started: usize = modules.len();
        match bytes.get(open_byte) {
            Some(&b'{') => collect_object_form(source, open_byte, modules),
            Some(&b'[') => collect_array_form(source, open_byte, modules),
            _ => {}
        }
        if modules.len() > modules_started {
            return;
        }
    }
}

fn collect_object_form(source: &str, object_open: usize, modules: &mut Vec<ExtractedModule>) {
    let bytes: &[u8] = source.as_bytes();
    let Some(object_close): Option<usize> = find_brace_close(bytes, object_open + 1) else {
        return;
    };
    let mut i: usize = object_open + 1;
    while i < object_close {
        i = skip_ws(bytes, i);
        if i >= object_close {
            break;
        }
        let (key, key_end): (String, usize) = match parse_pack_key(source, i) {
            Some(v) => v,
            None => return,
        };
        i = skip_ws(bytes, key_end);
        if bytes.get(i) != Some(&b':') {
            return;
        }
        i += 1;
        i = skip_ws(bytes, i);
        if bytes.get(i) != Some(&b'[') {
            return;
        }
        let array_open: usize = i;
        let Some(array_close): Option<usize> = find_bracket_close(bytes, array_open + 1) else {
            return;
        };
        let Some((module_text, deps_text)): Option<(String, String)> =
            split_pack_pair(source, array_open + 1, array_close)
        else {
            i = array_close + 1;
            continue;
        };
        let chunk_id: String = format!("deps:{}", deps_text.trim());
        modules.push(ExtractedModule {
            id: key,
            chunk_id: Some(chunk_id),
            source: module_text.trim().to_owned(),
        });
        i = array_close + 1;
        i = skip_ws_and_commas(bytes, i, object_close);
    }
}

fn collect_array_form(source: &str, array_open: usize, modules: &mut Vec<ExtractedModule>) {
    let bytes: &[u8] = source.as_bytes();
    let Some(array_close): Option<usize> = find_bracket_close(bytes, array_open + 1) else {
        return;
    };
    let mut i: usize = array_open + 1;
    let mut idx: usize = 0;
    while i < array_close {
        i = skip_ws(bytes, i);
        if i >= array_close {
            break;
        }
        if bytes.get(i) != Some(&b'[') {
            return;
        }
        let inner_open: usize = i;
        let Some(inner_close): Option<usize> = find_bracket_close(bytes, inner_open + 1) else {
            return;
        };
        let Some((module_text, deps_text)): Option<(String, String)> =
            split_pack_pair(source, inner_open + 1, inner_close)
        else {
            i = inner_close + 1;
            continue;
        };
        let chunk_id: String = format!("deps:{}", deps_text.trim());
        modules.push(ExtractedModule {
            id: idx.to_string(),
            chunk_id: Some(chunk_id),
            source: module_text.trim().to_owned(),
        });
        idx += 1;
        i = inner_close + 1;
        i = skip_ws_and_commas(bytes, i, array_close);
    }
}

fn split_pack_pair(source: &str, start: usize, hard_end: usize) -> Option<(String, String)> {
    let bytes: &[u8] = source.as_bytes();
    let i: usize = skip_ws(bytes, start);
    if i >= hard_end || bytes.get(i) != Some(&b'f') {
        return None;
    }
    let func_start: usize = i;
    let Ok(re): Result<Regex, regex::Error> = Regex::new(r"^function\s*\(") else {
        return None;
    };
    if !re.is_match(source.get(func_start..)?) {
        return None;
    }
    let paren_open: usize = source[func_start..]
        .find('(')
        .map(|o: usize| func_start + o)?;
    let paren_close: usize = find_paren_close(bytes, paren_open + 1)?;
    let body_open: usize = skip_ws(bytes, paren_close + 1);
    if bytes.get(body_open) != Some(&b'{') {
        return None;
    }
    let body_close: usize = find_brace_close(bytes, body_open + 1)?;
    let func_text: &str = source.get(func_start..=body_close)?;
    let after_func: usize = skip_ws_and_commas(bytes, body_close + 1, hard_end);
    if after_func >= hard_end || bytes.get(after_func) != Some(&b'{') {
        return Some((func_text.to_owned(), "{}".to_owned()));
    }
    let deps_open: usize = after_func;
    let deps_close: usize = find_brace_close(bytes, deps_open + 1)?;
    let deps_text: &str = source.get(deps_open..=deps_close)?;
    Some((func_text.to_owned(), deps_text.to_owned()))
}

fn parse_pack_key(source: &str, start: usize) -> Option<(String, usize)> {
    let bytes: &[u8] = source.as_bytes();
    match bytes.get(start)? {
        b'"' | b'\'' => {
            let q: u8 = bytes[start];
            let end: usize = skip_string(bytes, start, q)?;
            Some((source.get(start + 1..end - 1)?.to_owned(), end))
        }
        c if c.is_ascii_digit() => {
            let mut i: usize = start;
            while i < bytes.len() && bytes[i].is_ascii_alphanumeric() {
                i += 1;
            }
            Some((source.get(start..i)?.to_owned(), i))
        }
        _ => None,
    }
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
    fn detects_browserify_umd_wrapper() {
        let src: &str = r"(function(e,t,n){function r(i,f){if(!t[i]){if(!e[i]){var c='function'==typeof require&&require;if(!f&&c)return c(i,!0);if(o)return o(i,!0);throw new Error('Cannot find module \''+i+'\'')}var s=t[i]={exports:{}};e[i][0].call(s.exports,function(r){return o(e[i][1][r]||r)},s,s.exports,r,e,t,n)}return t[i].exports}var o='function'==typeof require&&require;return r})({1:[function(require,module,exports){module.exports='hi';},{}]}, {}, [1]);";
        let det: BundlerDetection = detect(src);
        assert!(det.matched, "{det:?}");
    }

    #[test]
    fn extracts_object_form_modules() {
        let src: &str = "})({\"1\":[function(require,module,exports){module.exports='one';},{}],\"2\":[function(require,module,exports){module.exports='two';},{}]},{},[1]);";
        let mods: Vec<ExtractedModule> = extract(src);
        assert_eq!(mods.len(), 2);
        assert!(mods.iter().any(|m: &ExtractedModule| m.id == "1"));
        assert!(mods.iter().any(|m: &ExtractedModule| m.id == "2"));
    }
}
