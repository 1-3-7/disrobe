use std::collections::BTreeMap;

use regex::Regex;

use super::ExtractedModule;
use super::scan::{find_brace_close, find_paren_close};

const WEBPACK_WRAPPER_PARAMS: &[&[&str]] = &[
    &["module", "exports", "__webpack_require__"],
    &["module", "exports", "require"],
    &["global", "module", "exports", "require"],
    &["module", "exports"],
];

fn unwrap_module_wrapper(source: &str) -> Option<String> {
    let bytes: &[u8] = source.as_bytes();
    let trimmed_start: usize = skip_ws(bytes, 0);
    let mut open_paren: Option<usize> = None;
    let func_start: usize = if bytes.get(trimmed_start) == Some(&b'(') {
        open_paren = Some(trimmed_start);
        skip_ws(bytes, trimmed_start + 1)
    } else {
        trimmed_start
    };
    let re: Regex = Regex::new(r"^function\s*[A-Za-z_$][A-Za-z0-9_$]*\s*\(|^function\s*\(").ok()?;
    let rest: &str = source.get(func_start..)?;
    let header: regex::Match<'_> = re.find(rest)?;
    let paren_open: usize = func_start + header.end() - 1;
    if bytes.get(paren_open) != Some(&b'(') {
        return None;
    }
    let paren_close: usize = find_paren_close(bytes, paren_open + 1)?;
    let params_raw: &str = source.get(paren_open + 1..paren_close)?;
    if !params_match_webpack(params_raw) {
        return None;
    }
    let body_open: usize = skip_ws(bytes, paren_close + 1);
    if bytes.get(body_open) != Some(&b'{') {
        return None;
    }
    let body_close: usize = find_brace_close(bytes, body_open + 1)?;
    let mut tail: usize = skip_ws(bytes, body_close + 1);
    if open_paren.is_some() {
        if bytes.get(tail) != Some(&b')') {
            return None;
        }
        tail = skip_ws(bytes, tail + 1);
    }
    if tail < bytes.len() && bytes[tail] != b';' {
        return None;
    }
    let inner: &str = source.get(body_open + 1..body_close)?;
    Some(dedent_block(inner))
}

fn params_match_webpack(params_raw: &str) -> bool {
    let names: Vec<&str> = params_raw
        .split(',')
        .map(str::trim)
        .filter(|s: &&str| !s.is_empty())
        .collect();
    if names.iter().any(|n: &&str| {
        !n.bytes()
            .all(|b: u8| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'$'))
    }) {
        return false;
    }
    WEBPACK_WRAPPER_PARAMS
        .iter()
        .any(|shape: &&[&str]| shape.len() == names.len() && shape.iter().eq(names.iter()))
}

fn dedent_block(inner: &str) -> String {
    let trimmed: &str = inner.trim_matches(['\n', '\r']);
    let min_indent: usize = trimmed
        .lines()
        .filter(|l: &&str| !l.trim().is_empty())
        .map(|l: &str| l.len() - l.trim_start().len())
        .min()
        .unwrap_or(0);
    let mut out: String = String::with_capacity(trimmed.len());
    for (i, line) in trimmed.lines().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        if line.len() >= min_indent {
            out.push_str(&line[min_indent..]);
        } else {
            out.push_str(line.trim_start());
        }
    }
    out.trim_end().to_owned()
}

fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    i
}

#[must_use]
pub fn build_id_to_path_map(modules: &[ExtractedModule]) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for m in modules {
        if !m.id.is_empty() {
            out.insert(m.id.clone(), to_relative(&m.id));
        }
    }
    out
}

#[must_use]
pub fn rewrite_requires(source: &str, map: &BTreeMap<String, String>) -> String {
    let Ok(re): Result<Regex, regex::Error> =
        Regex::new(r#"(__webpack_require__|require)\s*\(\s*(?:(\d+)|["']([^"']+)["'])\s*\)"#)
    else {
        return source.to_owned();
    };
    let result: String = re
        .replace_all(source, |caps: &regex::Captures<'_>| {
            let fn_name: &str = caps
                .get(1)
                .map_or("require", |m: regex::Match<'_>| m.as_str());
            let raw_id: String = caps.get(2).map_or_else(
                || {
                    caps.get(3)
                        .map_or_else(String::new, |m: regex::Match<'_>| m.as_str().to_owned())
                },
                |m: regex::Match<'_>| m.as_str().to_owned(),
            );
            map.get(&raw_id).map_or_else(
                || format!("{fn_name}(\"{raw_id}\")"),
                |resolved: &String| format!("{fn_name}(\"{resolved}\")"),
            )
        })
        .into_owned();
    result
}

fn to_relative(id: &str) -> String {
    if id.starts_with("./") || id.starts_with("../") {
        id.to_owned()
    } else if id.starts_with('/') {
        format!(".{id}")
    } else if id.chars().all(|c: char| c.is_ascii_digit()) {
        format!("./module-{id}.js")
    } else if id.contains('/') {
        format!("./{id}")
    } else {
        format!("./{id}.js")
    }
}

pub fn rewrite_modules(modules: &mut [ExtractedModule]) {
    let map: BTreeMap<String, String> = build_id_to_path_map(modules);
    for m in modules.iter_mut() {
        if let Some(unwrapped) = unwrap_module_wrapper(&m.source) {
            m.source = unwrapped;
        }
        m.source = rewrite_requires(&m.source, &map);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_numeric_require_to_relative_path() {
        let mods: Vec<ExtractedModule> = vec![
            ExtractedModule {
                id: "0".to_owned(),
                chunk_id: None,
                source: "var x = __webpack_require__(1);".to_owned(),
            },
            ExtractedModule {
                id: "1".to_owned(),
                chunk_id: None,
                source: "module.exports = 'one';".to_owned(),
            },
        ];
        let map: BTreeMap<String, String> = build_id_to_path_map(&mods);
        let rewritten: String = rewrite_requires(&mods[0].source, &map);
        assert!(rewritten.contains("./module-1.js"), "got: {rewritten}");
    }

    #[test]
    fn unwraps_webpack_module_wrapper_verbatim() {
        let src: &str = "(function(module, exports, __webpack_require__) {\n  var x = 1;\n  module.exports = x;\n})";
        let body: String = unwrap_module_wrapper(src).expect("unwrap");
        assert_eq!(body, "var x = 1;\nmodule.exports = x;");
    }

    #[test]
    fn unwraps_browserify_global_wrapper() {
        let src: &str = "function(global, module, exports, require){ return 42; }";
        let body: String = unwrap_module_wrapper(src).expect("unwrap");
        assert_eq!(body, "return 42;");
    }

    #[test]
    fn unwraps_two_param_wrapper() {
        let src: &str = "(function(module, exports){module.exports='ok';});";
        let body: String = unwrap_module_wrapper(src).expect("unwrap");
        assert_eq!(body, "module.exports='ok';");
    }

    #[test]
    fn does_not_unwrap_mismatched_params() {
        let src: &str = "(function(a, b, c){ return a; })";
        assert!(unwrap_module_wrapper(src).is_none());
    }

    #[test]
    fn does_not_unwrap_string_lookalike() {
        let src: &str = "\"(function(module, exports, __webpack_require__){ evil(); })\"";
        assert!(unwrap_module_wrapper(src).is_none());
    }

    #[test]
    fn does_not_unwrap_bare_variable() {
        let src: &str = "var f = function(module, exports){};";
        assert!(unwrap_module_wrapper(src).is_none());
    }

    #[test]
    fn does_not_unwrap_arrow_or_trailing_call() {
        let src: &str = "(function(module, exports, __webpack_require__){ return 1; })(a, b, c)";
        assert!(unwrap_module_wrapper(src).is_none());
    }

    #[test]
    fn rewrite_modules_unwraps_and_resolves_graph() {
        let mut mods: Vec<ExtractedModule> = vec![
            ExtractedModule {
                id: "0".to_owned(),
                chunk_id: None,
                source: "(function(module, exports, __webpack_require__){ var dep = __webpack_require__(1); module.exports = dep; })".to_owned(),
            },
            ExtractedModule {
                id: "1".to_owned(),
                chunk_id: None,
                source: "(function(module, exports, __webpack_require__){ module.exports = 'leaf'; })".to_owned(),
            },
        ];
        rewrite_modules(&mut mods);
        assert!(
            !mods[0].source.starts_with("(function"),
            "got: {}",
            mods[0].source
        );
        assert!(mods[0].source.contains("var dep ="));
        assert!(
            mods[0].source.contains("./module-1.js"),
            "got: {}",
            mods[0].source
        );
        assert!(mods[1].source.contains("'leaf'"));
        assert!(!mods[1].source.contains("function(module"));
    }

    #[test]
    fn rewrites_string_id_require() {
        let mods: Vec<ExtractedModule> = vec![
            ExtractedModule {
                id: "./src/a.js".to_owned(),
                chunk_id: None,
                source: "var b = require(\"./src/b.js\");".to_owned(),
            },
            ExtractedModule {
                id: "./src/b.js".to_owned(),
                chunk_id: None,
                source: "module.exports = 'b';".to_owned(),
            },
        ];
        let map: BTreeMap<String, String> = build_id_to_path_map(&mods);
        let rewritten: String = rewrite_requires(&mods[0].source, &map);
        assert!(rewritten.contains("./src/b.js"));
    }
}
