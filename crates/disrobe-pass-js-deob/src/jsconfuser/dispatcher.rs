use std::collections::BTreeMap;
use std::ops::Range;

use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;
use regex::Regex;
use serde::Serialize;

use super::scanner::{
    apply_splice_edits, consume_trailing_semicolon, decode_string_literal_at, find_paren_close,
    read_function_expression, scan_balanced_brace, skip_whitespace, split_top_level_args,
};

#[derive(Debug, Clone, Serialize)]
pub struct DispatcherReversalResult {
    pub table_id: Option<String>,
    pub entries_extracted: usize,
    pub call_sites_inlined: usize,
    pub rewritten_source: String,
}

pub fn reverse_dispatcher(source: &str) -> DispatcherReversalResult {
    let Some((table_id, table_range)): Option<(String, Range<usize>)> =
        find_table_declaration(source)
    else {
        return passthrough(source, None);
    };

    let entries: Vec<(String, String, Range<usize>)> = find_entry_assignments(source, &table_id);
    if entries.is_empty() {
        return passthrough(source, Some(table_id));
    }

    let Some((dispatcher_id, dispatcher_range)): Option<(String, Range<usize>)> =
        find_dispatcher_fn(source, &table_id)
    else {
        return passthrough(source, Some(table_id));
    };

    let mut bodies: BTreeMap<String, String> = BTreeMap::new();
    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    edits.push((table_range, None));
    edits.push((dispatcher_range, None));
    for (key, fn_source, range) in entries {
        if validate_function_source(&fn_source) {
            bodies.insert(key, fn_source);
            edits.push((range, None));
        }
    }
    if bodies.is_empty() {
        return passthrough(source, Some(table_id));
    }

    for (range, key, rest_args) in find_call_sites(source, &dispatcher_id, &bodies) {
        if let Some(body) = bodies.get(&key) {
            let replacement: String = format!("({body})({rest_args})");
            edits.push((range, Some(replacement)));
        }
    }

    let (rewritten, inlined): (String, usize) = apply_splice_edits(source, &mut edits);

    DispatcherReversalResult {
        table_id: Some(table_id),
        entries_extracted: bodies.len(),
        call_sites_inlined: inlined,
        rewritten_source: rewritten,
    }
}

fn passthrough(source: &str, table_id: Option<String>) -> DispatcherReversalResult {
    DispatcherReversalResult {
        table_id,
        entries_extracted: 0,
        call_sites_inlined: 0,
        rewritten_source: source.to_owned(),
    }
}

fn find_table_declaration(source: &str) -> Option<(String, Range<usize>)> {
    let re: Regex = Regex::new(
        r"(?ms)(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*Object\s*\.\s*create\s*\(\s*null\s*\)\s*;?",
    )
    .ok()?;
    let cap: regex::Captures<'_> = re.captures(source)?;
    let id: String = cap.get(1)?.as_str().to_owned();
    let whole: regex::Match<'_> = cap.get(0)?;
    Some((id, whole.start()..whole.end()))
}

fn find_entry_assignments(source: &str, table_id: &str) -> Vec<(String, String, Range<usize>)> {
    let escaped: String = regex::escape(table_id);
    let pattern: String = format!(
        r#"(?ms){escaped}\s*\[\s*(?:"([^"\\]*(?:\\.[^"\\]*)*)"|'([^'\\]*(?:\\.[^'\\]*)*)')\s*\]\s*=\s*function\b"#
    );
    let Ok(re): Result<Regex, regex::Error> = Regex::new(&pattern) else {
        return Vec::new();
    };
    let mut out: Vec<(String, String, Range<usize>)> = Vec::new();
    for cap in re.captures_iter(source) {
        let Some(whole): Option<regex::Match<'_>> = cap.get(0) else {
            continue;
        };
        let Some(key): Option<String> = cap
            .get(1)
            .or_else(|| cap.get(2))
            .map(|m| m.as_str().to_owned())
        else {
            continue;
        };
        let Some((fn_source, end_pos)): Option<(String, usize)> =
            read_function_expression(source, whole.end())
        else {
            continue;
        };
        let stmt_end: usize = consume_trailing_semicolon(source, end_pos);
        out.push((key, fn_source, whole.start()..stmt_end));
    }
    out
}

fn find_dispatcher_fn(source: &str, table_id: &str) -> Option<(String, Range<usize>)> {
    let escaped: String = regex::escape(table_id);
    let header_re: Regex = Regex::new(r"(?ms)function\s+([A-Za-z_$][\w$]*)\s*\(").ok()?;
    let bytes: &[u8] = source.as_bytes();
    let body_probe_re: Regex =
        Regex::new(&format!(r"(?ms){escaped}\s*\[[^\]]+\]\s*\.\s*apply\s*\(")).ok()?;
    for cap in header_re.captures_iter(source) {
        let Some(name_match): Option<regex::Match<'_>> = cap.get(1) else {
            continue;
        };
        let Some(whole): Option<regex::Match<'_>> = cap.get(0) else {
            continue;
        };
        let dispatcher_id: String = name_match.as_str().to_owned();
        if dispatcher_id == table_id {
            continue;
        }
        let Some(paren_close): Option<usize> = find_paren_close(bytes, whole.end()) else {
            continue;
        };
        let body_open: usize = skip_whitespace(bytes, paren_close + 1);
        if body_open >= bytes.len() || bytes[body_open] != b'{' {
            continue;
        }
        let Some(body_close): Option<usize> = scan_balanced_brace(source, body_open + 1) else {
            continue;
        };
        let Some(body): Option<&str> = source.get(body_open..=body_close) else {
            continue;
        };
        if !body_probe_re.is_match(body) {
            continue;
        }
        let stmt_end: usize = consume_trailing_semicolon(source, body_close + 1);
        return Some((dispatcher_id, whole.start()..stmt_end));
    }
    None
}

fn find_call_sites(
    source: &str,
    dispatcher_id: &str,
    bodies: &BTreeMap<String, String>,
) -> Vec<(Range<usize>, String, String)> {
    let escaped: String = regex::escape(dispatcher_id);
    let Ok(re): Result<Regex, regex::Error> = Regex::new(&format!(r"(?ms)\b{escaped}\s*\(")) else {
        return Vec::new();
    };
    let bytes: &[u8] = source.as_bytes();
    let mut out: Vec<(Range<usize>, String, String)> = Vec::new();
    for mat in re.find_iter(source) {
        let open_paren: usize = mat.end() - 1;
        let Some(close): Option<usize> = find_paren_close(bytes, open_paren + 1) else {
            continue;
        };
        let args: Vec<String> = split_top_level_args(&source[open_paren + 1..close]);
        if args.is_empty() {
            continue;
        }
        let Some(key): Option<String> =
            decode_string_literal_at(args[0].as_bytes(), 0).map(|(s, _)| s)
        else {
            continue;
        };
        if !bodies.contains_key(&key) {
            continue;
        }
        let rest_args: String = args[1..].join(", ");
        out.push((mat.start()..close + 1, key, rest_args));
    }
    out
}

fn validate_function_source(source: &str) -> bool {
    if source.trim().is_empty() {
        return false;
    }
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("dispatcher-entry.js").unwrap_or_default();
    let wrapped: String = format!("({source});");
    let parsed: oxc_parser::ParserReturn<'_> =
        Parser::new(&allocator, &wrapped, source_type).parse();
    parsed.errors.is_empty() && !parsed.panicked
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_table_declaration_only() {
        let src: &str = "var fns = Object.create(null); console.log('x');";
        let result: DispatcherReversalResult = reverse_dispatcher(src);
        assert_eq!(result.table_id.as_deref(), Some("fns"));
        assert_eq!(result.entries_extracted, 0);
        assert_eq!(result.call_sites_inlined, 0);
        assert_eq!(result.rewritten_source, src);
    }

    #[test]
    fn inlines_single_entry_single_call() {
        let src: &str = "var fns = Object.create(null);\
                   fns[\"a1\"] = function nm(){ return 1+2; };\
                   function dispatch(k){ return fns[k].apply(this, [].slice.call(arguments, 1)); }\
                   var z = dispatch(\"a1\");";
        let result: DispatcherReversalResult = reverse_dispatcher(src);
        assert_eq!(result.table_id.as_deref(), Some("fns"));
        assert_eq!(result.entries_extracted, 1);
        assert_eq!(result.call_sites_inlined, 1);
        assert!(
            result
                .rewritten_source
                .contains("(function nm(){ return 1+2; })()"),
            "missing inlined IIFE: {}",
            result.rewritten_source
        );
        assert!(!result.rewritten_source.contains("Object.create(null)"));
        assert!(!result.rewritten_source.contains("fns[\"a1\"]"));
    }

    #[test]
    fn inlines_multi_entry_multi_call() {
        let src: &str = "var fns = Object.create(null);\
                   fns[\"k1\"] = function(){ return 10; };\
                   fns[\"k2\"] = function(){ return 20; };\
                   function dispatch(k){ return fns[k].apply(this, [].slice.call(arguments, 1)); }\
                   var a = dispatch(\"k1\");\
                   var b = dispatch(\"k2\", 99);";
        let result: DispatcherReversalResult = reverse_dispatcher(src);
        assert_eq!(result.entries_extracted, 2);
        assert_eq!(result.call_sites_inlined, 2);
        assert!(
            result
                .rewritten_source
                .contains("(function(){ return 10; })()")
        );
        assert!(
            result
                .rewritten_source
                .contains("(function(){ return 20; })(99)")
        );
    }

    #[test]
    fn unknown_key_leaves_call_alone() {
        let src: &str = "var fns = Object.create(null);\
                   fns[\"known\"] = function(){ return 1; };\
                   function dispatch(k){ return fns[k].apply(this, [].slice.call(arguments, 1)); }\
                   var x = dispatch(\"unknown\", 5);";
        let result: DispatcherReversalResult = reverse_dispatcher(src);
        assert_eq!(result.entries_extracted, 1);
        assert_eq!(result.call_sites_inlined, 0);
        assert!(result.rewritten_source.contains("dispatch(\"unknown\", 5)"));
    }
}
