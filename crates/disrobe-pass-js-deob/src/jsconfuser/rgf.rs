use std::collections::BTreeMap;
use std::ops::Range;

use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;
use regex::Regex;
use serde::Serialize;

use super::scanner::{
    consume_trailing_semicolon, decode_string_literal_at, find_paren_close, scan_balanced_bracket,
};

#[derive(Debug, Clone, Serialize)]
pub struct RgfReversalResult {
    pub array_id: Option<String>,
    pub entries_extracted: usize,
    pub call_sites_inlined: usize,
    pub rewritten_source: String,
}

pub fn reverse_rgf(source: &str) -> RgfReversalResult {
    let Some(decl): Option<RgfDeclaration> = find_rgf_declaration(source) else {
        return passthrough(source, None);
    };

    let Some(entries): Option<Vec<String>> =
        parse_rgf_entries(&source[decl.entries_start..decl.entries_end]).filter(|v| !v.is_empty())
    else {
        return passthrough(source, Some(decl.array_id));
    };

    let mut bodies: BTreeMap<usize, String> = BTreeMap::new();
    for (idx, body) in entries.iter().enumerate() {
        if validate_function_body(body) {
            bodies.insert(idx, body.clone());
        }
    }
    if bodies.is_empty() {
        return passthrough(source, Some(decl.array_id));
    }

    let call_sites: Vec<CallSite> = find_call_sites(source, &decl.array_id);
    let events: Vec<Event> = build_events(&decl, &call_sites, &bodies);
    let (rewritten, inlined): (String, usize) = apply_events(source, &events, &bodies);

    RgfReversalResult {
        array_id: Some(decl.array_id),
        entries_extracted: bodies.len(),
        call_sites_inlined: inlined,
        rewritten_source: rewritten,
    }
}

fn passthrough(source: &str, array_id: Option<String>) -> RgfReversalResult {
    RgfReversalResult {
        array_id,
        entries_extracted: 0,
        call_sites_inlined: 0,
        rewritten_source: source.to_owned(),
    }
}

fn build_events(
    decl: &RgfDeclaration,
    call_sites: &[CallSite],
    bodies: &BTreeMap<usize, String>,
) -> Vec<Event> {
    let mut events: Vec<Event> = Vec::with_capacity(call_sites.len() + 1);
    events.push(Event::DropDecl {
        range: decl.decl_range.clone(),
    });
    for site in call_sites {
        if bodies.contains_key(&site.index) {
            events.push(Event::Inline {
                range: site.range.clone(),
                index: site.index,
            });
        }
    }
    events.sort_by_key(Event::start);
    events
}

fn apply_events(
    source: &str,
    events: &[Event],
    bodies: &BTreeMap<usize, String>,
) -> (String, usize) {
    let mut rewritten: String = String::with_capacity(source.len());
    let mut cursor: usize = 0;
    let mut inlined: usize = 0;
    for event in events {
        let (start, end): (usize, usize) = event.range();
        if start < cursor {
            continue;
        }
        rewritten.push_str(&source[cursor..start]);
        match event {
            Event::DropDecl { .. } => {}
            Event::Inline { index, .. } => {
                if let Some(body) = bodies.get(index) {
                    rewritten.push_str("(function(){");
                    rewritten.push_str(body);
                    rewritten.push_str("})()");
                    inlined += 1;
                } else {
                    rewritten.push_str(&source[start..end]);
                }
            }
        }
        cursor = end;
    }
    rewritten.push_str(&source[cursor..]);
    (rewritten, inlined)
}

#[derive(Debug, Clone)]
struct RgfDeclaration {
    array_id: String,
    decl_range: Range<usize>,
    entries_start: usize,
    entries_end: usize,
}

#[derive(Debug, Clone)]
struct CallSite {
    range: Range<usize>,
    index: usize,
}

#[derive(Debug, Clone)]
enum Event {
    DropDecl { range: Range<usize> },
    Inline { range: Range<usize>, index: usize },
}

impl Event {
    const fn start(&self) -> usize {
        match self {
            Self::DropDecl { range } | Self::Inline { range, .. } => range.start,
        }
    }
    const fn range(&self) -> (usize, usize) {
        match self {
            Self::DropDecl { range } | Self::Inline { range, .. } => (range.start, range.end),
        }
    }
}

fn find_rgf_declaration(source: &str) -> Option<RgfDeclaration> {
    let header_re: Regex =
        Regex::new(r"(?ms)(?:var|let|const)\s+(_rgf_\w*|_\w+_rgf)\s*=\s*\[").ok()?;
    let cap: regex::Captures<'_> = header_re.captures(source)?;
    let array_id: String = cap.get(1)?.as_str().to_owned();
    let whole: regex::Match<'_> = cap.get(0)?;
    let decl_start: usize = whole.start();
    let entries_start: usize = whole.end();

    let entries_end: usize = scan_balanced_bracket(source, entries_start)?;
    let body: &str = &source[entries_start..entries_end];
    if !body_contains_new_function(body) {
        return None;
    }

    let semi_end: usize = consume_trailing_semicolon(source, entries_end + 1);
    Some(RgfDeclaration {
        array_id,
        decl_range: decl_start..semi_end,
        entries_start,
        entries_end,
    })
}

fn body_contains_new_function(body: &str) -> bool {
    let Ok(re): Result<Regex, regex::Error> = Regex::new(r"(?ms)\bnew\s+Function\s*\(") else {
        return false;
    };
    re.is_match(body)
}

fn parse_rgf_entries(body: &str) -> Option<Vec<String>> {
    let bytes: &[u8] = body.as_bytes();
    let mut entries: Vec<String> = Vec::new();
    let mut i: usize = 0;
    let new_fn_re: Regex = Regex::new(r"(?ms)\bnew\s+Function\s*\(").ok()?;
    while i < bytes.len() {
        while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n' | b',') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let remainder: &str = &body[i..];
        let mat: regex::Match<'_> = new_fn_re.find(remainder)?;
        if mat.start() != 0 {
            return None;
        }
        let call_open: usize = i + mat.end();
        let (literal, after_call): (String, usize) = read_first_string_arg(bytes, call_open)?;
        entries.push(literal);
        i = after_call;
    }
    Some(entries)
}

fn read_first_string_arg(bytes: &[u8], call_open: usize) -> Option<(String, usize)> {
    let mut i: usize = call_open;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    let (literal, after_quote): (String, usize) = decode_string_literal_at(bytes, i)?;
    let close: usize = find_paren_close(bytes, after_quote)?;
    Some((literal, close + 1))
}

fn validate_function_body(body: &str) -> bool {
    if body.trim().is_empty() {
        return false;
    }
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("rgf-body.js").unwrap_or_default();
    let wrapped: String = format!("(function(){{{body}}})();");
    let parsed: oxc_parser::ParserReturn<'_> =
        Parser::new(&allocator, &wrapped, source_type).parse();
    parsed.errors.is_empty() && !parsed.panicked
}

fn find_call_sites(source: &str, array_id: &str) -> Vec<CallSite> {
    let id: String = regex::escape(array_id);
    let pattern: String = format!(
        r"(?ms){id}\s*\[\s*(\d+)\s*\]\s*\.\s*apply\s*\(\s*this\s*,\s*\[\s*{id}\s*,\s*(?:arguments|args)\s*\]\s*\)"
    );
    let Ok(re): Result<Regex, regex::Error> = Regex::new(&pattern) else {
        return Vec::new();
    };
    let mut out: Vec<CallSite> = Vec::new();
    for cap in re.captures_iter(source) {
        let Some(whole): Option<regex::Match<'_>> = cap.get(0) else {
            continue;
        };
        let Some(idx_match): Option<regex::Match<'_>> = cap.get(1) else {
            continue;
        };
        let Ok(index): Result<usize, std::num::ParseIntError> = idx_match.as_str().parse::<usize>()
        else {
            continue;
        };
        out.push(CallSite {
            range: whole.start()..whole.end(),
            index,
        });
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parses_two_entries() {
        let body: &str = "new Function('return 1'), new Function(\"return 2\")";
        let entries: Vec<String> = parse_rgf_entries(body).expect("entries parse");
        assert_eq!(entries, vec!["return 1", "return 2"]);
    }

    #[test]
    fn validates_simple_body() {
        assert!(validate_function_body("return 1+2"));
        assert!(validate_function_body("var x=1; return x"));
        assert!(!validate_function_body("@@@ not valid @@@"));
    }

    #[test]
    fn finds_call_site() {
        let src: &str = "x = _rgf_a[0].apply(this, [_rgf_a, arguments]);";
        let sites: Vec<CallSite> = find_call_sites(src, "_rgf_a");
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].index, 0);
    }
}
