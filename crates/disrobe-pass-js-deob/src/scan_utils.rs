use std::ops::Range;

use crate::error::{Error, Result};
pub(crate) use crate::source_text::head;
use regex::{Captures, Regex};

pub(crate) fn next_utf8_char(bytes: &[u8], at: usize) -> Option<char> {
    let end: usize = (at + 4).min(bytes.len());
    for take in (at + 1)..=end {
        if let Ok(chunk) = std::str::from_utf8(bytes.get(at..take)?) {
            return chunk.chars().next();
        }
    }
    None
}

pub(crate) fn copy_char_at(out: &mut String, source: &str, at: usize) -> usize {
    let character: Option<char> = source.get(at..).and_then(|rest: &str| rest.chars().next());
    out.push(character.unwrap_or(char::REPLACEMENT_CHARACTER));
    character.map_or(1, char::len_utf8)
}

#[must_use]
pub(crate) fn literal_and_comment_ranges(source: &str) -> Vec<Range<usize>> {
    let bytes: &[u8] = source.as_bytes();
    let mut ranges: Vec<Range<usize>> = Vec::new();
    let mut i: usize = 0;
    let mut prev_significant: u8 = b';';
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'\'' | b'"' | b'`' => {
                let end: usize = skip_quoted_span(bytes, i, b);
                ranges.push(i..end);
                prev_significant = b;
                i = end;
                continue;
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                let end: usize = skip_line_comment_span(bytes, i);
                ranges.push(i..end);
                i = end;
                continue;
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                let end: usize = skip_block_comment_span(bytes, i);
                ranges.push(i..end);
                i = end;
                continue;
            }
            b'/' if regex_literal_allowed(prev_significant) => {
                let end: usize = skip_regex_span(bytes, i);
                ranges.push(i..end);
                prev_significant = b'/';
                i = end;
                continue;
            }
            _ => {}
        }
        if !matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
            prev_significant = b;
        }
        i += 1;
    }
    ranges
}

#[must_use]
pub(crate) fn span_is_code(ranges: &[Range<usize>], start: usize, end: usize) -> bool {
    let starts_inside: bool = ranges
        .iter()
        .any(|range: &Range<usize>| range.start <= start && start < range.end);
    let ends_inside: bool = ranges
        .iter()
        .any(|range: &Range<usize>| range.start < end && end < range.end);
    !starts_inside && !ends_inside
}

pub(crate) fn replace_in_code(
    source: &str,
    re: &Regex,
    mut fold: impl FnMut(&Captures<'_>) -> Option<String>,
) -> (String, usize) {
    let skips: Vec<Range<usize>> = literal_and_comment_ranges(source);
    let mut out: String = String::with_capacity(source.len());
    let mut last: usize = 0;
    let mut count: usize = 0;
    for caps in re.captures_iter(source) {
        let Some(whole): Option<regex::Match<'_>> = caps.get(0) else {
            continue;
        };
        if whole.start() < last || !span_is_code(&skips, whole.start(), whole.end()) {
            continue;
        }
        let Some(replacement): Option<String> = fold(&caps) else {
            continue;
        };
        out.push_str(&source[last..whole.start()]);
        out.push_str(&replacement);
        last = whole.end();
        count += 1;
    }
    out.push_str(&source[last..]);
    (out, count)
}

const fn regex_literal_allowed(prev: u8) -> bool {
    matches!(
        prev,
        b'(' | b','
            | b'='
            | b':'
            | b'['
            | b'!'
            | b'&'
            | b'|'
            | b'?'
            | b'{'
            | b'}'
            | b';'
            | b'+'
            | b'-'
            | b'*'
            | b'%'
            | b'<'
            | b'>'
            | b'~'
            | b'^'
            | b'\n'
            | b'\r'
    )
}

fn skip_quoted_span(bytes: &[u8], start: usize, quote: u8) -> usize {
    let mut i: usize = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b if b == quote => return i + 1,
            _ => i += 1,
        }
    }
    bytes.len()
}

fn skip_line_comment_span(bytes: &[u8], start: usize) -> usize {
    let mut i: usize = start + 2;
    while i < bytes.len() && bytes[i] != b'\n' {
        i += 1;
    }
    i
}

fn skip_block_comment_span(bytes: &[u8], start: usize) -> usize {
    let mut i: usize = start + 2;
    while i + 1 < bytes.len() {
        if bytes[i] == b'*' && bytes[i + 1] == b'/' {
            return i + 2;
        }
        i += 1;
    }
    bytes.len()
}

fn skip_regex_span(bytes: &[u8], start: usize) -> usize {
    let mut i: usize = start + 1;
    let mut in_class: bool = false;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'[' => {
                in_class = true;
                i += 1;
            }
            b']' => {
                in_class = false;
                i += 1;
            }
            b'/' if !in_class => {
                i += 1;
                while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
                    i += 1;
                }
                return i;
            }
            b'\n' => return start + 1,
            _ => i += 1,
        }
    }
    bytes.len()
}

pub(crate) fn apply_splice_edits(
    source: &str,
    edits: &mut [(core::ops::Range<usize>, Option<String>)],
) -> (String, usize) {
    edits.sort_by_key(|edit: &(core::ops::Range<usize>, Option<String>)| edit.0.start);
    let literals: Vec<core::ops::Range<usize>> = literal_spans(source);
    let mut out: String = String::with_capacity(source.len());
    let mut cursor: usize = 0;
    let mut applied: usize = 0;
    for (range, replacement) in edits.iter() {
        if range.start < cursor
            || range.end < range.start
            || !source.is_char_boundary(range.end)
            || cuts_a_literal(range, &literals)
        {
            continue;
        }
        let Some(kept): Option<&str> = source.get(cursor..range.start) else {
            continue;
        };
        out.push_str(kept);
        if let Some(text) = replacement {
            out.push_str(text);
            applied += 1;
        }
        cursor = range.end;
    }
    out.push_str(source.get(cursor..).unwrap_or_default());
    (out, applied)
}

fn cuts_a_literal(edit: &core::ops::Range<usize>, literals: &[core::ops::Range<usize>]) -> bool {
    let inside = |offset: usize, literal: &core::ops::Range<usize>| {
        offset > literal.start && offset < literal.end
    };
    let first: usize =
        literals.partition_point(|literal: &core::ops::Range<usize>| literal.end <= edit.start);
    literals
        .get(first..)
        .unwrap_or_default()
        .iter()
        .take_while(|literal: &&core::ops::Range<usize>| {
            literal.start < edit.end.max(edit.start + 1)
        })
        .any(|literal: &core::ops::Range<usize>| {
            inside(edit.start, literal) || inside(edit.end, literal)
        })
}

struct LiteralSpans {
    spans: Vec<core::ops::Range<usize>>,
}

impl<'a> oxc_ast::Visit<'a> for LiteralSpans {
    fn visit_string_literal(&mut self, literal: &oxc_ast::ast::StringLiteral<'a>) {
        self.spans
            .push(literal.span.start as usize..literal.span.end as usize);
    }

    fn visit_template_element(&mut self, element: &oxc_ast::ast::TemplateElement<'a>) {
        self.spans
            .push(element.span.start as usize..element.span.end as usize);
    }

    fn visit_reg_exp_literal(&mut self, literal: &oxc_ast::ast::RegExpLiteral<'a>) {
        self.spans
            .push(literal.span.start as usize..literal.span.end as usize);
    }
}

fn literal_spans(source: &str) -> Vec<core::ops::Range<usize>> {
    let allocator: oxc_allocator::Allocator = oxc_allocator::Allocator::default();
    let source_type: oxc_span::SourceType =
        oxc_span::SourceType::from_path("splice.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> =
        oxc_parser::Parser::new(&allocator, source, source_type).parse();
    if parsed.panicked || !parsed.errors.is_empty() {
        return Vec::new();
    }
    let mut collector: LiteralSpans = LiteralSpans { spans: Vec::new() };
    oxc_ast::Visit::visit_program(&mut collector, &parsed.program);
    collector
        .spans
        .sort_by_key(|span: &core::ops::Range<usize>| span.start);
    collector.spans
}

#[must_use]
pub(crate) fn reparses(source: &str) -> bool {
    let source_type: oxc_span::SourceType =
        oxc_span::SourceType::from_path("reparse.js").unwrap_or_default();
    parses_as(source, source_type)
}

#[must_use]
pub(crate) fn reparses_script(source: &str) -> bool {
    parses_as(source, oxc_span::SourceType::cjs())
}

fn parses_as(source: &str, source_type: oxc_span::SourceType) -> bool {
    let allocator: oxc_allocator::Allocator = oxc_allocator::Allocator::default();
    let parsed: oxc_parser::ParserReturn<'_> =
        oxc_parser::Parser::new(&allocator, source, source_type).parse();
    !parsed.panicked && parsed.errors.is_empty()
}

const PARSE_GOALS: [oxc_span::SourceType; 2] = [
    oxc_span::SourceType::cjs(),
    oxc_span::SourceType::mjs().with_jsx(true),
];

#[derive(Debug, Clone, Copy)]
pub(crate) struct ReparseGate {
    input_goals: [bool; PARSE_GOALS.len()],
}

impl ReparseGate {
    #[must_use]
    pub(crate) fn for_input(source: &str) -> Self {
        Self {
            input_goals: PARSE_GOALS.map(|goal: oxc_span::SourceType| parses_as(source, goal)),
        }
    }

    pub(crate) fn still_parses(self, transform: &'static str, text: &str) -> Result<()> {
        let input_parses: bool = self.input_goals.contains(&true);
        let output_parses: bool = PARSE_GOALS.iter().zip(self.input_goals).any(
            |(goal, input_ok): (&oxc_span::SourceType, bool)| input_ok && parses_as(text, *goal),
        );
        if input_parses && !output_parses {
            return Err(Error::CorruptedByTransform { transform });
        }
        Ok(())
    }
}

#[must_use]
pub(crate) fn find_paren_close(bytes: &[u8], start: usize) -> Option<usize> {
    find_close(bytes, start, b'(', b')')
}

#[must_use]
pub(crate) fn find_brace_close(bytes: &[u8], start: usize) -> Option<usize> {
    find_close(bytes, start, b'{', b'}')
}

#[must_use]
pub(crate) fn skip_ws(bytes: &[u8], start: usize) -> usize {
    let mut i: usize = start;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    i
}

#[must_use]
pub(crate) fn find_statement_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i: usize = start;
    let mut paren: i32 = 0;
    let mut bracket: i32 = 0;
    let mut brace: i32 = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'\'' | b'"' | b'`' => {
                i = skip_string(bytes, i, b)?;
                continue;
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i = i.saturating_add(2);
                continue;
            }
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b'{' => brace += 1,
            b'}' => brace -= 1,
            b';' if paren == 0 && bracket == 0 && brace == 0 => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

#[must_use]
pub(crate) const fn regex_can_follow(prev: u8) -> bool {
    matches!(
        prev,
        b'(' | b','
            | b'='
            | b':'
            | b'['
            | b'!'
            | b'&'
            | b'|'
            | b'?'
            | b'{'
            | b'}'
            | b';'
            | b'+'
            | b'-'
            | b'*'
            | b'%'
            | b'<'
            | b'>'
            | b'~'
            | b'^'
            | b'\n'
            | b'\r'
    )
}

#[must_use]
pub(crate) fn skip_regex_literal(bytes: &[u8], start: usize) -> usize {
    let mut i: usize = start + 1;
    let mut in_class: bool = false;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'[' => {
                in_class = true;
                i += 1;
            }
            b']' => {
                in_class = false;
                i += 1;
            }
            b'/' if !in_class => {
                i += 1;
                while i < bytes.len()
                    && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'$')
                {
                    i += 1;
                }
                return i;
            }
            b'\n' => return start + 1,
            _ => i += 1,
        }
    }
    bytes.len()
}

#[must_use]
pub(crate) fn skip_string(bytes: &[u8], start: usize, quote: u8) -> Option<usize> {
    let mut i: usize = start + 1;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b == b'\\' {
            i += 2;
            continue;
        }
        if b == quote {
            return Some(i + 1);
        }
        i += 1;
    }
    None
}

fn find_close(bytes: &[u8], start: usize, open: u8, close: u8) -> Option<usize> {
    let mut depth: i32 = 1;
    let mut i: usize = start;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b == open {
            depth += 1;
        } else if b == close {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        } else if b == b'\'' || b == b'"' || b == b'`' {
            i = skip_string(bytes, i, b)?;
            continue;
        } else if b == b'/' && bytes.get(i + 1) == Some(&b'/') {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        } else if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = i.saturating_add(2);
            continue;
        }
        i += 1;
    }
    None
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_splice_edit_never_lands_inside_a_string_template_or_regex_literal() {
        let source: &str = "var a = 'keep me', b = `t${x}pl`, c = /re+x/g; f(a);";
        let at = |needle: &str| source.find(needle).expect("needle");
        let mut edits: Vec<(core::ops::Range<usize>, Option<String>)> = vec![
            (at("me'")..at("me'") + 2, Some("XX".to_owned())),
            (at("pl`") + 1..at("pl`") + 2, Some("Y".to_owned())),
            (at("e+x")..at("e+x") + 1, Some("Z".to_owned())),
            (
                at("'keep")..at("'keep") + "'keep me'".len(),
                Some("'whole'".to_owned()),
            ),
            (at("f(a)")..at("f(a)") + 1, Some("g".to_owned())),
        ];
        let (out, applied): (String, usize) = apply_splice_edits(source, &mut edits);
        assert_eq!(out, "var a = 'whole', b = `t${x}pl`, c = /re+x/g; g(a);");
        assert_eq!(applied, 2);
    }

    #[test]
    fn splice_edits_skip_ranges_that_overlap_leave_the_source_or_split_a_character() {
        let source: &str = "a\u{e9}bcd";
        let mut edits: Vec<(core::ops::Range<usize>, Option<String>)> = vec![
            (4..5, Some("C".to_owned())),
            (2..3, Some("x".to_owned())),
            (0..1, Some("A".to_owned())),
            (0..2, None),
            (5..9, Some("out".to_owned())),
            (
                core::ops::Range { start: 5, end: 4 },
                Some("backwards".to_owned()),
            ),
        ];
        let (out, applied): (String, usize) = apply_splice_edits(source, &mut edits);
        assert_eq!(out, "A\u{e9}bCd");
        assert_eq!(applied, 2);
    }

    #[test]
    fn matches_nested_braces() {
        let s: &[u8] = b"{ a { b } c }X";
        let close: usize = find_brace_close(s, 1).expect("balanced");
        assert_eq!(s[close], b'}');
        assert_eq!(close, s.len() - 2);
    }

    #[test]
    fn brace_inside_string_is_ignored() {
        let s: &[u8] = b"{ var x = '}}}}'; }";
        let close: usize = find_brace_close(s, 1).expect("balanced");
        assert_eq!(close, s.len() - 1);
    }

    #[test]
    fn brace_inside_line_comment_is_ignored() {
        let s: &[u8] = b"{ // }}}}\n }";
        let close: usize = find_brace_close(s, 1).expect("balanced");
        assert_eq!(close, s.len() - 1);
    }

    #[test]
    fn paren_with_escaped_quote() {
        let s: &[u8] = b"(f('\\)'))";
        let close: usize = find_paren_close(s, 1).expect("balanced");
        assert_eq!(close, s.len() - 1);
    }

    #[test]
    fn unbalanced_returns_none() {
        assert!(find_brace_close(b"{ a { b }", 1).is_none());
    }

    #[test]
    fn head_clamps_to_char_boundary() {
        let s: &str = "abcé";
        assert_eq!(head(s, 100), "abcé");
        assert_eq!(head(s, 5), "abcé");
        assert_eq!(head(s, 4), "abc");
        assert_eq!(head(s, 3), "abc");
        assert_eq!(head(s, 0), "");
    }

    #[test]
    fn head_never_panics_when_cap_splits_a_multibyte_run() {
        let s: String = "\u{20ac}".repeat(2000);
        let h: &str = head(&s, 4096);
        assert!(h.len() <= 4096);
        assert!(h.len() > 4096 - 4);
        assert!(s.is_char_boundary(h.len()));
    }
}
