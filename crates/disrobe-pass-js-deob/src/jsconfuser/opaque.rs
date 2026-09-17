use std::ops::Range;

use regex::Regex;
use serde::Serialize;

use super::algebraic_opaque::{AlgebraicOpaqueResult, fold_algebraic_opaque};
use super::scanner::{
    apply_splice_edits, find_paren_close, scan_balanced_brace, skip_string_literal, skip_whitespace,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PredicateValue {
    AlwaysTrue,
    AlwaysFalse,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpaqueReversalResult {
    pub predicates_folded: usize,
    pub rewritten_source: String,
}

#[must_use]
pub fn reverse_opaque_predicates(source: &str) -> OpaqueReversalResult {
    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    collect_if_edits(source, &mut edits);
    collect_ternary_edits(source, &mut edits);
    let (text_rewritten, text_folded): (String, usize) = if edits.is_empty() {
        (source.to_owned(), 0)
    } else {
        apply_splice_edits(source, &mut edits)
    };
    let algebraic: AlgebraicOpaqueResult = fold_algebraic_opaque(&text_rewritten);
    OpaqueReversalResult {
        predicates_folded: text_folded + algebraic.predicates_folded,
        rewritten_source: algebraic.rewritten_source,
    }
}

#[must_use]
pub fn recognize_predicate(text: &str) -> Option<PredicateValue> {
    let normalized: String = normalize(text);
    let n: String = strip_outer_parens(&normalized);
    match n.as_str() {
        "!![]" | "[].length===0" | "true" => return Some(PredicateValue::AlwaysTrue),
        "![]" | "[].length" | "0" | "''" | "\"\"" | "null" | "undefined" | "false" => {
            return Some(PredicateValue::AlwaysFalse);
        }
        _ => {}
    }
    match_string_eq(&n)
        .or_else(|| match_typeof(&n))
        .or_else(|| match_numeric(&n))
}

fn match_string_eq(s: &str) -> Option<PredicateValue> {
    let cap: regex::Captures<'_> =
        Regex::new(r#"^(?:'([^'\\]*)'|"([^"\\]*)")(===|!==|==|!=)(?:'([^'\\]*)'|"([^"\\]*)")$"#)
            .ok()?
            .captures(s)?;
    let lhs: &str = cap.get(1).or_else(|| cap.get(2))?.as_str();
    let op: &str = cap.get(3)?.as_str();
    let rhs: &str = cap.get(4).or_else(|| cap.get(5))?.as_str();
    let equal: bool = lhs == rhs;
    let truth: bool = match op {
        "===" | "==" => equal,
        "!==" | "!=" => !equal,
        _ => return None,
    };
    Some(pick(truth))
}

fn match_typeof(s: &str) -> Option<PredicateValue> {
    let cap: regex::Captures<'_> = Regex::new(
        r#"^typeof(?:'[^']*'|"[^"]*"|(-?\d+(?:\.\d+)?))===(?:'(string|number)'|"(string|number)")$"#,
    )
    .ok()?
    .captures(s)?;
    let actual: &str = if cap.get(1).is_some() {
        "number"
    } else {
        "string"
    };
    let claimed: &str = cap.get(2).or_else(|| cap.get(3))?.as_str();
    Some(pick(actual == claimed))
}

fn match_numeric(s: &str) -> Option<PredicateValue> {
    if let Some(cap) = Regex::new(r"^Array\((\d+)\)\.length===(\d+)$")
        .ok()?
        .captures(s)
    {
        return Some(pick(cap.get(1)?.as_str() == cap.get(2)?.as_str()));
    }
    let cap: regex::Captures<'_> = Regex::new(r"^\(?(-?\d+)([+\-*^])(-?\d+)\)?===(-?\d+)$")
        .ok()?
        .captures(s)?;
    let (a, b, r): (i64, i64, i64) = (
        cap.get(1)?.as_str().parse().ok()?,
        cap.get(3)?.as_str().parse().ok()?,
        cap.get(4)?.as_str().parse().ok()?,
    );
    let computed: i64 = match cap.get(2)?.as_str() {
        "+" => a.checked_add(b)?,
        "-" => a.checked_sub(b)?,
        "*" => a.checked_mul(b)?,
        "^" => a ^ b,
        _ => return None,
    };
    Some(pick(computed == r))
}

const fn pick(cond: bool) -> PredicateValue {
    if cond {
        PredicateValue::AlwaysTrue
    } else {
        PredicateValue::AlwaysFalse
    }
}

fn normalize(text: &str) -> String {
    let bytes: &[u8] = text.as_bytes();
    let mut out: String = String::with_capacity(text.len());
    let mut i: usize = 0;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if let Some(q) = quote {
            out.push(b as char);
            if b == b'\\' && i + 1 < bytes.len() {
                out.push(bytes[i + 1] as char);
                i += 2;
                continue;
            }
            if b == q {
                quote = None;
            }
        } else if matches!(b, b'\'' | b'"' | b'`') {
            quote = Some(b);
            out.push(b as char);
        } else if !matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
            out.push(b as char);
        }
        i += 1;
    }
    out
}

fn strip_outer_parens(s: &str) -> String {
    let mut t: &str = s;
    while t.len() >= 2 && t.starts_with('(') && t.ends_with(')') {
        let inner: &str = &t[1..t.len() - 1];
        let mut depth: i32 = 0;
        let mut bad: bool = false;
        for (idx, &b) in inner.as_bytes().iter().enumerate() {
            if b == b'(' {
                depth += 1;
            } else if b == b')' {
                depth -= 1;
                if depth < 0 && idx + 1 < inner.len() {
                    bad = true;
                    break;
                }
            }
        }
        if bad || depth != 0 {
            break;
        }
        t = inner;
    }
    t.to_owned()
}

fn collect_if_edits(source: &str, edits: &mut Vec<(Range<usize>, Option<String>)>) {
    let Ok(re): Result<Regex, regex::Error> = Regex::new(r"\bif\s*\(") else {
        return;
    };
    let bytes: &[u8] = source.as_bytes();
    for mat in re.find_iter(source) {
        let open: usize = mat.end() - 1;
        let Some(close): Option<usize> = find_paren_close(bytes, open + 1) else {
            continue;
        };
        let cond: &str = source[open + 1..close].trim();
        if let Some(kept) = fold_logical(cond) {
            edits.push((mat.start()..close + 1, Some(format!("if ({kept})"))));
            continue;
        }
        let Some(value): Option<PredicateValue> = recognize_predicate(cond) else {
            continue;
        };
        let body_start: usize = skip_whitespace(bytes, close + 1);
        if body_start >= bytes.len() {
            continue;
        }
        let (consequent, body_end): (String, usize) = if bytes[body_start] == b'{' {
            let Some(body_close): Option<usize> = scan_balanced_brace(source, body_start + 1)
            else {
                continue;
            };
            (
                source[body_start + 1..body_close].trim().to_owned(),
                body_close + 1,
            )
        } else {
            let stmt_end: usize = find_simple_statement_end(bytes, body_start);
            if stmt_end >= bytes.len() || bytes[stmt_end] != b';' {
                continue;
            }
            let end: usize = stmt_end + 1;
            (source[body_start..stmt_end].trim().to_owned(), end)
        };
        let else_branch: Option<ElseBranch> = parse_else(source, body_end);
        let region_end: usize = else_branch
            .as_ref()
            .map_or(body_end, |branch: &ElseBranch| branch.end);
        let alternate: String =
            else_branch.map_or_else(String::new, |branch: ElseBranch| branch.body);
        let replacement: String = match value {
            PredicateValue::AlwaysTrue => consequent,
            PredicateValue::AlwaysFalse => alternate,
        };
        edits.push((mat.start()..region_end, Some(replacement)));
    }
}

struct ElseBranch {
    body: String,
    end: usize,
}

fn parse_else(source: &str, after_if: usize) -> Option<ElseBranch> {
    let bytes: &[u8] = source.as_bytes();
    let kw_start: usize = skip_whitespace(bytes, after_if);
    if !source[kw_start..].starts_with("else") {
        return None;
    }
    let after_kw: usize = kw_start + "else".len();
    if after_kw < bytes.len() && is_ident_byte(bytes[after_kw]) {
        return None;
    }
    let value_start: usize = skip_whitespace(bytes, after_kw);
    if value_start >= bytes.len() {
        return None;
    }
    if bytes[value_start] == b'{' {
        let close: usize = scan_balanced_brace(source, value_start + 1)?;
        return Some(ElseBranch {
            body: source[value_start + 1..close].trim().to_owned(),
            end: close + 1,
        });
    }
    if source[value_start..].starts_with("if") {
        return None;
    }
    let stmt_end: usize = find_simple_statement_end(bytes, value_start);
    Some(ElseBranch {
        body: source[value_start..stmt_end].trim().to_owned(),
        end: skip_semicolon(bytes, stmt_end),
    })
}

fn find_simple_statement_end(bytes: &[u8], start: usize) -> usize {
    let mut i: usize = start;
    let mut paren: i32 = 0;
    let mut brace: i32 = 0;
    let mut bracket: i32 = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' | b'"' | b'`' => {
                let Some(after): Option<usize> = skip_string_literal(bytes, i, bytes[i]) else {
                    return bytes.len();
                };
                i = after;
                continue;
            }
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'{' => brace += 1,
            b'}' if paren == 0 && bracket == 0 => {
                if brace == 0 {
                    return i;
                }
                brace -= 1;
            }
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b';' if paren == 0 && brace == 0 && bracket == 0 => return i,
            _ => {}
        }
        i += 1;
    }
    bytes.len()
}

fn skip_semicolon(bytes: &[u8], pos: usize) -> usize {
    if bytes.get(pos) == Some(&b';') {
        pos + 1
    } else {
        pos
    }
}

const fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

fn fold_logical(cond: &str) -> Option<String> {
    for (op, want) in [
        ("&&", PredicateValue::AlwaysTrue),
        ("||", PredicateValue::AlwaysFalse),
    ] {
        let Some((lhs, rhs)): Option<(&str, &str)> = split_top_level(cond, op) else {
            continue;
        };
        let l: &str = lhs.trim();
        let r: &str = rhs.trim();
        if recognize_predicate(l) == Some(want) {
            return Some(r.to_owned());
        }
        if recognize_predicate(r) == Some(want) {
            return Some(l.to_owned());
        }
    }
    None
}

fn split_top_level<'a>(cond: &'a str, op: &str) -> Option<(&'a str, &'a str)> {
    let bytes: &[u8] = cond.as_bytes();
    let op_bytes: &[u8] = op.as_bytes();
    let mut s: Scanner = Scanner::new();
    let mut i: usize = 0;
    while i + op_bytes.len() <= bytes.len() {
        if s.step(bytes, &mut i) {
            continue;
        }
        if s.is_top() && &bytes[i..i + op_bytes.len()] == op_bytes {
            return Some((&cond[..i], &cond[i + op_bytes.len()..]));
        }
        i += 1;
    }
    None
}

#[derive(Debug)]
struct Scanner {
    depth: [i32; 3],
    quote: Option<u8>,
}

impl Scanner {
    const fn new() -> Self {
        Self {
            depth: [0; 3],
            quote: None,
        }
    }
    const fn is_top(&self) -> bool {
        matches!(self.depth, [0, 0, 0]) && self.quote.is_none()
    }
    fn step(&mut self, bytes: &[u8], i: &mut usize) -> bool {
        let b: u8 = bytes[*i];
        if let Some(q) = self.quote {
            if b == b'\\' {
                *i += 2;
                return true;
            }
            if b == q {
                self.quote = None;
            }
            *i += 1;
            return true;
        }
        match b {
            b'\'' | b'"' | b'`' => self.quote = Some(b),
            b'(' => self.depth[0] += 1,
            b')' => self.depth[0] -= 1,
            b'[' => self.depth[1] += 1,
            b']' => self.depth[1] -= 1,
            b'{' => self.depth[2] += 1,
            b'}' => self.depth[2] -= 1,
            _ => {}
        }
        false
    }
}

fn collect_ternary_edits(source: &str, edits: &mut Vec<(Range<usize>, Option<String>)>) {
    let bytes: &[u8] = source.as_bytes();
    let mut s: Scanner = Scanner::new();
    let mut i: usize = 0;
    while i < bytes.len() {
        if s.step(bytes, &mut i) {
            continue;
        }
        let b: u8 = bytes[i];
        let next: Option<u8> = bytes.get(i + 1).copied();
        if b == b'?'
            && next != Some(b'.')
            && next != Some(b'?')
            && s.quote.is_none()
            && let Some((start, pred, cons_end, alt_end)) = parse_ternary(source, i)
            && let Some(value) = recognize_predicate(pred.trim())
        {
            let cons: &str = source[i + 1..cons_end].trim();
            let alt: &str = source[cons_end + 1..alt_end].trim();
            let chosen: &str = if value == PredicateValue::AlwaysTrue {
                cons
            } else {
                alt
            };
            edits.push((start..alt_end, Some(chosen.to_owned())));
            i = alt_end;
            continue;
        }
        i += 1;
    }
}

fn parse_ternary(source: &str, q_pos: usize) -> Option<(usize, String, usize, usize)> {
    let bytes: &[u8] = source.as_bytes();
    let mut j: usize = q_pos;
    while j > 0 && matches!(bytes[j - 1], b' ' | b'\t') {
        j -= 1;
    }
    if j == 0 || bytes[j - 1] != b')' {
        return None;
    }
    let mut depth: i32 = 1;
    let mut k: usize = j - 1;
    while k > 0 {
        k -= 1;
        if bytes[k] == b')' {
            depth += 1;
        } else if bytes[k] == b'(' {
            depth -= 1;
            if depth == 0 {
                let pred: String = source.get(k + 1..j - 1)?.to_owned();
                let (cons_end, alt_end): (usize, usize) = read_ternary_branches(source, q_pos + 1)?;
                return Some((k, pred, cons_end, alt_end));
            }
        }
    }
    None
}

fn read_ternary_branches(source: &str, after_q: usize) -> Option<(usize, usize)> {
    let bytes: &[u8] = source.as_bytes();
    let mut s: Scanner = Scanner::new();
    let mut cons_end: Option<usize> = None;
    let mut i: usize = after_q;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if s.is_top() {
            match b {
                b')' | b']' | b'}' => break,
                b':' if cons_end.is_none() => cons_end = Some(i),
                b';' | b',' => return cons_end.map(|c| (c, i)),
                _ => {}
            }
        }
        if s.step(bytes, &mut i) {
            continue;
        }
        i += 1;
    }
    cons_end.map(|c| (c, i))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn recognize_variants() {
        let pairs: &[(&str, PredicateValue)] = &[
            ("!![]", PredicateValue::AlwaysTrue),
            ("![]", PredicateValue::AlwaysFalse),
            ("[].length === 0", PredicateValue::AlwaysTrue),
            ("[].length", PredicateValue::AlwaysFalse),
            ("'a' === 'a'", PredicateValue::AlwaysTrue),
            ("'a' === 'b'", PredicateValue::AlwaysFalse),
            ("typeof 'x' === 'string'", PredicateValue::AlwaysTrue),
            ("typeof 0 === 'number'", PredicateValue::AlwaysTrue),
            ("(7 ^ 0) === 7", PredicateValue::AlwaysTrue),
            ("1 + 1 === 2", PredicateValue::AlwaysTrue),
            ("Array(1).length === 1", PredicateValue::AlwaysTrue),
        ];
        for (input, expected) in pairs {
            assert_eq!(
                recognize_predicate(input),
                Some(*expected),
                "predicate `{input}` mis-classified"
            );
        }
    }

    #[test]
    fn recognize_negative_cases() {
        for input in [
            "x",
            "obj.field",
            "a === b",
            "typeof x === 'string'",
            "Math.random() > 0.5",
        ] {
            assert_eq!(
                recognize_predicate(input),
                None,
                "false positive on `{input}`"
            );
        }
    }

    #[test]
    fn fold_and_short_circuit() {
        let src: &str = "if (!![] && x > 0) { doIt(); }";
        let result: OpaqueReversalResult = reverse_opaque_predicates(src);
        assert_eq!(result.predicates_folded, 1);
        assert!(
            result.rewritten_source.contains("if (x > 0) { doIt(); }"),
            "expected AND fold, got: {}",
            result.rewritten_source
        );
    }

    #[test]
    fn fold_or_short_circuit() {
        let src: &str = "if (![] || ready) { run(); }";
        let result: OpaqueReversalResult = reverse_opaque_predicates(src);
        assert_eq!(result.predicates_folded, 1);
        assert!(
            result.rewritten_source.contains("if (ready) { run(); }"),
            "expected OR fold, got: {}",
            result.rewritten_source
        );
    }
}
