use std::ops::Range;

use regex::Regex;
use serde::Serialize;

use super::scanner::{apply_splice_edits, scan_balanced_brace, scan_balanced_bracket};

#[derive(Debug, Clone, Serialize)]
pub struct ShuffleReversalResult {
    pub blocks_reordered: usize,
    pub rewritten_source: String,
}

#[must_use]
pub fn reverse_shuffle(source: &str) -> ShuffleReversalResult {
    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    let bytes: &[u8] = source.as_bytes();
    let Ok(decl_re): Result<Regex, regex::Error> = Regex::new(
        r"(?ms)(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*\[\s*((?:-?\d+\s*,\s*){2,}-?\d+)\s*\]\s*;",
    ) else {
        return passthrough(source);
    };
    for caps in decl_re.captures_iter(source) {
        let Some(name): Option<&str> = caps.get(1).map(|m: regex::Match<'_>| m.as_str()) else {
            continue;
        };
        let Some(list_match): Option<regex::Match<'_>> = caps.get(2) else {
            continue;
        };
        let order: Vec<usize> = parse_order(list_match.as_str());
        if order.is_empty() {
            continue;
        }
        if !is_valid_permutation(&order) {
            continue;
        }
        let Some((stmt_start, stmt_end, items)) = locate_companion_block(source, bytes, name)
        else {
            continue;
        };
        if items.len() != order.len() {
            continue;
        }
        let mut reordered: Vec<&str> = Vec::with_capacity(items.len());
        for &idx in &order {
            let Some(stmt) = items.get(idx) else {
                reordered.clear();
                break;
            };
            reordered.push(stmt);
        }
        if reordered.is_empty() {
            continue;
        }
        let joined: String = reordered.join("\n");
        if let Some(whole) = caps.get(0) {
            edits.push((whole.start()..whole.end(), Some(String::new())));
        }
        edits.push((stmt_start..stmt_end, Some(joined)));
    }
    if edits.is_empty() {
        return passthrough(source);
    }
    let reordered_count: usize = edits
        .iter()
        .filter(|(_, repl): &&(Range<usize>, Option<String>)| {
            repl.as_ref().is_some_and(|s: &String| !s.is_empty())
        })
        .count();
    let (rewritten, _): (String, usize) = apply_splice_edits(source, &mut edits);
    ShuffleReversalResult {
        blocks_reordered: reordered_count,
        rewritten_source: rewritten,
    }
}

fn passthrough(source: &str) -> ShuffleReversalResult {
    ShuffleReversalResult {
        blocks_reordered: 0,
        rewritten_source: source.to_owned(),
    }
}

fn parse_order(raw: &str) -> Vec<usize> {
    raw.split(',')
        .filter_map(|s: &str| s.trim().parse::<usize>().ok())
        .collect()
}

fn is_valid_permutation(order: &[usize]) -> bool {
    let len: usize = order.len();
    let mut seen: Vec<bool> = vec![false; len];
    for &v in order {
        if v >= len || seen[v] {
            return false;
        }
        seen[v] = true;
    }
    true
}

fn locate_companion_block(
    source: &str,
    bytes: &[u8],
    order_name: &str,
) -> Option<(usize, usize, Vec<String>)> {
    let pattern: &str = r"(?ms)\(\s*function\s*\(\s*\)\s*\{\s*var\s+([A-Za-z_$][\w$]*)\s*=\s*\[";
    let _ = order_name;
    let Ok(re): Result<Regex, regex::Error> = Regex::new(pattern) else {
        return None;
    };
    let mat: regex::Match<'_> = re.find(source)?;
    let array_open: usize = mat.end() - 1;
    let array_close: usize = scan_balanced_bracket(source, array_open + 1)?;
    let body_text: &str = source.get(array_open + 1..array_close)?;
    let items: Vec<String> = split_top_level_statements(body_text);
    let after_array: usize = array_close + 1;
    let mut tail: usize = after_array;
    while tail < bytes.len() && bytes[tail] != b'}' {
        tail += 1;
    }
    let outer_close: usize = scan_balanced_brace(source, mat.end())?;
    let mut stop: usize = outer_close + 1;
    while stop < bytes.len() && matches!(bytes[stop], b')' | b'(' | b';' | b' ' | b'\n' | b'\r') {
        stop += 1;
    }
    Some((mat.start(), stop, items))
}

fn split_top_level_statements(body: &str) -> Vec<String> {
    let bytes: &[u8] = body.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut start: usize = 0;
    let mut paren: i32 = 0;
    let mut brace: i32 = 0;
    let mut bracket: i32 = 0;
    let mut quote: Option<u8> = None;
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if let Some(q) = quote {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match b {
            b'\'' | b'"' | b'`' => quote = Some(b),
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b'{' => brace += 1,
            b'}' => brace -= 1,
            b',' if paren == 0 && bracket == 0 && brace == 0 => {
                out.push(body[start..i].trim().to_owned());
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    let tail: &str = body[start..].trim();
    if !tail.is_empty() {
        out.push(tail.to_owned());
    }
    out.into_iter().filter(|s: &String| !s.is_empty()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restores_order_from_three_statement_block() {
        let src: &str = "var __ord = [2, 0, 1];\n(function () { var __stmts = [\"first()\", \"second()\", \"third()\"]; })();";
        let r: ShuffleReversalResult = reverse_shuffle(src);
        assert_eq!(r.blocks_reordered, 1);
        let pos_third: Option<usize> = r.rewritten_source.find("third()");
        let pos_first: Option<usize> = r.rewritten_source.find("first()");
        let pos_second: Option<usize> = r.rewritten_source.find("second()");
        assert!(pos_third.is_some() && pos_first.is_some() && pos_second.is_some());
        assert!(pos_third < pos_first);
        assert!(pos_first < pos_second);
    }

    #[test]
    fn ignores_mismatched_lengths() {
        let src: &str =
            "var __ord = [1, 0];\n(function () { var __stmts = [\"a\", \"b\", \"c\"]; })();";
        let r: ShuffleReversalResult = reverse_shuffle(src);
        assert_eq!(r.blocks_reordered, 0);
    }

    #[test]
    fn ignores_non_permutation() {
        let src: &str =
            "var __ord = [0, 0, 0];\n(function () { var __stmts = [\"a\", \"b\", \"c\"]; })();";
        let r: ShuffleReversalResult = reverse_shuffle(src);
        assert_eq!(r.blocks_reordered, 0);
    }
}
