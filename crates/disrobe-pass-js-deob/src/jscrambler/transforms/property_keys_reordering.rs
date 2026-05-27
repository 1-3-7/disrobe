use core::ops::Range;

use super::{TransformOpts, TransformOutput, TransformStats};
use crate::error::{Error, Result};
use crate::jscrambler::scanner::{
    apply_splice_edits, find_brace_close, is_ident_char, is_valid_js_ident, skip_string_literal,
};

pub(in crate::jscrambler) fn detect(source: &str) -> usize {
    scan(source).0
}

pub(in crate::jscrambler) fn reverse(source: &str, _opts: &TransformOpts) -> TransformOutput {
    let (count, edits): (usize, Vec<(Range<usize>, Option<String>)>) = scan(source);
    let mut stats: TransformStats = TransformStats {
        matched: count,
        ..TransformStats::default()
    };
    if edits.is_empty() {
        return TransformOutput {
            source: source.to_owned(),
            stats,
        };
    }
    let mut edits_mut: Vec<(Range<usize>, Option<String>)> = edits;
    let (rewritten, applied): (String, usize) = apply_splice_edits(source, &mut edits_mut);
    stats.reversed = applied;
    TransformOutput {
        source: rewritten,
        stats,
    }
}

pub(in crate::jscrambler) fn reverse_strict(
    source: &str,
    opts: &TransformOpts,
) -> Result<TransformOutput> {
    let out: TransformOutput = reverse(source, opts);
    if out.stats.matched == 0 {
        return Err(Error::TransformNotYetImplemented {
            transform: "propertyKeysReordering",
        });
    }
    Ok(out)
}

fn scan(source: &str) -> (usize, Vec<(Range<usize>, Option<String>)>) {
    let bytes: &[u8] = source.as_bytes();
    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    let mut count: usize = 0;
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if matches!(b, b'\'' | b'"' | b'`') {
            let Some(end): Option<usize> = skip_string_literal(bytes, i, b) else {
                break;
            };
            i = end;
            continue;
        }
        if b == b'{' && is_object_literal_context(bytes, i) {
            let Some(close): Option<usize> = find_brace_close(bytes, i + 1) else {
                i += 1;
                continue;
            };
            let inner: &str = match source.get(i + 1..close) {
                Some(s) => s,
                None => {
                    i = close + 1;
                    continue;
                }
            };
            if let Some(reordered) = try_reorder(inner) {
                count += 1;
                edits.push((i + 1..close, Some(reordered)));
            }
            i = close + 1;
            continue;
        }
        i += 1;
    }
    (count, edits)
}

fn is_object_literal_context(bytes: &[u8], pos: usize) -> bool {
    let mut j: usize = pos;
    while j > 0 {
        j -= 1;
        if matches!(bytes[j], b' ' | b'\t' | b'\r' | b'\n') {
            continue;
        }
        return matches!(bytes[j], b'=' | b'(' | b',' | b'[' | b':' | b'?' | b'>')
            || (slice_eq_back(bytes, j + 1, b"return") || slice_eq_back(bytes, j + 1, b"throw"));
    }
    false
}

fn slice_eq_back(bytes: &[u8], end: usize, needle: &[u8]) -> bool {
    if end < needle.len() {
        return false;
    }
    let start: usize = end - needle.len();
    if &bytes[start..end] != needle {
        return false;
    }
    if start > 0 && is_ident_char(bytes[start - 1]) {
        return false;
    }
    true
}

fn try_reorder(inner: &str) -> Option<String> {
    let bytes: &[u8] = inner.as_bytes();
    let mut props: Vec<(String, String)> = Vec::new();
    let mut i: usize = 0;
    let mut start: usize = 0;
    let mut depth_paren: i32 = 0;
    let mut depth_brace: i32 = 0;
    let mut depth_bracket: i32 = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'\'' | b'"' | b'`' => {
                let end: usize = skip_string_literal(bytes, i, b)?;
                i = end;
                continue;
            }
            b'(' => depth_paren += 1,
            b')' => depth_paren -= 1,
            b'{' => depth_brace += 1,
            b'}' => depth_brace -= 1,
            b'[' => depth_bracket += 1,
            b']' => depth_bracket -= 1,
            b',' if depth_paren == 0 && depth_brace == 0 && depth_bracket == 0 => {
                let part: &str = &inner[start..i];
                if let Some((k, v)) = split_prop(part) {
                    props.push((k, v));
                } else {
                    return None;
                }
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if start < bytes.len() {
        let part: &str = inner[start..].trim();
        if !part.is_empty() {
            if let Some((k, v)) = split_prop(part) {
                props.push((k, v));
            } else {
                return None;
            }
        }
    }
    if props.len() < 2 {
        return None;
    }
    let original_order: Vec<String> = props
        .iter()
        .map(|p: &(String, String)| p.0.clone())
        .collect();
    props.sort_by(|a: &(String, String), b: &(String, String)| a.0.cmp(&b.0));
    let new_order: Vec<String> = props
        .iter()
        .map(|p: &(String, String)| p.0.clone())
        .collect();
    if original_order == new_order {
        return None;
    }
    let mut out: String = String::from(" ");
    for (idx, (k, v)) in props.iter().enumerate() {
        if idx > 0 {
            out.push_str(", ");
        }
        if is_valid_js_ident(k) {
            out.push_str(k);
        } else {
            out.push('"');
            out.push_str(k);
            out.push('"');
        }
        out.push_str(": ");
        out.push_str(v);
    }
    out.push(' ');
    Some(out)
}

fn split_prop(part: &str) -> Option<(String, String)> {
    let trimmed: &str = part.trim();
    if trimmed.is_empty() {
        return None;
    }
    let bytes: &[u8] = trimmed.as_bytes();
    let mut depth_paren: i32 = 0;
    let mut depth_brace: i32 = 0;
    let mut depth_bracket: i32 = 0;
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'\'' | b'"' | b'`' => {
                let end: usize = skip_string_literal(bytes, i, b)?;
                i = end;
                continue;
            }
            b'(' => depth_paren += 1,
            b')' => depth_paren -= 1,
            b'{' => depth_brace += 1,
            b'}' => depth_brace -= 1,
            b'[' => depth_bracket += 1,
            b']' => depth_bracket -= 1,
            b':' if depth_paren == 0 && depth_brace == 0 && depth_bracket == 0 => {
                let raw_key: &str = trimmed[..i].trim();
                let value: &str = trimmed[i + 1..].trim();
                let key: String = raw_key
                    .trim_matches(|c: char| c == '\'' || c == '"')
                    .to_owned();
                if key.is_empty() || value.is_empty() {
                    return None;
                }
                return Some((key, value.to_owned()));
            }
            _ => {}
        }
        i += 1;
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detect_finds_reordered_keys() {
        let src: &str = "var o = {b: 1, a: 2};";
        assert!(detect(src) >= 1);
    }

    #[test]
    fn reorders_keys_alphabetically() {
        let src: &str = "var o = {c: 1, a: 2, b: 3};";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert!(out.stats.reversed >= 1);
        let a_pos: usize = out.source.find("a: 2").unwrap();
        let b_pos: usize = out.source.find("b: 3").unwrap();
        let c_pos: usize = out.source.find("c: 1").unwrap();
        assert!(a_pos < b_pos);
        assert!(b_pos < c_pos);
    }

    #[test]
    fn no_op_on_already_sorted() {
        let src: &str = "var o = {a: 1, b: 2};";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
    }

    #[test]
    fn returns_typed_error_in_strict_mode_when_nothing_matches() {
        let res: Result<TransformOutput> = reverse_strict("var x = 1;", &TransformOpts::default());
        assert!(res.is_err());
    }

    #[test]
    fn skips_block_statement_braces() {
        let src: &str = "function f() { var x = 1; return x; }";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
    }
}
