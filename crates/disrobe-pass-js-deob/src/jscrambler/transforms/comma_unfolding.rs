use core::ops::Range;

use super::{TransformOpts, TransformOutput, TransformStats};
use crate::jscrambler::scanner::{
    apply_splice_edits, find_paren_close, skip_string_literal, skip_ws, slice_eq,
};

pub(in crate::jscrambler) fn detect(source: &str) -> usize {
    count_unfoldable_sequences(source).0
}

pub(in crate::jscrambler) fn reverse(source: &str, _opts: &TransformOpts) -> TransformOutput {
    let (count, edits): (usize, Vec<(Range<usize>, Option<String>)>) =
        count_unfoldable_sequences(source);
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

fn count_unfoldable_sequences(source: &str) -> (usize, Vec<(Range<usize>, Option<String>)>) {
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
        if !slice_eq(bytes, i, b"return") || (i > 0 && is_id_char(bytes[i - 1])) {
            i += 1;
            continue;
        }
        let after_return: usize = i + b"return".len();
        if after_return >= bytes.len() || is_id_char(bytes[after_return]) {
            i += 1;
            continue;
        }
        let lp: usize = skip_ws(bytes, after_return);
        if bytes.get(lp) != Some(&b'(') {
            i = lp;
            continue;
        }
        let Some(rp): Option<usize> = find_paren_close(bytes, lp + 1) else {
            i = lp + 1;
            continue;
        };
        let inner: &str = match source.get(lp + 1..rp) {
            Some(s) => s,
            None => {
                i = rp + 1;
                continue;
            }
        };
        let parts: Vec<&str> = split_top_level_commas(inner);
        if parts.len() < 2 {
            i = rp + 1;
            continue;
        }
        let trailing: &str = parts.last().copied().unwrap_or("");
        if trailing.is_empty() {
            i = rp + 1;
            continue;
        }
        let mut replacement: String = String::with_capacity(inner.len() + 16);
        for stmt in parts.iter().take(parts.len() - 1) {
            replacement.push_str(stmt.trim());
            replacement.push_str(";\n");
        }
        replacement.push_str("return ");
        replacement.push_str(trailing.trim());
        let stmt_end: usize = if bytes.get(rp + 1) == Some(&b';') {
            rp + 2
        } else {
            rp + 1
        };
        edits.push((i..stmt_end, Some(format!("{replacement};"))));
        count += 1;
        i = stmt_end;
    }
    (count, edits)
}

fn split_top_level_commas(text: &str) -> Vec<&str> {
    let bytes: &[u8] = text.as_bytes();
    let mut out: Vec<&str> = Vec::new();
    let mut start: usize = 0;
    let mut i: usize = 0;
    let mut paren: i32 = 0;
    let mut bracket: i32 = 0;
    let mut brace: i32 = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'\'' | b'"' | b'`' => {
                let Some(end): Option<usize> = skip_string_literal(bytes, i, b) else {
                    return Vec::new();
                };
                i = end;
                continue;
            }
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b'{' => brace += 1,
            b'}' => brace -= 1,
            b',' if paren == 0 && bracket == 0 && brace == 0 => {
                out.push(&text[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    out.push(&text[start..]);
    out
}

const fn is_id_char(b: u8) -> bool {
    matches!(b, b'_' | b'$') || b.is_ascii_alphanumeric()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_return_sequence() {
        let src: &str = "function f(){ return (a(), b(), c); }";
        assert_eq!(detect(src), 1);
    }

    #[test]
    fn reverses_return_sequence_to_statements() {
        let src: &str = "function f(){ return (a(), b(), c); }";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.stats.reversed, 1);
        assert!(out.source.contains("a();"));
        assert!(out.source.contains("b();"));
        assert!(out.source.contains("return c;"));
    }

    #[test]
    fn no_op_on_single_value_return() {
        let src: &str = "function f(){ return x; }";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
    }
}
