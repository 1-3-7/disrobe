use core::ops::Range;

use super::{TransformOpts, TransformOutput, TransformStats};
use crate::jscrambler::scanner::{
    apply_splice_edits, decode_x_or_u_escapes, is_valid_js_ident, skip_string_literal,
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
        if b == b'[' && i > 0 && is_member_lhs(bytes, i) {
            let key_start: usize = i + 1;
            let Some(key_quote_byte): Option<u8> = bytes.get(key_start).copied() else {
                i += 1;
                continue;
            };
            if !matches!(key_quote_byte, b'\'' | b'"') {
                i += 1;
                continue;
            }
            let Some(string_end): Option<usize> =
                skip_string_literal(bytes, key_start, key_quote_byte)
            else {
                i += 1;
                continue;
            };
            let close: usize = string_end;
            if bytes.get(close) != Some(&b']') {
                i += 1;
                continue;
            }
            let inner: &str = match source.get(key_start + 1..string_end - 1) {
                Some(s) => s,
                None => {
                    i += 1;
                    continue;
                }
            };
            count += 1;
            let decoded: String = decode_x_or_u_escapes(inner).unwrap_or_else(|| inner.to_owned());
            if !is_valid_js_ident(&decoded) {
                i += 1;
                continue;
            }
            edits.push((i..close + 1, Some(format!(".{decoded}"))));
            i = close + 1;
            continue;
        }
        i += 1;
    }
    (count, edits)
}

fn is_member_lhs(bytes: &[u8], lbracket: usize) -> bool {
    if lbracket == 0 {
        return false;
    }
    let mut j: usize = lbracket;
    while j > 0 {
        let prev: u8 = bytes[j - 1];
        if matches!(prev, b' ' | b'\t') {
            j -= 1;
            continue;
        }
        return matches!(prev, b')' | b']') || super::super::scanner::is_ident_char(prev);
    }
    false
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_bracket_member_access() {
        let src: &str = r#"a["foo"]"#;
        assert_eq!(detect(src), 1);
    }

    #[test]
    fn reverses_bracket_to_dot_when_ident_safe() {
        let src: &str = r#"var v = obj["foo"];"#;
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.stats.reversed, 1);
        assert!(out.source.contains("obj.foo"));
    }

    #[test]
    fn reverses_hex_encoded_key_to_dot() {
        let src: &str = r#"var v = obj["\x66\x6f\x6f"];"#;
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.stats.reversed, 1);
        assert!(out.source.contains("obj.foo"));
    }

    #[test]
    fn skips_non_ident_keys() {
        let src: &str = r#"var v = obj["foo-bar"];"#;
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.stats.reversed, 0);
        assert_eq!(out.source, src);
    }

    #[test]
    fn skips_reserved_word_keys() {
        let src: &str = r#"var v = obj["return"];"#;
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.stats.reversed, 0);
    }
}
