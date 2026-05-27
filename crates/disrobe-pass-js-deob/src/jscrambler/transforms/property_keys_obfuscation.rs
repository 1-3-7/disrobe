use core::ops::Range;

use super::{TransformOpts, TransformOutput, TransformStats};
use crate::jscrambler::scanner::{
    apply_splice_edits, decode_x_or_u_escapes, is_valid_js_ident, js_quote, skip_string_literal,
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
        if matches!(b, b'`') {
            let Some(end): Option<usize> = skip_string_literal(bytes, i, b) else {
                break;
            };
            i = end;
            continue;
        }
        if matches!(b, b'\'' | b'"') {
            let Some(end): Option<usize> = skip_string_literal(bytes, i, b) else {
                break;
            };
            if let Some(inner) = source.get(i + 1..end - 1)
                && contains_escape(inner)
            {
                count += 1;
                if let Some(decoded) = decode_x_or_u_escapes(inner)
                    && decoded != inner
                {
                    if is_object_property_key_context(bytes, i) && is_valid_js_ident(&decoded) {
                        edits.push((i..end, Some(decoded)));
                    } else {
                        let quoted: String = js_quote(&decoded, b as char);
                        edits.push((i..end, Some(quoted)));
                    }
                }
            }
            i = end;
            continue;
        }
        i += 1;
    }
    (count, edits)
}

fn contains_escape(s: &str) -> bool {
    let bytes: &[u8] = s.as_bytes();
    let mut i: usize = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'\\' && matches!(bytes[i + 1], b'x' | b'u') {
            return true;
        }
        i += 1;
    }
    false
}

fn is_object_property_key_context(bytes: &[u8], string_start: usize) -> bool {
    let mut j: usize = string_start;
    while j > 0 {
        j -= 1;
        if matches!(bytes[j], b' ' | b'\t' | b'\r' | b'\n') {
            continue;
        }
        return matches!(bytes[j], b'{' | b',');
    }
    false
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_hex_encoded_keys() {
        let src: &str = r#"var o = {"\x66\x6f\x6f": 1};"#;
        assert!(detect(src) >= 1);
    }

    #[test]
    fn reverses_hex_key_to_ident_property() {
        let src: &str = r#"var o = {"\x66\x6f\x6f": 1};"#;
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.stats.reversed, 1);
        assert!(out.source.contains("foo: 1"));
    }

    #[test]
    fn keeps_string_when_key_not_valid_ident() {
        let src: &str = r#"var o = {"\x66\x2d\x6f": 1};"#;
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.stats.reversed, 1);
        assert!(out.source.contains("\"f-o\""));
    }

    #[test]
    fn no_op_on_clean_keys() {
        let src: &str = "var o = {foo: 1};";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
    }
}
