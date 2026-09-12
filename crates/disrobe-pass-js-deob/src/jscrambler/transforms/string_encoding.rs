use core::ops::Range;

use super::{TransformOpts, TransformOutput, TransformStats};
use crate::jscrambler::scanner::{
    apply_splice_edits, decode_x_or_u_escapes, js_quote, skip_string_literal,
};

pub(in crate::jscrambler) fn detect(source: &str) -> usize {
    let bytes: &[u8] = source.as_bytes();
    let mut count: usize = 0;
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if matches!(b, b'\'' | b'"') {
            let Some(end): Option<usize> = skip_string_literal(bytes, i, b) else {
                break;
            };
            if let Some(inner) = source.get(i + 1..end - 1)
                && contains_string_escape(inner)
            {
                count += 1;
            }
            i = end;
            continue;
        }
        i += 1;
    }
    count
}

pub(in crate::jscrambler) fn reverse(source: &str, _opts: &TransformOpts) -> TransformOutput {
    let bytes: &[u8] = source.as_bytes();
    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    let mut stats: TransformStats = TransformStats::default();
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if matches!(b, b'\'' | b'"') {
            let Some(end): Option<usize> = skip_string_literal(bytes, i, b) else {
                break;
            };
            if let Some(inner) = source.get(i + 1..end - 1)
                && contains_string_escape(inner)
            {
                stats.matched += 1;
                if let Some(decoded) = decode_x_or_u_escapes(inner)
                    && decoded != inner
                {
                    let quoted: String = js_quote(&decoded, b as char);
                    edits.push((i..end, Some(quoted)));
                } else {
                    stats.skipped += 1;
                }
            }
            i = end;
            continue;
        }
        i += 1;
    }
    if edits.is_empty() {
        return TransformOutput {
            source: source.to_owned(),
            stats,
        };
    }
    let (rewritten, applied): (String, usize) = apply_splice_edits(source, &mut edits);
    stats.reversed = applied;
    TransformOutput {
        source: rewritten,
        stats,
    }
}

fn contains_string_escape(s: &str) -> bool {
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_hex_escape_strings() {
        let src: &str = r"var s = '\x68\x69';";
        assert!(detect(src) >= 1);
    }

    #[test]
    fn reverses_hex_escape_to_ascii() {
        let src: &str = r"var s = '\x68\x69';";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.stats.reversed, 1);
        assert!(out.source.contains("'hi'"));
    }

    #[test]
    fn no_op_on_clean_source() {
        let src: &str = r"var s = 'hi';";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.stats.matched, 0);
        assert_eq!(out.source, src);
    }

    #[test]
    fn reverses_unicode_curly_escape() {
        let src: &str = r"var s = '\u{1F600}';";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.stats.reversed, 1);
        assert!(out.source.contains('\u{1F600}'));
    }
}
