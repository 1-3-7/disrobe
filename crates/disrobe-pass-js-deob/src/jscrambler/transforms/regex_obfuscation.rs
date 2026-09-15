use core::ops::Range;

use super::{TransformOpts, TransformOutput, TransformStats};
use crate::jscrambler::scanner::{apply_splice_edits, decode_x_or_u_escapes, skip_string_literal};

pub(in crate::jscrambler) fn detect(source: &str) -> usize {
    let bytes: &[u8] = source.as_bytes();
    let mut i: usize = 0;
    let mut count: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if matches!(b, b'\'' | b'"' | b'`') {
            let Some(end): Option<usize> = skip_string_literal(bytes, i, b) else {
                break;
            };
            i = end;
            continue;
        }
        if b == b'/'
            && i + 1 < bytes.len()
            && !matches!(bytes[i + 1], b'/' | b'*')
            && let Some((end, body)) = find_regex_literal(source, bytes, i)
            && body.contains("\\x")
        {
            count += 1;
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
        if matches!(b, b'\'' | b'"' | b'`') {
            let Some(end): Option<usize> = skip_string_literal(bytes, i, b) else {
                break;
            };
            i = end;
            continue;
        }
        if b == b'/'
            && i + 1 < bytes.len()
            && !matches!(bytes[i + 1], b'/' | b'*')
            && let Some((end, body)) = find_regex_literal(source, bytes, i)
        {
            if !body.contains("\\x") {
                i = end;
                continue;
            }
            stats.matched += 1;
            let decoded: String = decode_x_in_regex_body(&body);
            if decoded == body {
                stats.skipped += 1;
            } else {
                let flags: &str = source
                    .get(end_of_pattern(bytes, i)..end)
                    .unwrap_or_default();
                let rebuilt: String = format!("/{decoded}/{flags}");
                edits.push((i..end, Some(rebuilt)));
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

fn find_regex_literal(source: &str, bytes: &[u8], start: usize) -> Option<(usize, String)> {
    let mut i: usize = start + 1;
    let body_start: usize = i;
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
                let body: String = source.get(body_start..i)?.to_owned();
                let mut j: usize = i + 1;
                while j < bytes.len() && bytes[j].is_ascii_alphabetic() {
                    j += 1;
                }
                return Some((j, body));
            }
            b'\n' => return None,
            _ => i += 1,
        }
    }
    None
}

fn end_of_pattern(bytes: &[u8], start: usize) -> usize {
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
            b'/' if !in_class => return i + 1,
            _ => i += 1,
        }
    }
    i
}

fn decode_x_in_regex_body(body: &str) -> String {
    decode_x_or_u_escapes(body).unwrap_or_else(|| body.to_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_x_escape_in_regex() {
        let src: &str = r"var re = /\x66\x6f\x6f/;";
        assert_eq!(detect(src), 1);
    }

    #[test]
    fn reverses_x_escape_in_regex_body() {
        let src: &str = r"var re = /\x66\x6f\x6f/;";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.stats.reversed, 1);
        assert!(out.source.contains("/foo/"));
    }

    #[test]
    fn preserves_flags() {
        let src: &str = r"var re = /\x61\x62/gi;";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert!(out.source.contains("/ab/gi"));
    }

    #[test]
    fn no_op_on_clean_regex() {
        let src: &str = "var re = /foo/g;";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
    }
}
