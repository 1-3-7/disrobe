use core::ops::Range;

use super::{TransformOpts, TransformOutput, TransformStats};
use crate::jscrambler::scanner::{apply_splice_edits, skip_string_literal};

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
    let bytes: &[u8] = body.as_bytes();
    let mut out: String = String::with_capacity(body.len());
    let mut i: usize = 0;
    let mut guard: u8 = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' {
            let Some(ch): Option<char> = body.get(i..).and_then(|rest: &str| rest.chars().next())
            else {
                break;
            };
            out.push(ch);
            i += ch.len_utf8();
            guard = guard.saturating_sub(1);
            continue;
        }
        if guard == 0
            && let Some((decoded, consumed)) = literal_hex_escape(bytes, i)
        {
            out.push(decoded);
            i += consumed;
            continue;
        }
        out.push('\\');
        i += 1;
        let Some(escaped): Option<char> = body.get(i..).and_then(|rest: &str| rest.chars().next())
        else {
            break;
        };
        out.push(escaped);
        i += escaped.len_utf8();
        guard = match escaped {
            'u' => 4,
            'x' => 2,
            'c' | 'k' | 'p' | 'P' => 1,
            _ => 0,
        };
    }
    out
}

fn literal_hex_escape(bytes: &[u8], backslash: usize) -> Option<(char, usize)> {
    let digits: usize = match bytes.get(backslash + 1)? {
        b'x' => 2,
        b'u' => 4,
        _ => return None,
    };
    let hex: &[u8] = bytes.get(backslash + 2..backslash + 2 + digits)?;
    if !hex.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let text: &str = core::str::from_utf8(hex).ok()?;
    let value: u32 = u32::from_str_radix(text, 16).ok()?;
    let decoded: char = char::from_u32(value)?;
    let literal_safe: bool = decoded.is_ascii_alphabetic()
        || matches!(
            decoded,
            ' ' | '_' | '!' | '#' | '%' | '&' | ':' | ';' | '<' | '=' | '>' | '@' | '~'
        );
    literal_safe.then_some((decoded, 2 + digits))
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
    fn decoding_keeps_every_other_regex_escape_intact() {
        let src: &str = r"var re = /\x61\/\d\n\x2e\x2f\u0062\c\x41/g;";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, r"var re = /a\/\d\n\x2e\x2fb\c\x41/g;");
    }

    #[test]
    fn no_op_on_clean_regex() {
        let src: &str = "var re = /foo/g;";
        let out: TransformOutput = reverse(src, &TransformOpts::default());
        assert_eq!(out.source, src);
    }
}
