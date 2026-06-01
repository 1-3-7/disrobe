use base64::Engine as _;
use regex::{Captures, Regex};
use serde::Serialize;

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Serialize)]
pub(super) struct GlobalsEvalStats {
    pub(super) call_sites: usize,
    pub(super) evaluated: usize,
    pub(super) failed: usize,
}

pub(super) fn evaluate_globals(source: &str) -> (String, GlobalsEvalStats) {
    let mut stats: GlobalsEvalStats = GlobalsEvalStats::default();
    let Ok(single): Result<Regex, regex::Error> = Regex::new(
        r"\b(atob|unescape|decodeURI|decodeURIComponent)\s*\(\s*'([^'\\]*(?:\\.[^'\\]*)*)'\s*\)",
    ) else {
        return (source.to_owned(), stats);
    };
    let Ok(double): Result<Regex, regex::Error> = Regex::new(
        r#"\b(atob|unescape|decodeURI|decodeURIComponent)\s*\(\s*"([^"\\]*(?:\\.[^"\\]*)*)"\s*\)"#,
    ) else {
        return (source.to_owned(), stats);
    };

    let current: String = source.to_owned();
    let after_single: std::borrow::Cow<'_, str> =
        single.replace_all(&current, |caps: &Captures<'_>| {
            stats.call_sites += 1;
            apply_global(&caps[1], &js_unescape(&caps[2])).map_or_else(
                || {
                    stats.failed += 1;
                    caps[0].to_owned()
                },
                |decoded| {
                    stats.evaluated += 1;
                    js_quote(&decoded)
                },
            )
        });
    let intermediate: String = after_single.into_owned();
    let after_double: std::borrow::Cow<'_, str> =
        double.replace_all(&intermediate, |caps: &Captures<'_>| {
            stats.call_sites += 1;
            apply_global(&caps[1], &js_unescape(&caps[2])).map_or_else(
                || {
                    stats.failed += 1;
                    caps[0].to_owned()
                },
                |decoded| {
                    stats.evaluated += 1;
                    js_quote(&decoded)
                },
            )
        });
    (after_double.into_owned(), stats)
}

fn apply_global(name: &str, arg: &str) -> Option<String> {
    match name {
        "atob" => atob(arg),
        "unescape" => Some(js_unescape_global(arg)),
        "decodeURI" | "decodeURIComponent" => decode_uri_utf8(arg),
        _ => None,
    }
}

fn atob(s: &str) -> Option<String> {
    let bytes: Vec<u8> = base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .ok()?;
    let mut out: String = String::with_capacity(bytes.len());
    for b in bytes {
        out.push(b as char);
    }
    Some(out)
}

fn js_unescape_global(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len());
    let bytes: &[u8] = s.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 5 < bytes.len()
                && bytes[i + 1] == b'u'
                && let (Some(a), Some(b), Some(c), Some(d)) = (
                    hex_digit_u32(bytes[i + 2]),
                    hex_digit_u32(bytes[i + 3]),
                    hex_digit_u32(bytes[i + 4]),
                    hex_digit_u32(bytes[i + 5]),
                )
            {
                let cp: u32 = (a << 12) | (b << 8) | (c << 4) | d;
                if let Some(ch) = char::from_u32(cp) {
                    out.push(ch);
                    i += 6;
                    continue;
                }
            }
            if i + 2 < bytes.len()
                && let (Some(hi), Some(lo)) = (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2]))
            {
                out.push(((hi << 4) | lo) as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn decode_uri_utf8(s: &str) -> Option<String> {
    let bytes: &[u8] = s.as_bytes();
    let mut buf: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let hi: u8 = hex_digit(bytes[i + 1])?;
            let lo: u8 = hex_digit(bytes[i + 2])?;
            buf.push((hi << 4) | lo);
            i += 3;
        } else {
            buf.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(buf).ok()
}

const fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

const fn hex_digit_u32(b: u8) -> Option<u32> {
    match hex_digit(b) {
        Some(v) => Some(v as u32),
        None => None,
    }
}

fn js_unescape(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len());
    let mut iter: std::str::Chars<'_> = s.chars();
    while let Some(c) = iter.next() {
        if c == '\\' {
            match iter.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('\\') | None => out.push('\\'),
                Some('\'') => out.push('\''),
                Some('"') => out.push('"'),
                Some('0') => out.push('\0'),
                Some('x') => {
                    let hi: Option<char> = iter.next();
                    let lo: Option<char> = iter.next();
                    if let (Some(h), Some(l)) = (hi, lo)
                        && let (Some(a), Some(b)) = (h.to_digit(16), l.to_digit(16))
                        && let Ok(byte) = u8::try_from((a << 4) | b)
                    {
                        out.push(byte as char);
                    }
                }
                Some(other) => out.push(other),
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn js_quote(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            _ => out.push(c),
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn atob_decodes_base64_literal() {
        let (out, stats): (String, GlobalsEvalStats) =
            evaluate_globals("var x = atob('SGVsbG8=');");
        assert_eq!(out, "var x = 'Hello';");
        assert_eq!(stats.call_sites, 1);
        assert_eq!(stats.evaluated, 1);
    }

    #[test]
    fn unescape_decodes_url_encoded_literal() {
        let (out, stats): (String, GlobalsEvalStats) =
            evaluate_globals(r"var x = unescape('hello%20world');");
        assert_eq!(out, "var x = 'hello world';");
        assert_eq!(stats.evaluated, 1);
    }

    #[test]
    fn decode_uri_handles_unicode() {
        let (out, stats): (String, GlobalsEvalStats) =
            evaluate_globals(r"var euro = decodeURI('%E2%82%AC');");
        assert!(out.contains('€'), "expected euro sign; got: {out}");
        assert_eq!(stats.evaluated, 1);
    }

    #[test]
    fn leaves_non_literal_args_alone() {
        let src: &str = "var x = atob(input);";
        let (out, stats): (String, GlobalsEvalStats) = evaluate_globals(src);
        assert_eq!(out, src);
        assert_eq!(stats.call_sites, 0);
    }

    #[test]
    fn multiple_calls_in_one_pass() {
        let src: &str = "var a = atob('YQ=='), b = unescape('%62');";
        let (out, stats): (String, GlobalsEvalStats) = evaluate_globals(src);
        assert_eq!(out, "var a = 'a', b = 'b';");
        assert_eq!(stats.call_sites, 2);
        assert_eq!(stats.evaluated, 2);
    }

    #[test]
    fn bad_base64_does_not_replace() {
        let src: &str = "var x = atob('!!!invalid');";
        let (out, stats): (String, GlobalsEvalStats) = evaluate_globals(src);
        assert_eq!(out, src);
        assert!(stats.failed >= 1);
    }

    #[test]
    fn double_quoted_args_supported() {
        let (out, stats): (String, GlobalsEvalStats) =
            evaluate_globals(r#"var x = atob("SGVsbG8=");"#);
        assert_eq!(out, "var x = 'Hello';");
        assert_eq!(stats.evaluated, 1);
    }
}
