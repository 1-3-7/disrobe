use std::ops::Range;

use serde::Serialize;

use super::scanner::{apply_splice_edits, skip_string_literal};

#[derive(Debug, Clone, Serialize)]
pub struct StringEncodingResult {
    pub literals_decoded: usize,
    pub rewritten_source: String,
}

#[must_use]
pub fn reverse_string_encoding(source: &str) -> StringEncodingResult {
    let bytes: &[u8] = source.as_bytes();
    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if matches!(b, b'\'' | b'"') {
            let Some(end): Option<usize> = skip_string_literal(bytes, i, b) else {
                break;
            };
            if let Some(inner_str) = source.get(i + 1..end - 1)
                && contains_escape(inner_str)
                && let Some(decoded) = decode_escapes(inner_str)
                && decoded != inner_str
            {
                let quote: char = b as char;
                let needs_double: bool = decoded.contains('"');
                let needs_single: bool = decoded.contains('\'');
                let final_quote: char = if needs_single && !needs_double {
                    '"'
                } else if needs_double && !needs_single {
                    '\''
                } else {
                    quote
                };
                let mut rendered: String = String::with_capacity(decoded.len() + 2);
                rendered.push(final_quote);
                for ch in decoded.chars() {
                    match ch {
                        '\\' => rendered.push_str("\\\\"),
                        '\n' => rendered.push_str("\\n"),
                        '\r' => rendered.push_str("\\r"),
                        '\t' => rendered.push_str("\\t"),
                        c if c == final_quote => {
                            rendered.push('\\');
                            rendered.push(c);
                        }
                        c => rendered.push(c),
                    }
                }
                rendered.push(final_quote);
                edits.push((i..end, Some(rendered)));
            }
            i = end;
            continue;
        }
        i += 1;
    }
    if edits.is_empty() {
        return StringEncodingResult {
            literals_decoded: 0,
            rewritten_source: source.to_owned(),
        };
    }
    let (rewritten, decoded_count): (String, usize) = apply_splice_edits(source, &mut edits);
    StringEncodingResult {
        literals_decoded: decoded_count,
        rewritten_source: rewritten,
    }
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

fn decode_escapes(s: &str) -> Option<String> {
    let bytes: &[u8] = s.as_bytes();
    let mut out: String = String::with_capacity(s.len());
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b == b'\\' && i + 1 < bytes.len() {
            let esc: u8 = bytes[i + 1];
            match esc {
                b'x' => {
                    if i + 3 >= bytes.len() {
                        return None;
                    }
                    let hi: char = bytes[i + 2] as char;
                    let lo: char = bytes[i + 3] as char;
                    let value: u32 = u32::from_str_radix(&format!("{hi}{lo}"), 16).ok()?;
                    out.push(char::from_u32(value)?);
                    i += 4;
                    continue;
                }
                b'u' if bytes.get(i + 2) == Some(&b'{') => {
                    let close_rel: usize = bytes[i + 3..].iter().position(|&b: &u8| b == b'}')?;
                    let close: usize = i + 3 + close_rel;
                    let hex: &str = s.get(i + 3..close)?;
                    let value: u32 = u32::from_str_radix(hex, 16).ok()?;
                    out.push(char::from_u32(value)?);
                    i = close + 1;
                    continue;
                }
                b'u' => {
                    if i + 5 >= bytes.len() {
                        return None;
                    }
                    let hex: &str = s.get(i + 2..i + 6)?;
                    let unit: u32 = u32::from_str_radix(hex, 16).ok()?;
                    if (0xD800..=0xDBFF).contains(&unit)
                        && matches!(bytes.get(i + 6), Some(b'\\'))
                        && bytes.get(i + 7) == Some(&b'u')
                        && bytes.len() >= i + 12
                    {
                        let low_hex: &str = s.get(i + 8..i + 12)?;
                        let low: u32 = u32::from_str_radix(low_hex, 16).ok()?;
                        if (0xDC00..=0xDFFF).contains(&low) {
                            let code: u32 = 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00);
                            out.push(char::from_u32(code)?);
                            i += 12;
                            continue;
                        }
                    }
                    out.push(char::from_u32(unit)?);
                    i += 6;
                    continue;
                }
                b'n' => out.push('\n'),
                b't' => out.push('\t'),
                b'r' => out.push('\r'),
                b'\\' => out.push('\\'),
                b'\'' => out.push('\''),
                b'"' => out.push('"'),
                b'`' => out.push('`'),
                b'0' => out.push('\0'),
                b'b' => out.push('\u{0008}'),
                b'f' => out.push('\u{000C}'),
                b'v' => out.push('\u{000B}'),
                other => out.push(other as char),
            }
            i += 2;
            continue;
        }
        let ch: char = s.get(i..)?.chars().next()?;
        out.push(ch);
        i += ch.len_utf8();
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_x_escapes_to_plain_ascii() {
        let src: &str = "var s = '\\x68\\x69';";
        let r: StringEncodingResult = reverse_string_encoding(src);
        assert_eq!(r.literals_decoded, 1);
        assert!(r.rewritten_source.contains("'hi'"));
    }

    #[test]
    fn decodes_unicode_curly_escapes() {
        let src: &str = "var s = '\\u{1F600}';";
        let r: StringEncodingResult = reverse_string_encoding(src);
        assert_eq!(r.literals_decoded, 1);
        assert!(r.rewritten_source.contains('\u{1F600}'));
    }

    #[test]
    fn leaves_plain_strings_alone() {
        let src: &str = "var s = 'hello';";
        let r: StringEncodingResult = reverse_string_encoding(src);
        assert_eq!(r.literals_decoded, 0);
        assert_eq!(r.rewritten_source, src);
    }

    #[test]
    fn switches_quote_when_decoded_contains_original_quote() {
        let src: &str = r"var s = '\x27hi\x27';";
        let r: StringEncodingResult = reverse_string_encoding(src);
        assert_eq!(r.literals_decoded, 1);
        assert!(r.rewritten_source.contains("\"'hi'\""));
    }
}
