use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub(super) struct NormalizeStringsResult {
    pub literals_normalized: usize,
    pub rewritten_source: String,
}

#[must_use]
pub(super) fn normalize_escaped_strings(source: &str) -> NormalizeStringsResult {
    let bytes: &[u8] = source.as_bytes();
    let mut out: String = String::with_capacity(source.len());
    let mut i: usize = 0;
    let mut normalized: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'\'' | b'"' => {
                if let Some((text, end, changed)) = normalize_literal(source, bytes, i, b) {
                    out.push_str(&text);
                    if changed {
                        normalized += 1;
                    }
                    i = end;
                } else {
                    out.push(b as char);
                    i += 1;
                }
            }
            b'`' => {
                if let Some((slice, end)) = skip_template(source, bytes, i) {
                    out.push_str(slice);
                    i = end;
                } else {
                    out.push('`');
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                let start: usize = i;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                out.push_str(&source[start..i]);
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                let start: usize = i;
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(bytes.len());
                out.push_str(&source[start..i]);
            }
            _ => {
                let ch_len: usize = utf8_len(b);
                let end: usize = (i + ch_len).min(bytes.len());
                out.push_str(&source[i..end]);
                i = end;
            }
        }
    }
    NormalizeStringsResult {
        literals_normalized: normalized,
        rewritten_source: out,
    }
}

const fn utf8_len(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b >> 5 == 0b110 {
        2
    } else if b >> 4 == 0b1110 {
        3
    } else if b >> 3 == 0b11110 {
        4
    } else {
        1
    }
}

fn normalize_literal(
    source: &str,
    bytes: &[u8],
    start: usize,
    quote: u8,
) -> Option<(String, usize, bool)> {
    let mut decoded: String = String::new();
    let mut changed: bool = false;
    let mut j: usize = start + 1;
    while j < bytes.len() {
        let b: u8 = bytes[j];
        if b == quote {
            let mut lit: String = String::with_capacity(decoded.len() + 2);
            lit.push(quote as char);
            lit.push_str(&decoded);
            lit.push(quote as char);
            return Some((lit, j + 1, changed));
        }
        if b == b'\\' {
            let esc: u8 = *bytes.get(j + 1)?;
            match esc {
                b'x' => {
                    let hi: u8 = *bytes.get(j + 2)?;
                    let lo: u8 = *bytes.get(j + 3)?;
                    if let Some(c) = decode_hex2(hi, lo)
                        && is_safe_inline(c, quote)
                    {
                        decoded.push(c);
                        changed = true;
                        j += 4;
                        continue;
                    }
                    decoded.push('\\');
                    decoded.push('x');
                    j += 2;
                }
                b'u' => {
                    let parsed: Option<(char, usize)> = if bytes.get(j + 2) == Some(&b'{') {
                        let close: usize = find_byte(bytes, j + 3, b'}')?;
                        let hex: &str = source.get(j + 3..close)?;
                        decode_hex_var(hex).map(|c: char| (c, close + 1))
                    } else {
                        let h: &str = source.get(j + 2..j + 6)?;
                        decode_hex4(h).map(|c: char| (c, j + 6))
                    };
                    if let Some((c, next)) = parsed
                        && is_safe_inline(c, quote)
                    {
                        decoded.push(c);
                        changed = true;
                        j = next;
                        continue;
                    }
                    decoded.push('\\');
                    decoded.push('u');
                    j += 2;
                }
                other => {
                    decoded.push('\\');
                    decoded.push(other as char);
                    j += 2;
                }
            }
            continue;
        }
        let ch_len: usize = utf8_len(b);
        let end: usize = (j + ch_len).min(bytes.len());
        decoded.push_str(source.get(j..end)?);
        j = end;
    }
    None
}

fn is_safe_inline(c: char, quote: u8) -> bool {
    if c == quote as char || c == '\\' {
        return false;
    }
    if c == '\n' || c == '\r' || c == '\t' {
        return false;
    }
    !c.is_control()
}

fn decode_hex2(hi: u8, lo: u8) -> Option<char> {
    let v: u8 = u8::from_str_radix(core::str::from_utf8(&[hi, lo]).ok()?, 16).ok()?;
    Some(v as char)
}

fn decode_hex4(h: &str) -> Option<char> {
    let v: u32 = u32::from_str_radix(h, 16).ok()?;
    char::from_u32(v)
}

fn decode_hex_var(h: &str) -> Option<char> {
    let v: u32 = u32::from_str_radix(h, 16).ok()?;
    char::from_u32(v)
}

fn find_byte(bytes: &[u8], start: usize, needle: u8) -> Option<usize> {
    let mut i: usize = start;
    while i < bytes.len() {
        if bytes[i] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn skip_template<'a>(source: &'a str, bytes: &[u8], start: usize) -> Option<(&'a str, usize)> {
    let mut i: usize = start + 1;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b == b'\\' {
            i += 2;
            continue;
        }
        if b == b'`' {
            return Some((source.get(start..i + 1)?, i + 1));
        }
        i += 1;
    }
    None
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn decodes_hex_space_escape() {
        let src: &str = "var x='calculator\\x20ready';";
        let r: NormalizeStringsResult = normalize_escaped_strings(src);
        assert_eq!(r.literals_normalized, 1);
        assert!(
            r.rewritten_source.contains("'calculator ready'"),
            "got {}",
            r.rewritten_source
        );
    }

    #[test]
    fn decodes_unicode_escape() {
        let src: &str = "const s=\"a\\u0062c\";";
        let r: NormalizeStringsResult = normalize_escaped_strings(src);
        assert!(
            r.rewritten_source.contains("\"abc\""),
            "got {}",
            r.rewritten_source
        );
    }

    #[test]
    fn keeps_quote_escape_intact() {
        let src: &str = "var x='it\\x27s';";
        let r: NormalizeStringsResult = normalize_escaped_strings(src);
        assert!(
            r.rewritten_source.contains("it\\x27s"),
            "must not break quoting: {}",
            r.rewritten_source
        );
    }

    #[test]
    fn leaves_plain_strings_unchanged() {
        let src: &str = "var x='hello world';";
        let r: NormalizeStringsResult = normalize_escaped_strings(src);
        assert_eq!(r.literals_normalized, 0);
        assert_eq!(r.rewritten_source, src);
    }

    #[test]
    fn ignores_escapes_in_template() {
        let src: &str = "var x=`a\\x20b`;";
        let r: NormalizeStringsResult = normalize_escaped_strings(src);
        assert_eq!(r.rewritten_source, src);
    }
}
