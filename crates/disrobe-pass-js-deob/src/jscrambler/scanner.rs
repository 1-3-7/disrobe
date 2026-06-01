use core::ops::Range;

pub(super) fn skip_ws(bytes: &[u8], start: usize) -> usize {
    let mut i: usize = start;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    i
}

pub(super) fn slice_eq(bytes: &[u8], start: usize, needle: &[u8]) -> bool {
    bytes
        .get(start..start + needle.len())
        .is_some_and(|s: &[u8]| s == needle)
}

pub(super) fn skip_string_literal(bytes: &[u8], start: usize, quote: u8) -> Option<usize> {
    let mut i: usize = start + 1;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b == b'\\' {
            i += 2;
            continue;
        }
        if b == quote {
            return Some(i + 1);
        }
        if quote == b'`' && b == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            i += 2;
            let mut depth: i32 = 1;
            while i < bytes.len() && depth > 0 {
                match bytes[i] {
                    b'{' => depth += 1,
                    b'}' => depth -= 1,
                    b'\'' | b'"' | b'`' => {
                        i = skip_string_literal(bytes, i, bytes[i])?;
                        continue;
                    }
                    _ => {}
                }
                i += 1;
            }
            continue;
        }
        i += 1;
    }
    None
}

pub(super) fn find_paren_close(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth: i32 = 1;
    let mut i: usize = start;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            b'\'' | b'"' | b'`' => {
                i = skip_string_literal(bytes, i, bytes[i])?;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    None
}

pub(super) fn find_brace_close(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth: i32 = 1;
    let mut i: usize = start;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            b'\'' | b'"' | b'`' => {
                i = skip_string_literal(bytes, i, bytes[i])?;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    None
}

pub(super) fn apply_splice_edits(
    source: &str,
    edits: &mut [(Range<usize>, Option<String>)],
) -> (String, usize) {
    edits.sort_by_key(|e: &(Range<usize>, Option<String>)| e.0.start);
    let mut out: String = String::with_capacity(source.len());
    let mut cursor: usize = 0;
    let mut applied: usize = 0;
    for (range, replacement) in edits.iter() {
        if range.start < cursor {
            continue;
        }
        out.push_str(&source[cursor..range.start]);
        if let Some(s) = replacement {
            out.push_str(s);
            applied += 1;
        }
        cursor = range.end;
    }
    out.push_str(&source[cursor..]);
    (out, applied)
}

pub(super) const fn is_ident_char(b: u8) -> bool {
    matches!(b, b'_' | b'$') || b.is_ascii_alphanumeric()
}

pub(super) const fn is_ident_start(b: u8) -> bool {
    matches!(b, b'_' | b'$') || b.is_ascii_alphabetic()
}

pub(super) fn boundary_before(bytes: &[u8], pos: usize) -> bool {
    if pos == 0 {
        return true;
    }
    !is_ident_char(bytes[pos - 1])
}

pub(super) fn boundary_after(bytes: &[u8], pos: usize) -> bool {
    bytes.get(pos).is_none_or(|b: &u8| !is_ident_char(*b))
}

pub(super) fn decode_x_or_u_escapes(s: &str) -> Option<String> {
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
        out.push(b as char);
        i += 1;
    }
    Some(out)
}

pub(super) fn js_quote(s: &str, prefer: char) -> String {
    let needs_double: bool = s.contains('"');
    let needs_single: bool = s.contains('\'');
    let quote: char = if needs_single && !needs_double {
        '"'
    } else if needs_double && !needs_single {
        '\''
    } else {
        prefer
    };
    let mut out: String = String::with_capacity(s.len() + 2);
    out.push(quote);
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

pub(super) fn is_valid_js_ident(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let bytes: &[u8] = s.as_bytes();
    if !is_ident_start(bytes[0]) {
        return false;
    }
    if matches!(
        s,
        "do" | "if"
            | "in"
            | "for"
            | "let"
            | "new"
            | "try"
            | "var"
            | "case"
            | "else"
            | "enum"
            | "null"
            | "this"
            | "true"
            | "void"
            | "with"
            | "await"
            | "break"
            | "catch"
            | "class"
            | "const"
            | "false"
            | "super"
            | "throw"
            | "while"
            | "yield"
            | "delete"
            | "export"
            | "import"
            | "return"
            | "switch"
            | "typeof"
            | "default"
            | "extends"
            | "finally"
            | "continue"
            | "function"
            | "debugger"
            | "instanceof"
    ) {
        return false;
    }
    bytes.iter().all(|b: &u8| is_ident_char(*b))
}
