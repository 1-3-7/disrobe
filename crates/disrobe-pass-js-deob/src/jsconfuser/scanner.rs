pub(super) fn scan_balanced_brace(source: &str, start: usize) -> Option<usize> {
    let bytes: &[u8] = source.as_bytes();
    let mut depth: i32 = 1;
    let mut i: usize = start;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'\'' | b'"' | b'`' => {
                i = skip_string_literal(bytes, i, b)?;
                continue;
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i += 2;
                continue;
            }
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

pub(super) fn skip_whitespace(bytes: &[u8], start: usize) -> usize {
    let mut i: usize = start;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    i
}

pub(super) fn scan_balanced_bracket(source: &str, start: usize) -> Option<usize> {
    let bytes: &[u8] = source.as_bytes();
    let mut depth: i32 = 1;
    let mut i: usize = start;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'\'' | b'"' | b'`' => {
                i = skip_string_literal(bytes, i, b)?;
                continue;
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i += 2;
                continue;
            }
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
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

pub(super) fn consume_trailing_semicolon(source: &str, after_bracket: usize) -> usize {
    let bytes: &[u8] = source.as_bytes();
    let mut i: usize = after_bracket;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    if i < bytes.len() && bytes[i] == b';' {
        i + 1
    } else {
        after_bracket
    }
}

pub(super) fn find_paren_close(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i: usize = start;
    let mut depth: i32 = 1;
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

pub(super) fn apply_splice_edits(
    source: &str,
    edits: &mut [(std::ops::Range<usize>, Option<String>)],
) -> (String, usize) {
    edits.sort_by_key(|e| e.0.start);
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

pub(super) fn split_top_level_args(text: &str) -> Vec<String> {
    let bytes: &[u8] = text.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut start: usize = 0;
    let mut i: usize = 0;
    let mut paren: i32 = 0;
    let mut bracket: i32 = 0;
    let mut brace: i32 = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'\'' | b'"' | b'`' => {
                let Some(after): Option<usize> = skip_string_literal(bytes, i, b) else {
                    return Vec::new();
                };
                i = after;
                continue;
            }
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b'{' => brace += 1,
            b'}' => brace -= 1,
            b',' if paren == 0 && bracket == 0 && brace == 0 => {
                out.push(text[start..i].trim().to_owned());
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    let tail: &str = text[start..].trim();
    if !tail.is_empty() || !out.is_empty() {
        out.push(tail.to_owned());
    }
    out
}

pub(super) fn read_function_expression(
    source: &str,
    after_keyword: usize,
) -> Option<(String, usize)> {
    let bytes: &[u8] = source.as_bytes();
    if after_keyword < 8 {
        return None;
    }
    let header_start: usize = after_keyword.checked_sub(8)?;
    if &bytes[header_start..after_keyword] != b"function" {
        return None;
    }
    let mut i: usize = after_keyword;
    while i < bytes.len() && bytes[i] != b'(' {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    let paren_close: usize = find_paren_close(bytes, i + 1)?;
    let body_open: usize = skip_whitespace(bytes, paren_close + 1);
    if body_open >= bytes.len() || bytes[body_open] != b'{' {
        return None;
    }
    let body_close: usize = scan_balanced_brace(source, body_open + 1)?;
    let fn_source: String = source.get(header_start..=body_close)?.to_owned();
    Some((fn_source, body_close + 1))
}

pub(super) fn decode_string_literal_at(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    if start >= bytes.len() {
        return None;
    }
    let quote: u8 = bytes[start];
    if !matches!(quote, b'\'' | b'"' | b'`') {
        return None;
    }
    let mut j: usize = start + 1;
    let mut literal: String = String::new();
    while j < bytes.len() {
        let b: u8 = bytes[j];
        if b == b'\\' {
            if j + 1 >= bytes.len() {
                return None;
            }
            let esc: u8 = bytes[j + 1];
            match esc {
                b'n' => literal.push('\n'),
                b't' => literal.push('\t'),
                b'r' => literal.push('\r'),
                b'\\' => literal.push('\\'),
                b'\'' => literal.push('\''),
                b'"' => literal.push('"'),
                b'`' => literal.push('`'),
                b'0' => literal.push('\0'),
                b'x' => {
                    if j + 3 >= bytes.len() {
                        return None;
                    }
                    let hi: char = bytes[j + 2] as char;
                    let lo: char = bytes[j + 3] as char;
                    let v: u8 = u8::from_str_radix(&format!("{hi}{lo}"), 16).ok()?;
                    literal.push(v as char);
                    j += 4;
                    continue;
                }
                other => literal.push(other as char),
            }
            j += 2;
            continue;
        }
        if b == quote {
            return Some((literal, j + 1));
        }
        literal.push(b as char);
        j += 1;
    }
    None
}
