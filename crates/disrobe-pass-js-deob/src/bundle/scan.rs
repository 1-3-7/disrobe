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
                i = skip_string(bytes, i, bytes[i])?;
                continue;
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i = i.saturating_add(2);
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
                i = skip_string(bytes, i, bytes[i])?;
                continue;
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i = i.saturating_add(2);
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    None
}

pub(super) fn find_bracket_close(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth: i32 = 1;
    let mut i: usize = start;
    while i < bytes.len() {
        match bytes[i] {
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            b'\'' | b'"' | b'`' => {
                i = skip_string(bytes, i, bytes[i])?;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    None
}

pub(super) fn skip_string(bytes: &[u8], start: usize, quote: u8) -> Option<usize> {
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
        i += 1;
    }
    None
}

#[derive(Debug, Clone)]
pub(super) struct ObjectEntry {
    pub key: String,
    pub value_span: (usize, usize),
}

pub(super) fn find_top_level_object_entries(
    source: &str,
    object_open: usize,
) -> Option<Vec<ObjectEntry>> {
    let bytes: &[u8] = source.as_bytes();
    if bytes.get(object_open)? != &b'{' {
        return None;
    }
    let object_close: usize = find_brace_close(bytes, object_open + 1)?;
    let mut entries: Vec<ObjectEntry> = Vec::new();
    let mut i: usize = object_open + 1;
    while i < object_close {
        i = skip_trivia_and_commas(bytes, i, object_close);
        if i >= object_close {
            break;
        }
        let (key, key_end): (String, usize) = parse_object_key(source, i)?;
        i = skip_trivia(bytes, key_end, object_close);
        let separator: u8 = *bytes.get(i)?;
        let value_start: usize = match separator {
            b':' => {
                i += 1;
                skip_trivia(bytes, i, object_close)
            }
            b'(' => i,
            _ => return None,
        };
        let value_end: usize = read_value_end(bytes, value_start, object_close)?;
        entries.push(ObjectEntry {
            key,
            value_span: (value_start, value_end),
        });
        i = value_end;
    }
    Some(entries)
}

fn parse_object_key(source: &str, start: usize) -> Option<(String, usize)> {
    let bytes: &[u8] = source.as_bytes();
    match bytes.get(start)? {
        b'\'' | b'"' => {
            let quote: u8 = bytes[start];
            let end: usize = skip_string(bytes, start, quote)?;
            let inner: &str = source.get(start + 1..end - 1)?;
            Some((inner.to_owned(), end))
        }
        b'[' => {
            let close: usize = find_bracket_close(bytes, start + 1)?;
            let inner: &str = source.get(start + 1..close)?.trim();
            let unquoted: String = inner.trim_matches(['\'', '"']).to_owned();
            Some((unquoted, close + 1))
        }
        c if c.is_ascii_digit() => {
            let mut i: usize = start;
            while i < bytes.len() && bytes[i].is_ascii_alphanumeric() {
                i += 1;
            }
            Some((source.get(start..i)?.to_owned(), i))
        }
        c if c.is_ascii_alphabetic() || *c == b'_' || *c == b'$' => {
            let mut i: usize = start;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'_' | b'$'))
            {
                i += 1;
            }
            Some((source.get(start..i)?.to_owned(), i))
        }
        _ => None,
    }
}

fn read_value_end(bytes: &[u8], start: usize, hard_end: usize) -> Option<usize> {
    let mut i: usize = start;
    let mut paren: i32 = 0;
    let mut bracket: i32 = 0;
    let mut brace: i32 = 0;
    while i < hard_end {
        match bytes[i] {
            b',' if paren == 0 && bracket == 0 && brace == 0 => return Some(i),
            b'(' => paren += 1,
            b')' => {
                paren -= 1;
                if paren < 0 {
                    return Some(i);
                }
            }
            b'[' => bracket += 1,
            b']' => {
                bracket -= 1;
                if bracket < 0 {
                    return Some(i);
                }
            }
            b'{' => brace += 1,
            b'}' => {
                brace -= 1;
                if brace < 0 {
                    return Some(i);
                }
            }
            b'\'' | b'"' | b'`' => {
                i = skip_string(bytes, i, bytes[i])?;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    Some(hard_end)
}

fn skip_trivia(bytes: &[u8], start: usize, hard_end: usize) -> usize {
    skip_trivia_inner(bytes, start, hard_end, false)
}

fn skip_trivia_and_commas(bytes: &[u8], start: usize, hard_end: usize) -> usize {
    skip_trivia_inner(bytes, start, hard_end, true)
}

fn skip_trivia_inner(bytes: &[u8], start: usize, hard_end: usize, skip_commas: bool) -> usize {
    let limit: usize = hard_end.min(bytes.len());
    let mut i: usize = start;
    while i < limit {
        match bytes[i] {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b',' if skip_commas => i += 1,
            b'/' if i + 1 < limit && bytes[i + 1] == b'/' => {
                i += 2;
                while i < limit && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if i + 1 < limit && bytes[i + 1] == b'*' => {
                i += 2;
                while i + 1 < limit && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(limit);
            }
            _ => break,
        }
    }
    i
}
