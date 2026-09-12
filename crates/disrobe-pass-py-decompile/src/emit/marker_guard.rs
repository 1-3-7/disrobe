use std::collections::BTreeSet;

use disrobe_py_marshal::{CodeObject, Object};

const MARKER_PREFIX: &str = "__DR_";
const MAX_SCAN_DEPTH: usize = 64;
const MAX_SCANNED_STRINGS: usize = 1 << 16;
const MAX_SCANNED_LITERAL_BYTES: usize = 1 << 20;
const UNNAMED_STEM: &str = "UNNAMED";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakedMarker {
    pub stem: String,
    pub line: usize,
}

fn token_at(text: &str, at: usize) -> Option<&str> {
    let rest: &str = text.get(at..)?;
    let end: usize = rest
        .char_indices()
        .find(|(_, ch): &(usize, char)| !(ch.is_ascii_alphanumeric() || *ch == '_'))
        .map_or(rest.len(), |(idx, _): (usize, char)| idx);
    rest.get(..end)
}

fn stem_of(token: &str) -> String {
    let trimmed: &str = token
        .strip_prefix(MARKER_PREFIX)
        .unwrap_or(token)
        .trim_matches('_');
    if trimmed.is_empty() {
        UNNAMED_STEM.to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn collect_tokens(text: &str, into: &mut BTreeSet<String>) {
    let mut from: usize = 0;
    while let Some(found) = text
        .get(from..)
        .and_then(|rest: &str| rest.find(MARKER_PREFIX))
    {
        let at: usize = from.saturating_add(found);
        let Some(token): Option<&str> = token_at(text, at) else {
            return;
        };
        from = at.saturating_add(token.len().max(MARKER_PREFIX.len()));
        into.insert(token.to_owned());
    }
}

fn is_marker_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn collect_byte_tokens(value: &[u8], byte_budget: &mut usize, into: &mut BTreeSet<String>) {
    let length: usize = value.len().min(*byte_budget);
    *byte_budget = byte_budget.saturating_sub(length);
    let bytes: &[u8] = &value[..length];
    let mut cursor: usize = 0;
    while let Some(found) = bytes.get(cursor..).and_then(|rest: &[u8]| {
        rest.windows(MARKER_PREFIX.len())
            .position(|window: &[u8]| window == MARKER_PREFIX.as_bytes())
    }) {
        let at: usize = cursor.saturating_add(found);
        let mut end: usize = at;
        while bytes
            .get(end)
            .is_some_and(|byte: &u8| is_marker_token_byte(*byte))
        {
            end = end.saturating_add(1);
        }
        let token: String = bytes[at..end]
            .iter()
            .map(|byte: &u8| char::from(*byte))
            .collect();
        cursor = end.max(at.saturating_add(MARKER_PREFIX.len()));
        let complete: bool = end < bytes.len()
            || length == value.len()
            || value
                .get(length)
                .is_some_and(|byte: &u8| !is_marker_token_byte(*byte));
        if complete {
            into.insert(token);
        }
    }
}

fn collect_object(
    object: &Object,
    depth: usize,
    budget: &mut usize,
    byte_budget: &mut usize,
    into: &mut BTreeSet<String>,
) {
    if depth > MAX_SCAN_DEPTH || *budget == 0 {
        return;
    }
    match object {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => {
            *budget = budget.saturating_sub(1);
            collect_tokens(value, into);
        }
        Object::Bytes(value) => {
            *budget = budget.saturating_sub(1);
            collect_byte_tokens(value, byte_budget, into);
        }
        Object::Tuple(items)
        | Object::List(items)
        | Object::Set(items)
        | Object::FrozenSet(items) => {
            for item in items {
                collect_object(item, depth.saturating_add(1), budget, byte_budget, into);
            }
        }
        Object::Dict(entries) | Object::FrozenDict(entries) => {
            for (key, value) in entries {
                collect_object(key, depth.saturating_add(1), budget, byte_budget, into);
                collect_object(value, depth.saturating_add(1), budget, byte_budget, into);
            }
        }
        Object::Code(inner) => {
            collect_code(inner, depth.saturating_add(1), budget, byte_budget, into);
        }
        _ => {}
    }
}

fn collect_code(
    code: &CodeObject,
    depth: usize,
    budget: &mut usize,
    byte_budget: &mut usize,
    into: &mut BTreeSet<String>,
) {
    if depth > MAX_SCAN_DEPTH || *budget == 0 {
        return;
    }
    for object in &code.consts {
        collect_object(object, depth, budget, byte_budget, into);
    }
}

#[must_use]
pub fn authentic_literal_markers(code: &CodeObject) -> BTreeSet<String> {
    let mut found: BTreeSet<String> = BTreeSet::new();
    let mut budget: usize = MAX_SCANNED_STRINGS;
    let mut byte_budget: usize = MAX_SCANNED_LITERAL_BYTES;
    collect_code(code, 0, &mut budget, &mut byte_budget, &mut found);
    found
}

fn string_is_formatted(source: &str, quote_at: usize) -> bool {
    let bytes: &[u8] = source.as_bytes();
    let mut start: usize = quote_at;
    while start > 0 && bytes[start.saturating_sub(1)].is_ascii_alphabetic() {
        start = start.saturating_sub(1);
    }
    bytes[start..quote_at]
        .iter()
        .any(|byte: &u8| matches!(*byte, b'f' | b'F' | b't' | b'T'))
}

fn is_triple_quote(bytes: &[u8], at: usize, quote: u8) -> bool {
    bytes.get(at..at.saturating_add(3)) == Some(&[quote, quote, quote])
}

fn leaked(token: &str, line: usize) -> LeakedMarker {
    LeakedMarker {
        stem: stem_of(token),
        line,
    }
}

fn marker_in_comment(source: &str, comment_at: usize) -> Option<&str> {
    let comment: &str = source.get(comment_at..)?;
    let end: usize = comment.find('\n').unwrap_or(comment.len());
    let marker_at: usize = comment.get(..end)?.find(MARKER_PREFIX)?;
    token_at(source, comment_at.saturating_add(marker_at))
}

fn scan_string(
    source: &str,
    cursor: &mut usize,
    line: &mut usize,
    quote: u8,
    triple: bool,
    formatted: bool,
    authentic_literals: &BTreeSet<String>,
) -> Option<LeakedMarker> {
    let bytes: &[u8] = source.as_bytes();
    while *cursor < bytes.len() {
        if source
            .get(*cursor..)
            .is_some_and(|rest: &str| rest.starts_with(MARKER_PREFIX))
        {
            let token: &str = token_at(source, *cursor)?;
            if !authentic_literals.contains(token) {
                return Some(leaked(token, *line));
            }
            *cursor = (*cursor).saturating_add(token.len());
            continue;
        }
        if formatted && bytes[*cursor] == b'{' {
            if bytes.get((*cursor).saturating_add(1)) == Some(&b'{') {
                *cursor = (*cursor).saturating_add(2);
                continue;
            }
            *cursor = (*cursor).saturating_add(1);
            if let Some(marker) = scan_interpolation(source, cursor, line, authentic_literals) {
                return Some(marker);
            }
            continue;
        }
        if formatted && bytes[*cursor] == b'}' {
            *cursor = (*cursor).saturating_add(
                if bytes.get((*cursor).saturating_add(1)) == Some(&b'}') {
                    2
                } else {
                    1
                },
            );
            continue;
        }
        if bytes[*cursor] == b'\\' {
            if bytes.get((*cursor).saturating_add(1)) == Some(&b'\n') {
                *line = (*line).saturating_add(1);
            }
            *cursor = (*cursor).saturating_add(2).min(bytes.len());
            continue;
        }
        if triple && is_triple_quote(bytes, *cursor, quote) {
            *cursor = (*cursor).saturating_add(3);
            return None;
        }
        if !triple && bytes[*cursor] == quote {
            *cursor = (*cursor).saturating_add(1);
            return None;
        }
        if bytes[*cursor] == b'\n' {
            *line = (*line).saturating_add(1);
        }
        *cursor = (*cursor).saturating_add(1);
    }
    None
}

fn scan_interpolation(
    source: &str,
    cursor: &mut usize,
    line: &mut usize,
    authentic_literals: &BTreeSet<String>,
) -> Option<LeakedMarker> {
    let bytes: &[u8] = source.as_bytes();
    let mut braces: usize = 0;
    while *cursor < bytes.len() {
        if source
            .get(*cursor..)
            .is_some_and(|rest: &str| rest.starts_with(MARKER_PREFIX))
        {
            let token: &str = token_at(source, *cursor)?;
            return Some(leaked(token, *line));
        }
        match bytes[*cursor] {
            b'#' => {
                if let Some(token) = marker_in_comment(source, *cursor) {
                    return Some(leaked(token, *line));
                }
                while *cursor < bytes.len() && bytes[*cursor] != b'\n' {
                    *cursor = (*cursor).saturating_add(1);
                }
            }
            quote @ (b'\'' | b'"') => {
                let triple: bool = is_triple_quote(bytes, *cursor, quote);
                let formatted: bool = string_is_formatted(source, *cursor);
                *cursor = (*cursor).saturating_add(if triple { 3 } else { 1 });
                if let Some(marker) = scan_string(
                    source,
                    cursor,
                    line,
                    quote,
                    triple,
                    formatted,
                    authentic_literals,
                ) {
                    return Some(marker);
                }
            }
            b'{' => {
                braces = braces.saturating_add(1);
                *cursor = (*cursor).saturating_add(1);
            }
            b'}' if braces == 0 => {
                *cursor = (*cursor).saturating_add(1);
                return None;
            }
            b'}' => {
                braces = braces.saturating_sub(1);
                *cursor = (*cursor).saturating_add(1);
            }
            b'\n' => {
                *line = (*line).saturating_add(1);
                *cursor = (*cursor).saturating_add(1);
            }
            _ => *cursor = (*cursor).saturating_add(1),
        }
    }
    None
}

#[must_use]
pub fn carries_a_marker(source: &str) -> bool {
    source.contains(MARKER_PREFIX)
}

#[must_use]
pub fn find_leaked_marker(
    source: &str,
    authentic_literals: &BTreeSet<String>,
) -> Option<LeakedMarker> {
    if !carries_a_marker(source) {
        return None;
    }
    let bytes: &[u8] = source.as_bytes();
    let mut cursor: usize = 0;
    let mut line: usize = 1;
    while cursor < bytes.len() {
        if source
            .get(cursor..)
            .is_some_and(|rest: &str| rest.starts_with(MARKER_PREFIX))
        {
            let token: &str = token_at(source, cursor)?;
            return Some(leaked(token, line));
        }
        match bytes[cursor] {
            b'#' => {
                if let Some(token) = marker_in_comment(source, cursor) {
                    return Some(leaked(token, line));
                }
                while cursor < bytes.len() && bytes[cursor] != b'\n' {
                    cursor = cursor.saturating_add(1);
                }
            }
            quote @ (b'\'' | b'\"') => {
                let triple: bool = is_triple_quote(bytes, cursor, quote);
                let formatted: bool = string_is_formatted(source, cursor);
                cursor = cursor.saturating_add(if triple { 3 } else { 1 });
                if let Some(marker) = scan_string(
                    source,
                    &mut cursor,
                    &mut line,
                    quote,
                    triple,
                    formatted,
                    authentic_literals,
                ) {
                    return Some(marker);
                }
            }
            b'\n' => {
                line = line.saturating_add(1);
                cursor = cursor.saturating_add(1);
            }
            _ => cursor = cursor.saturating_add(1),
        }
    }
    None
}
