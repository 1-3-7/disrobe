use super::eval::{EvalError, EvalResult};
use super::value::{Key, Value};

const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

fn push_lower_hex_byte(out: &mut String, byte: u8) {
    out.push(LOWER_HEX[(byte >> 4) as usize] as char);
    out.push(LOWER_HEX[(byte & 0x0f) as usize] as char);
}

pub(crate) fn call_method(receiver: &Value, name: &str, args: &[Value]) -> EvalResult {
    match receiver {
        Value::Str(s) => str_method(s, name, args),
        Value::Bytes(b) => bytes_method(b, name, args),
        Value::List(items) | Value::Tuple(items) => seq_method(items, name, args),
        _ => Err(EvalError::Unsupported),
    }
}

fn str_method(s: &str, name: &str, args: &[Value]) -> EvalResult {
    match (name, args) {
        ("upper", []) => Ok(Value::Str(s.to_uppercase())),
        ("lower", []) => Ok(Value::Str(s.to_lowercase())),
        ("strip", []) => Ok(Value::Str(s.trim().to_owned())),
        ("lstrip", []) => Ok(Value::Str(s.trim_start().to_owned())),
        ("rstrip", []) => Ok(Value::Str(s.trim_end().to_owned())),
        ("strip", [Value::Str(chars)]) => Ok(Value::Str(trim_chars(s, chars, true, true))),
        ("lstrip", [Value::Str(chars)]) => Ok(Value::Str(trim_chars(s, chars, true, false))),
        ("rstrip", [Value::Str(chars)]) => Ok(Value::Str(trim_chars(s, chars, false, true))),
        ("encode", []) => Ok(Value::Bytes(s.as_bytes().to_vec())),
        ("encode", [Value::Str(codec)]) => encode_str(s, codec),
        ("split", []) => Ok(Value::List(
            s.split_whitespace()
                .map(|p: &str| Value::Str(p.to_owned()))
                .collect(),
        )),
        ("split", [Value::Str(sep)]) if !sep.is_empty() => Ok(Value::List(
            s.split(sep.as_str())
                .map(|p: &str| Value::Str(p.to_owned()))
                .collect(),
        )),
        ("rsplit", []) => Ok(Value::List(
            s.split_whitespace()
                .map(|p: &str| Value::Str(p.to_owned()))
                .collect(),
        )),
        ("replace", [Value::Str(old), Value::Str(new)]) if !old.is_empty() => {
            Ok(Value::Str(s.replace(old.as_str(), new.as_str())))
        }
        ("join", [Value::List(items) | Value::Tuple(items)]) => {
            let mut parts: Vec<String> = Vec::with_capacity(items.len());
            for item in items {
                let Value::Str(part) = item else {
                    return Err(EvalError::TypeMismatch);
                };
                parts.push(part.clone());
            }
            Ok(Value::Str(parts.join(s)))
        }
        ("startswith", [Value::Str(prefix)]) => Ok(Value::Bool(s.starts_with(prefix.as_str()))),
        ("endswith", [Value::Str(suffix)]) => Ok(Value::Bool(s.ends_with(suffix.as_str()))),
        ("find", [Value::Str(needle)]) => Ok(Value::Int(
            s.find(needle.as_str())
                .map_or(-1, |i: usize| i128::try_from(i).unwrap_or(-1)),
        )),
        ("count", [Value::Str(needle)]) if !needle.is_empty() => Ok(Value::Int(
            i128::try_from(s.matches(needle.as_str()).count()).map_err(|_| EvalError::Overflow)?,
        )),
        ("title", []) => Ok(Value::Str(title_case(s))),
        ("capitalize", []) => {
            let mut out: String = String::with_capacity(s.len());
            let mut chars: core::str::Chars<'_> = s.chars();
            if let Some(first) = chars.next() {
                out.extend(first.to_uppercase());
                for c in chars {
                    out.extend(c.to_lowercase());
                }
            }
            Ok(Value::Str(out))
        }
        ("swapcase", []) => Ok(Value::Str(
            s.chars()
                .map(|c: char| {
                    if c.is_uppercase() {
                        c.to_lowercase().collect::<String>()
                    } else if c.is_lowercase() {
                        c.to_uppercase().collect::<String>()
                    } else {
                        c.to_string()
                    }
                })
                .collect(),
        )),
        ("isdigit", []) => Ok(Value::Bool(
            !s.is_empty() && s.chars().all(|c: char| c.is_ascii_digit()),
        )),
        ("isalpha", []) => Ok(Value::Bool(
            !s.is_empty() && s.chars().all(char::is_alphabetic),
        )),
        ("isalnum", []) => Ok(Value::Bool(
            !s.is_empty() && s.chars().all(char::is_alphanumeric),
        )),
        ("isspace", []) => Ok(Value::Bool(
            !s.is_empty() && s.chars().all(char::is_whitespace),
        )),
        ("zfill", [Value::Int(width)]) if *width >= 0 => {
            let w: usize = usize::try_from(*width).map_err(|_| EvalError::Overflow)?;
            if s.len() >= w {
                Ok(Value::Str(s.to_owned()))
            } else {
                Ok(Value::Str(format!("{s:0>w$}")))
            }
        }
        ("removeprefix", [Value::Str(prefix)]) => Ok(Value::Str(
            s.strip_prefix(prefix.as_str()).unwrap_or(s).to_owned(),
        )),
        ("removesuffix", [Value::Str(suffix)]) if !suffix.is_empty() => Ok(Value::Str(
            s.strip_suffix(suffix.as_str()).unwrap_or(s).to_owned(),
        )),
        ("rfind", [Value::Str(needle)]) => Ok(Value::Int(char_index(s, s.rfind(needle.as_str())))),
        ("index", [Value::Str(needle)]) => s
            .find(needle.as_str())
            .map_or(Err(EvalError::IndexOutOfRange), |byte_idx: usize| {
                Ok(Value::Int(char_index(s, Some(byte_idx))))
            }),
        ("rindex", [Value::Str(needle)]) => s
            .rfind(needle.as_str())
            .map_or(Err(EvalError::IndexOutOfRange), |byte_idx: usize| {
                Ok(Value::Int(char_index(s, Some(byte_idx))))
            }),
        ("ljust", [Value::Int(width)]) if *width >= 0 => pad_str(s, *width, ' ', PadSide::Left),
        ("ljust", [Value::Int(width), Value::Str(fill)])
            if *width >= 0 && fill.chars().count() == 1 =>
        {
            pad_str(
                s,
                *width,
                fill.chars().next().ok_or(EvalError::TypeMismatch)?,
                PadSide::Left,
            )
        }
        ("rjust", [Value::Int(width)]) if *width >= 0 => pad_str(s, *width, ' ', PadSide::Right),
        ("rjust", [Value::Int(width), Value::Str(fill)])
            if *width >= 0 && fill.chars().count() == 1 =>
        {
            pad_str(
                s,
                *width,
                fill.chars().next().ok_or(EvalError::TypeMismatch)?,
                PadSide::Right,
            )
        }
        ("center", [Value::Int(width)]) if *width >= 0 => pad_str(s, *width, ' ', PadSide::Center),
        ("center", [Value::Int(width), Value::Str(fill)])
            if *width >= 0 && fill.chars().count() == 1 =>
        {
            pad_str(
                s,
                *width,
                fill.chars().next().ok_or(EvalError::TypeMismatch)?,
                PadSide::Center,
            )
        }
        ("expandtabs", []) => Ok(Value::Str(expand_tabs(s, 8))),
        ("expandtabs", [Value::Int(n)]) if (0..=256).contains(n) => {
            let width: usize = usize::try_from(*n).map_err(|_| EvalError::Overflow)?;
            Ok(Value::Str(expand_tabs(s, width)))
        }
        ("splitlines", []) => Ok(Value::List(
            split_lines(s)
                .into_iter()
                .map(Value::Str)
                .collect::<Vec<Value>>(),
        )),
        ("partition", [Value::Str(sep)]) if !sep.is_empty() => Ok(partition(s, sep, false)),
        ("rpartition", [Value::Str(sep)]) if !sep.is_empty() => Ok(partition(s, sep, true)),
        ("format", fmt_args) => str_format(s, fmt_args),
        ("translate", [Value::Dict(table)]) => str_translate(s, table),
        _ => Err(EvalError::Unsupported),
    }
}

#[derive(Debug, Clone, Copy)]
enum PadSide {
    Left,
    Right,
    Center,
}

fn pad_str(s: &str, width: i128, fill: char, side: PadSide) -> EvalResult {
    let current: usize = s.chars().count();
    let target: usize = usize::try_from(width).map_err(|_| EvalError::Overflow)?;
    if current >= target {
        return Ok(Value::Str(s.to_owned()));
    }
    let pad_total: usize = target - current;
    let (left, right): (usize, usize) = match side {
        PadSide::Left => (0, pad_total),
        PadSide::Right => (pad_total, 0),
        PadSide::Center => {
            let left: usize = pad_total / 2;
            (left, pad_total - left)
        }
    };
    let mut out: String = String::with_capacity(target);
    for _ in 0..left {
        out.push(fill);
    }
    out.push_str(s);
    for _ in 0..right {
        out.push(fill);
    }
    Ok(Value::Str(out))
}

fn expand_tabs(s: &str, width: usize) -> String {
    let mut out: String = String::with_capacity(s.len());
    let mut column: usize = 0;
    for c in s.chars() {
        match c {
            '\t' => {
                let spaces: usize = if width == 0 {
                    0
                } else {
                    width - (column % width)
                };
                for _ in 0..spaces {
                    out.push(' ');
                }
                column += spaces;
            }
            '\n' | '\r' => {
                out.push(c);
                column = 0;
            }
            c => {
                out.push(c);
                column += 1;
            }
        }
    }
    out
}

fn split_lines(s: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut current: String = String::new();
    let mut chars: core::iter::Peekable<core::str::Chars<'_>> = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\n' => {
                out.push(core::mem::take(&mut current));
            }
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push(core::mem::take(&mut current));
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

fn partition(s: &str, sep: &str, from_right: bool) -> Value {
    let found: Option<usize> = if from_right {
        s.rfind(sep)
    } else {
        s.find(sep)
    };
    found.map_or_else(
        || {
            if from_right {
                Value::Tuple(vec![
                    Value::Str(String::new()),
                    Value::Str(String::new()),
                    Value::Str(s.to_owned()),
                ])
            } else {
                Value::Tuple(vec![
                    Value::Str(s.to_owned()),
                    Value::Str(String::new()),
                    Value::Str(String::new()),
                ])
            }
        },
        |idx: usize| {
            let head: String = s[..idx].to_owned();
            let tail: String = s[idx + sep.len()..].to_owned();
            Value::Tuple(vec![
                Value::Str(head),
                Value::Str(sep.to_owned()),
                Value::Str(tail),
            ])
        },
    )
}

fn char_index(s: &str, byte_idx: Option<usize>) -> i128 {
    byte_idx.map_or(-1, |b: usize| {
        i128::try_from(s[..b].chars().count()).unwrap_or(-1)
    })
}

fn str_format(s: &str, args: &[Value]) -> EvalResult {
    let mut out: String = String::with_capacity(s.len());
    let mut auto_index: usize = 0;
    let mut chars: core::iter::Peekable<core::str::Chars<'_>> = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' => {
                if chars.peek() == Some(&'{') {
                    chars.next();
                    out.push('{');
                    continue;
                }
                let mut field: String = String::new();
                let mut closed: bool = false;
                for inner in chars.by_ref() {
                    if inner == '}' {
                        closed = true;
                        break;
                    }
                    field.push(inner);
                }
                if !closed {
                    return Err(EvalError::Unsupported);
                }
                if field.contains([':', '!', '.', '[']) {
                    return Err(EvalError::Unsupported);
                }
                let value: &Value = if field.is_empty() {
                    let idx: usize = auto_index;
                    auto_index += 1;
                    args.get(idx).ok_or(EvalError::IndexOutOfRange)?
                } else {
                    let idx: usize = field.parse::<usize>().map_err(|_| EvalError::Unsupported)?;
                    args.get(idx).ok_or(EvalError::IndexOutOfRange)?
                };
                out.push_str(&format_value_str(value)?);
            }
            '}' => {
                if chars.peek() == Some(&'}') {
                    chars.next();
                    out.push('}');
                } else {
                    return Err(EvalError::Unsupported);
                }
            }
            c => out.push(c),
        }
    }
    Ok(Value::Str(out))
}

fn format_value_str(v: &Value) -> core::result::Result<String, EvalError> {
    match v {
        Value::Str(s) => Ok(s.clone()),
        Value::Int(n) => Ok(n.to_string()),
        Value::Bool(b) => Ok(if *b { "True" } else { "False" }.to_owned()),
        Value::None => Ok("None".to_owned()),
        _ => Err(EvalError::Unsupported),
    }
}

fn str_translate(s: &str, table: &std::collections::BTreeMap<Key, Value>) -> EvalResult {
    let mut out: String = String::with_capacity(s.len());
    for c in s.chars() {
        let key: Key = Key::Int(i128::from(c as u32));
        match table.get(&key) {
            Some(Value::Int(code)) => {
                let cp: u32 = u32::try_from(*code).map_err(|_| EvalError::Overflow)?;
                out.push(char::from_u32(cp).ok_or(EvalError::TypeMismatch)?);
            }
            Some(Value::Str(replacement)) => out.push_str(replacement),
            Some(Value::None) => {}
            Some(_) => return Err(EvalError::TypeMismatch),
            None => out.push(c),
        }
    }
    Ok(Value::Str(out))
}

fn trim_chars(s: &str, chars: &str, left: bool, right: bool) -> String {
    let set: Vec<char> = chars.chars().collect();
    let mut trimmed: &str = s;
    if left {
        trimmed = trimmed.trim_start_matches(|c: char| set.contains(&c));
    }
    if right {
        trimmed = trimmed.trim_end_matches(|c: char| set.contains(&c));
    }
    trimmed.to_owned()
}

fn encode_str(s: &str, codec: &str) -> EvalResult {
    match normalize_codec(codec).as_str() {
        "utf-8" | "utf8" | "ascii" | "latin-1" | "latin1" | "iso-8859-1" => {
            Ok(Value::Bytes(s.as_bytes().to_vec()))
        }
        _ => Err(EvalError::Unsupported),
    }
}

fn normalize_codec(codec: &str) -> String {
    codec.trim().to_lowercase().replace('_', "-")
}

fn title_case(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len());
    let mut prev_alpha: bool = false;
    for c in s.chars() {
        if c.is_alphabetic() {
            if prev_alpha {
                out.extend(c.to_lowercase());
            } else {
                out.extend(c.to_uppercase());
            }
            prev_alpha = true;
        } else {
            out.push(c);
            prev_alpha = false;
        }
    }
    out
}

fn bytes_method(b: &[u8], name: &str, args: &[Value]) -> EvalResult {
    match (name, args) {
        ("decode", []) => Ok(Value::Str(
            std::str::from_utf8(b)
                .map_err(|_| EvalError::TypeMismatch)?
                .to_owned(),
        )),
        ("decode", [Value::Str(codec)]) => decode_bytes(b, codec),
        ("hex", []) => {
            let mut out: String = String::with_capacity(b.len() * 2);
            for byte in b {
                push_lower_hex_byte(&mut out, *byte);
            }
            Ok(Value::Str(out))
        }
        ("startswith", [Value::Bytes(prefix)]) => Ok(Value::Bool(b.starts_with(prefix))),
        ("endswith", [Value::Bytes(suffix)]) => Ok(Value::Bool(b.ends_with(suffix))),
        ("fromhex", [Value::Str(hex)]) => bytes_from_hex(hex),
        ("upper", []) => Ok(Value::Bytes(b.to_ascii_uppercase())),
        ("lower", []) => Ok(Value::Bytes(b.to_ascii_lowercase())),
        ("strip", []) => Ok(Value::Bytes(bytes_trim(b, true, true))),
        ("lstrip", []) => Ok(Value::Bytes(bytes_trim(b, true, false))),
        ("rstrip", []) => Ok(Value::Bytes(bytes_trim(b, false, true))),
        ("replace", [Value::Bytes(old), Value::Bytes(new)]) if !old.is_empty() => {
            Ok(Value::Bytes(bytes_replace(b, old, new)))
        }
        ("count", [Value::Bytes(needle)]) if !needle.is_empty() => Ok(Value::Int(
            i128::try_from(count_subslices(b, needle)).map_err(|_| EvalError::Overflow)?,
        )),
        ("find", [Value::Bytes(needle)]) => Ok(Value::Int(
            find_subslice(b, needle).map_or(-1, |i: usize| i128::try_from(i).unwrap_or(-1)),
        )),
        ("index", [Value::Bytes(needle)]) => {
            find_subslice(b, needle).map_or(Err(EvalError::IndexOutOfRange), |i: usize| {
                i128::try_from(i)
                    .map(Value::Int)
                    .map_err(|_| EvalError::Overflow)
            })
        }
        ("join", [Value::List(items) | Value::Tuple(items)]) => {
            let mut out: Vec<u8> = Vec::new();
            for (i, item) in items.iter().enumerate() {
                let Value::Bytes(part) = item else {
                    return Err(EvalError::TypeMismatch);
                };
                if i > 0 {
                    out.extend_from_slice(b);
                }
                out.extend_from_slice(part);
            }
            Ok(Value::Bytes(out))
        }
        _ => Err(EvalError::Unsupported),
    }
}

fn bytes_trim(b: &[u8], left: bool, right: bool) -> Vec<u8> {
    let mut start: usize = 0;
    let mut end: usize = b.len();
    if left {
        while start < end && b[start].is_ascii_whitespace() {
            start += 1;
        }
    }
    if right {
        while end > start && b[end - 1].is_ascii_whitespace() {
            end -= 1;
        }
    }
    b[start..end].to_vec()
}

fn bytes_replace(haystack: &[u8], old: &[u8], new: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(haystack.len());
    let mut i: usize = 0;
    while i < haystack.len() {
        if haystack[i..].starts_with(old) {
            out.extend_from_slice(new);
            i += old.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    out
}

fn count_subslices(haystack: &[u8], needle: &[u8]) -> usize {
    let mut count: usize = 0;
    let mut i: usize = 0;
    while i + needle.len() <= haystack.len() {
        if haystack[i..].starts_with(needle) {
            count += 1;
            i += needle.len();
        } else {
            i += 1;
        }
    }
    count
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window: &[u8]| window == needle)
}

fn bytes_from_hex(hex: &str) -> EvalResult {
    let cleaned: String = hex.chars().filter(|c: &char| !c.is_whitespace()).collect();
    if !cleaned.len().is_multiple_of(2) {
        return Err(EvalError::TypeMismatch);
    }
    let mut out: Vec<u8> = Vec::with_capacity(cleaned.len() / 2);
    let bytes: &[u8] = cleaned.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        let pair: &str =
            core::str::from_utf8(&bytes[i..i + 2]).map_err(|_| EvalError::TypeMismatch)?;
        let byte: u8 = u8::from_str_radix(pair, 16).map_err(|_| EvalError::TypeMismatch)?;
        out.push(byte);
        i += 2;
    }
    Ok(Value::Bytes(out))
}

fn decode_bytes(b: &[u8], codec: &str) -> EvalResult {
    match normalize_codec(codec).as_str() {
        "utf-8" | "utf8" | "ascii" => Ok(Value::Str(
            std::str::from_utf8(b)
                .map_err(|_| EvalError::TypeMismatch)?
                .to_owned(),
        )),
        "latin-1" | "latin1" | "iso-8859-1" => {
            let s: String = b.iter().map(|byte: &u8| char::from(*byte)).collect();
            Ok(Value::Str(s))
        }
        _ => Err(EvalError::Unsupported),
    }
}

fn seq_method(items: &[Value], name: &str, args: &[Value]) -> EvalResult {
    match (name, args) {
        ("count", [needle]) => {
            let mut n: i128 = 0;
            for item in items {
                if item == needle {
                    n = n.checked_add(1).ok_or(EvalError::Overflow)?;
                }
            }
            Ok(Value::Int(n))
        }
        ("index", [needle]) => {
            for (i, item) in items.iter().enumerate() {
                if item == needle {
                    return i128::try_from(i)
                        .map(Value::Int)
                        .map_err(|_| EvalError::Overflow);
                }
            }
            Err(EvalError::IndexOutOfRange)
        }
        _ => Err(EvalError::Unsupported),
    }
}
