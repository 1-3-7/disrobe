use super::eval::{EvalError, EvalResult};
use super::value::Value;

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
        _ => Err(EvalError::Unsupported),
    }
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
            use core::fmt::Write as _;
            let mut out: String = String::with_capacity(b.len() * 2);
            for byte in b {
                write!(out, "{byte:02x}").map_err(|_| EvalError::TypeMismatch)?;
            }
            Ok(Value::Str(out))
        }
        ("startswith", [Value::Bytes(prefix)]) => Ok(Value::Bool(b.starts_with(prefix))),
        ("endswith", [Value::Bytes(suffix)]) => Ok(Value::Bool(b.ends_with(suffix))),
        ("fromhex", [Value::Str(hex)]) => bytes_from_hex(hex),
        _ => Err(EvalError::Unsupported),
    }
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
