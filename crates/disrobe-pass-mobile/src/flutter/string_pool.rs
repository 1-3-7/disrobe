use serde::{Deserialize, Serialize};

const MIN_STRING_CHARS: usize = 2;

const MAX_STRING_CHARS: usize = 1 << 16;

const SMI_TAG_MASK: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DartStringRole {
    LibraryUri,
    GetterSelector,
    SetterSelector,
    InitSelector,
    ClassName,
    MethodOrField,
    Literal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartPoolString {
    pub offset: usize,
    pub text: String,
    pub role: DartStringRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartStringPool {
    pub total_strings: usize,
    pub library_uris: Vec<String>,
    pub class_names: Vec<String>,
    pub getter_selectors: Vec<String>,
    pub setter_selectors: Vec<String>,
    pub init_selectors: Vec<String>,
    pub method_or_field_names: Vec<String>,
    pub literals: Vec<String>,
    pub strings: Vec<DartPoolString>,
}

#[must_use]
pub fn recover_string_pool(isolate_data: &[u8]) -> DartStringPool {
    let raw: Vec<DartPoolString> = scan_one_byte_strings(isolate_data);
    let mut library_uris: Vec<String> = Vec::new();
    let mut class_names: Vec<String> = Vec::new();
    let mut getter_selectors: Vec<String> = Vec::new();
    let mut setter_selectors: Vec<String> = Vec::new();
    let mut init_selectors: Vec<String> = Vec::new();
    let mut method_or_field_names: Vec<String> = Vec::new();
    let mut literals: Vec<String> = Vec::new();

    for s in &raw {
        match s.role {
            DartStringRole::LibraryUri => library_uris.push(s.text.clone()),
            DartStringRole::ClassName => class_names.push(s.text.clone()),
            DartStringRole::GetterSelector => {
                getter_selectors.push(scrub_selector(&s.text, "get:"));
            }
            DartStringRole::SetterSelector => {
                setter_selectors.push(scrub_selector(&s.text, "set:"));
            }
            DartStringRole::InitSelector => {
                init_selectors.push(scrub_selector(&s.text, "init:"));
            }
            DartStringRole::MethodOrField => {
                method_or_field_names.push(strip_privacy_hash(&s.text));
            }
            DartStringRole::Literal => literals.push(s.text.clone()),
        }
    }

    dedup_sorted(&mut library_uris);
    dedup_sorted(&mut class_names);
    dedup_sorted(&mut getter_selectors);
    dedup_sorted(&mut setter_selectors);
    dedup_sorted(&mut init_selectors);
    dedup_sorted(&mut method_or_field_names);
    dedup_sorted(&mut literals);

    DartStringPool {
        total_strings: raw.len(),
        library_uris,
        class_names,
        getter_selectors,
        setter_selectors,
        init_selectors,
        method_or_field_names,
        literals,
        strings: raw,
    }
}

fn dedup_sorted(v: &mut Vec<String>) {
    v.sort_unstable();
    v.dedup();
}

#[must_use]
fn scrub_selector(text: &str, prefix: &str) -> String {
    let body: &str = text.strip_prefix(prefix).unwrap_or(text);
    strip_privacy_hash(body)
}

#[must_use]
fn strip_privacy_hash(name: &str) -> String {
    match name.split_once('@') {
        Some((head, tail)) => match tail.find('.') {
            Some(dot) => format!("{head}{}", &tail[dot..]),
            None => head.to_owned(),
        },
        None => name.to_owned(),
    }
}

#[must_use]
fn scan_one_byte_strings(data: &[u8]) -> Vec<DartPoolString> {
    let mut out: Vec<DartPoolString> = Vec::new();
    let mut i: usize = 0;
    let len: usize = data.len();
    while i + 1 < len {
        if let Some((char_count, header_len)) = read_smi_length(data, i) {
            let body_start: usize = i + header_len;
            let body_end: usize = body_start + char_count;
            if (MIN_STRING_CHARS..=MAX_STRING_CHARS).contains(&char_count)
                && body_end <= len
                && is_one_byte_string_body(&data[body_start..body_end])
                && let Ok(text) = std::str::from_utf8(&data[body_start..body_end])
            {
                let role: DartStringRole = classify(text);
                out.push(DartPoolString {
                    offset: i,
                    text: text.to_owned(),
                    role,
                });
                i = body_end;
                continue;
            }
        }
        i += 1;
    }
    out
}

#[must_use]
fn read_smi_length(data: &[u8], at: usize) -> Option<(usize, usize)> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    let mut consumed: usize = 0;
    while consumed < 10 {
        let byte: u8 = *data.get(at + consumed)?;
        consumed += 1;
        if byte >= 0x80 {
            value |= u64::from(byte & 0x7f).checked_shl(shift)?;
            if value & SMI_TAG_MASK != 0 {
                return None;
            }
            let char_count: u64 = value >> 1;
            return Some((usize::try_from(char_count).ok()?, consumed));
        }
        value |= u64::from(byte & 0x7f).checked_shl(shift)?;
        shift += 7;
    }
    None
}

#[must_use]
fn is_one_byte_string_body(body: &[u8]) -> bool {
    body.iter().all(|b: &u8| (0x20..0x7f).contains(b))
}

#[must_use]
fn classify(text: &str) -> DartStringRole {
    if is_library_uri(text) {
        return DartStringRole::LibraryUri;
    }
    if text.starts_with("get:") {
        return DartStringRole::GetterSelector;
    }
    if text.starts_with("set:") {
        return DartStringRole::SetterSelector;
    }
    if text.starts_with("init:") {
        return DartStringRole::InitSelector;
    }
    if is_class_name(text) {
        return DartStringRole::ClassName;
    }
    if is_member_name(text) {
        return DartStringRole::MethodOrField;
    }
    DartStringRole::Literal
}

#[must_use]
fn is_library_uri(s: &str) -> bool {
    s.starts_with("package:")
        || s.starts_with("dart:")
        || (s.contains('/') && s.ends_with(".dart"))
        || s.ends_with(".dart")
}

#[must_use]
fn is_identifier_run(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c: char| c.is_ascii_alphanumeric() || c == '_')
}

#[must_use]
fn is_class_name(s: &str) -> bool {
    if !is_identifier_run(s) {
        return false;
    }
    let first: char = match s.chars().next() {
        Some(c) => c,
        None => return false,
    };
    let leading: char = if first == '_' {
        match s.chars().nth(1) {
            Some(c) => c,
            None => return false,
        }
    } else {
        first
    };
    leading.is_ascii_uppercase()
}

#[must_use]
fn is_member_name(s: &str) -> bool {
    let core: &str = s.split('@').next().unwrap_or(s);
    let dotless: &str = core.split('.').next().unwrap_or(core);
    if dotless.is_empty()
        || !dotless
            .chars()
            .all(|c: char| c.is_ascii_alphanumeric() || c == '_')
    {
        return false;
    }
    let first: char = match dotless.chars().next() {
        Some(c) => c,
        None => return false,
    };
    let leading: char = if first == '_' {
        match dotless.chars().nth(1) {
            Some(c) => c,
            None => return false,
        }
    } else {
        first
    };
    leading.is_ascii_lowercase()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn smi_len(char_count: usize) -> Vec<u8> {
        let mut value: u64 = (char_count as u64) << 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let low: u8 = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(low | 0x80);
                return out;
            }
            out.push(low);
        }
    }

    fn string_object(text: &str) -> Vec<u8> {
        let mut out: Vec<u8> = smi_len(text.len());
        out.extend_from_slice(text.as_bytes());
        out
    }

    #[test]
    fn decodes_single_byte_length_string() {
        let mut buf: Vec<u8> = vec![0x00, 0x00];
        buf.extend_from_slice(&string_object("widget-alpha"));
        buf.push(0x00);
        let pool: DartStringPool = recover_string_pool(&buf);
        assert!(
            pool.literals.iter().any(|s: &String| s == "widget-alpha"),
            "12-char string must decode from a one-byte SMI length, got {:?}",
            pool.literals
        );
    }

    #[test]
    fn decodes_multi_byte_length_string() {
        let long: String = format!("error: {}", "spaced words ".repeat(8));
        assert!(
            long.len() > 63,
            "must exceed the single-byte length boundary"
        );
        let mut buf: Vec<u8> = vec![0x00];
        buf.extend_from_slice(&string_object(&long));
        let pool: DartStringPool = recover_string_pool(&buf);
        assert!(
            pool.literals.iter().any(|s: &String| s == &long),
            "a >63-char literal needs a two-byte SMI length to decode, got {:?}",
            pool.literals
        );
    }

    #[test]
    fn classifies_selectors_and_libraries() {
        let mut buf: Vec<u8> = Vec::new();
        for tok in [
            "get:length",
            "set:value",
            "init:_table",
            "package:app/main.dart",
            "dart:core",
            "InventoryItem",
            "_PrivateState",
            "extendedValue",
        ] {
            buf.push(0x00);
            buf.extend_from_slice(&string_object(tok));
        }
        let pool: DartStringPool = recover_string_pool(&buf);
        assert!(pool.getter_selectors.iter().any(|s: &String| s == "length"));
        assert!(pool.setter_selectors.iter().any(|s: &String| s == "value"));
        assert!(pool.init_selectors.iter().any(|s: &String| s == "_table"));
        assert!(
            pool.library_uris
                .iter()
                .any(|s: &String| s == "package:app/main.dart")
        );
        assert!(pool.library_uris.iter().any(|s: &String| s == "dart:core"));
        assert!(
            pool.class_names
                .iter()
                .any(|s: &String| s == "InventoryItem")
        );
        assert!(
            pool.class_names
                .iter()
                .any(|s: &String| s == "_PrivateState")
        );
        assert!(
            pool.method_or_field_names
                .iter()
                .any(|s: &String| s == "extendedValue")
        );
    }

    #[test]
    fn selector_prefix_and_privacy_hash_are_stripped() {
        let mut b: Vec<u8> = vec![0u8];
        b.extend_from_slice(&string_object("get:_error@5048458"));
        let pool: DartStringPool = recover_string_pool(&b);
        assert_eq!(
            pool.getter_selectors.first().map(String::as_str),
            Some("_error"),
            "the get: prefix and the @hash must both be stripped"
        );
    }

    #[test]
    fn rejects_odd_smi_as_non_string() {
        let odd_len_terminal: u8 = (((3u64 << 1) | 1) as u8) | 0x80;
        let mut buf: Vec<u8> = vec![odd_len_terminal];
        buf.extend_from_slice(b"abc");
        let pool: DartStringPool = recover_string_pool(&buf);
        assert!(
            !pool.literals.iter().any(|s: &String| s == "abc"),
            "a set tag bit means Mint, not a one-byte string header"
        );
    }

    #[test]
    fn rejects_non_ascii_body() {
        let mut buf: Vec<u8> = smi_len(4);
        buf.extend_from_slice(&[0xff, 0xfe, 0x41, 0x42]);
        let pool: DartStringPool = recover_string_pool(&buf);
        assert!(
            pool.strings.is_empty(),
            "binary bytes are not a one-byte string"
        );
    }

    #[test]
    fn empty_input_yields_empty_pool() {
        let pool: DartStringPool = recover_string_pool(&[]);
        assert_eq!(pool.total_strings, 0);
        assert!(pool.literals.is_empty());
    }
}
