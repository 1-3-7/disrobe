use std::collections::BTreeSet;

use super::filters::{Decoded, decode_stream};
use super::limits;
use super::object::{ObjId, PdfDict, PdfDocument, PdfObject};

#[must_use]
pub fn pdf_string_to_text(bytes: &[u8]) -> String {
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        let units: Vec<u16> = rest
            .chunks_exact(2)
            .map(|chunk: &[u8]| u16::from_be_bytes([chunk[0], chunk[1]]))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_owned(),
        Err(_) => bytes.iter().map(|byte: &u8| char::from(*byte)).collect(),
    }
}

#[must_use]
pub fn name_to_string(name: &[u8]) -> String {
    String::from_utf8_lossy(name).into_owned()
}

#[must_use]
pub fn collect_name_tree(doc: &PdfDocument, start: &PdfObject) -> Vec<(String, PdfObject)> {
    let mut leaves: Vec<(String, PdfObject)> = Vec::new();
    let mut visited: BTreeSet<ObjId> = BTreeSet::new();
    let mut work: Vec<PdfDict> = Vec::new();
    if let Some(dict) = doc.resolve(start).as_dict() {
        work.push(dict.clone());
    }
    let mut nodes: usize = 0;
    while let Some(node) = work.pop() {
        nodes += 1;
        if nodes > limits::MAX_NAME_TREE_NODES || leaves.len() >= limits::MAX_FINDINGS {
            break;
        }
        if let Some(PdfObject::Array(names)) = doc.dict_get(&node, b"Names") {
            let mut index: usize = 0;
            while index + 1 < names.len() {
                let key: String = doc
                    .resolve(&names[index])
                    .as_string()
                    .map_or_else(String::new, pdf_string_to_text);
                let value: PdfObject = doc.resolve(&names[index + 1]).clone();
                leaves.push((key, value));
                index += 2;
                if leaves.len() >= limits::MAX_FINDINGS {
                    break;
                }
            }
        }
        if let Some(PdfObject::Array(kids)) = doc.dict_get(&node, b"Kids") {
            for kid in kids {
                if let Some(id) = kid.as_reference()
                    && !visited.insert(id)
                {
                    continue;
                }
                if let Some(dict) = doc.resolve(kid).as_dict() {
                    work.push(dict.clone());
                }
            }
        }
    }
    leaves
}

#[must_use]
pub fn extract_javascript(doc: &PdfDocument, value: &PdfObject) -> Option<String> {
    let resolved: &PdfObject = doc.resolve(value);
    let text: String = match resolved {
        PdfObject::String(bytes) => pdf_string_to_text(bytes),
        PdfObject::Stream(stream) => {
            let decoded: Decoded = decode_stream(doc, stream);
            pdf_string_to_text(&decoded.data)
        }
        PdfObject::Array(items) => {
            let mut joined: String = String::new();
            for item in items {
                if let Some(part) = extract_javascript(doc, item) {
                    joined.push_str(&part);
                    if joined.len() >= limits::MAX_STRING_CONCAT {
                        break;
                    }
                }
            }
            joined
        }
        _ => return None,
    };
    if text.is_empty() {
        return None;
    }
    let mut text: String = text;
    text.truncate(cutoff(&text, limits::MAX_FINDING_TEXT));
    Some(text)
}

const SENSITIVE_NAMES: &[&[u8]] = &[
    b"JavaScript",
    b"JS",
    b"Launch",
    b"OpenAction",
    b"AA",
    b"EmbeddedFile",
    b"EmbeddedFiles",
    b"Names",
    b"Filespec",
    b"URI",
    b"GoToR",
    b"SubmitForm",
    b"RichMedia",
    b"XFA",
    b"AcroForm",
    b"Win",
];

#[must_use]
pub fn scan_hex_obfuscated_names(buf: &[u8]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut seen: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut index: usize = 0;
    while index < buf.len() {
        if buf[index] != b'/' {
            index += 1;
            continue;
        }
        let start: usize = index;
        index += 1;
        let mut decoded: Vec<u8> = Vec::new();
        let mut had_hex: bool = false;
        while let Some(&byte) = buf.get(index) {
            if super::parse::is_whitespace(byte) || super::parse::is_delimiter(byte) {
                break;
            }
            if byte == b'#'
                && let Some(high) = buf.get(index + 1).copied().and_then(hex_digit)
                && let Some(low) = buf.get(index + 2).copied().and_then(hex_digit)
            {
                decoded.push((high << 4) | low);
                index += 3;
                had_hex = true;
                continue;
            }
            decoded.push(byte);
            index += 1;
            if decoded.len() >= limits::MAX_NAME_BYTES {
                break;
            }
        }
        if had_hex
            && SENSITIVE_NAMES.contains(&decoded.as_slice())
            && seen.insert(buf[start..index].to_vec())
        {
            out.push((
                String::from_utf8_lossy(&buf[start..index]).into_owned(),
                format!("/{}", String::from_utf8_lossy(&decoded)),
            ));
            if out.len() >= limits::MAX_FINDINGS {
                break;
            }
        }
    }
    out
}

const fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn cutoff(text: &str, max: usize) -> usize {
    if text.len() <= max {
        return text.len();
    }
    let mut boundary: usize = max;
    while boundary > 0 && !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    boundary
}
