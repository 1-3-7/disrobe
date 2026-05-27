use std::collections::BTreeMap;

use base64::Engine;
use serde::{Deserialize, Serialize};

use super::ExtractedModule;
use crate::error::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynthesizedSourceMap {
    pub version: u8,
    pub file: String,
    pub sources: Vec<String>,
    #[serde(rename = "sourcesContent")]
    pub sources_content: Vec<Option<String>>,
    pub names: Vec<String>,
    pub mappings: String,
}

impl SynthesizedSourceMap {
    #[must_use]
    pub fn empty(file: impl Into<String>) -> Self {
        Self {
            version: 3,
            file: file.into(),
            sources: Vec::new(),
            sources_content: Vec::new(),
            names: Vec::new(),
            mappings: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DecodedInlineMap {
    pub mime: String,
    pub raw_json: String,
}

pub fn decode_inline_data_url(url: &str) -> Result<DecodedInlineMap> {
    let prefix: &str = "data:";
    if !url.starts_with(prefix) {
        return Err(Error::OxcParse("not a data url".to_owned()));
    }
    let rest: &str = &url[prefix.len()..];
    let comma_pos: usize = rest
        .find(',')
        .ok_or_else(|| Error::OxcParse("malformed data url".to_owned()))?;
    let header: &str = &rest[..comma_pos];
    let payload: &str = &rest[comma_pos + 1..];
    let (mime, is_b64): (String, bool) = parse_header(header);
    let raw_json: String = if is_b64 {
        let decoded: Vec<u8> = base64::engine::general_purpose::STANDARD
            .decode(payload.as_bytes())
            .map_err(|e: base64::DecodeError| Error::OxcParse(e.to_string()))?;
        String::from_utf8(decoded).map_err(|_| Error::Utf8)?
    } else {
        urlencoding_decode(payload)
    };
    Ok(DecodedInlineMap { mime, raw_json })
}

fn parse_header(header: &str) -> (String, bool) {
    let mut mime: String = "application/json".to_owned();
    let mut is_b64: bool = false;
    for part in header.split(';') {
        let trimmed: &str = part.trim();
        if trimmed.eq_ignore_ascii_case("base64") {
            is_b64 = true;
        } else if trimmed.contains('/') {
            trimmed.clone_into(&mut mime);
        }
    }
    (mime, is_b64)
}

fn urlencoding_decode(s: &str) -> String {
    let bytes: &[u8] = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i: usize = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi: u8 = hex_nibble(bytes[i + 1]);
                let lo: u8 = hex_nibble(bytes[i + 2]);
                if hi == 0xFF || lo == 0xFF {
                    out.push(bytes[i]);
                    i += 1;
                } else {
                    out.push((hi << 4) | lo);
                    i += 3;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_owned())
}

const fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0xFF,
    }
}

pub fn synthesize_from_modules(
    file: impl Into<String>,
    modules: &[ExtractedModule],
) -> SynthesizedSourceMap {
    let mut sources: Vec<String> = Vec::with_capacity(modules.len());
    let mut contents: Vec<Option<String>> = Vec::with_capacity(modules.len());
    let mut mappings: String = String::new();
    let mut prev_source_idx: i64 = 0;

    for (i, m) in modules.iter().enumerate() {
        sources.push(if m.id.is_empty() {
            format!("module-{i}.js")
        } else {
            m.id.clone()
        });
        contents.push(Some(m.source.clone()));
        let current: i64 = i64::try_from(i).unwrap_or(i64::MAX);
        let source_delta: i64 = current - prev_source_idx;
        prev_source_idx = current;
        let mut segment: String = String::new();
        encode_vlq(0, &mut segment);
        encode_vlq(source_delta, &mut segment);
        encode_vlq(0, &mut segment);
        encode_vlq(0, &mut segment);
        if !mappings.is_empty() {
            mappings.push(';');
        }
        mappings.push_str(&segment);
    }

    SynthesizedSourceMap {
        version: 3,
        file: file.into(),
        sources,
        sources_content: contents,
        names: Vec::new(),
        mappings,
    }
}

fn encode_vlq(value: i64, out: &mut String) {
    let mut vlq: u64 = to_vlq_signed(value);
    loop {
        let mut digit: u8 = (vlq & 0b1_1111) as u8;
        vlq >>= 5;
        if vlq > 0 {
            digit |= 0b10_0000;
        }
        out.push(base64_char(digit));
        if vlq == 0 {
            break;
        }
    }
}

const fn to_vlq_signed(v: i64) -> u64 {
    if v < 0 {
        ((v.unsigned_abs()) << 1) | 1
    } else {
        (v.unsigned_abs()) << 1
    }
}

const fn base64_char(b: u8) -> char {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    TABLE[(b & 0b11_1111) as usize] as char
}

pub fn serialize(map: &SynthesizedSourceMap) -> Result<String> {
    serde_json::to_string_pretty(map).map_err(|e: serde_json::Error| Error::OxcParse(e.to_string()))
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceMapEmit {
    pub per_chunk: BTreeMap<String, SynthesizedSourceMap>,
    pub embedded: BTreeMap<String, DecodedInlineMap>,
}

pub fn emit(
    chunk_modules: &BTreeMap<String, Vec<ExtractedModule>>,
    inline_urls: &BTreeMap<String, String>,
) -> SourceMapEmit {
    let mut per_chunk: BTreeMap<String, SynthesizedSourceMap> = BTreeMap::new();
    for (chunk_id, modules) in chunk_modules {
        per_chunk.insert(
            chunk_id.clone(),
            synthesize_from_modules(format!("{chunk_id}.js"), modules),
        );
    }
    let mut embedded: BTreeMap<String, DecodedInlineMap> = BTreeMap::new();
    for (chunk_id, url) in inline_urls {
        if url.starts_with("data:")
            && let Ok(decoded) = decode_inline_data_url(url)
        {
            embedded.insert(chunk_id.clone(), decoded);
        }
    }
    SourceMapEmit {
        per_chunk,
        embedded,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn vlq_encodes_signed_zero() {
        let mut s: String = String::new();
        encode_vlq(0, &mut s);
        assert_eq!(s, "A");
    }

    #[test]
    fn vlq_encodes_negative() {
        let mut s: String = String::new();
        encode_vlq(-1, &mut s);
        assert_eq!(s, "D");
    }

    #[test]
    fn decode_base64_inline_roundtrip() {
        let payload: &str = "eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IiJ9";
        let url: String = format!("data:application/json;base64,{payload}");
        let decoded: DecodedInlineMap = decode_inline_data_url(&url).expect("decode");
        assert!(decoded.raw_json.contains("\"version\":3"));
    }

    #[test]
    fn synthesize_emits_valid_v3_shape() {
        let modules: Vec<ExtractedModule> = vec![
            ExtractedModule {
                id: "./a.ts".to_owned(),
                chunk_id: None,
                source: "export const a = 1;".to_owned(),
            },
            ExtractedModule {
                id: "./b.ts".to_owned(),
                chunk_id: None,
                source: "export const b = 2;".to_owned(),
            },
        ];
        let map: SynthesizedSourceMap = synthesize_from_modules("entry.js", &modules);
        assert_eq!(map.version, 3);
        assert_eq!(map.sources.len(), 2);
        let json: String = serialize(&map).expect("serialize");
        assert!(json.contains("\"version\": 3"));
        assert!(json.contains("./a.ts"));
    }
}
