//! Source-map v3 reconstruction. The decoder is a clean-room implementation of
//! the Base64 VLQ encoding and relative-offset `mappings` playback described by
//! the Source Map v3 spec (Mozilla / TC39 source-map-spec): each segment is a
//! cumulative delta of `[generatedColumn, sourceIndex, sourceLine, sourceColumn,
//! nameIndex]`, six bits per Base64 digit with bit-5 as the continuation flag
//! and the least-significant bit of the assembled value carrying the sign. `;`
//! starts a new generated line (resetting the generated column) and `,`
//! separates segments. The synthesizer half builds a fresh per-module map.

use std::collections::BTreeMap;

use base64::Engine;
use serde::{Deserialize, Serialize};

use super::ExtractedModule;
use crate::error::{Error, Result};

const VLQ_CONTINUATION: u32 = 0b10_0000;
const VLQ_VALUE_MASK: u32 = 0b01_1111;
const VLQ_SHIFT: u32 = 5;

const fn base64_value(c: u8) -> Option<u32> {
    let v: u8 = match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(v as u32)
}

#[must_use]
pub fn decode_vlq(segment: &str) -> Option<Vec<i64>> {
    let bytes: &[u8] = segment.as_bytes();
    let mut out: Vec<i64> = Vec::new();
    let mut value: u32 = 0;
    let mut shift: u32 = 0;
    let mut in_progress: bool = false;
    for &c in bytes {
        let digit: u32 = base64_value(c)?;
        in_progress = true;
        let chunk: u32 = digit & VLQ_VALUE_MASK;
        value = value.checked_add(chunk.checked_shl(shift)?)?;
        if digit & VLQ_CONTINUATION != 0 {
            shift = shift.checked_add(VLQ_SHIFT)?;
        } else {
            let negative: bool = value & 1 == 1;
            let magnitude: i64 = i64::from(value >> 1);
            out.push(if negative { -magnitude } else { magnitude });
            value = 0;
            shift = 0;
            in_progress = false;
        }
    }
    if in_progress {
        return None;
    }
    Some(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MappingSegment {
    pub generated_column: i64,
    pub source_index: Option<i64>,
    pub source_line: Option<i64>,
    pub source_column: Option<i64>,
    pub name_index: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecodedMappings {
    pub lines: Vec<Vec<MappingSegment>>,
    pub segment_count: usize,
}

#[must_use]
pub fn decode_mappings(mappings: &str) -> Option<DecodedMappings> {
    let mut lines: Vec<Vec<MappingSegment>> = Vec::new();
    let mut segment_count: usize = 0;
    let mut source_index: i64 = 0;
    let mut source_line: i64 = 0;
    let mut source_column: i64 = 0;
    let mut name_index: i64 = 0;

    for raw_line in mappings.split(';') {
        let mut generated_column: i64 = 0;
        let mut line_segments: Vec<MappingSegment> = Vec::new();
        if !raw_line.is_empty() {
            for raw_segment in raw_line.split(',') {
                if raw_segment.is_empty() {
                    continue;
                }
                let fields: Vec<i64> = decode_vlq(raw_segment)?;
                if fields.is_empty() {
                    continue;
                }
                generated_column = generated_column.checked_add(fields[0])?;
                let segment: MappingSegment = match fields.len() {
                    1 => MappingSegment {
                        generated_column,
                        source_index: None,
                        source_line: None,
                        source_column: None,
                        name_index: None,
                    },
                    4 | 5 => {
                        source_index = source_index.checked_add(fields[1])?;
                        source_line = source_line.checked_add(fields[2])?;
                        source_column = source_column.checked_add(fields[3])?;
                        let name: Option<i64> = if fields.len() == 5 {
                            name_index = name_index.checked_add(fields[4])?;
                            Some(name_index)
                        } else {
                            None
                        };
                        MappingSegment {
                            generated_column,
                            source_index: Some(source_index),
                            source_line: Some(source_line),
                            source_column: Some(source_column),
                            name_index: name,
                        }
                    }
                    _ => return None,
                };
                line_segments.push(segment);
                segment_count += 1;
            }
        }
        lines.push(line_segments);
    }

    Some(DecodedMappings {
        lines,
        segment_count,
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoveredSourceMap {
    pub version: u8,
    pub file: Option<String>,
    pub sources: Vec<String>,
    pub names: Vec<String>,
    pub mappings: DecodedMappings,
    pub source_token_counts: BTreeMap<String, usize>,
    pub referenced_names: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawSourceMap {
    #[serde(default)]
    version: u8,
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    sources: Vec<Option<String>>,
    #[serde(default)]
    names: Vec<String>,
    #[serde(default)]
    mappings: String,
}

pub fn parse_source_map(raw_json: &str) -> Result<RecoveredSourceMap> {
    let raw: RawSourceMap = serde_json::from_str(raw_json)
        .map_err(|e: serde_json::Error| Error::OxcParse(e.to_string()))?;
    let sources: Vec<String> = raw
        .sources
        .into_iter()
        .map(|s: Option<String>| s.unwrap_or_default())
        .collect();
    let decoded: DecodedMappings = decode_mappings(&raw.mappings)
        .ok_or_else(|| Error::OxcParse("malformed source map mappings".to_owned()))?;

    let mut source_token_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut referenced_names: Vec<String> = Vec::new();
    let mut seen_names: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    for line in &decoded.lines {
        for segment in line {
            if let Some(idx) = segment.source_index {
                let key: String = usize::try_from(idx)
                    .ok()
                    .and_then(|i: usize| sources.get(i))
                    .cloned()
                    .unwrap_or_else(|| format!("source-{idx}"));
                *source_token_counts.entry(key).or_insert(0) += 1;
            }
            if let Some(name_idx) = segment.name_index
                && let Ok(i) = usize::try_from(name_idx)
                && seen_names.insert(i)
                && let Some(name) = raw.names.get(i)
            {
                referenced_names.push(name.clone());
            }
        }
    }

    Ok(RecoveredSourceMap {
        version: if raw.version == 0 { 3 } else { raw.version },
        file: raw.file,
        sources,
        names: raw.names,
        mappings: decoded,
        source_token_counts,
        referenced_names,
    })
}

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
    fn vlq_decodes_basic_segments() {
        assert_eq!(decode_vlq("A"), Some(vec![0]));
        assert_eq!(decode_vlq("D"), Some(vec![-1]));
        assert_eq!(decode_vlq("AAAA"), Some(vec![0, 0, 0, 0]));
        assert_eq!(decode_vlq("UAAA"), Some(vec![10, 0, 0, 0]));
        assert_eq!(decode_vlq("IAAa"), Some(vec![4, 0, 0, 13]));
    }

    #[test]
    fn vlq_roundtrips_encode_decode() {
        for v in [0_i64, 1, -1, 5, -5, 100, -100, 1023, -1024, 12345, -98765] {
            let mut s: String = String::new();
            encode_vlq(v, &mut s);
            assert_eq!(decode_vlq(&s), Some(vec![v]), "value {v} via {s}");
        }
    }

    #[test]
    fn vlq_rejects_unterminated_continuation() {
        assert_eq!(decode_vlq("g"), None);
    }

    #[test]
    fn mappings_playback_accumulates_relative_offsets() {
        let decoded: DecodedMappings = decode_mappings("AAAA,IAAa;;UAAA").expect("decode");
        assert_eq!(decoded.lines.len(), 3);
        let first: &Vec<MappingSegment> = &decoded.lines[0];
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].generated_column, 0);
        assert_eq!(first[0].source_line, Some(0));
        assert_eq!(first[1].generated_column, 4);
        assert_eq!(first[1].source_column, Some(13));
        let third: &Vec<MappingSegment> = &decoded.lines[2];
        assert_eq!(third[0].generated_column, 10);
    }

    #[test]
    fn parse_source_map_recovers_sources_and_token_counts() {
        let raw: &str = r#"{"version":3,"file":"out.js","sources":["a.js","b.js"],"names":["greet"],"mappings":"AAAA;ICAA,SAAAA"}"#;
        let parsed: RecoveredSourceMap = parse_source_map(raw).expect("parse");
        assert_eq!(parsed.version, 3);
        assert_eq!(parsed.sources, vec!["a.js", "b.js"]);
        assert!(parsed.source_token_counts.contains_key("a.js"));
        assert!(parsed.source_token_counts.contains_key("b.js"));
        assert_eq!(parsed.referenced_names, vec!["greet"]);
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
