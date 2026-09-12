use disrobe_core::codec::DecodeError;
use disrobe_core::codec::hex::encode as bytes_to_hex;
use disrobe_core::codec::hex::nibble as hex_nibble;
use disrobe_pass_py_disasm::{Instruction, disassemble, render_dis};
use disrobe_py_marshal::{CodeObject, Object, PyVersion, load as marshal_load};
use liblzma::read::XzDecoder;
use serde::Serialize;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum HyperionVariant {
    V2Lzma,
    V3LzmaMarshal,
    KramerSuccessor,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct HyperionV2V3Detection {
    pub variant: HyperionVariant,
    pub matched: bool,
    pub confidence: f32,
    pub markers: Vec<String>,
    pub layers_estimated: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct HyperionPeelStep {
    pub variant: HyperionVariant,
    pub decoder: String,
    pub byte_size_in: usize,
    pub byte_size_out: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct HyperionV2V3PeelResult {
    pub initial: HyperionV2V3Detection,
    pub steps: Vec<HyperionPeelStep>,
    pub layers_remaining: usize,
    pub final_bytes_len: usize,
    pub final_source_preview: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum InnerStageKind {
    Lzma,
    Zlib,
    Xor,
    Marshal,
}

#[derive(Debug, Clone, Serialize)]
pub struct InnerStage {
    pub kind: InnerStageKind,
    pub bytes_in: usize,
    pub bytes_out: usize,
    pub key_hex: Option<String>,
    pub code_object_count: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InnerDecodeResult {
    pub variant: HyperionVariant,
    pub stages: Vec<InnerStage>,
    pub recovered_source: Option<String>,
    pub disasm: Option<String>,
    pub code_object_summaries: Vec<CodeObjectSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeObjectSummary {
    pub name: String,
    pub qualname: String,
    pub filename: String,
    pub argcount: i32,
    pub posonlyargcount: i32,
    pub kwonlyargcount: i32,
    pub stacksize: i32,
    pub flags: i32,
    pub firstlineno: i32,
    pub code_len: usize,
    pub consts_count: usize,
    pub names_count: usize,
    pub nested_index_path: Vec<usize>,
}

const HEAD_SCAN_BYTES: usize = 16 * 1024;
const PREVIEW_BYTES: usize = 512;
const MAX_XOR_KEY_LEN: usize = 4 * 1024;
const MAX_NESTED_CODE_DEPTH: usize = 32;
const INNER_DEFAULT_MARSHAL_VERSION: PyVersion = PyVersion::PY311;

#[must_use]
pub fn detect(source: &[u8]) -> HyperionV2V3Detection {
    let head_slice: &[u8] = &source[..source.len().min(HEAD_SCAN_BYTES)];
    let text_head: &str = std::str::from_utf8(head_slice).unwrap_or("");
    let mut markers: Vec<String> = Vec::new();
    let mut variant: HyperionVariant = HyperionVariant::Unknown;
    let mut confidence: f32 = 0.0;
    let mut layers_estimated: usize = 0;

    let has_lzma_import: bool =
        text_head.contains("import lzma") || text_head.contains("from lzma");
    let has_marshal_import: bool =
        text_head.contains("import marshal") || text_head.contains("from marshal");
    let has_base64_import: bool =
        text_head.contains("import base64") || text_head.contains("from base64");
    let has_zlib_import: bool =
        text_head.contains("import zlib") || text_head.contains("from zlib");
    let has_hyperion_author: bool = text_head.contains("billythegoat356");
    let has_kramer_marker: bool = text_head.contains("Kramer") || text_head.contains("Specter");
    let has_xor_call: bool =
        text_head.contains("xor_bytes") || text_head.contains("xor(") || text_head.contains("XOR(");
    let has_hex_decode: bool =
        text_head.contains("bytes.fromhex(") || text_head.contains("fromhex(");

    if has_lzma_import {
        markers.push("import-lzma".to_owned());
        layers_estimated += 1;
    }
    if has_marshal_import {
        markers.push("import-marshal".to_owned());
        layers_estimated += 1;
    }
    if has_base64_import {
        markers.push("import-base64".to_owned());
        layers_estimated += 1;
    }
    if has_zlib_import {
        markers.push("import-zlib".to_owned());
        layers_estimated += 1;
    }
    if has_hyperion_author {
        markers.push("hyperion-author".to_owned());
    }
    if has_kramer_marker {
        markers.push("kramer-marker".to_owned());
    }
    if has_xor_call {
        markers.push("xor-call".to_owned());
    }
    if has_hex_decode {
        markers.push("hex-decode".to_owned());
    }

    let stub_marker: bool = text_head.contains("exec(")
        || text_head.contains("eval(")
        || text_head.contains("getattr(");
    let big_bytes_literal: bool =
        source.len() > 64 && (text_head.contains("b'") || text_head.contains("b\""));

    let kramer_signal: bool = has_kramer_marker || (has_xor_call && has_hex_decode);
    if kramer_signal && has_lzma_import {
        variant = HyperionVariant::KramerSuccessor;
        confidence = 0.9;
    } else if has_lzma_import && has_marshal_import && stub_marker && big_bytes_literal {
        variant = HyperionVariant::V3LzmaMarshal;
        confidence = 0.85;
    } else if has_lzma_import && stub_marker && big_bytes_literal {
        variant = HyperionVariant::V2Lzma;
        confidence = 0.75;
    } else if has_hyperion_author && has_lzma_import {
        variant = HyperionVariant::V2Lzma;
        confidence = 0.7;
    }

    HyperionV2V3Detection {
        variant,
        matched: variant != HyperionVariant::Unknown,
        confidence,
        markers,
        layers_estimated,
    }
}

pub const PEEL_ALL_DEFAULT_ITERS: usize = 8;

pub fn peel_all_layers(source: &[u8], max_iters: usize) -> Result<HyperionV2V3PeelResult> {
    let cap: usize = max_iters.max(1);
    let initial: HyperionV2V3Detection = detect(source);
    if !initial.matched {
        return Err(Error::NoFamilyMatched);
    }
    let mut current_bytes: Vec<u8> = source.to_vec();
    let mut accumulated_steps: Vec<HyperionPeelStep> = Vec::with_capacity(cap);
    let mut last_remaining: usize = initial.layers_estimated;
    let mut last_len: usize = current_bytes.len();
    let mut final_preview: String = String::new();
    for _ in 0..cap {
        let det: HyperionV2V3Detection = detect(&current_bytes);
        if !det.matched {
            break;
        }
        let (step_result, decoded): (HyperionV2V3PeelResult, Vec<u8>) =
            match peel_one_layer_decoded(&current_bytes) {
                Ok(r) => r,
                Err(_) => break,
            };
        if step_result.steps.is_empty() {
            break;
        }
        accumulated_steps.extend(step_result.steps.iter().cloned());
        last_remaining = step_result.layers_remaining;
        last_len = step_result.final_bytes_len;
        final_preview = step_result.final_source_preview;
        current_bytes = decoded;
        if !detect(&current_bytes).matched {
            break;
        }
    }
    Ok(HyperionV2V3PeelResult {
        initial,
        steps: accumulated_steps,
        layers_remaining: last_remaining,
        final_bytes_len: last_len,
        final_source_preview: final_preview,
    })
}

pub fn peel_one_layer(source: &[u8]) -> Result<HyperionV2V3PeelResult> {
    peel_one_layer_decoded(source).map(|(result, _): (HyperionV2V3PeelResult, Vec<u8>)| result)
}

fn peel_one_layer_decoded(source: &[u8]) -> Result<(HyperionV2V3PeelResult, Vec<u8>)> {
    let detection: HyperionV2V3Detection = detect(source);
    if !detection.matched {
        return Err(Error::NoFamilyMatched);
    }
    let text: &str = std::str::from_utf8(source).map_err(Error::from)?;
    let raw: Vec<u8> = extract_largest_bytes_literal(text)?;
    let bytes_in: usize = raw.len();

    let mut steps: Vec<HyperionPeelStep> = Vec::new();
    let after_lzma: Vec<u8> = decompress_xz(&raw)
        .or_else(|_| decompress_zlib(&raw))
        .map_err(|e| Error::Lzma(format!("{e}")))?;
    let label: &str = if detection.variant == HyperionVariant::V3LzmaMarshal {
        "lzma+marshal"
    } else {
        "lzma"
    };
    steps.push(HyperionPeelStep {
        variant: detection.variant,
        decoder: label.to_owned(),
        byte_size_in: bytes_in,
        byte_size_out: after_lzma.len(),
    });

    let layers_remaining: usize = detection.layers_estimated.saturating_sub(steps.len());
    let preview: String = preview_of(&after_lzma);
    let final_bytes_len: usize = after_lzma.len();
    Ok((
        HyperionV2V3PeelResult {
            initial: detection,
            steps,
            layers_remaining,
            final_bytes_len,
            final_source_preview: preview,
        },
        after_lzma,
    ))
}

pub fn decode_inner(source: &[u8]) -> Result<InnerDecodeResult> {
    decode_inner_with_version(source, INNER_DEFAULT_MARSHAL_VERSION)
}

pub fn decode_inner_with_version(
    source: &[u8],
    marshal_version: PyVersion,
) -> Result<InnerDecodeResult> {
    let detection: HyperionV2V3Detection = detect(source);
    if !detection.matched {
        return Err(Error::NoFamilyMatched);
    }
    let text: &str = std::str::from_utf8(source).map_err(Error::from)?;
    let outer_blob: Vec<u8> = extract_largest_bytes_literal(text)?;

    let mut stages: Vec<InnerStage> = Vec::with_capacity(4);

    let after_compress: Vec<u8> = if let Ok(decompressed) = decompress_xz(&outer_blob) {
        stages.push(InnerStage {
            kind: InnerStageKind::Lzma,
            bytes_in: outer_blob.len(),
            bytes_out: decompressed.len(),
            key_hex: None,
            code_object_count: None,
        });
        decompressed
    } else {
        let decompressed: Vec<u8> = decompress_zlib(&outer_blob)
            .map_err(|e: std::io::Error| Error::Lzma(format!("{e}")))?;
        stages.push(InnerStage {
            kind: InnerStageKind::Zlib,
            bytes_in: outer_blob.len(),
            bytes_out: decompressed.len(),
            key_hex: None,
            code_object_count: None,
        });
        decompressed
    };

    let after_xor: Vec<u8> = if matches!(detection.variant, HyperionVariant::KramerSuccessor) {
        let key: Vec<u8> = extract_xor_key(text)?;
        let xored: Vec<u8> = apply_xor(&after_compress, &key);
        stages.push(InnerStage {
            kind: InnerStageKind::Xor,
            bytes_in: after_compress.len(),
            bytes_out: xored.len(),
            key_hex: Some(bytes_to_hex(&key)),
            code_object_count: None,
        });
        xored
    } else {
        after_compress
    };

    let marshal_in_len: usize = after_xor.len();
    let root_obj: Object =
        marshal_load(&after_xor, marshal_version).map_err(|e| Error::Marshal(format!("{e}")))?;

    let mut summaries: Vec<CodeObjectSummary> = Vec::new();
    let mut top_code: Option<CodeObject> = None;
    collect_code_objects(&root_obj, &mut Vec::new(), &mut summaries, &mut top_code, 0);

    stages.push(InnerStage {
        kind: InnerStageKind::Marshal,
        bytes_in: marshal_in_len,
        bytes_out: marshal_in_len,
        key_hex: None,
        code_object_count: Some(summaries.len()),
    });

    let disasm: Option<String> = top_code.as_ref().map(|co: &CodeObject| {
        let ins: Vec<Instruction> = disassemble(co, marshal_version);
        render_dis(&ins)
    });
    let recovered_source: Option<String> = disasm.as_ref().map(|d: &String| {
        if d.is_empty() {
            String::new()
        } else {
            format!("# disassembled bytecode\n{d}")
        }
    });

    Ok(InnerDecodeResult {
        variant: detection.variant,
        stages,
        recovered_source,
        disasm,
        code_object_summaries: summaries,
    })
}

fn collect_code_objects(
    obj: &Object,
    path: &mut Vec<usize>,
    summaries: &mut Vec<CodeObjectSummary>,
    top: &mut Option<CodeObject>,
    depth: usize,
) {
    if depth > MAX_NESTED_CODE_DEPTH {
        return;
    }
    match obj {
        Object::Code(co) => {
            if top.is_none() {
                *top = Some((**co).clone());
            }
            summaries.push(summarize_code(co.as_ref(), path));
            for (idx, c) in co.consts.iter().enumerate() {
                path.push(idx);
                collect_code_objects(c, path, summaries, top, depth + 1);
                path.pop();
            }
        }
        Object::Tuple(items)
        | Object::List(items)
        | Object::Set(items)
        | Object::FrozenSet(items) => {
            for (idx, c) in items.iter().enumerate() {
                path.push(idx);
                collect_code_objects(c, path, summaries, top, depth + 1);
                path.pop();
            }
        }
        Object::Dict(d) | Object::FrozenDict(d) => {
            for (idx, (_, v)) in d.iter().enumerate() {
                path.push(idx);
                collect_code_objects(v, path, summaries, top, depth + 1);
                path.pop();
            }
        }
        _ => {}
    }
}

fn summarize_code(co: &CodeObject, path: &[usize]) -> CodeObjectSummary {
    CodeObjectSummary {
        name: object_to_string(&co.name),
        qualname: object_to_string(&co.qualname),
        filename: object_to_string(&co.filename),
        argcount: co.argcount,
        posonlyargcount: co.posonlyargcount,
        kwonlyargcount: co.kwonlyargcount,
        stacksize: co.stacksize,
        flags: co.flags,
        firstlineno: co.firstlineno,
        code_len: co.code.len(),
        consts_count: co.consts.len(),
        names_count: co.names.len(),
        nested_index_path: path.to_vec(),
    }
}

fn object_to_string(obj: &Object) -> String {
    match obj {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => value.clone(),
        Object::None => String::new(),
        other => format!("{other:?}"),
    }
}

fn extract_xor_key(text: &str) -> Result<Vec<u8>> {
    if let Some(hex_payload) = find_fromhex_argument(text) {
        let cleaned: String = hex_payload
            .chars()
            .filter(|c: &char| c.is_ascii_hexdigit())
            .collect();
        if cleaned.is_empty()
            || cleaned.len() > MAX_XOR_KEY_LEN * 2
            || !cleaned.len().is_multiple_of(2)
        {
            return Err(Error::XorKey(format!(
                "fromhex argument has invalid length {len}",
                len = cleaned.len()
            )));
        }
        return hex_decode(&cleaned);
    }
    if let Some(literal) = find_xor_key_bytes_literal(text) {
        let decoded: Vec<u8> = decode_python_bytes(literal)?;
        if decoded.is_empty() || decoded.len() > MAX_XOR_KEY_LEN {
            return Err(Error::XorKey(format!(
                "xor key literal has out-of-range length {len}",
                len = decoded.len()
            )));
        }
        return Ok(decoded);
    }
    Err(Error::XorKeyMissing)
}

fn find_fromhex_argument(text: &str) -> Option<&str> {
    let needle: &str = "fromhex(";
    let start: usize = text.find(needle)?;
    let body_start: usize = start + needle.len();
    let body: &str = text.get(body_start..)?;
    let mut quote: Option<u8> = None;
    let mut quote_start: usize = 0;
    let bytes: &[u8] = body.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match quote {
            None => {
                if matches!(b, b'\'' | b'"') {
                    quote = Some(b);
                    quote_start = i + 1;
                }
            }
            Some(q) if b == q => {
                return body.get(quote_start..i);
            }
            _ => {}
        }
    }
    None
}

fn find_xor_key_bytes_literal(text: &str) -> Option<&str> {
    let needle: &str = "xor_bytes(";
    let start: usize = text.find(needle)?;
    let body_start: usize = start + needle.len();
    let body: &str = text.get(body_start..)?;
    let bytes: &[u8] = body.as_bytes();
    let mut depth: i32 = 1;
    let mut comma_at: Option<usize> = None;
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        match b {
            b'\\' => i += 2,
            b'\'' | b'"' => {
                let quote_end: usize = match find_unescaped(&bytes[i + 1..], b) {
                    Some(off) => i + 1 + off + 1,
                    None => return None,
                };
                i = quote_end;
            }
            b'(' => {
                depth += 1;
                i += 1;
            }
            b')' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
                i += 1;
            }
            b',' if depth == 1 => {
                comma_at = Some(i);
                i += 1;
            }
            _ => i += 1,
        }
    }
    let scan_from: usize = comma_at? + 1;
    let tail_bytes: &[u8] = bytes.get(scan_from..)?;
    let b_rel: usize = tail_bytes.iter().position(|&b| b == b'b')?;
    let b_abs: usize = scan_from + b_rel;
    let opener: u8 = *bytes.get(b_abs + 1)?;
    if !matches!(opener, b'\'' | b'"') {
        return None;
    }
    let literal_start: usize = b_abs + 2;
    let rest: &str = body.get(literal_start..)?;
    let end_off: usize = find_unescaped(rest.as_bytes(), opener)?;
    rest.get(..end_off)
}

#[inline]
fn apply_xor(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    let mut out: Vec<u8> = Vec::with_capacity(data.len());
    let key_len: usize = key.len();
    for (i, &b) in data.iter().enumerate() {
        out.push(b ^ key[i % key_len]);
    }
    out
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    disrobe_core::codec::hex::decode(s).map_err(|err: DecodeError| Error::XorKey(err.to_string()))
}

fn extract_largest_bytes_literal(text: &str) -> Result<Vec<u8>> {
    let mut best: Option<&str> = None;
    let mut cursor: usize = 0;
    while let Some((lit, next_cursor)) = next_bytes_literal(text, cursor) {
        if best.is_none_or(|b: &str| lit.len() > b.len()) {
            best = Some(lit);
        }
        cursor = next_cursor;
    }
    let Some(literal): Option<&str> = best else {
        return Err(Error::LiteralNotFound);
    };
    decode_python_bytes(literal)
}

fn next_bytes_literal(text: &str, cursor: usize) -> Option<(&str, usize)> {
    let window: &str = text.get(cursor..)?;
    let rel: usize = window.find("b'").or_else(|| window.find("b\""))?;
    let idx: usize = cursor + rel;
    let opener: u8 = *text.as_bytes().get(idx + 1)?;
    let body_start: usize = idx + 2;
    let rest: &str = text.get(body_start..)?;
    let end_off: usize = find_unescaped(rest.as_bytes(), opener)?;
    let lit: &str = rest.get(..end_off)?;
    Some((lit, body_start + end_off + 1))
}

fn find_unescaped(bytes: &[u8], opener: u8) -> Option<usize> {
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == opener {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn decode_python_bytes(s: &str) -> Result<Vec<u8>> {
    let bytes: &[u8] = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i: usize = 0;
    while i < bytes.len() {
        let b: u8 = bytes[i];
        if b != b'\\' {
            out.push(b);
            i += 1;
            continue;
        }
        if i + 1 >= bytes.len() {
            break;
        }
        let escape: u8 = bytes[i + 1];
        match escape {
            b'x' => {
                if i + 3 >= bytes.len() {
                    return Err(Error::LiteralNotFound);
                }
                let hi: u8 = hex_nibble(bytes[i + 2]).ok_or(Error::LiteralNotFound)?;
                let lo: u8 = hex_nibble(bytes[i + 3]).ok_or(Error::LiteralNotFound)?;
                out.push((hi << 4) | lo);
                i += 4;
            }
            b'n' => {
                out.push(b'\n');
                i += 2;
            }
            b'r' => {
                out.push(b'\r');
                i += 2;
            }
            b't' => {
                out.push(b'\t');
                i += 2;
            }
            b'\\' => {
                out.push(b'\\');
                i += 2;
            }
            b'\'' => {
                out.push(b'\'');
                i += 2;
            }
            b'"' => {
                out.push(b'"');
                i += 2;
            }
            b'0' => {
                out.push(0);
                i += 2;
            }
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }
    Ok(out)
}

fn decompress_xz(input: &[u8]) -> std::io::Result<Vec<u8>> {
    let decoder: XzDecoder<&[u8]> = XzDecoder::new(input);
    crate::codec::bounded_read_to_end(decoder)?.ok_or_else(decompression_bomb_error)
}

fn decompress_zlib(input: &[u8]) -> std::io::Result<Vec<u8>> {
    let decoder: flate2::read::ZlibDecoder<&[u8]> = flate2::read::ZlibDecoder::new(input);
    crate::codec::bounded_read_to_end(decoder)?.ok_or_else(decompression_bomb_error)
}

fn decompression_bomb_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!(
            "decompressed output exceeds {} byte ceiling",
            crate::codec::DECOMPRESS_CEILING
        ),
    )
}

fn preview_of(bytes: &[u8]) -> String {
    let slice: &[u8] = &bytes[..bytes.len().min(PREVIEW_BYTES)];
    String::from_utf8_lossy(slice).into_owned()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::io::Write;

    use disrobe_core::codec::hex::push_byte as push_lower_hex_byte;
    use disrobe_py_marshal::{CodeEra, CodeObject, Object, dump as marshal_dump};
    use liblzma::write::XzEncoder;

    use super::*;

    fn xz_compress(input: &[u8]) -> Vec<u8> {
        let mut encoder: XzEncoder<Vec<u8>> = XzEncoder::new(Vec::new(), 6);
        encoder.write_all(input).expect("xz write");
        encoder.finish().expect("xz finish")
    }

    fn python_bytes_literal(bytes: &[u8]) -> String {
        let mut s: String = String::with_capacity(bytes.len() * 4 + 4);
        s.push('b');
        s.push('\'');
        for &b in bytes {
            if b == b'\\' {
                s.push_str("\\\\");
            } else if b == b'\'' {
                s.push_str("\\'");
            } else if (0x20..0x7f).contains(&b) {
                s.push(b as char);
            } else {
                s.push_str("\\x");
                push_lower_hex_byte(&mut s, b);
            }
        }
        s.push('\'');
        s
    }

    fn build_code_object(name: &str, nested: Vec<CodeObject>) -> CodeObject {
        let mut co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
        co.name = Object::ShortAscii {
            value: name.to_owned(),
            interned: false,
        };
        co.qualname = Object::ShortAscii {
            value: name.to_owned(),
            interned: false,
        };
        co.filename = Object::ShortAscii {
            value: format!("<{name}>"),
            interned: false,
        };
        co.firstlineno = 1;
        co.code = vec![0x97, 0x00, 0x64, 0x00, 0x53, 0x00];
        co.consts = nested
            .into_iter()
            .map(|c: CodeObject| Object::Code(Box::new(c)))
            .collect();
        co
    }

    #[test]
    fn detects_v2_lzma_stub() {
        let payload: Vec<u8> = xz_compress(b"def main(): return 42\n");
        let literal: String = python_bytes_literal(&payload);
        let stub: String =
            format!("import lzma\nimport base64\nexec(lzma.decompress({literal}))\n");
        let det: HyperionV2V3Detection = detect(stub.as_bytes());
        assert_eq!(det.variant, HyperionVariant::V2Lzma);
        assert!(det.matched);
    }

    #[test]
    fn detects_v3_lzma_marshal_stub() {
        let payload: Vec<u8> = xz_compress(b"def main(): return 42\n");
        let literal: String = python_bytes_literal(&payload);
        let stub: String = format!(
            "import lzma\nimport marshal\nimport base64\nexec(marshal.loads(lzma.decompress({literal})))\n"
        );
        let det: HyperionV2V3Detection = detect(stub.as_bytes());
        assert_eq!(det.variant, HyperionVariant::V3LzmaMarshal);
    }

    #[test]
    fn detects_kramer_successor_marker() {
        let payload: Vec<u8> = xz_compress(b"x = 1\n");
        let literal: String = python_bytes_literal(&payload);
        let stub: String =
            format!("import lzma\n# Kramer obfuscator\nexec(lzma.decompress({literal}))\n");
        let det: HyperionV2V3Detection = detect(stub.as_bytes());
        assert_eq!(det.variant, HyperionVariant::KramerSuccessor);
    }

    #[test]
    fn peels_v2_lzma_layer() {
        let payload: Vec<u8> = xz_compress(b"def main(): return 42\n");
        let literal: String = python_bytes_literal(&payload);
        let stub: String =
            format!("import lzma\nimport base64\nexec(lzma.decompress({literal}))\n");
        let result: HyperionV2V3PeelResult = peel_one_layer(stub.as_bytes()).expect("peel");
        assert_eq!(result.steps.len(), 1);
        assert!(result.final_source_preview.contains("def main"));
    }

    #[test]
    fn peel_all_layers_single_iteration_matches_peel_one() {
        let payload: Vec<u8> = xz_compress(b"def main(): return 42\n");
        let literal: String = python_bytes_literal(&payload);
        let stub: String =
            format!("import lzma\nimport base64\nexec(lzma.decompress({literal}))\n");
        let result: HyperionV2V3PeelResult =
            peel_all_layers(stub.as_bytes(), PEEL_ALL_DEFAULT_ITERS).expect("peel-all");
        assert_eq!(result.steps.len(), 1);
        assert!(result.final_source_preview.contains("def main"));
    }

    #[test]
    fn peel_all_layers_iterates_nested_lzma_wrapping() {
        let inner: Vec<u8> = xz_compress(b"def main(): return 7\n");
        let inner_literal: String = python_bytes_literal(&inner);
        let inner_stub: String =
            format!("import lzma\nimport base64\nexec(lzma.decompress({inner_literal}))\n");
        let middle: Vec<u8> = xz_compress(inner_stub.as_bytes());
        let middle_literal: String = python_bytes_literal(&middle);
        let outer: String =
            format!("import lzma\nimport base64\nexec(lzma.decompress({middle_literal}))\n");
        let result: HyperionV2V3PeelResult =
            peel_all_layers(outer.as_bytes(), 4).expect("peel-all nested");
        assert!(result.steps.len() >= 2, "steps = {}", result.steps.len());
        assert!(
            result.final_source_preview.contains("def main"),
            "preview: {}",
            result.final_source_preview
        );
    }

    fn varied_ascii(len: usize) -> String {
        const ALPHABET: &[u8; 64] =
            b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";
        let mut out: String = String::with_capacity(len);
        let mut state: u32 = 0x1357_9bdf;
        for _ in 0..len {
            state = state
                .wrapping_mul(1_664_525u32)
                .wrapping_add(1_013_904_223u32);
            let pick: usize = (state >> 24) as usize % ALPHABET.len();
            out.push(ALPHABET[pick] as char);
        }
        out
    }

    #[test]
    fn peel_all_layers_carries_a_layer_larger_than_the_preview_into_the_next_layer() {
        let filler: String = varied_ascii(4096);
        let inner_source: String = format!("def main(): return 7\nPAD = '{filler}'\n");
        let inner: Vec<u8> = xz_compress(inner_source.as_bytes());
        let inner_literal: String = python_bytes_literal(&inner);
        let inner_stub: String =
            format!("import lzma\nimport base64\nexec(lzma.decompress({inner_literal}))\n");
        assert!(
            inner_stub.len() > PREVIEW_BYTES,
            "the middle layer must exceed the preview cap or this control proves nothing; len = {}",
            inner_stub.len()
        );
        let middle: Vec<u8> = xz_compress(inner_stub.as_bytes());
        let middle_literal: String = python_bytes_literal(&middle);
        let outer: String =
            format!("import lzma\nimport base64\nexec(lzma.decompress({middle_literal}))\n");
        let result: HyperionV2V3PeelResult =
            peel_all_layers(outer.as_bytes(), 4).expect("peel-all nested");
        assert!(result.steps.len() >= 2, "steps = {}", result.steps.len());
        assert!(
            result.final_source_preview.contains("def main"),
            "the innermost source was not reached, so an intermediate layer was cut to \
             {PREVIEW_BYTES} bytes before being peeled: {}",
            result.final_source_preview
        );
    }

    #[test]
    fn peel_all_layers_rejects_non_match() {
        let err: Error = peel_all_layers(b"print('hi')\n", 4).expect_err("non-match must fail");
        assert!(matches!(err, Error::NoFamilyMatched));
    }

    fn build_hyperion_v3_stub(co: &CodeObject) -> String {
        let marshalled: Vec<u8> = marshal_dump(
            &Object::Code(Box::new(co.clone())),
            INNER_DEFAULT_MARSHAL_VERSION,
        )
        .expect("marshal dump");
        let compressed: Vec<u8> = xz_compress(&marshalled);
        let literal: String = python_bytes_literal(&compressed);
        format!(
            "import lzma\nimport marshal\nimport base64\nexec(marshal.loads(lzma.decompress({literal})))\n"
        )
    }

    #[test]
    fn inner_decode_hyperion_v3_flat_returns_marshal_stage_and_one_code_object() {
        let co: CodeObject = build_code_object("entry_flat", Vec::new());
        let stub: String = build_hyperion_v3_stub(&co);
        let result: InnerDecodeResult = decode_inner(stub.as_bytes()).expect("decode_inner");
        assert_eq!(result.variant, HyperionVariant::V3LzmaMarshal);
        assert!(result.stages.iter().any(|s| s.kind == InnerStageKind::Lzma));
        assert!(
            result
                .stages
                .iter()
                .any(|s| s.kind == InnerStageKind::Marshal),
            "stages={:?}",
            result.stages
        );
        assert_eq!(result.code_object_summaries.len(), 1);
        assert_eq!(result.code_object_summaries[0].name, "entry_flat");
        assert!(result.disasm.as_deref().is_some_and(|d| !d.is_empty()));
    }

    #[test]
    fn inner_decode_hyperion_v3_walks_nested_consts_for_each_code_object() {
        let inner_a: CodeObject = build_code_object("helper_a", Vec::new());
        let inner_b: CodeObject = build_code_object("helper_b", Vec::new());
        let entry: CodeObject = build_code_object("entry_nested", vec![inner_a, inner_b]);
        let stub: String = build_hyperion_v3_stub(&entry);
        let result: InnerDecodeResult = decode_inner(stub.as_bytes()).expect("decode_inner nested");
        let names: Vec<String> = result
            .code_object_summaries
            .iter()
            .map(|s: &CodeObjectSummary| s.name.clone())
            .collect();
        assert!(names.iter().any(|n: &String| n == "entry_nested"));
        assert!(names.iter().any(|n: &String| n == "helper_a"));
        assert!(names.iter().any(|n: &String| n == "helper_b"));
        let marshal_stage: &InnerStage = result
            .stages
            .iter()
            .find(|s| s.kind == InnerStageKind::Marshal)
            .expect("marshal stage present");
        assert_eq!(marshal_stage.code_object_count, Some(3));
    }

    #[test]
    fn inner_decode_hyperion_v3_root_not_code_yields_zero_summaries() {
        let plain_root: Object = Object::Tuple(vec![Object::Int(1), Object::Int(2)]);
        let marshalled: Vec<u8> =
            marshal_dump(&plain_root, INNER_DEFAULT_MARSHAL_VERSION).expect("dump");
        let compressed: Vec<u8> = xz_compress(&marshalled);
        let literal: String = python_bytes_literal(&compressed);
        let stub: String = format!(
            "import lzma\nimport marshal\nimport base64\nexec(marshal.loads(lzma.decompress({literal})))\n"
        );
        let result: InnerDecodeResult = decode_inner(stub.as_bytes()).expect("decode_inner plain");
        assert!(result.code_object_summaries.is_empty());
        assert!(result.disasm.is_none());
    }

    #[test]
    fn inner_decode_kramer_via_xor_with_fromhex_key_recovers_code_object() {
        let co: CodeObject = build_code_object("kramer_entry", Vec::new());
        let marshalled: Vec<u8> =
            marshal_dump(&Object::Code(Box::new(co)), INNER_DEFAULT_MARSHAL_VERSION).expect("dump");
        let key: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37];
        let xored: Vec<u8> = apply_xor(&marshalled, &key);
        let compressed: Vec<u8> = xz_compress(&xored);
        let literal: String = python_bytes_literal(&compressed);
        let key_hex: String = bytes_to_hex(&key);
        let stub: String = format!(
            "import lzma\nimport marshal\n# Kramer obfuscator\nKEY = bytes.fromhex('{key_hex}').decode('latin1')\nexec(marshal.loads(xor_bytes(lzma.decompress({literal}), KEY)))\n"
        );
        let result: InnerDecodeResult =
            decode_inner(stub.as_bytes()).expect("decode_inner kramer hex");
        assert_eq!(result.variant, HyperionVariant::KramerSuccessor);
        let xor_stage: &InnerStage = result
            .stages
            .iter()
            .find(|s| s.kind == InnerStageKind::Xor)
            .expect("xor stage present");
        assert_eq!(xor_stage.key_hex.as_deref(), Some(key_hex.as_str()));
        assert_eq!(result.code_object_summaries.len(), 1);
        assert_eq!(result.code_object_summaries[0].name, "kramer_entry");
    }

    #[test]
    fn inner_decode_kramer_via_xor_with_bytes_literal_key_recovers_code_object() {
        let co: CodeObject = build_code_object("kramer_literal", Vec::new());
        let marshalled: Vec<u8> =
            marshal_dump(&Object::Code(Box::new(co)), INNER_DEFAULT_MARSHAL_VERSION).expect("dump");
        let key: Vec<u8> = b"abcXYZ".to_vec();
        let xored: Vec<u8> = apply_xor(&marshalled, &key);
        let compressed: Vec<u8> = xz_compress(&xored);
        let literal: String = python_bytes_literal(&compressed);
        let key_literal: String = python_bytes_literal(&key);
        let stub: String = format!(
            "import lzma\nimport marshal\n# Kramer obfuscator\nexec(marshal.loads(xor_bytes(lzma.decompress({literal}), {key_literal})))\n"
        );
        let result: InnerDecodeResult =
            decode_inner(stub.as_bytes()).expect("decode_inner kramer literal");
        assert_eq!(result.variant, HyperionVariant::KramerSuccessor);
        assert_eq!(result.code_object_summaries[0].name, "kramer_literal");
        assert!(result.stages.iter().any(|s| s.kind == InnerStageKind::Xor));
    }
}
