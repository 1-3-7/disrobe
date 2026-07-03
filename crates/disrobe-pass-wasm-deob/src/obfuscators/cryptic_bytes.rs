use std::collections::BTreeMap;

use serde::Serialize;
use walrus::{Module, ModuleConfig};
use wasmparser::{Operator, Parser, Payload};

use crate::error::{Error, Result};

const CAFEBABE: u32 = 0xCAFE_BABE_u32;
const XMR_KEYWORDS: &[&[u8]] = &[
    b"randomx",
    b"cryptonight",
    b"monero",
    b"xmr",
    b"hashrate",
    b"miner",
];

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct CrypticBytesDetection {
    pub cafe_constant_hits: u32,
    pub xor_loops_detected: u32,
    pub xmr_keyword_hits: BTreeMap<String, u32>,
    pub xor_keys: Vec<u8>,
    pub matched: bool,
    pub confidence: f32,
}

impl CrypticBytesDetection {
    #[inline]
    #[must_use]
    pub fn signature_strength(&self) -> u32 {
        let keyword_sum: u32 = self
            .xmr_keyword_hits
            .values()
            .copied()
            .fold(0u32, |acc: u32, v: u32| acc.saturating_add(v));
        self.cafe_constant_hits
            .saturating_add(self.xor_loops_detected.saturating_mul(2))
            .saturating_add(keyword_sum)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CrypticBytesPeel {
    pub detection: CrypticBytesDetection,
    pub cleaned_bytes: Vec<u8>,
    pub peeled_layer_bytes: usize,
}

pub fn detect(input: &[u8]) -> Result<CrypticBytesDetection> {
    if input.len() < 8 || &input[..4] != b"\0asm" {
        return Err(Error::Parse(
            "DR-WASMDEOB-CRYPTIC: not a wasm module".to_owned(),
        ));
    }
    let mut det: CrypticBytesDetection = CrypticBytesDetection::default();
    for payload in Parser::new(0).parse_all(input) {
        let payload: Payload<'_> = payload.map_err(|e| Error::Parse(format!("{e}")))?;
        match payload {
            Payload::CodeSectionEntry(body) => {
                let reader: wasmparser::OperatorsReader<'_> = body
                    .get_operators_reader()
                    .map_err(|e| Error::Parse(format!("{e}")))?;
                let mut xor_count_in_fn: u32 = 0u32;
                let mut had_loop: bool = false;
                let mut last_const: Option<u8> = None;
                for op in reader {
                    let op: Operator<'_> = op.map_err(|e| Error::Parse(format!("{e}")))?;
                    match op {
                        Operator::I32Const { value } => {
                            let unsigned: u32 = u32::from_ne_bytes(value.to_ne_bytes());
                            if unsigned == CAFEBABE {
                                det.cafe_constant_hits = det.cafe_constant_hits.saturating_add(1);
                            }
                            #[allow(clippy::cast_possible_truncation)]
                            let key_byte: u8 = (unsigned & 0xFFu32) as u8;
                            last_const = Some(key_byte);
                        }
                        Operator::I32Xor => {
                            xor_count_in_fn = xor_count_in_fn.saturating_add(1);
                            if let Some(k) = last_const {
                                if !det.xor_keys.contains(&k) {
                                    det.xor_keys.push(k);
                                }
                            }
                        }
                        Operator::Loop { .. } => {
                            had_loop = true;
                        }
                        _ => {}
                    }
                }
                if had_loop && xor_count_in_fn >= 1 {
                    det.xor_loops_detected = det.xor_loops_detected.saturating_add(1);
                }
            }
            Payload::DataSection(reader) => {
                for seg in reader {
                    let seg: wasmparser::Data<'_> =
                        seg.map_err(|e| Error::Parse(format!("{e}")))?;
                    scan_keywords(seg.data, &mut det.xmr_keyword_hits);
                }
            }
            Payload::CustomSection(c) => {
                scan_keywords(c.data(), &mut det.xmr_keyword_hits);
            }
            _ => {}
        }
    }
    let strength: u32 = det.signature_strength();
    let strength_f: f32 =
        f32::from(u16::try_from(strength.min(u32::from(u16::MAX))).unwrap_or(u16::MAX));
    det.confidence = (strength_f / 8.0_f32).clamp(0.0_f32, 1.0_f32);
    det.matched = strength >= 3;
    Ok(det)
}

fn scan_keywords(haystack: &[u8], counts: &mut BTreeMap<String, u32>) {
    let lower: Vec<u8> = haystack
        .iter()
        .map(|b: &u8| b.to_ascii_lowercase())
        .collect();
    for keyword in XMR_KEYWORDS {
        let mut hits: u32 = 0u32;
        let mut i: usize = 0usize;
        while i + keyword.len() <= lower.len() {
            if &lower[i..i + keyword.len()] == *keyword {
                hits = hits.saturating_add(1);
                i = i.saturating_add(keyword.len());
            } else {
                i = i.saturating_add(1);
            }
        }
        if hits > 0 {
            let key: String = String::from_utf8_lossy(keyword).into_owned();
            counts
                .entry(key)
                .and_modify(|v: &mut u32| *v = v.saturating_add(hits))
                .or_insert(hits);
        }
    }
}

/// Peels one XOR layer from a cryptic-bytes wasm miner.
///
/// The obfuscator encrypts the miner payload that lives in the module's data
/// segments and decrypts it at runtime inside an in-module XOR loop keyed by a
/// single byte. The module header, type/function/code structure, and section
/// framing are never encrypted, so peeling XORs only the data-segment payload
/// bytes (the genuinely encrypted region) and leaves the rest of the module
/// untouched, re-emitting valid wasm rather than mutating the raw byte stream.
///
/// The recovered module is checked with [`wasmparser::validate`]. If detection
/// did not fire, no key was recovered, or the decrypted module fails to
/// validate, the function reports honest non-recovery (`peeled_layer_bytes`
/// is `0` and `cleaned_bytes` is the unmodified input) instead of emitting a
/// corrupt blob.
pub fn peel_xor_layer(input: &[u8]) -> Result<CrypticBytesPeel> {
    let detection: CrypticBytesDetection = detect(input)?;
    if !detection.matched || detection.xor_keys.is_empty() {
        return Ok(non_recovery(detection, input));
    }
    let key: u8 = detection.xor_keys[0];
    let mut module: Module = parse_module(input)?;
    let data_ids: Vec<walrus::DataId> = module.data.iter().map(walrus::Data::id).collect();
    let mut peeled: usize = 0usize;
    for did in data_ids {
        let data: &mut walrus::Data = module.data.get_mut(did);
        if data.value.is_empty() {
            continue;
        }
        for byte in &mut data.value {
            *byte ^= key;
        }
        peeled = peeled.saturating_add(data.value.len());
    }
    if peeled == 0 {
        return Ok(non_recovery(detection, input));
    }
    let cleaned: Vec<u8> = module.emit_wasm();
    if wasmparser::validate(&cleaned).is_err() {
        return Ok(non_recovery(detection, input));
    }
    Ok(CrypticBytesPeel {
        detection,
        cleaned_bytes: cleaned,
        peeled_layer_bytes: peeled,
    })
}

fn non_recovery(detection: CrypticBytesDetection, input: &[u8]) -> CrypticBytesPeel {
    CrypticBytesPeel {
        detection,
        cleaned_bytes: input.to_vec(),
        peeled_layer_bytes: 0usize,
    }
}

fn parse_module(wasm: &[u8]) -> Result<Module> {
    let mut config: ModuleConfig = ModuleConfig::new();
    config.generate_producers_section(false);
    Module::from_buffer_with_config(wasm, &config)
        .map_err(|e| Error::Parse(format!("DR-WASMDEOB-CRYPTIC: walrus parse: {e}")))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn synth_module_with_xor_loop_and_cafe_keyword() -> Vec<u8> {
        let wat: &str = r#"
            (module
              (memory 1)
              (data (i32.const 0) "randomx-cryptonight-monero")
              (func (export "decrypt") (param i32) (result i32)
                (local i32)
                local.get 0
                local.set 1
                i32.const 0xCAFEBABE
                drop
                (loop $l
                  local.get 1
                  i32.const 0x42
                  i32.xor
                  local.set 1
                  local.get 1
                  i32.const 0
                  i32.ne
                  br_if $l)
                local.get 1))
        "#;
        wat::parse_str(wat).expect("parse wat")
    }

    #[test]
    fn detects_cafebabe_xor_loop_and_xmr_keyword() {
        let bytes: Vec<u8> = synth_module_with_xor_loop_and_cafe_keyword();
        let det: CrypticBytesDetection = detect(&bytes).expect("detect");
        assert!(det.matched, "expected match, got {det:?}");
        assert!(det.cafe_constant_hits >= 1);
        assert!(det.xor_loops_detected >= 1);
        assert!(det.xmr_keyword_hits.get("randomx").copied().unwrap_or(0) >= 1);
        assert!(det.xor_keys.contains(&0x42));
        assert!(det.confidence > 0.0);
    }

    const XOR_KEY: u8 = 0x42u8;

    fn canonical(wasm: &[u8]) -> Vec<u8> {
        parse_module(wasm).expect("walrus parse").emit_wasm()
    }

    fn encrypt_data_segments(wasm: &[u8], key: u8) -> Vec<u8> {
        let mut module: Module = parse_module(wasm).expect("walrus parse");
        let data_ids: Vec<walrus::DataId> = module.data.iter().map(walrus::Data::id).collect();
        for did in data_ids {
            let data: &mut walrus::Data = module.data.get_mut(did);
            for byte in &mut data.value {
                *byte ^= key;
            }
        }
        module.emit_wasm()
    }

    #[test]
    fn peel_xor_layer_recovers_byte_exact_payload() {
        let plaintext: Vec<u8> = canonical(&synth_module_with_xor_loop_and_cafe_keyword());
        let encrypted: Vec<u8> = encrypt_data_segments(&plaintext, XOR_KEY);
        assert_ne!(
            plaintext, encrypted,
            "encrypting the data segment must change the module bytes"
        );

        let peel: CrypticBytesPeel = peel_xor_layer(&encrypted).expect("peel");
        assert!(peel.peeled_layer_bytes > 0, "must peel a real region");
        assert_eq!(
            peel.cleaned_bytes, plaintext,
            "peeled module must be byte-identical to the original plaintext module"
        );
        wasmparser::validate(&peel.cleaned_bytes).expect("recovered module must validate as wasm");

        let payload: Vec<u8> = data_segment_bytes(&peel.cleaned_bytes);
        assert!(
            windowed_contains(&payload, b"randomx"),
            "decrypted data segment must expose the original miner payload"
        );
    }

    #[test]
    fn peel_xor_layer_never_fabricates_header_or_touches_code() {
        let plaintext: Vec<u8> = canonical(&synth_module_with_xor_loop_and_cafe_keyword());
        let encrypted: Vec<u8> = encrypt_data_segments(&plaintext, XOR_KEY);

        let peel: CrypticBytesPeel = peel_xor_layer(&encrypted).expect("peel");
        assert_eq!(
            peel.peeled_layer_bytes,
            data_segment_bytes(&plaintext).len(),
            "only the data-segment payload is XORed, not the whole file"
        );
        assert_eq!(
            code_section_bytes(&peel.cleaned_bytes),
            code_section_bytes(&encrypted),
            "the code section is never re-keyed by the peel"
        );
    }

    fn data_segment_bytes(wasm: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        for payload in Parser::new(0).parse_all(wasm) {
            if let Payload::DataSection(reader) = payload.expect("payload") {
                for seg in reader {
                    out.extend_from_slice(seg.expect("data segment").data);
                }
            }
        }
        out
    }

    fn code_section_bytes(wasm: &[u8]) -> Vec<u8> {
        for payload in Parser::new(0).parse_all(wasm) {
            if let Payload::CodeSectionStart { range, .. } = payload.expect("payload") {
                return wasm[range].to_vec();
            }
        }
        Vec::new()
    }

    fn windowed_contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn rejects_non_wasm() {
        assert!(detect(b"not wasm").is_err());
    }
}
