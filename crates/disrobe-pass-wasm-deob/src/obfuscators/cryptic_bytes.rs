use std::collections::BTreeMap;

use serde::Serialize;
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

pub fn peel_xor_layer(input: &[u8]) -> Result<CrypticBytesPeel> {
    let detection: CrypticBytesDetection = detect(input)?;
    if !detection.matched || detection.xor_keys.is_empty() {
        return Ok(CrypticBytesPeel {
            detection,
            cleaned_bytes: input.to_vec(),
            peeled_layer_bytes: 0usize,
        });
    }
    let key: u8 = detection.xor_keys[0];
    let mut cleaned: Vec<u8> = input.to_vec();
    let mut peeled: usize = 0usize;
    if cleaned.len() > 8 {
        for byte in cleaned.iter_mut().skip(8) {
            *byte ^= key;
            peeled = peeled.saturating_add(1);
        }
    }
    cleaned[0..4].copy_from_slice(b"\0asm");
    cleaned[4..8].copy_from_slice(&1u32.to_le_bytes());
    Ok(CrypticBytesPeel {
        detection,
        cleaned_bytes: cleaned,
        peeled_layer_bytes: peeled,
    })
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

    #[test]
    fn peel_xor_layer_round_trips_header() {
        let bytes: Vec<u8> = synth_module_with_xor_loop_and_cafe_keyword();
        let peel: CrypticBytesPeel = peel_xor_layer(&bytes).expect("peel");
        assert!(peel.peeled_layer_bytes > 0);
        assert_eq!(&peel.cleaned_bytes[..4], b"\0asm");
    }

    #[test]
    fn rejects_non_wasm() {
        assert!(detect(b"not wasm").is_err());
    }
}
