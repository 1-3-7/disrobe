use std::io::Read;

use base64::Engine;
use flate2::read::ZlibDecoder;
use serde::Serialize;

use crate::detect::{Detection, Family, detect};
use crate::error::{Error, Result};
use crate::hyperion_v2v3::{
    HyperionV2V3Detection, HyperionVariant, InnerDecodeResult as HyperionInnerDecodeResult,
    decode_inner as decode_hyperion_inner, detect as detect_hyperion,
};

const MAX_DEPTH: usize = 32;

#[derive(Debug, Clone, Serialize)]
pub struct PeelStep {
    pub family: Family,
    pub decoder: String,
    pub byte_size_in: usize,
    pub byte_size_out: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeelResult {
    pub initial: Detection,
    pub steps: Vec<PeelStep>,
    pub final_source: String,
    pub converged: bool,
    pub hyperion_inner: Option<HyperionInnerDecodeResult>,
}

pub fn peel(source: &[u8]) -> Result<PeelResult> {
    let initial: Detection = detect(source);
    let mut current: Vec<u8> = source.to_vec();
    let mut steps: Vec<PeelStep> = Vec::new();
    let mut converged: bool = false;
    let mut hyperion_inner: Option<HyperionInnerDecodeResult> = None;

    for depth in 0..MAX_DEPTH {
        let detection: Detection = detect(&current);
        let hyperion_detection: HyperionV2V3Detection = detect_hyperion(&current);
        let hyperion_inner_eligible: bool = matches!(
            hyperion_detection.variant,
            HyperionVariant::V3LzmaMarshal | HyperionVariant::KramerSuccessor
        );
        if hyperion_inner_eligible
            && hyperion_inner.is_none()
            && let Ok(inner) = decode_hyperion_inner(&current)
        {
            let inner_bytes_in: usize = current.len();
            let inner_bytes_out: usize =
                inner.stages.last().map_or(inner_bytes_in, |s| s.bytes_out);
            let inner_label: String = inner
                .stages
                .iter()
                .map(|s| format!("{kind:?}", kind = s.kind).to_ascii_lowercase())
                .collect::<Vec<String>>()
                .join("+");
            steps.push(PeelStep {
                family: Family::Hyperion,
                decoder: format!("hyperion-inner({inner_label})"),
                byte_size_in: inner_bytes_in,
                byte_size_out: inner_bytes_out,
            });
            hyperion_inner = Some(inner);
            converged = true;
            break;
        }
        let next_step: Option<(Family, String, Vec<u8>)> = match detection.family {
            Family::GenericDropper | Family::Pyfuscator => try_peel_dropper(&current)
                .map(|(label, payload)| (detection.family, label, payload)),
            Family::Hyperion => try_peel_hyperion(&current)
                .map(|payload| (Family::Hyperion, "hyperion-zlib".to_owned(), payload)),
            _ => None,
        };
        let Some((step_family, label, payload)): Option<(Family, String, Vec<u8>)> = next_step
        else {
            converged = true;
            break;
        };
        let bytes_in: usize = current.len();
        steps.push(PeelStep {
            family: step_family,
            decoder: label,
            byte_size_in: bytes_in,
            byte_size_out: payload.len(),
        });
        current = payload;
        if depth + 1 == MAX_DEPTH {
            return Err(Error::DepthLimit(MAX_DEPTH));
        }
    }

    let final_source: String = String::from_utf8_lossy(&current).into_owned();
    Ok(PeelResult {
        initial,
        steps,
        final_source,
        converged,
        hyperion_inner,
    })
}

fn try_peel_dropper(source: &[u8]) -> Option<(String, Vec<u8>)> {
    let text: &str = std::str::from_utf8(source).ok()?;
    let literal: &str = extract_first_bytes_literal(text)?;
    let raw: Vec<u8> = decode_python_bytes(literal).ok()?;

    if let Ok(de) = base64::engine::general_purpose::STANDARD.decode(&raw) {
        if let Ok(infl) = inflate(&de) {
            return Some(("base64+zlib".to_owned(), infl));
        }
        return Some(("base64".to_owned(), de));
    }

    if let Ok(de) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&raw) {
        return Some(("base64-urlsafe".to_owned(), de));
    }

    if let Ok(decoded) = base85_decode(&raw) {
        if let Ok(infl) = inflate(&decoded) {
            return Some(("base85+zlib".to_owned(), infl));
        }
        return Some(("base85".to_owned(), decoded));
    }

    if let Ok(infl) = inflate(&raw) {
        return Some(("zlib".to_owned(), infl));
    }

    None
}

fn try_peel_hyperion(source: &[u8]) -> Option<Vec<u8>> {
    let text: &str = std::str::from_utf8(source).ok()?;
    let literal: &str = find_largest_bytes_literal(text)?;
    let raw: Vec<u8> = decode_python_bytes(literal).ok()?;
    inflate(&raw).ok()
}

fn extract_first_bytes_literal(text: &str) -> Option<&str> {
    let idx: usize = text.find("b'").or_else(|| text.find("b\""))?;
    let opener: u8 = *text.as_bytes().get(idx + 1)?;
    let body_start: usize = idx + 2;
    let rest: &str = text.get(body_start..)?;
    let end_off: usize = find_unescaped(rest.as_bytes(), opener)?;
    rest.get(..end_off)
}

fn find_largest_bytes_literal(text: &str) -> Option<&str> {
    let mut best: Option<(&str, usize)> = None;
    let mut cursor: usize = 0;
    while let Some((lit, next_cursor)) = next_bytes_literal(text, cursor) {
        let score: usize = lit.len();
        if best.is_none_or(|(_, s)| score > s) {
            best = Some((lit, score));
        }
        cursor = next_cursor;
    }
    best.map(|(s, _)| s)
}

fn next_bytes_literal(text: &str, cursor: usize) -> Option<(&str, usize)> {
    let window: &str = text.get(cursor..)?;
    let rel: usize = window.find("b'").or_else(|| window.find("b\""))?;
    let idx: usize = cursor + rel;
    let &opener: &u8 = text.as_bytes().get(idx + 1)?;
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
                    break;
                }
                let high: u8 = hex_nibble(bytes[i + 2]).ok_or(Error::LiteralNotFound)?;
                let low: u8 = hex_nibble(bytes[i + 3]).ok_or(Error::LiteralNotFound)?;
                out.push((high << 4) | low);
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

#[inline]
const fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn inflate(input: &[u8]) -> Result<Vec<u8>> {
    let mut decoder: ZlibDecoder<&[u8]> = ZlibDecoder::new(input);
    let mut out: Vec<u8> = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| Error::Zlib(format!("{e}")))?;
    Ok(out)
}

fn base85_decode(input: &[u8]) -> Result<Vec<u8>> {
    let alphabet: &[u8] =
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";
    let mut lookup: [u8; 256] = [u8::MAX; 256];
    for (i, &c) in alphabet.iter().enumerate() {
        lookup[c as usize] = u8::try_from(i).map_err(|_| Error::LiteralNotFound)?;
    }
    let mut out: Vec<u8> = Vec::with_capacity(input.len() * 4 / 5 + 4);
    for chunk in input.chunks(5) {
        if chunk.len() < 5 {
            break;
        }
        let mut acc: u32 = 0;
        for &c in chunk {
            let v: u8 = lookup[c as usize];
            if v == u8::MAX {
                return Err(Error::LiteralNotFound);
            }
            acc = acc.checked_mul(85).ok_or(Error::LiteralNotFound)?;
            acc = acc
                .checked_add(u32::from(v))
                .ok_or(Error::LiteralNotFound)?;
        }
        out.extend_from_slice(&acc.to_be_bytes());
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn no_family_returns_converged() {
        let src: &[u8] = b"def main(): return 1";
        let Ok(result): Result<PeelResult> = peel(src) else {
            panic!("peel must succeed on plain source");
        };
        assert!(result.converged);
        assert!(result.steps.is_empty());
    }

    #[test]
    fn extract_first_bytes_literal_basic() {
        let s: &str = "exec(b'hello world')";
        let Some(lit): Option<&str> = extract_first_bytes_literal(s) else {
            panic!("expected literal");
        };
        assert_eq!(lit, "hello world");
    }
}
