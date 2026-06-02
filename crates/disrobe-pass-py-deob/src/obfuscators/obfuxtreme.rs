use std::collections::BTreeMap;

use aes::Aes256;
use cbc::Decryptor;
use cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};

use crate::codec::{
    b64_decode, b64_encode, decode_python_bytes_literal, extract_largest_python_bytes_literal,
    python_bytes_literal, zlib_compress, zlib_decompress,
};
use crate::error::{Error, Result};
use crate::obfuscators::{DetectReport, Obfuscator, ObfuscatorPass, PeelOutcome, Quality};

type Aes256CbcDec = Decryptor<Aes256>;

#[derive(Debug, Clone, Copy)]
pub struct ObfuXtremePass;

const RUNTIME_PAYLOAD_PREFIX: &str = "# ObfuXtreme-runtime-payload-base64: ";
const BANNER: &str = "# ObfuXtreme v1";

impl ObfuscatorPass for ObfuXtremePass {
    fn id(&self) -> Obfuscator {
        Obfuscator::ObfuXtreme
    }

    fn detect(&self, source: &[u8]) -> DetectReport {
        let head: &[u8] = &source[..source.len().min(64 * 1024)];
        let text: &str = std::str::from_utf8(head).unwrap_or("");
        let banner: bool = text.contains("ObfuXtreme") || text.contains("__obfuxtreme__");
        let v4_loader: bool = text.contains("ObfuXtreme v4 Loader");
        let aes_idiom: bool = text.contains("AES.new(_KEY, AES.MODE_CBC")
            || text.contains("from Crypto.Cipher import AES");
        let b85_decode: bool = text.contains("base64.b85decode");
        let xor_split: bool = text.contains("def _xor(parts):");
        let mut markers: Vec<String> = Vec::new();
        if banner {
            markers.push("obfuxtreme-banner".to_owned());
        }
        if v4_loader {
            markers.push("obfuxtreme-v4-loader-banner".to_owned());
        }
        if aes_idiom {
            markers.push("obfuxtreme-aes-cbc".to_owned());
        }
        if b85_decode {
            markers.push("obfuxtreme-b85".to_owned());
        }
        if xor_split {
            markers.push("obfuxtreme-xor-key-split".to_owned());
        }
        let matched: bool = banner || v4_loader || (aes_idiom && b85_decode && xor_split);
        let confidence: f32 = if v4_loader && aes_idiom && b85_decode && xor_split {
            0.99
        } else if banner {
            0.92
        } else if matched {
            0.85
        } else {
            0.0
        };
        DetectReport {
            obfuscator: self.id(),
            matched,
            confidence,
            markers,
        }
    }

    fn peel(&self, source: &[u8]) -> Result<PeelOutcome> {
        let text: &str = std::str::from_utf8(source).map_err(Error::from)?;
        if text.contains("ObfuXtreme v4 Loader") {
            return Ok(peel_v4_upstream(self.id(), text));
        }
        let mut stages: Vec<String> = Vec::new();
        let mut lossy_notes: Vec<String> = Vec::new();
        let mut diagnostics: BTreeMap<String, String> = BTreeMap::new();
        let runtime_b64: Option<&str> = text
            .lines()
            .find_map(|l: &str| l.strip_prefix(RUNTIME_PAYLOAD_PREFIX));
        let recovered: String = if let Some(b64) = runtime_b64 {
            stages.push("runtime-sidecar".to_owned());
            let decoded: Vec<u8> = b64_decode(b64.trim().as_bytes())?;
            let inflated: Vec<u8> = zlib_decompress(&decoded)?;
            stages.push("base64".to_owned());
            stages.push("zlib".to_owned());
            String::from_utf8(inflated).map_err(|e| Error::AstCleanup(format!("{e}")))?
        } else if let Some(lit) = extract_largest_python_bytes_literal(text) {
            let raw: Vec<u8> = decode_python_bytes_literal(lit)?;
            let b64: Vec<u8> = b64_decode(&raw).unwrap_or(raw);
            stages.push("base64".to_owned());
            let inflated: Vec<u8> = zlib_decompress(&b64)?;
            stages.push("zlib".to_owned());
            lossy_notes.push(
                "runtime payload sidecar absent; relying on inlined literal extraction".to_owned(),
            );
            String::from_utf8(inflated).map_err(|e| Error::AstCleanup(format!("{e}")))?
        } else {
            return Err(Error::LiteralNotFound);
        };
        diagnostics.insert("stage_count".to_owned(), stages.len().to_string());
        Ok(PeelOutcome {
            obfuscator: self.id(),
            stages_applied: stages,
            recovered_source: recovered,
            confidence: 0.9,
            quality: Quality::Partial,
            lossy_notes: {
                lossy_notes.push(
                    "runtime-eval segments cannot be reversed statically; AST shape preserved"
                        .to_owned(),
                );
                lossy_notes
            },
            diagnostics,
        })
    }
}

fn peel_v4_upstream(id: Obfuscator, text: &str) -> PeelOutcome {
    let mut ctx: V4Ctx = V4Ctx::new();
    ctx.stages.push("v4-detect".to_owned());
    let key_parts: Vec<Vec<u8>> = extract_xor_split(text, "_KEY = _xor(");
    let iv_parts: Vec<Vec<u8>> = extract_xor_split(text, "_IV  = _xor(");
    let payload_b85: Option<&str> = extract_b85_payload(text);
    ctx.diagnostics
        .insert("key_parts".to_owned(), key_parts.len().to_string());
    ctx.diagnostics
        .insert("iv_parts".to_owned(), iv_parts.len().to_string());
    ctx.diagnostics.insert(
        "payload_b85_present".to_owned(),
        payload_b85.is_some().to_string(),
    );

    let Some(payload_str): Option<&str> = payload_b85 else {
        ctx.lossy_notes
            .push("could not extract base85 payload from loader".to_owned());
        return into_detect_only(id, ctx, text);
    };
    if key_parts.is_empty() || iv_parts.is_empty() {
        ctx.lossy_notes
            .push("could not extract key/iv xor parts from loader".to_owned());
        return into_detect_only(id, ctx, text);
    }
    ctx.stages.push("xor-key-recover".to_owned());
    ctx.stages.push("xor-iv-recover".to_owned());
    let key: Vec<u8> = xor_join(&key_parts);
    let iv: Vec<u8> = xor_join(&iv_parts);
    ctx.diagnostics
        .insert("key_len".to_owned(), key.len().to_string());
    ctx.diagnostics
        .insert("iv_len".to_owned(), iv.len().to_string());

    let Ok(mut enc) = b85_decode_python(payload_str.as_bytes()) else {
        ctx.lossy_notes
            .push("base85 payload decode failed".to_owned());
        return into_detect_only(id, ctx, text);
    };
    ctx.stages.push("base85-decode".to_owned());

    if key.len() != 32 || iv.len() != 16 {
        ctx.lossy_notes.push(format!(
            "AES key/iv shape mismatch (got key={}, iv={}; expected 32/16)",
            key.len(),
            iv.len()
        ));
        return into_detect_only(id, ctx, text);
    }

    let Some(plain) = decrypt_aes256_cbc_pkcs7(&key, &iv, &mut enc) else {
        ctx.lossy_notes
            .push("AES-256-CBC decrypt/unpad failed".to_owned());
        return into_detect_only(id, ctx, text);
    };
    ctx.stages.push("aes-256-cbc-decrypt".to_owned());

    let Ok(inflated) = zlib_decompress(&plain) else {
        ctx.lossy_notes
            .push("zlib decompress failed on AES plaintext".to_owned());
        return into_detect_only(id, ctx, text);
    };
    ctx.stages.push("zlib-decompress".to_owned());
    ctx.diagnostics
        .insert("marshalled_len".to_owned(), inflated.len().to_string());
    ctx.lossy_notes.push(
        "ObfuXtreme v4 inner payload is a marshal.dumps(compile(tree, ...)) blob; \
         disrobe-pass-py-disasm can decompile the code object back to source"
            .to_owned(),
    );
    PeelOutcome {
        obfuscator: id,
        stages_applied: ctx.stages,
        recovered_source: format!(
            "# obfuxtreme v4 recovered marshalled code object ({} bytes)\n# pipe through disrobe-pass-py-disasm to recover source",
            inflated.len()
        ),
        confidence: 0.9,
        quality: Quality::Partial,
        lossy_notes: ctx.lossy_notes,
        diagnostics: ctx.diagnostics,
    }
}

#[derive(Debug, Default)]
struct V4Ctx {
    stages: Vec<String>,
    diagnostics: BTreeMap<String, String>,
    lossy_notes: Vec<String>,
}

impl V4Ctx {
    fn new() -> Self {
        Self::default()
    }
}

fn decrypt_aes256_cbc_pkcs7(key: &[u8], iv: &[u8], buf: &mut [u8]) -> Option<Vec<u8>> {
    let dec: Aes256CbcDec = Aes256CbcDec::new_from_slices(key, iv).ok()?;
    let out: &[u8] = dec.decrypt_padded_mut::<Pkcs7>(buf).ok()?;
    Some(out.to_vec())
}

fn into_detect_only(id: Obfuscator, ctx: V4Ctx, text: &str) -> PeelOutcome {
    PeelOutcome {
        obfuscator: id,
        stages_applied: ctx.stages,
        recovered_source: text.to_owned(),
        confidence: 0.4,
        quality: Quality::DetectOnly,
        lossy_notes: ctx.lossy_notes,
        diagnostics: ctx.diagnostics,
    }
}

fn extract_xor_split(text: &str, prefix: &str) -> Vec<Vec<u8>> {
    let start: usize = match text.find(prefix) {
        Some(p) => p + prefix.len(),
        None => return Vec::new(),
    };
    let rest: &str = &text[start..];
    let end: usize = match find_list_close(rest.as_bytes()) {
        Some(e) => e,
        None => return Vec::new(),
    };
    let inner: &str = &rest[..end];
    let trimmed: &str = inner.trim_start_matches('(').trim_end_matches(')').trim();
    let mut parts: Vec<Vec<u8>> = Vec::new();
    let bytes: &[u8] = trimmed.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] == b'b'
            && i + 1 < bytes.len()
            && (bytes[i + 1] == b'\'' || bytes[i + 1] == b'"')
        {
            let quote: u8 = bytes[i + 1];
            let mut j: usize = i + 2;
            let mut part: Vec<u8> = Vec::new();
            while j < bytes.len() && bytes[j] != quote {
                if bytes[j] == b'\\' && j + 1 < bytes.len() {
                    let (byte, advance): (u8, usize) = decode_escape(bytes, j);
                    if advance == 1 {
                        part.push(b'\\');
                        j += 1;
                    } else {
                        part.push(byte);
                        j += advance;
                    }
                } else {
                    part.push(bytes[j]);
                    j += 1;
                }
            }
            parts.push(part);
            i = j + 1;
        } else {
            i += 1;
        }
    }
    parts
}

/// Index of the `]` that closes the `_xor([...])` parts list, skipping `]`/`)` bytes that occur
/// literally inside a `b'...'` / `b"..."` byte-string. Returns the offset of the closing `]` so
/// the caller's `trim_end_matches(')')` is harmless. Without literal-awareness a payload byte of
/// `0x5d` (`]`) or `0x29` (`)`) would truncate key/iv extraction and force a false `DetectOnly`.
fn find_list_close(bytes: &[u8]) -> Option<usize> {
    let mut i: usize = 0;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let c: u8 = bytes[i];
        match quote {
            Some(q) => {
                if c == b'\\' {
                    i += 2;
                    continue;
                }
                if c == q {
                    quote = None;
                }
            }
            None => {
                if c == b'\'' || c == b'"' {
                    quote = Some(c);
                } else if c == b']' {
                    return Some(i);
                }
            }
        }
        i += 1;
    }
    None
}

fn decode_escape(bytes: &[u8], j: usize) -> (u8, usize) {
    let n: u8 = bytes[j + 1];
    match n {
        b'x' if j + 3 < bytes.len() => {
            parse_hex2(bytes[j + 2], bytes[j + 3]).map_or((b'\\', 1), |h: u8| (h, 4))
        }
        b'n' => (b'\n', 2),
        b'r' => (b'\r', 2),
        b't' => (b'\t', 2),
        b'\\' => (b'\\', 2),
        b'\'' => (b'\'', 2),
        b'"' => (b'"', 2),
        b'0' => (0, 2),
        _ => (b'\\', 1),
    }
}

fn parse_hex2(a: u8, b: u8) -> Option<u8> {
    let h: u8 = hex_nibble(a)?;
    let l: u8 = hex_nibble(b)?;
    Some((h << 4) | l)
}

const fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn xor_join(parts: &[Vec<u8>]) -> Vec<u8> {
    if parts.is_empty() {
        return Vec::new();
    }
    let len: usize = parts[0].len();
    let mut out: Vec<u8> = parts[0].clone();
    for p in &parts[1..] {
        for (o, &b) in out.iter_mut().zip(p.iter()).take(len) {
            *o ^= b;
        }
    }
    out
}

fn extract_b85_payload(text: &str) -> Option<&str> {
    let needle: &str = "base64.b85decode(";
    let start: usize = text.find(needle)? + needle.len();
    let after: &str = &text[start..];
    let q: u8 = match after.as_bytes().first() {
        Some(&b'\'') => b'\'',
        Some(&b'"') => b'"',
        _ => return None,
    };
    let body: &str = &after[1..];
    let end: usize = body.bytes().position(|c: u8| c == q)?;
    Some(&body[..end])
}

fn b85_decode_python(input: &[u8]) -> std::result::Result<Vec<u8>, ()> {
    let mut chars: Vec<u8> = Vec::with_capacity(input.len());
    for &b in input {
        if !b.is_ascii_whitespace() {
            chars.push(b);
        }
    }
    let mut out: Vec<u8> = Vec::with_capacity(chars.len() * 4 / 5 + 1);
    let mut i: usize = 0;
    while i < chars.len() {
        let take: usize = (chars.len() - i).min(5);
        let mut acc: u64 = 0;
        for k in 0..take {
            let c: u8 = chars[i + k];
            let v: u8 = match c {
                b'0'..=b'9' => c - b'0',
                b'A'..=b'Z' => c - b'A' + 10,
                b'a'..=b'z' => c - b'a' + 36,
                b'!' => 62,
                b'#' => 63,
                b'$' => 64,
                b'%' => 65,
                b'&' => 66,
                b'(' => 67,
                b')' => 68,
                b'*' => 69,
                b'+' => 70,
                b'-' => 71,
                b';' => 72,
                b'<' => 73,
                b'=' => 74,
                b'>' => 75,
                b'?' => 76,
                b'@' => 77,
                b'^' => 78,
                b'_' => 79,
                b'`' => 80,
                b'{' => 81,
                b'|' => 82,
                b'}' => 83,
                b'~' => 84,
                _ => return Err(()),
            };
            acc = acc * 85 + u64::from(v);
        }
        for _ in take..5 {
            acc = acc * 85 + 84;
        }
        let bytes: [u8; 4] = u32::try_from(acc & 0xFFFF_FFFF).unwrap_or(0).to_be_bytes();
        let written: usize = match take {
            5 => 4,
            4 => 3,
            3 => 2,
            2 => 1,
            _ => return Err(()),
        };
        out.extend_from_slice(&bytes[..written]);
        i += 5;
    }
    Ok(out)
}

#[must_use]
pub fn bake(source: &str) -> String {
    let zipped: Vec<u8> = zlib_compress(source.as_bytes());
    let encoded: String = b64_encode(&zipped);
    let literal: String = python_bytes_literal(encoded.as_bytes());
    format!(
        "{BANNER}\n__obfuxtreme__ = '1'\n{RUNTIME_PAYLOAD_PREFIX}{encoded}\nexec(__import__('zlib').decompress(__import__('base64').b64decode({literal})))\n"
    )
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn obfuxtreme_roundtrip_via_sidecar() {
        let original: &str =
            "match x:\n    case 1:\n        print('one')\n    case _:\n        print('?')\n";
        let obf: String = bake(original);
        assert!(ObfuXtremePass.detect(obf.as_bytes()).matched);
        let out: PeelOutcome = ObfuXtremePass.peel(obf.as_bytes()).expect("peel");
        assert_eq!(out.recovered_source, original);
    }
}
