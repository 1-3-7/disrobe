use crate::error::{Error, Result};
use crate::obfuscator::string_decode::{
    LoaderRecovery, extract_string_char_arrays, recover_xor_base64_loader,
    structural_xor_base64_loader,
};
use crate::obfuscator::vm_devirt::{devirt_to_peel, extract_embedded_payload};
use crate::obfuscator::{DeobfOptions, LuaObfuscatorKind, ObfuscatorDetection, PeelResult};

const MARKERS: &[&[u8]] = &[b"-- MoonSec v1", b"moonsec_v1", b"--[[ MoonSec V1 ]]"];

#[must_use]
pub fn detect(src: &[u8]) -> Option<ObfuscatorDetection> {
    let mut found: Vec<String> = Vec::new();
    for m in MARKERS {
        if disrobe_core::byte_search::contains(src, m) {
            found.push(String::from_utf8_lossy(m).into_owned());
        }
    }
    if !found.is_empty() {
        return Some(ObfuscatorDetection {
            kind: LuaObfuscatorKind::MoonSecV1,
            variant: Some("string-pool+simple-cff".to_owned()),
            confidence: 88,
            markers: found,
        });
    }
    detect_markerless(src)
}

#[must_use]
fn detect_markerless(src: &[u8]) -> Option<ObfuscatorDetection> {
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(src);
    let recovery: LoaderRecovery = structural_xor_base64_loader(&text)?;
    Some(ObfuscatorDetection {
        kind: LuaObfuscatorKind::MoonSecV1,
        variant: Some("markerless-base64-xor-loadstring-loader".to_owned()),
        confidence: 70,
        markers: vec![format!(
            "structural base64+xor loadstring loader: {} base64 chars decrypt to plausible lua",
            recovery.base64_len
        )],
    })
}

pub fn peel(src: &[u8], _opts: &DeobfOptions) -> Result<PeelResult> {
    if detect(src).is_none() {
        return Err(Error::NoObfuscatorSignature("MoonSec V1"));
    }
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(src);
    let embedded_payload: Option<Vec<u8>> = extract_embedded_payload(&text);
    if let Some(payload) = embedded_payload {
        return devirt_to_peel(src, &text, &payload, "moonsec-v1");
    }
    if let Some(recovery) = recover_xor_base64_loader(&text) {
        return Ok(decode_loader_peel(&recovery));
    }
    let pool: Vec<String> = recover_string_pool(&text);
    if pool.is_empty() {
        return Ok(PeelResult::passthrough(
            src,
            vec![
                "moonsec v1: neither a static VMPAYLOAD blob nor a string.char pool is present in this artifact"
                    .to_owned(),
            ],
        ));
    }
    let mut out: String = String::from("local MOONSEC_V1_STRINGS = {\n");
    for s in &pool {
        out.push_str("  ");
        out.push_str(&quote_lua(s));
        out.push_str(",\n");
    }
    out.push_str("}\n");
    Ok(PeelResult {
        deobfuscated: out.into_bytes(),
        passes_run: vec!["moonsec-v1-string-char-pool-recover".to_owned()],
        residual_markers: vec![
            "moonsec v1 vm: string.char pool recovered; bytecode/CFF dispatch layer remains"
                .to_owned(),
        ],
        recovered_strings: pool,
        fully_recovered: false,
    })
}

#[must_use]
fn key_hex(key: &[u8]) -> String {
    const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let mut out: String = String::with_capacity(key.len() * 2);
    for byte in key.iter().copied() {
        out.push(char::from(HEX_UPPER[usize::from(byte >> 4)]));
        out.push(char::from(HEX_UPPER[usize::from(byte & 0x0f)]));
    }
    out
}

#[must_use]
fn decode_loader_peel(recovery: &LoaderRecovery) -> PeelResult {
    let is_bytecode: bool =
        recovery.plaintext.starts_with(b"\x1bLua") || recovery.plaintext.starts_with(b"\x1bLJ");
    let pass: String = format!(
        "moonsec-v1-base64-xor-loader-decrypt (key 0x{}, {} base64 chars)",
        key_hex(&recovery.key),
        recovery.base64_len,
    );
    if is_bytecode {
        return PeelResult {
            deobfuscated: recovery.plaintext.clone(),
            passes_run: vec![pass],
            residual_markers: vec![
                "moonsec v1: base64+xor loader decrypted to a Lua bytecode chunk; route the recovered chunk through the Lua reader/decompiler".to_owned(),
            ],
            recovered_strings: Vec::new(),
            fully_recovered: false,
        };
    }
    PeelResult {
        deobfuscated: recovery.plaintext.clone(),
        passes_run: vec![pass],
        residual_markers: Vec::new(),
        recovered_strings: Vec::new(),
        fully_recovered: true,
    }
}

#[must_use]
fn recover_string_pool(text: &str) -> Vec<String> {
    extract_string_char_arrays(text)
        .into_iter()
        .filter_map(|bytes: Vec<u8>| {
            let s: String = String::from_utf8_lossy(&bytes).into_owned();
            let printable: bool = s
                .chars()
                .all(|c: char| !c.is_control() || c == '\n' || c == '\t' || c == '\r');
            if printable && s.chars().any(|c: char| !c.is_whitespace()) {
                Some(s)
            } else {
                None
            }
        })
        .collect()
}

#[must_use]
fn quote_lua(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\{}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
