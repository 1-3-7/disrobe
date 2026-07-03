use std::collections::BTreeMap;

use aes::Aes256;
use cbc::Decryptor;
use cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use disrobe_pass_py_decompile::bytecode::version::PyVersion as DecompileVersion;
use disrobe_pass_py_decompile::engine::{build_real_source, marshal_to_decompile};
use disrobe_pass_py_disasm::{Instruction, disassemble, render_dis};
use disrobe_py_marshal::{CodeObject, Object, PyVersion, load as marshal_load};

use crate::codec::{
    b64_decode, b64_encode, b85_decode, decode_python_bytes_literal,
    extract_largest_python_bytes_literal, python_bytes_literal, zlib_compress, zlib_decompress,
};
use crate::error::{Error, Result};
use crate::obfuscators::{DetectReport, Obfuscator, ObfuscatorPass, PeelOutcome, Quality};

type Aes256CbcDec = Decryptor<Aes256>;

const OBFUXTREME_MARSHAL_VERSION: PyVersion = PyVersion::PY314;
const MAX_NESTED_CODE_DEPTH: usize = 32;
const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

fn push_lower_hex_byte(out: &mut String, byte: u8) {
    out.push(LOWER_HEX[(byte >> 4) as usize] as char);
    out.push(LOWER_HEX[(byte & 0x0f) as usize] as char);
}

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
        let recovered_is_source: bool = parses_as_python(&recovered);
        let quality: Quality = if recovered_is_source {
            Quality::Full
        } else {
            lossy_notes.push(
                "recovered payload does not parse as Python; runtime-eval segments remain"
                    .to_owned(),
            );
            Quality::Partial
        };
        Ok(PeelOutcome {
            obfuscator: self.id(),
            stages_applied: stages,
            recovered_source: recovered,
            confidence: if recovered_is_source { 0.95 } else { 0.9 },
            quality,
            lossy_notes,
            diagnostics,
        })
    }
}

fn peel_v4_upstream(id: Obfuscator, text: &str) -> PeelOutcome {
    let mut ctx: V4Ctx = V4Ctx::new();
    ctx.stages.push("v4-detect".to_owned());
    let marshal_version: PyVersion =
        detect_expected_version(text).unwrap_or(OBFUXTREME_MARSHAL_VERSION);
    ctx.diagnostics.insert(
        "marshal_version".to_owned(),
        format!("{}.{}", marshal_version.major, marshal_version.minor),
    );
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

    let Ok(mut enc) = b85_decode(payload_str.as_bytes()) else {
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

    let Ok(root) = marshal_load(&inflated, marshal_version) else {
        ctx.lossy_notes
            .push("AES+zlib reversed but marshal load of the inner code object failed".to_owned());
        return into_detect_only(id, ctx, text);
    };
    ctx.stages.push("marshal-load".to_owned());
    let Some(top): Option<CodeObject> = top_code_object(&root) else {
        ctx.lossy_notes
            .push("marshalled payload held no code object".to_owned());
        return into_detect_only(id, ctx, text);
    };
    let instructions: Vec<Instruction> = disassemble(&top, marshal_version);
    ctx.diagnostics.insert(
        "instruction_count".to_owned(),
        instructions.len().to_string(),
    );

    let decompiled: Option<String> = decompile_top(&top, marshal_version);
    let Some(raw_source): Option<String> = decompiled else {
        let listing: String = render_dis(&instructions);
        ctx.stages.push("bytecode-disassemble".to_owned());
        ctx.lossy_notes.push(
            "AES+zlib+marshal reversed; source structurer did not converge, emitting bytecode disassembly"
                .to_owned(),
        );
        return PeelOutcome {
            obfuscator: id,
            stages_applied: ctx.stages,
            recovered_source: format!(
                "# obfuxtreme v4 recovered code object disassembly\n{listing}"
            ),
            confidence: 0.9,
            quality: Quality::Partial,
            lossy_notes: ctx.lossy_notes,
            diagnostics: ctx.diagnostics,
        };
    };
    ctx.stages.push("decompile".to_owned());

    let (recovered, decrypted): (String, usize) = decrypt_inline_strings(&raw_source, &key);
    if decrypted > 0 {
        ctx.stages.push("string-aes-decrypt".to_owned());
    }
    ctx.diagnostics
        .insert("strings_decrypted".to_owned(), decrypted.to_string());

    let still_wrapped: bool =
        recovered.contains("_decrypt_str(b") || recovered.contains("_decrypt_bytes(b");
    let parses: bool = parses_as_python(&recovered);
    let quality: Quality = if parses && !still_wrapped {
        Quality::Full
    } else {
        Quality::Partial
    };
    ctx.diagnostics
        .insert("recovered_parses".to_owned(), parses.to_string());

    if quality == Quality::Full {
        ctx.lossy_notes.push(
            "ObfuXtreme v4 fully reversed: AES key/iv recovered from the loader xor-split, payload AES-256-CBC decrypted, marshalled code object decompiled to source, and every _decrypt_str/_decrypt_bytes constant statically AES-decrypted to its literal. Control-flow flattening (state-machine) and local renames are structural and remain in the recovered source."
                .to_owned(),
        );
    } else if still_wrapped {
        ctx.lossy_notes.push(
            "ObfuXtreme v4 decompiled to source; some _decrypt_str/_decrypt_bytes constants could not be statically AES-decrypted and remain wrapped"
                .to_owned(),
        );
    } else {
        ctx.lossy_notes.push(
            "ObfuXtreme v4 decompiled but recovered source did not re-parse cleanly".to_owned(),
        );
    }

    PeelOutcome {
        obfuscator: id,
        stages_applied: ctx.stages,
        recovered_source: recovered,
        confidence: if quality == Quality::Full { 0.95 } else { 0.9 },
        quality,
        lossy_notes: ctx.lossy_notes,
        diagnostics: ctx.diagnostics,
    }
}

fn detect_expected_version(text: &str) -> Option<PyVersion> {
    let needle: &str = "EXPECTED_PY = (";
    let start: usize = text.find(needle)? + needle.len();
    let rest: &str = &text[start..];
    let end: usize = rest.find(')')?;
    let inner: &str = &rest[..end];
    let mut parts: std::str::Split<'_, char> = inner.split(',');
    let major: u8 = parts.next()?.trim().parse::<u8>().ok()?;
    let minor: u8 = parts.next()?.trim().parse::<u8>().ok()?;
    Some(PyVersion::new(major, minor))
}

fn decompile_top(top: &CodeObject, marshal_version: PyVersion) -> Option<String> {
    let decompile_version: DecompileVersion = marshal_to_decompile(marshal_version).ok()?;
    let source: String = build_real_source(top, &decompile_version, marshal_version).ok()?;
    if source.trim().is_empty() {
        return None;
    }
    Some(source)
}

fn decrypt_inline_strings(source: &str, key: &[u8]) -> (String, usize) {
    let mut out: String = String::with_capacity(source.len());
    let mut decrypted: usize = 0;
    let mut i: usize = 0;
    while i < source.len() {
        if let Some((rendered, next)) = try_decrypt_call_at(source, i, key) {
            out.push_str(&rendered);
            decrypted += 1;
            i = next;
            continue;
        }
        let ch: char = source[i..].chars().next().unwrap_or('\u{fffd}');
        out.push(ch);
        i += ch.len_utf8();
    }
    (out, decrypted)
}

fn try_decrypt_call_at(source: &str, i: usize, key: &[u8]) -> Option<(String, usize)> {
    let (wrapper_len, is_bytes): (usize, bool) = match_decrypt_call(&source[i..])?;
    let after_open: usize = i + wrapper_len;
    let (literal, consumed): (Vec<u8>, usize) = parse_byte_string_literal(&source[after_open..])?;
    let close: usize = after_open + consumed;
    if source.as_bytes().get(close) != Some(&b')') {
        return None;
    }
    let rendered: String = decrypt_one(&literal, key, is_bytes)?;
    Some((rendered, close + 1))
}

fn match_decrypt_call(s: &str) -> Option<(usize, bool)> {
    const STR_CALL: &str = "_decrypt_str(";
    const BYTES_CALL: &str = "_decrypt_bytes(";
    if s.starts_with(BYTES_CALL) {
        return Some((BYTES_CALL.len(), true));
    }
    if s.starts_with(STR_CALL) {
        return Some((STR_CALL.len(), false));
    }
    None
}

fn parse_byte_string_literal(s: &str) -> Option<(Vec<u8>, usize)> {
    let bytes: &[u8] = s.as_bytes();
    if bytes.first() != Some(&b'b') {
        return None;
    }
    let quote: u8 = *bytes.get(1)?;
    if quote != b'\'' && quote != b'"' {
        return None;
    }
    let mut out: Vec<u8> = Vec::new();
    let mut i: usize = 2;
    while i < bytes.len() {
        let c: u8 = bytes[i];
        if c == quote {
            return Some((out, i + 1));
        }
        if c == b'\\' {
            let (byte, advance): (u8, usize) = decode_escape(bytes, i);
            if advance == 1 {
                out.push(b'\\');
                i += 1;
            } else {
                out.push(byte);
                i += advance;
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    None
}

fn decrypt_one(literal: &[u8], key: &[u8], is_bytes: bool) -> Option<String> {
    if literal.len() < 32 || !literal.len().is_multiple_of(16) {
        return None;
    }
    let (iv, ct): (&[u8], &[u8]) = literal.split_at(16);
    let mut buf: Vec<u8> = ct.to_vec();
    let plain: Vec<u8> = decrypt_aes256_cbc_pkcs7(key, iv, &mut buf)?;
    if is_bytes {
        Some(render_bytes_literal(&plain))
    } else {
        let text: String = String::from_utf8_lossy(&plain).into_owned();
        Some(render_str_literal(&text))
    }
}

fn render_str_literal(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str("\\x");
                push_lower_hex_byte(&mut out, c as u8);
            }
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

fn render_bytes_literal(data: &[u8]) -> String {
    let mut out: String = String::with_capacity(data.len() + 3);
    out.push_str("b'");
    for &b in data {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'\'' => out.push_str("\\'"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(char::from(b)),
            other => {
                out.push_str("\\x");
                push_lower_hex_byte(&mut out, other);
            }
        }
    }
    out.push('\'');
    out
}

fn top_code_object(obj: &Object) -> Option<CodeObject> {
    fn walk(obj: &Object, depth: usize) -> Option<CodeObject> {
        if depth > MAX_NESTED_CODE_DEPTH {
            return None;
        }
        match obj {
            Object::Code(co) => Some((**co).clone()),
            Object::Tuple(items)
            | Object::List(items)
            | Object::Set(items)
            | Object::FrozenSet(items) => items.iter().find_map(|c: &Object| walk(c, depth + 1)),
            Object::Dict(d) | Object::FrozenDict(d) => d
                .iter()
                .find_map(|(_, v): (&Object, &Object)| walk(v, depth + 1)),
            _ => None,
        }
    }
    walk(obj, 0)
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

fn parses_as_python(source: &str) -> bool {
    use ruff_python_ast::Mod;
    use ruff_python_parser::{Mode, ParseOptions, Parsed, parse};
    if source.trim().is_empty() {
        return false;
    }
    parse(source, ParseOptions::from(Mode::Module))
        .is_ok_and(|p: Parsed<Mod>| p.errors().is_empty())
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

    #[test]
    fn detect_expected_version_parses_loader_guard() {
        let text: &str = "EXPECTED_PY = (3, 12)\n";
        assert_eq!(detect_expected_version(text), Some(PyVersion::new(3, 12)));
        assert_eq!(detect_expected_version("no version here"), None);
    }

    #[test]
    fn decrypt_inline_strings_roundtrips_aes_wrapped_constant() {
        use aes::Aes256;
        use cbc::Encryptor;
        use cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
        type Enc = Encryptor<Aes256>;

        let key: [u8; 32] = [7u8; 32];
        let iv: [u8; 16] = [3u8; 16];
        let plaintext: &[u8] = b"hello world";
        let mut buf: Vec<u8> = vec![0u8; plaintext.len() + 16];
        buf[..plaintext.len()].copy_from_slice(plaintext);
        let enc: Enc = Enc::new_from_slices(&key, &iv).expect("enc");
        let ct: &[u8] = enc
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            .expect("encrypt");
        let mut wrapped: Vec<u8> = iv.to_vec();
        wrapped.extend_from_slice(ct);
        let literal: String = render_bytes_literal(&wrapped);
        let source: String = format!("x = _decrypt_str({literal})\n");

        let (out, n): (String, usize) = decrypt_inline_strings(&source, &key);
        assert_eq!(n, 1);
        assert_eq!(out, "x = 'hello world'\n");
    }

    #[test]
    fn render_str_literal_escapes_quotes_and_controls() {
        assert_eq!(render_str_literal("a'b"), "'a\\'b'");
        assert_eq!(render_str_literal("x\ny"), "'x\\ny'");
    }

    #[test]
    fn parse_byte_string_literal_handles_hex_escapes() {
        let (bytes, consumed): (Vec<u8>, usize) =
            parse_byte_string_literal("b'\\x00AB'rest").expect("parse");
        assert_eq!(bytes, vec![0x00, b'A', b'B']);
        assert_eq!(consumed, "b'\\x00AB'".len());
    }
}
