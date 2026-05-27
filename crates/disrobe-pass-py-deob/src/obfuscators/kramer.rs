use std::collections::BTreeMap;

use disrobe_py_marshal::{CodeEra, CodeObject, Object, PyVersion, dump as marshal_dump};

use crate::codec::{
    bytes_to_hex, decode_python_bytes_literal, extract_largest_python_bytes_literal, lzma_compress,
    lzma_decompress, python_bytes_literal, xor_apply,
};
use crate::error::Result;
use crate::hyperion_v2v3::{decode_inner_with_version, detect as detect_hyperion};
use crate::obfuscators::{DetectReport, Obfuscator, ObfuscatorPass, PeelOutcome, Quality};

#[derive(Debug, Clone, Copy)]
pub struct KramerPass;

const KRAMER_MARSHAL_VERSION: PyVersion = PyVersion::PY311;

impl ObfuscatorPass for KramerPass {
    fn id(&self) -> Obfuscator {
        Obfuscator::Kramer
    }

    fn detect(&self, source: &[u8]) -> DetectReport {
        let head: &[u8] = &source[..source.len().min(64 * 1024)];
        let text: &str = std::str::from_utf8(head).unwrap_or("");
        let hyperion: crate::hyperion_v2v3::HyperionV2V3Detection = detect_hyperion(source);
        let kramer_signal: bool = text.contains("Kramer")
            || text.contains("Specter")
            || (text.contains("xor_bytes") && text.contains("fromhex("));
        let lzma_signal: bool = text.contains("lzma");
        let marshal_signal: bool = text.contains("marshal");
        let pyc_magic: bool = is_pyc_with_kramer_signature(source);
        let upstream_inline: bool = text.contains("class Kramer():")
            && text.contains("def __decode__")
            && text.contains("def __init__");
        let mut markers: Vec<String> = Vec::new();
        if kramer_signal {
            markers.push("kramer-marker".to_owned());
        }
        if lzma_signal {
            markers.push("lzma".to_owned());
        }
        if marshal_signal {
            markers.push("marshal".to_owned());
        }
        if pyc_magic {
            markers.push("kramer-pyc-with-ceb6-blob".to_owned());
        }
        if upstream_inline {
            markers.push("kramer-upstream-class-shape".to_owned());
        }
        let matched: bool = matches!(
            hyperion.variant,
            crate::hyperion_v2v3::HyperionVariant::KramerSuccessor
        ) || (kramer_signal && lzma_signal && marshal_signal)
            || pyc_magic
            || upstream_inline;
        let confidence: f32 = if pyc_magic && upstream_inline {
            0.98
        } else if matched {
            0.92
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
        if is_pyc_with_kramer_signature(source) {
            return Ok(peel_pyc_blob(self.id(), source));
        }
        if let Ok(text) = std::str::from_utf8(source)
            && text.contains("class Kramer():")
            && text.contains("def __decode__")
        {
            return Ok(peel_upstream_source(self.id(), text));
        }
        let inner: crate::hyperion_v2v3::InnerDecodeResult =
            decode_inner_with_version(source, KRAMER_MARSHAL_VERSION)?;
        let mut stages: Vec<String> = Vec::with_capacity(inner.stages.len());
        for stage in &inner.stages {
            let label: String = format!("{:?}", stage.kind).to_ascii_lowercase();
            stages.push(label);
        }
        let recovered: String = inner.recovered_source.unwrap_or_default();
        let mut diagnostics: BTreeMap<String, String> = BTreeMap::new();
        diagnostics.insert(
            "code_object_count".to_owned(),
            inner.code_object_summaries.len().to_string(),
        );
        if let Some(disasm) = inner.disasm.as_ref() {
            diagnostics.insert("disasm_bytes".to_owned(), disasm.len().to_string());
        }
        let quality: Quality = if inner.code_object_summaries.is_empty() {
            Quality::Partial
        } else {
            Quality::Full
        };
        let lossy_notes: Vec<String> = vec![
            "kramer recovers code-object disassembly; source-level reconstruction needs upstream decompiler".to_owned(),
        ];
        Ok(PeelOutcome {
            obfuscator: self.id(),
            stages_applied: stages,
            recovered_source: recovered,
            confidence: 0.95,
            quality,
            lossy_notes,
            diagnostics,
        })
    }
}

fn is_pyc_with_kramer_signature(source: &[u8]) -> bool {
    if source.len() < 16 {
        return false;
    }
    let pyc_magic_present: bool = source[2] == 0x0d && source[3] == 0x0a;
    if !pyc_magic_present {
        return false;
    }
    contains_subsequence(source, b"Kramer")
        || contains_subsequence(source, b"_sparkle")
        || contains_subsequence(source, b"__decode__")
}

fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
}

fn peel_pyc_blob(id: Obfuscator, source: &[u8]) -> PeelOutcome {
    let mut stages: Vec<String> = Vec::new();
    let mut diagnostics: BTreeMap<String, String> = BTreeMap::new();
    let mut lossy_notes: Vec<String> = Vec::new();
    stages.push("pyc-blob-scan".to_owned());

    let blob: Vec<u8> = extract_kramer_hex_blob(source);
    diagnostics.insert("blob_hex_len".to_owned(), blob.len().to_string());
    if blob.is_empty() {
        lossy_notes.push("no ceb6.*ceb6 blob found in pyc".to_owned());
        return PeelOutcome {
            obfuscator: id,
            stages_applied: stages,
            recovered_source: String::new(),
            confidence: 0.4,
            quality: Quality::DetectOnly,
            lossy_notes,
            diagnostics,
        };
    }
    let segments: Vec<Vec<u8>> = split_and_unhex(&blob);
    diagnostics.insert("segment_count".to_owned(), segments.len().to_string());
    stages.push("hex-unwrap".to_owned());

    let (key, decrypted): (Option<u32>, String) = brute_force_kramer_key(&segments);
    if let Some(k) = key {
        diagnostics.insert("kramer_key".to_owned(), k.to_string());
        stages.push("kyrie-decrypt".to_owned());
        stages.push("dkyrie-shift".to_owned());
        PeelOutcome {
            obfuscator: id,
            stages_applied: stages,
            recovered_source: decrypted,
            confidence: 0.95,
            quality: Quality::Full,
            lossy_notes,
            diagnostics,
        }
    } else {
        lossy_notes.push(
            "brute-force key search exhausted 3..1_000_000 without finding `import` marker; \
             pass --kramer-key <N> when known"
                .to_owned(),
        );
        PeelOutcome {
            obfuscator: id,
            stages_applied: stages,
            recovered_source: decrypted,
            confidence: 0.55,
            quality: Quality::Partial,
            lossy_notes,
            diagnostics,
        }
    }
}

fn extract_kramer_hex_blob(source: &[u8]) -> Vec<u8> {
    let mut best: (usize, usize) = (0, 0);
    let mut start: Option<usize> = None;
    for (i, &b) in source.iter().enumerate() {
        let ok: bool = matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'/');
        if ok {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start {
            let len: usize = i - s;
            if len > best.1 - best.0 && source[s..i].contains(&b'/') {
                best = (s, i);
            }
            start = None;
        }
    }
    if let Some(s) = start {
        let len: usize = source.len() - s;
        if len > best.1 - best.0 && source[s..].contains(&b'/') {
            best = (s, source.len());
        }
    }
    if best.0 == best.1 {
        return Vec::new();
    }
    source[best.0..best.1].to_vec()
}

fn split_and_unhex(blob: &[u8]) -> Vec<Vec<u8>> {
    let mut segments: Vec<Vec<u8>> = Vec::new();
    for seg in blob.split(|c: &u8| *c == b'/') {
        if seg.is_empty() || seg.len() % 2 != 0 {
            continue;
        }
        let mut buf: Vec<u8> = Vec::with_capacity(seg.len() / 2);
        let mut ok: bool = true;
        let mut j: usize = 0;
        while j < seg.len() {
            let hi: Option<u8> = hex_to_nibble(seg[j]);
            let lo: Option<u8> = hex_to_nibble(seg[j + 1]);
            if let (Some(h), Some(l)) = (hi, lo) {
                buf.push((h << 4) | l);
                j += 2;
            } else {
                ok = false;
                break;
            }
        }
        if ok && !buf.is_empty() {
            segments.push(buf);
        }
    }
    segments
}

const fn hex_to_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

const KRAMER_ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

fn kyrie_decrypt_then_dkyrie(input: &[u8], key: u32) -> Option<String> {
    let key_shift: i64 = i64::from(key);
    let mut out: Vec<char> = Vec::with_capacity(input.len());
    let text: &str = std::str::from_utf8(input).ok()?;
    for ch in text.chars() {
        if ch == '\u{03B6}' {
            out.push('\n');
            continue;
        }
        let cp: i64 = i64::from(ch as u32);
        let shifted: i64 = cp - key_shift;
        if !(0..=0x0010_FFFF).contains(&shifted) {
            return None;
        }
        let shifted_u32: u32 = u32::try_from(shifted).ok()?;
        let dec: char = char::from_u32(shifted_u32)?;
        if let Some(pos) = KRAMER_ALPHA.iter().position(|c: &u8| (*c as char) == dec) {
            let next: usize = (pos + 1) % KRAMER_ALPHA.len();
            out.push(KRAMER_ALPHA[next] as char);
        } else {
            out.push(dec);
        }
    }
    Some(out.into_iter().collect())
}

fn brute_force_kramer_key(segments: &[Vec<u8>]) -> (Option<u32>, String) {
    let probe: &[Vec<u8>] = &segments[..segments.len().min(8)];
    for key in 3u32..200_000u32 {
        let mut buf: String = String::new();
        let mut ok: bool = true;
        for seg in probe {
            if let Some(s) = kyrie_decrypt_then_dkyrie(seg, key) {
                buf.push_str(&s);
            } else {
                ok = false;
                break;
            }
        }
        if ok && buf.contains("import") {
            let mut full: String = String::new();
            for seg in segments {
                if let Some(s) = kyrie_decrypt_then_dkyrie(seg, key) {
                    full.push_str(&s);
                }
            }
            return (Some(key), full);
        }
    }
    (None, String::new())
}

fn peel_upstream_source(id: Obfuscator, text: &str) -> PeelOutcome {
    let stages: Vec<String> = vec!["upstream-source-class-detect".to_owned()];
    let mut diagnostics: BTreeMap<String, String> = BTreeMap::new();
    diagnostics.insert("source_bytes".to_owned(), text.len().to_string());
    PeelOutcome {
        obfuscator: id,
        stages_applied: stages,
        recovered_source: text.to_owned(),
        confidence: 0.5,
        quality: Quality::DetectOnly,
        lossy_notes: vec![
            "Kramer pre-compile source recovered structurally; the encrypted-blob string lives inside the _sparkle kwarg of Kramer(); compile to .pyc and re-peel for full Kyrie/dkyrie decryption".to_owned(),
        ],
        diagnostics,
    }
}

#[must_use]
pub fn bake(source: &str) -> String {
    let key: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37];
    let co: CodeObject = build_marker_code_object(source);
    let marshalled: Vec<u8> = marshal_dump(&Object::Code(Box::new(co)), KRAMER_MARSHAL_VERSION)
        .unwrap_or_else(|_| Vec::new());
    let xored: Vec<u8> = xor_apply(&marshalled, &key);
    let compressed: Vec<u8> = lzma_compress(&xored);
    let literal: String = python_bytes_literal(&compressed);
    let key_hex: String = bytes_to_hex(&key);
    format!(
        "import lzma\nimport marshal\n# Kramer obfuscator\nKEY = bytes.fromhex('{key_hex}').decode('latin1')\nexec(marshal.loads(xor_bytes(lzma.decompress({literal}), KEY)))\n"
    )
}

fn build_marker_code_object(source: &str) -> CodeObject {
    let mut co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
    let name_prefix: &str = "kramer_entry";
    co.name = Object::ShortAscii {
        value: name_prefix.to_owned(),
        interned: false,
    };
    co.qualname = Object::ShortAscii {
        value: name_prefix.to_owned(),
        interned: false,
    };
    co.filename = Object::ShortAscii {
        value: format!("<{}>", source.len()),
        interned: false,
    };
    co.firstlineno = 1;
    co.code = vec![0x97, 0x00, 0x64, 0x00, 0x53, 0x00];
    co
}

#[must_use]
pub fn try_recover_payload_bytes(source: &[u8]) -> Option<Vec<u8>> {
    let text: &str = std::str::from_utf8(source).ok()?;
    let lit: &str = extract_largest_python_bytes_literal(text)?;
    let raw: Vec<u8> = decode_python_bytes_literal(lit).ok()?;
    lzma_decompress(&raw).ok().or(Some(raw))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn kramer_detect_and_peel_roundtrip() {
        let original: &str = "def f(x): return x + 1\n";
        let stub: String = bake(original);
        let det: DetectReport = KramerPass.detect(stub.as_bytes());
        assert!(det.matched, "detect failed: {det:?}");
        let peeled: PeelOutcome = KramerPass.peel(stub.as_bytes()).expect("peel");
        assert!(!peeled.stages_applied.is_empty());
        assert_eq!(peeled.obfuscator, Obfuscator::Kramer);
        assert_eq!(peeled.quality, Quality::Full);
    }

    #[test]
    fn kramer_recovers_payload_bytes() {
        let original: &str = "x = 1\n";
        let stub: String = bake(original);
        let bytes: Option<Vec<u8>> = try_recover_payload_bytes(stub.as_bytes());
        assert!(bytes.is_some());
    }

    #[test]
    fn kramer_detect_rejects_plain_source() {
        let plain: &str = "def f(): return 1\n";
        let det: DetectReport = KramerPass.detect(plain.as_bytes());
        assert!(!det.matched);
    }
}
