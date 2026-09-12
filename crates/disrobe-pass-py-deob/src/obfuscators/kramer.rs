use std::collections::BTreeMap;

use disrobe_core::byte_search::contains as contains_subsequence;
use disrobe_py_marshal::{CodeEra, CodeObject, Object, PyVersion, dump as marshal_dump};

use crate::codec::{
    bytes_to_hex, decode_python_bytes_literal, extract_largest_python_bytes_literal, lzma_compress,
    lzma_decompress, python_bytes_literal, xor_apply,
};
use crate::error::Result;
use crate::hyperion_v2v3::{decode_inner_with_version, detect as detect_hyperion};
use crate::obfuscators::de4py_family::{
    FamilyDecode, decode_sparkle_any, extract_hex_blob_from_pyc, extract_sparkle,
};
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

fn peel_pyc_blob(id: Obfuscator, source: &[u8]) -> PeelOutcome {
    let mut diagnostics: BTreeMap<String, String> = BTreeMap::new();
    let Some(blob_bytes): Option<&[u8]> = extract_hex_blob_from_pyc(source) else {
        return detect_only(
            id,
            vec!["pyc-blob-scan".to_owned()],
            diagnostics,
            vec!["no `/`-joined hex _sparkle blob found in pyc".to_owned()],
        );
    };
    diagnostics.insert("blob_hex_len".to_owned(), blob_bytes.len().to_string());
    let Ok(blob): std::result::Result<&str, _> = std::str::from_utf8(blob_bytes) else {
        return detect_only(
            id,
            vec!["pyc-blob-scan".to_owned()],
            diagnostics,
            vec!["pyc hex blob was not valid ascii".to_owned()],
        );
    };
    decode_sparkle_outcome(id, blob, "pyc-blob-scan")
}

fn decode_sparkle_outcome(id: Obfuscator, blob: &str, first_stage: &str) -> PeelOutcome {
    let mut diagnostics: BTreeMap<String, String> = BTreeMap::new();
    let Some(decode): Option<FamilyDecode> = decode_sparkle_any(blob) else {
        return detect_only(
            id,
            vec![first_stage.to_owned(), "hex-token-decode".to_owned()],
            diagnostics,
            vec![
                "Kramer hex _sparkle decode did not converge on printable source (>=95% ascii); \
                 per-build ord-shift not anchorable from leading bytes"
                    .to_owned(),
            ],
        );
    };
    diagnostics.insert(
        "sparkle_token_count".to_owned(),
        decode.token_count.to_string(),
    );
    diagnostics.insert("ord_shift".to_owned(), decode.shift.to_string());
    diagnostics.insert(
        "printable_ratio".to_owned(),
        format!("{:.4}", decode.printable_ratio),
    );
    PeelOutcome {
        obfuscator: id,
        stages_applied: vec![
            first_stage.to_owned(),
            "hex-token-unhexlify".to_owned(),
            "ord-shift".to_owned(),
            "alnum-ring-rotate".to_owned(),
        ],
        recovered_source: decode.recovered,
        confidence: 0.95,
        quality: Quality::Full,
        lossy_notes: vec![
            "de4py Kramer: hex _sparkle tokens decoded statically; per-build ord-shift recovered by printable-ratio anchoring; no runtime key or network needed"
                .to_owned(),
        ],
        diagnostics,
    }
}

const fn detect_only(
    id: Obfuscator,
    stages: Vec<String>,
    diagnostics: BTreeMap<String, String>,
    lossy_notes: Vec<String>,
) -> PeelOutcome {
    PeelOutcome {
        obfuscator: id,
        stages_applied: stages,
        recovered_source: String::new(),
        confidence: 0.4,
        quality: Quality::DetectOnly,
        lossy_notes,
        diagnostics,
    }
}

fn peel_upstream_source(id: Obfuscator, text: &str) -> PeelOutcome {
    extract_sparkle(text).map_or_else(
        || {
            detect_only(
                id,
                vec!["upstream-source-class-detect".to_owned()],
                BTreeMap::new(),
                vec![
                    "Kramer class detected but no _sparkle='''...''' payload extractable"
                        .to_owned(),
                ],
            )
        },
        |blob: &str| decode_sparkle_outcome(id, blob, "upstream-source-class-detect"),
    )
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
    co.consts = vec![Object::Unicode {
        value: source.to_owned(),
        interned: false,
    }];
    co
}

#[must_use]
pub fn try_recover_payload_bytes(source: &[u8]) -> Option<Vec<u8>> {
    let text: &str = std::str::from_utf8(source).ok()?;
    let lit: &str = extract_largest_python_bytes_literal(text)?;
    let raw: Vec<u8> = decode_python_bytes_literal(lit).ok()?;
    let decompressed: Vec<u8> = lzma_decompress(&raw).ok()?;
    let Some(key): Option<Vec<u8>> = extract_fromhex_key(text) else {
        return Some(decompressed);
    };
    Some(xor_apply(&decompressed, &key))
}

fn extract_fromhex_key(text: &str) -> Option<Vec<u8>> {
    let needle: &str = "fromhex(";
    let start: usize = text.find(needle)?;
    let body: &str = text.get(start + needle.len()..)?;
    let bytes: &[u8] = body.as_bytes();
    let mut quote: Option<u8> = None;
    let mut quote_start: usize = 0;
    for (i, &b) in bytes.iter().enumerate() {
        match quote {
            None if matches!(b, b'\'' | b'"') => {
                quote = Some(b);
                quote_start = i + 1;
            }
            Some(q) if b == q => {
                let hex: &str = body.get(quote_start..i)?;
                let cleaned: String = hex.chars().filter(char::is_ascii_hexdigit).collect();
                if cleaned.is_empty() || !cleaned.len().is_multiple_of(2) {
                    return None;
                }
                return hex_to_bytes(&cleaned);
            }
            _ => {}
        }
    }
    None
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    let bytes: &[u8] = hex.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi: u8 = nibble(pair[0])?;
        let lo: u8 = nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

#[inline]
const fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
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
        let recovered: Vec<u8> =
            try_recover_payload_bytes(stub.as_bytes()).expect("payload recovers");

        let expected_co: CodeObject = build_marker_code_object(original);
        let expected_marshal: Vec<u8> =
            marshal_dump(&Object::Code(Box::new(expected_co)), KRAMER_MARSHAL_VERSION)
                .expect("marshal dump");
        assert_eq!(
            recovered, expected_marshal,
            "recovered bytes must be the un-xored marshalled body, not lzma/xor ciphertext"
        );

        let root: Object =
            disrobe_py_marshal::load(&recovered, KRAMER_MARSHAL_VERSION).expect("marshal load");
        let Object::Code(co) = root else {
            panic!("recovered payload root is not a code object: {root:?}");
        };
        let Some(Object::Unicode { value, .. }) = co.consts.first() else {
            panic!(
                "recovered code object lost the source const: {:?}",
                co.consts
            );
        };
        assert_eq!(value, original);
        assert!(
            value.contains('x'),
            "recovered source must contain x: {value:?}"
        );
        assert!(
            value.contains('1'),
            "recovered source must contain 1: {value:?}"
        );

        assert!(
            contains_subsequence(&recovered, b"x = 1\n"),
            "marshalled body must embed the literal source bytes"
        );
    }

    #[test]
    fn kramer_detect_rejects_plain_source() {
        let plain: &str = "def f(): return 1\n";
        let det: DetectReport = KramerPass.detect(plain.as_bytes());
        assert!(!det.matched);
    }
}
