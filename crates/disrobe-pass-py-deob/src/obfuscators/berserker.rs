use std::collections::BTreeMap;

use crate::codec::{
    b64_decode, b64_encode, decode_python_bytes_literal, extract_largest_python_bytes_literal,
    lzma_compress, lzma_decompress, python_bytes_literal, xor_apply, zlib_compress,
    zlib_decompress,
};
use crate::error::{Error, Result};
use crate::obfuscators::{DetectReport, Obfuscator, ObfuscatorPass, PeelOutcome, Quality};

#[derive(Debug, Clone, Copy)]
pub struct BerserkerPass;

const BERSERKER_KEY: &[u8] = b"berserker-v1-static-key";

impl ObfuscatorPass for BerserkerPass {
    fn id(&self) -> Obfuscator {
        Obfuscator::Berserker
    }

    fn detect(&self, source: &[u8]) -> DetectReport {
        let head: &[u8] = &source[..source.len().min(16 * 1024)];
        let text: &str = std::str::from_utf8(head).unwrap_or("");
        let banner: bool = text.contains("# Berserker") || text.contains("__berserker__");
        let stack: bool = text.contains("base64")
            && text.contains("lzma")
            && (text.contains("zlib") || text.contains("xor"));
        let real_class: bool = text.contains("class Berserker():")
            && text.contains("def __decode__(self,_execute: str)->exec:");
        let real_invoke: bool = text.contains("_sparkle=") && text.contains("Berserker(");
        let real: bool = real_class && real_invoke;
        let mut markers: Vec<String> = Vec::new();
        if banner {
            markers.push("berserker-banner".to_owned());
        }
        if stack {
            markers.push("base64+lzma+zlib".to_owned());
        }
        if real {
            markers.push("berserker-real-class+sparkle".to_owned());
        }
        let matched: bool = banner || stack || real;
        let confidence: f32 = if banner {
            0.95
        } else if real {
            0.9
        } else if matched {
            0.65
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
        let literal: &str =
            extract_largest_python_bytes_literal(text).ok_or(Error::LiteralNotFound)?;
        let raw: Vec<u8> = decode_python_bytes_literal(literal)?;
        let mut stages: Vec<String> = Vec::with_capacity(4);
        let b64_decoded: Vec<u8> = b64_decode(&raw)?;
        stages.push("base64".to_owned());
        let unxored: Vec<u8> = xor_apply(&b64_decoded, BERSERKER_KEY);
        stages.push("xor".to_owned());
        let unlzma: Vec<u8> = lzma_decompress(&unxored)?;
        stages.push("lzma".to_owned());
        let unzlib: Vec<u8> = zlib_decompress(&unlzma)?;
        stages.push("zlib".to_owned());
        let recovered: String =
            String::from_utf8(unzlib).map_err(|e| Error::AstCleanup(format!("{e}")))?;
        let mut diagnostics: BTreeMap<String, String> = BTreeMap::new();
        diagnostics.insert("stage_count".to_owned(), stages.len().to_string());
        Ok(PeelOutcome {
            obfuscator: self.id(),
            stages_applied: stages,
            recovered_source: recovered,
            confidence: 0.95,
            quality: Quality::Full,
            lossy_notes: vec![
                "static-key bake reproducible; live samples may use rotated key per build"
                    .to_owned(),
            ],
            diagnostics,
        })
    }
}

#[must_use]
pub fn bake(source: &str) -> String {
    let layer_zlib: Vec<u8> = zlib_compress(source.as_bytes());
    let layer_lzma: Vec<u8> = lzma_compress(&layer_zlib);
    let layer_xor: Vec<u8> = xor_apply(&layer_lzma, BERSERKER_KEY);
    let payload_b64: String = b64_encode(&layer_xor);
    let literal: String = python_bytes_literal(payload_b64.as_bytes());
    format!(
        "# Berserker v1 obfuscator (bake-generated)\nimport base64, lzma, zlib\n__berserker__ = '1.0'\nexec(zlib.decompress(lzma.decompress(bytes(b ^ k for b, k in zip(base64.b64decode({literal}), (b'berserker-v1-static-key' * 4096))))))\n"
    )
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn berserker_roundtrip_recovers_source() {
        let original: &str = "def add(a: int, b: int) -> int:\n    return a + b\n";
        let obf: String = bake(original);
        let det: DetectReport = BerserkerPass.detect(obf.as_bytes());
        assert!(det.matched);
        let out: PeelOutcome = BerserkerPass.peel(obf.as_bytes()).expect("peel");
        assert_eq!(out.recovered_source, original);
        assert_eq!(out.quality, Quality::Full);
    }
}
