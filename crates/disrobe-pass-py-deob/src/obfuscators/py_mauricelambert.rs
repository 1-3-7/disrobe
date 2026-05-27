use std::collections::BTreeMap;

use crate::codec::{
    b64_decode, b64_encode, decode_python_bytes_literal, extract_largest_python_bytes_literal,
    python_bytes_literal, xor_apply,
};
use crate::error::{Error, Result};
use crate::obfuscators::{DetectReport, Obfuscator, ObfuscatorPass, PeelOutcome, Quality};

#[derive(Debug, Clone, Copy)]
pub struct PyObfuscatorMauricelambertPass;

const MAURICE_KEY: &[u8] = b"PyObfuscator-Mauricelambert";

impl ObfuscatorPass for PyObfuscatorMauricelambertPass {
    fn id(&self) -> Obfuscator {
        Obfuscator::PyObfuscatorMauricelambert
    }

    fn detect(&self, source: &[u8]) -> DetectReport {
        let head: &[u8] = &source[..source.len().min(16 * 1024)];
        let text: &str = std::str::from_utf8(head).unwrap_or("");
        let banner: bool = text.contains("Mauricelambert")
            || text.contains("__pyobfuscator__")
            || text.contains("PyObfuscator");
        let real_gzip: bool = text.contains("from gzip import decompress as __")
            && text.contains("_=exec")
            && text.contains("_(__(b'\\x1f\\x8b\\x08");
        let mut markers: Vec<String> = Vec::new();
        if banner {
            markers.push("pyobfuscator-mauricelambert".to_owned());
        }
        if real_gzip {
            markers.push("gzip-decompress-exec-bytes-magic".to_owned());
        }
        let matched: bool = banner || real_gzip;
        let confidence: f32 = if banner {
            0.9
        } else if real_gzip {
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
        let text: &str = std::str::from_utf8(source).map_err(Error::from)?;
        let literal: &str =
            extract_largest_python_bytes_literal(text).ok_or(Error::LiteralNotFound)?;
        let raw: Vec<u8> = decode_python_bytes_literal(literal)?;
        let mut stages: Vec<String> = Vec::with_capacity(2);
        let b64: Vec<u8> = b64_decode(&raw)?;
        stages.push("base64".to_owned());
        let unxored: Vec<u8> = xor_apply(&b64, MAURICE_KEY);
        stages.push("xor".to_owned());
        let recovered: String =
            String::from_utf8(unxored).map_err(|e| Error::AstCleanup(format!("{e}")))?;
        let mut diagnostics: BTreeMap<String, String> = BTreeMap::new();
        diagnostics.insert("payload_len".to_owned(), raw.len().to_string());
        Ok(PeelOutcome {
            obfuscator: self.id(),
            stages_applied: stages,
            recovered_source: recovered,
            confidence: 0.9,
            quality: Quality::Full,
            lossy_notes: vec![
                "upstream Mauricelambert randomizes per-build key; canonical key in bake"
                    .to_owned(),
            ],
            diagnostics,
        })
    }
}

#[must_use]
pub fn bake(source: &str) -> String {
    let xored: Vec<u8> = xor_apply(source.as_bytes(), MAURICE_KEY);
    let encoded: String = b64_encode(&xored);
    let literal: String = python_bytes_literal(encoded.as_bytes());
    format!(
        "# PyObfuscator (Mauricelambert)\n__pyobfuscator__ = '1.0'\nimport base64\nexec(bytes(b ^ k for b, k in zip(base64.b64decode({literal}), (b'PyObfuscator-Mauricelambert' * 4096))).decode())\n"
    )
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn maurice_roundtrip() {
        let original: &str = "def g(): yield from range(3)\n";
        let obf: String = bake(original);
        assert!(
            PyObfuscatorMauricelambertPass
                .detect(obf.as_bytes())
                .matched
        );
        let out: PeelOutcome = PyObfuscatorMauricelambertPass
            .peel(obf.as_bytes())
            .expect("peel");
        assert_eq!(out.recovered_source, original);
    }
}
