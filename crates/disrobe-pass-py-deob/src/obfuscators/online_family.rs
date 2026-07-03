use std::collections::BTreeMap;

use crate::codec::{
    b64_decode, b64_encode, decode_python_bytes_literal, extract_largest_python_bytes_literal,
    python_bytes_literal, zlib_compress, zlib_decompress,
};
use crate::error::{Error, Result};
use crate::obfuscators::{DetectReport, Obfuscator, ObfuscatorPass, PeelOutcome, Quality};

#[derive(Debug, Clone, Copy)]
pub struct OnlineFamilyPass;

impl ObfuscatorPass for OnlineFamilyPass {
    fn id(&self) -> Obfuscator {
        Obfuscator::OnlineFamily
    }

    fn detect(&self, source: &[u8]) -> DetectReport {
        let head: &[u8] = &source[..source.len().min(16 * 1024)];
        let text: &str = std::str::from_utf8(head).unwrap_or("");
        let signatures: &[&str] = &[
            "pyobfuscator.com",
            "pyobfuscate.com",
            "online-pyobfuscator",
            "__online_pyobf__",
        ];
        let mut markers: Vec<String> = Vec::new();
        let mut matched: bool = false;
        for sig in signatures {
            if text.contains(sig) {
                markers.push((*sig).to_owned());
                matched = true;
            }
        }
        let canonical_wrapper: bool = text
            .contains("exec(__import__('zlib').decompress(__import__('base64').")
            && (text.contains("b64decode") || text.contains("b85decode"));
        if canonical_wrapper {
            markers.push("canonical-online-wrapper".to_owned());
            matched = true;
        }
        DetectReport {
            obfuscator: self.id(),
            matched,
            confidence: if matched { 0.85 } else { 0.0 },
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
        let inflated: Vec<u8> = zlib_decompress(&b64)?;
        stages.push("zlib".to_owned());
        let recovered: String =
            String::from_utf8(inflated).map_err(|e| Error::AstCleanup(format!("{e}")))?;
        let mut diagnostics: BTreeMap<String, String> = BTreeMap::new();
        diagnostics.insert("payload_len".to_owned(), raw.len().to_string());
        Ok(PeelOutcome {
            obfuscator: self.id(),
            stages_applied: stages,
            recovered_source: recovered,
            confidence: 0.9,
            quality: Quality::Full,
            lossy_notes: vec!["online-family samples occasionally chain b85 + zlib; iterate peel for layered output".to_owned()],
            diagnostics,
        })
    }
}

#[must_use]
pub fn bake(source: &str) -> String {
    let zipped: Vec<u8> = zlib_compress(source.as_bytes());
    let encoded: String = b64_encode(&zipped);
    let literal: String = python_bytes_literal(encoded.as_bytes());
    format!(
        "# pyobfuscator.com / pyobfuscate.com online family\n__online_pyobf__ = '1'\nexec(__import__('zlib').decompress(__import__('base64').b64decode({literal})))\n"
    )
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn online_family_roundtrip() {
        let original: &str = "x: int = 1\ny: int = 2\nprint(x + y)\n";
        let obf: String = bake(original);
        assert!(OnlineFamilyPass.detect(obf.as_bytes()).matched);
        let out: PeelOutcome = OnlineFamilyPass.peel(obf.as_bytes()).expect("peel");
        assert_eq!(out.recovered_source, original);
    }
}
