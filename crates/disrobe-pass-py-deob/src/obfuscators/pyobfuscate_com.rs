use std::collections::BTreeMap;

use crate::codec::{
    b64_decode, b64_encode, decode_python_bytes_literal, extract_largest_python_bytes_literal,
    python_bytes_literal, zlib_compress, zlib_decompress,
};
use crate::error::{Error, Result};
use crate::obfuscators::{DetectReport, Obfuscator, ObfuscatorPass, PeelOutcome, Quality};

#[derive(Debug, Clone, Copy)]
pub struct PyobfuscateComPass;

impl ObfuscatorPass for PyobfuscateComPass {
    fn id(&self) -> Obfuscator {
        Obfuscator::PyobfuscateCom
    }

    fn detect(&self, source: &[u8]) -> DetectReport {
        let head: &[u8] = &source[..source.len().min(16 * 1024)];
        let text: &str = std::str::from_utf8(head).unwrap_or("");
        let banner: bool = text.contains("pyobfuscate.com") || text.contains("__pyobfuscate_com__");
        let pattern: bool =
            text.contains("exec(__import__('zlib').decompress(__import__('base64').b64decode(");
        let matched: bool = banner || pattern;
        let mut markers: Vec<String> = Vec::new();
        if banner {
            markers.push("pyobfuscate-com-banner".to_owned());
        }
        if pattern {
            markers.push("canonical-dropper".to_owned());
        }
        DetectReport {
            obfuscator: self.id(),
            matched,
            confidence: if banner {
                0.95
            } else if pattern {
                0.75
            } else {
                0.0
            },
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
            confidence: 0.95,
            quality: Quality::Full,
            lossy_notes: vec![
                "online tool uses fixed wrapper; layered samples need iterative peel".to_owned(),
            ],
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
        "# pyobfuscate.com online obfuscator output\n__pyobfuscate_com__ = '1'\nexec(__import__('zlib').decompress(__import__('base64').b64decode({literal})))\n"
    )
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn pyobfuscate_com_roundtrip() {
        let original: &str = "from math import sqrt\nprint(sqrt(2))\n";
        let obf: String = bake(original);
        assert!(PyobfuscateComPass.detect(obf.as_bytes()).matched);
        let out: PeelOutcome = PyobfuscateComPass.peel(obf.as_bytes()).expect("peel");
        assert_eq!(out.recovered_source, original);
    }
}
