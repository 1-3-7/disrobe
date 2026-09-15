use std::collections::BTreeMap;

use crate::codec::{
    b64_decode, b64_encode, decode_python_bytes_literal, extract_largest_python_bytes_literal,
    lzma_compress, lzma_decompress, python_bytes_literal,
};
use crate::error::{Error, Result};
use crate::obfuscators::{DetectReport, Obfuscator, ObfuscatorPass, PeelOutcome, Quality};

#[derive(Debug, Clone, Copy)]
pub struct WodxPass;

impl ObfuscatorPass for WodxPass {
    fn id(&self) -> Obfuscator {
        Obfuscator::Wodx
    }

    fn detect(&self, source: &[u8]) -> DetectReport {
        let head: &[u8] = &source[..source.len().min(16 * 1024)];
        let text: &str = std::str::from_utf8(head).unwrap_or("");
        let banner: bool = text.contains("Wodx") || text.contains("__wodx__");
        DetectReport {
            obfuscator: self.id(),
            matched: banner,
            confidence: if banner { 0.9 } else { 0.0 },
            markers: if banner {
                vec!["wodx-banner".to_owned()]
            } else {
                Vec::new()
            },
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
        let inflated: Vec<u8> = lzma_decompress(&b64)?;
        stages.push("lzma".to_owned());
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
                "Wodx variants chain marshal+lzma; v1 single layer reversed here".to_owned(),
            ],
            diagnostics,
        })
    }
}

#[must_use]
pub fn bake(source: &str) -> String {
    let lz: Vec<u8> = lzma_compress(source.as_bytes());
    let encoded: String = b64_encode(&lz);
    let literal: String = python_bytes_literal(encoded.as_bytes());
    format!(
        "# Wodx obfuscator\n__wodx__ = 'v1'\nimport base64, lzma\nexec(lzma.decompress(base64.b64decode({literal})))\n"
    )
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn wodx_roundtrip() {
        let original: &str = "async def main():\n    return 1\n";
        let obf: String = bake(original);
        assert!(WodxPass.detect(obf.as_bytes()).matched);
        let out: PeelOutcome = WodxPass.peel(obf.as_bytes()).expect("peel");
        assert_eq!(out.recovered_source, original);
    }
}
