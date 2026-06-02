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
        if is_gzip(&raw) {
            return peel_real_gzip(self.id(), &raw);
        }
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
                "synthetic base64+xor self-test layer; real upstream uses the gzip-decompress path"
                    .to_owned(),
            ],
            diagnostics,
        })
    }
}

#[inline]
fn is_gzip(bytes: &[u8]) -> bool {
    matches!(bytes, [0x1f, 0x8b, 0x08, ..])
}

fn gzip_decompress(input: &[u8]) -> Result<Vec<u8>> {
    let decoder: flate2::read::GzDecoder<&[u8]> = flate2::read::GzDecoder::new(input);
    crate::codec::bounded_read_to_end(decoder)
        .map_err(|e: std::io::Error| Error::Zlib(format!("gzip: {e}")))?
        .ok_or(Error::DecompressionTooLarge {
            limit: crate::codec::DECOMPRESS_CEILING,
        })
}

fn peel_real_gzip(id: Obfuscator, raw: &[u8]) -> Result<PeelOutcome> {
    let inner: Vec<u8> = gzip_decompress(raw)?;
    let inner_source: String = String::from_utf8_lossy(&inner).into_owned();
    let mut diagnostics: BTreeMap<String, String> = BTreeMap::new();
    diagnostics.insert("gzip_payload_len".to_owned(), raw.len().to_string());
    diagnostics.insert("inner_layer_len".to_owned(), inner.len().to_string());
    let inner_is_char_arith: bool = inner_source.contains("chr(")
        && inner_source.contains("def ")
        && inner_source.contains("__import__");
    Ok(PeelOutcome {
        obfuscator: id,
        stages_applied: vec![
            "bytes-literal-extract".to_owned(),
            "gzip-decompress".to_owned(),
        ],
        recovered_source: inner_source,
        confidence: 0.7,
        quality: Quality::Partial,
        lossy_notes: vec![if inner_is_char_arith {
            "PyObfuscator (Mauricelambert) real output: gzip layer peeled. Inner layer is the tool's char-arithmetic stage (chr(int±k)/byte-xor name mangling) which requires a Python AST evaluator to fold to clean source; the gzip-decompressed layer is emitted as the recovered intermediate.".to_owned()
        } else {
            "PyObfuscator (Mauricelambert) real output: gzip layer peeled to plaintext source."
                .to_owned()
        }],
        diagnostics,
    })
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
