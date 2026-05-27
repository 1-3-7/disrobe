use std::collections::BTreeMap;

use crate::codec::{
    b85_decode, b85_encode, decode_python_bytes_literal, extract_largest_python_bytes_literal,
    python_bytes_literal, xor_apply, zlib_compress, zlib_decompress,
};
use crate::error::{Error, Result};
use crate::obfuscators::{DetectReport, Obfuscator, ObfuscatorPass, PeelOutcome, Quality};

#[derive(Debug, Clone, Copy)]
pub struct JawbreakerPass;

const JAWBREAKER_KEY: &[u8] = b"de4py-jawbreaker";

impl ObfuscatorPass for JawbreakerPass {
    fn id(&self) -> Obfuscator {
        Obfuscator::Jawbreaker
    }

    fn detect(&self, source: &[u8]) -> DetectReport {
        let head: &[u8] = &source[..source.len().min(64 * 1024)];
        let text: &str = std::str::from_utf8(head).unwrap_or("");
        let banner: bool = text.contains("# Jawbreaker") || text.contains("__jawbreaker__");
        let stack: bool = text.contains("b85decode") && text.contains("zlib");
        let upstream_triple: bool = text.contains("b16decode as ")
            && text.contains("b32decode as ")
            && text.contains("b64decode as ");
        let hastebin: bool = text.contains("hastebin.com/raw/");
        let mut markers: Vec<String> = Vec::new();
        if banner {
            markers.push("jawbreaker-banner".to_owned());
        }
        if stack {
            markers.push("b85+zlib".to_owned());
        }
        if upstream_triple {
            markers.push("jawbreaker-b16-b32-b64-triple".to_owned());
        }
        if hastebin {
            markers.push("jawbreaker-hastebin-url".to_owned());
        }
        let matched: bool = banner || stack || upstream_triple;
        let confidence: f32 = if upstream_triple && hastebin {
            0.99
        } else if banner {
            0.95
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
        if text.contains("b16decode as ")
            && text.contains("b32decode as ")
            && text.contains("b64decode as ")
        {
            return Ok(peel_upstream(self.id(), text));
        }
        let literal: &str =
            extract_largest_python_bytes_literal(text).ok_or(Error::LiteralNotFound)?;
        let raw: Vec<u8> = decode_python_bytes_literal(literal)?;
        let mut stages: Vec<String> = Vec::with_capacity(3);
        let decoded: Vec<u8> = b85_decode(&raw)?;
        stages.push("base85".to_owned());
        let unxored: Vec<u8> = xor_apply(&decoded, JAWBREAKER_KEY);
        stages.push("xor".to_owned());
        let inflated: Vec<u8> = zlib_decompress(&unxored)?;
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
                "live builds may use per-build XOR key; bake uses canonical de4py key".to_owned(),
            ],
            diagnostics,
        })
    }
}

fn peel_upstream(id: Obfuscator, text: &str) -> PeelOutcome {
    let mut stages: Vec<String> = vec!["upstream-detect".to_owned()];
    let hex_payload: Option<&str> = extract_outer_hex_payload(text);
    let mut diagnostics: BTreeMap<String, String> = BTreeMap::new();
    let mut recovered: String = String::new();
    let mut quality: Quality = Quality::DetectOnly;
    let mut confidence: f32 = 0.4;
    let lossy_notes: Vec<String> = vec![
        "Jawbreaker upstream: triple-encoded b16(b32(b64(...))) shell whose inner content is an exec() of a urlopen() of a hastebin URL. Static decoding yields the URL+request shell only; the actual user source lives on the remote Hastebin paste (which expires after ~30 days). Wire up the network fetch in disrobe-cli to complete recovery.".to_owned(),
    ];
    if let Some(hex) = hex_payload {
        stages.push("hex-strip".to_owned());
        let hex_clean: String = hex.chars().filter(char::is_ascii_hexdigit).collect();
        if let Ok(b16_bytes) = hex_decode(&hex_clean) {
            stages.push("base16".to_owned());
            if let Ok(b32_bytes) = b32_decode(&b16_bytes) {
                stages.push("base32".to_owned());
                if let Ok(b64_bytes) = crate::codec::b64_decode(&b32_bytes) {
                    stages.push("base64".to_owned());
                    if let Ok(s) = String::from_utf8(b64_bytes) {
                        diagnostics.insert("inner_shell_len".to_owned(), s.len().to_string());
                        if let Some(url) = extract_hastebin_url(&s) {
                            diagnostics.insert("hastebin_url".to_owned(), url.to_owned());
                            recovered = format!(
                                "# jawbreaker recovered inner shell:\n# fetch this URL to obtain the original user source:\n#   {url}\n{s}"
                            );
                            quality = Quality::Partial;
                            confidence = 0.85;
                        } else {
                            recovered = s;
                            quality = Quality::Partial;
                            confidence = 0.7;
                        }
                    }
                }
            }
        }
    }
    if recovered.is_empty() {
        text.clone_into(&mut recovered);
    }
    PeelOutcome {
        obfuscator: id,
        stages_applied: stages,
        recovered_source: recovered,
        confidence,
        quality,
        lossy_notes,
        diagnostics,
    }
}

fn extract_outer_hex_payload(text: &str) -> Option<&str> {
    let needle: &str = "b16decode(\"";
    let start: usize = text.rfind(needle)?;
    let after: &str = &text[start + needle.len()..];
    let end: usize = after.find('"')?;
    Some(&after[..end])
}

fn hex_decode(s: &str) -> std::result::Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    let mut out: Vec<u8> = Vec::with_capacity(s.len() / 2);
    let bytes: &[u8] = s.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        let hi: u8 = hex_val(bytes[i]).ok_or(())?;
        let lo: u8 = hex_val(bytes[i + 1]).ok_or(())?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

const fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'A'..=b'F' => Some(c - b'A' + 10),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

fn b32_decode(input: &[u8]) -> std::result::Result<Vec<u8>, ()> {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut buf: u64 = 0;
    let mut bits: u32 = 0;
    let mut out: Vec<u8> = Vec::with_capacity((input.len() * 5) / 8 + 1);
    for &c in input {
        if c == b'=' || c == b'\n' || c == b'\r' || c == b' ' {
            continue;
        }
        let Some(pos): Option<usize> = ALPHA.iter().position(|&x: &u8| x == c) else {
            return Err(());
        };
        let v: u8 = u8::try_from(pos).map_err(|_| ())?;
        buf = (buf << 5) | u64::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff).to_le_bytes()[0]);
        }
    }
    Ok(out)
}

fn extract_hastebin_url(s: &str) -> Option<&str> {
    let needle: &str = "https://hastebin.com/raw/";
    let start: usize = s.find(needle)?;
    let after: &str = &s[start..];
    let end: usize = after.find(['"', '\'', ')', ' ']).unwrap_or(after.len());
    Some(&after[..end])
}

#[must_use]
pub fn bake(source: &str) -> String {
    let zipped: Vec<u8> = zlib_compress(source.as_bytes());
    let xored: Vec<u8> = xor_apply(&zipped, JAWBREAKER_KEY);
    let encoded: Vec<u8> = b85_encode(&xored);
    let literal: String = python_bytes_literal(&encoded);
    format!(
        "# Jawbreaker (de4py target) bake\nimport base64, zlib\n__jawbreaker__ = '1'\nexec(zlib.decompress(bytes(b ^ k for b, k in zip(base64.b85decode({literal}), (b'de4py-jawbreaker' * 4096)))))\n"
    )
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn jawbreaker_roundtrip() {
        let original: &str = "class Foo:\n    def bar(self):\n        return 42\n";
        let obf: String = bake(original);
        let det: DetectReport = JawbreakerPass.detect(obf.as_bytes());
        assert!(det.matched);
        let out: PeelOutcome = JawbreakerPass.peel(obf.as_bytes()).expect("peel");
        assert_eq!(out.recovered_source, original);
    }
}
