use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::metadata::{MetadataRoot, parse_metadata_root, read_us_heap_strings};
use crate::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use crate::peel::cctor_constants::{fold_cctor_constants, immediates_in_named_method};
use crate::peel::string_emu::{looks_encrypted, looks_readable};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkaterStrings {
    pub key: Option<u8>,
    pub recovered: Vec<RecoveredString>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredString {
    pub cipher: String,
    pub text: String,
}

impl SkaterStrings {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            key: None,
            recovered: Vec::new(),
        }
    }
}

#[must_use]
pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let trimmed: &str = input.trim();
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    let mut out: Vec<u8> = Vec::with_capacity(trimmed.len() * 3 / 4 + 1);
    for ch in trimmed.chars() {
        if ch == '=' {
            break;
        }
        let v: u32 = match ch {
            'A'..='Z' => ch as u32 - 'A' as u32,
            'a'..='z' => ch as u32 - 'a' as u32 + 26,
            '0'..='9' => ch as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            _ => return None,
        };
        bits = (bits << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    Some(out)
}

#[must_use]
pub fn skater_decrypt(cipher_b64: &str, key: u8) -> Option<String> {
    let raw: Vec<u8> = base64_decode(cipher_b64)?;
    let plain: Vec<u8> = raw.iter().map(|&b: &u8| b ^ key).collect();
    String::from_utf8(plain).ok()
}

pub fn recover_skater_strings(image: &[u8]) -> Result<SkaterStrings> {
    let pe: PeImage = parse(image)?;
    let clr: ClrHeader = parse_clr_header(image, &pe)?;
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr)?;
    let metadata_slice: &[u8] = crate::metadata::metadata_slice(image, &pe, &clr, &root)?;
    let us_strings: Vec<String> = root
        .streams
        .get("#US")
        .map(|h: &crate::metadata::StreamHeader| read_us_heap_strings(metadata_slice, *h))
        .unwrap_or_default();

    let mut key_bytes: Vec<u8> = Vec::new();
    for v in fold_cctor_constants(image).all_immediates {
        if (0..=255).contains(&v) {
            key_bytes.push(v as u8);
        }
    }
    for v in
        immediates_in_named_method(image, |n: &str| n.contains("ecrypt") || n.contains("ecode"))
    {
        if (0..=255).contains(&v) {
            key_bytes.push(v as u8);
        }
    }
    key_bytes.sort_unstable();
    key_bytes.dedup();

    for &key in &key_bytes {
        if key == 0 {
            continue;
        }
        let mut recovered: Vec<RecoveredString> = Vec::new();
        for cipher in &us_strings {
            if cipher.is_empty() || !is_base64ish(cipher) {
                continue;
            }
            let Some(plain): Option<String> = skater_decrypt(cipher, key) else {
                continue;
            };
            if looks_readable(&plain) && !looks_encrypted(&plain) && plain != *cipher {
                recovered.push(RecoveredString {
                    cipher: cipher.clone(),
                    text: plain,
                });
            }
        }
        if !recovered.is_empty() {
            return Ok(SkaterStrings {
                key: Some(key),
                recovered,
            });
        }
    }
    Ok(SkaterStrings::empty())
}

fn is_base64ish(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c: char| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
        && s.len() >= 4
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn base64_encode(data: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out: String = String::new();
        for chunk in data.chunks(3) {
            let b: [u8; 3] = [
                chunk[0],
                chunk.get(1).copied().unwrap_or(0),
                chunk.get(2).copied().unwrap_or(0),
            ];
            let n: u32 = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            out.push(ALPHABET[(n >> 18) as usize & 0x3F] as char);
            out.push(ALPHABET[(n >> 12) as usize & 0x3F] as char);
            if chunk.len() > 1 {
                out.push(ALPHABET[(n >> 6) as usize & 0x3F] as char);
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(ALPHABET[n as usize & 0x3F] as char);
            } else {
                out.push('=');
            }
        }
        out
    }

    #[test]
    fn base64_decode_matches_known_vector() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
    }

    #[test]
    fn skater_decrypt_inverts_documented_forward_transform() {
        let key: u8 = 0x7F;
        let plain: &str = "License=ACME-PRO-2026;Seats=50";
        let cipher_bytes: Vec<u8> = plain.bytes().map(|b: u8| b ^ key).collect();
        let cipher_b64: String = base64_encode(&cipher_bytes);
        let recovered: String = skater_decrypt(&cipher_b64, key).expect("decrypt");
        assert_eq!(recovered, plain);
    }

    #[test]
    fn wrong_key_does_not_invert() {
        let key: u8 = 0x7F;
        let plain: &str = "Server=db.internal";
        let cipher_bytes: Vec<u8> = plain.bytes().map(|b: u8| b ^ key).collect();
        let cipher_b64: String = base64_encode(&cipher_bytes);
        let wrong: Option<String> = skater_decrypt(&cipher_b64, key ^ 0x11);
        assert_ne!(wrong.as_deref(), Some(plain));
    }
}
