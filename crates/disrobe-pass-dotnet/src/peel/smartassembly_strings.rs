use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::metadata::{MetadataRoot, parse_metadata_root, read_us_heap_strings};
use crate::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use crate::peel::cctor_constants::{StaticFieldConstants, fold_cctor_constants};
use crate::peel::string_emu::{looks_encrypted, looks_readable};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmartAssemblyStrings {
    pub key: Option<u32>,
    pub us_strings_total: u32,
    pub recovered: Vec<RecoveredString>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredString {
    pub cipher_index: u32,
    pub text: String,
}

impl SmartAssemblyStrings {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            key: None,
            us_strings_total: 0,
            recovered: Vec::new(),
        }
    }
}

#[must_use]
pub fn smartassembly_xor_decrypt(cipher_units: &[u16], key: u32) -> String {
    let key_bytes: [u8; 4] = key.to_le_bytes();
    let mut out: Vec<u16> = Vec::with_capacity(cipher_units.len());
    for (i, &unit) in cipher_units.iter().enumerate() {
        let lo: u8 = (unit & 0xFF) as u8 ^ key_bytes[(2 * i) % 4];
        let hi: u8 = (unit >> 8) as u8 ^ key_bytes[(2 * i + 1) % 4];
        out.push(u16::from(lo) | (u16::from(hi) << 8));
    }
    String::from_utf16_lossy(&out)
}

pub fn recover_smartassembly_strings(image: &[u8]) -> Result<SmartAssemblyStrings> {
    let pe: PeImage = parse(image)?;
    let clr: ClrHeader = parse_clr_header(image, &pe)?;
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr)?;
    let metadata_slice: &[u8] = crate::metadata::metadata_slice(image, &pe, &clr, &root)?;
    let us_strings: Vec<String> = root
        .streams
        .get("#US")
        .map(|h: &crate::metadata::StreamHeader| read_us_heap_strings(metadata_slice, *h))
        .unwrap_or_default();

    let mut result: SmartAssemblyStrings = SmartAssemblyStrings::empty();
    result.us_strings_total = u32::try_from(us_strings.len()).unwrap_or(u32::MAX);

    let constants: StaticFieldConstants = fold_cctor_constants(image);
    let key_candidates: Vec<u32> = constants
        .all_immediates
        .iter()
        .filter(|&&v: &&i64| v != 0 && v == (v & 0xFFFF_FFFF))
        .map(|&v: &i64| v as u32)
        .collect();

    for &key in &key_candidates {
        let mut recovered: Vec<RecoveredString> = Vec::new();
        for (idx, cipher) in us_strings.iter().enumerate() {
            if !looks_encrypted(cipher) {
                continue;
            }
            let cipher_units: Vec<u16> = cipher.encode_utf16().collect();
            let plain: String = smartassembly_xor_decrypt(&cipher_units, key);
            if looks_readable(&plain) && !looks_encrypted(&plain) && plain != *cipher {
                recovered.push(RecoveredString {
                    cipher_index: u32::try_from(idx).unwrap_or(u32::MAX),
                    text: plain,
                });
            }
        }
        if !recovered.is_empty() {
            result.key = Some(key);
            result.recovered = recovered;
            return Ok(result);
        }
    }
    Ok(result)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn xor_decrypt_inverts_documented_forward_transform() {
        let key: u32 = 0x5A3C_71E9;
        let plain: &str = "Data Source=prod-sql;Password=Sup3r";
        let plain_units: Vec<u16> = plain.encode_utf16().collect();
        let key_bytes: [u8; 4] = key.to_le_bytes();
        let cipher_units: Vec<u16> = plain_units
            .iter()
            .enumerate()
            .map(|(i, &u): (usize, &u16)| {
                let lo: u8 = (u & 0xFF) as u8 ^ key_bytes[(2 * i) % 4];
                let hi: u8 = (u >> 8) as u8 ^ key_bytes[(2 * i + 1) % 4];
                u16::from(lo) | (u16::from(hi) << 8)
            })
            .collect();
        let recovered: String = smartassembly_xor_decrypt(&cipher_units, key);
        assert_eq!(recovered, plain);
    }

    #[test]
    fn wrong_key_does_not_recover_plaintext() {
        let key: u32 = 0x5A3C_71E9;
        let plain: &str = "Server=db;User Id=sa";
        let plain_units: Vec<u16> = plain.encode_utf16().collect();
        let kb: [u8; 4] = key.to_le_bytes();
        let cipher_units: Vec<u16> = plain_units
            .iter()
            .enumerate()
            .map(|(i, &u): (usize, &u16)| {
                let lo: u8 = (u & 0xFF) as u8 ^ kb[(2 * i) % 4];
                let hi: u8 = (u >> 8) as u8 ^ kb[(2 * i + 1) % 4];
                u16::from(lo) | (u16::from(hi) << 8)
            })
            .collect();
        let wrong: String = smartassembly_xor_decrypt(&cipher_units, key ^ 0x0001_0000);
        assert_ne!(wrong, plain);
    }
}
