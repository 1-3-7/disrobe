use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::metadata::{
    MetadataRoot, StreamHeader, parse_metadata_root, read_strings_heap, read_us_heap_strings,
};
use crate::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use crate::peel::cctor_constants::{fold_cctor_constants, immediates_in_named_method};
use crate::peel::string_emu::{looks_encrypted, looks_readable};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpicesRecovery {
    pub rot_shift: Option<u32>,
    pub recovered_strings: Vec<RecoveredString>,
    pub homoglyph_unmapped: Vec<UnmappedName>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredString {
    pub cipher: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnmappedName {
    pub obfuscated: String,
    pub unmapped: String,
}

impl SpicesRecovery {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            rot_shift: None,
            recovered_strings: Vec::new(),
            homoglyph_unmapped: Vec::new(),
        }
    }
}

#[must_use]
pub const fn cyrillic_homoglyph_to_latin(c: char) -> Option<char> {
    Some(match c {
        '\u{0410}' => 'A',
        '\u{0412}' => 'B',
        '\u{0415}' => 'E',
        '\u{041A}' => 'K',
        '\u{041C}' => 'M',
        '\u{041D}' => 'H',
        '\u{041E}' => 'O',
        '\u{0420}' => 'P',
        '\u{0421}' => 'C',
        '\u{0422}' => 'T',
        '\u{0425}' => 'X',
        '\u{0430}' => 'a',
        '\u{0435}' => 'e',
        '\u{043E}' => 'o',
        '\u{0440}' => 'p',
        '\u{0441}' => 'c',
        '\u{0443}' => 'y',
        '\u{0445}' => 'x',
        '\u{0455}' => 's',
        '\u{0456}' => 'i',
        '\u{0458}' => 'j',
        '\u{04BB}' => 'h',
        _ => return None,
    })
}

#[must_use]
pub fn unmap_homoglyph_name(name: &str) -> Option<String> {
    if !name
        .chars()
        .any(|c: char| cyrillic_homoglyph_to_latin(c).is_some())
    {
        return None;
    }
    let unmapped: String = name
        .chars()
        .map(|c: char| cyrillic_homoglyph_to_latin(c).unwrap_or(c))
        .collect();
    Some(unmapped)
}

#[must_use]
pub fn rot_n_decrypt(cipher: &str, shift: u16) -> String {
    let units: Vec<u16> = cipher
        .encode_utf16()
        .map(|u: u16| u.wrapping_sub(shift))
        .collect();
    String::from_utf16_lossy(&units)
}

const MAX_ROT_SHIFT: u16 = 64;

pub fn recover_spices(image: &[u8]) -> Result<SpicesRecovery> {
    let pe: PeImage = parse(image)?;
    let clr: ClrHeader = parse_clr_header(image, &pe)?;
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr)?;
    let metadata_slice: &[u8] =
        pe.slice_at_rva(image, clr.metadata.rva, clr.metadata.size as usize)?;

    let us_strings: Vec<String> = root
        .streams
        .get("#US")
        .map(|h: &StreamHeader| read_us_heap_strings(metadata_slice, *h))
        .unwrap_or_default();
    let names: std::collections::BTreeMap<u32, String> = root
        .streams
        .get("#Strings")
        .map(|h: &StreamHeader| read_strings_heap(metadata_slice, *h))
        .unwrap_or_default();

    let mut result: SpicesRecovery = SpicesRecovery::empty();

    for name in names.values() {
        if let Some(unmapped) = unmap_homoglyph_name(name) {
            result.homoglyph_unmapped.push(UnmappedName {
                obfuscated: name.clone(),
                unmapped,
            });
        }
    }

    let mut shift_candidates: Vec<u16> = Vec::new();
    for v in fold_cctor_constants(image).all_immediates {
        if (1..=i64::from(MAX_ROT_SHIFT)).contains(&v) {
            shift_candidates.push(v as u16);
        }
    }
    for v in immediates_in_named_method(image, |n: &str| {
        n.contains("ecrypt") || n.contains("ecode") || n.contains("nscramble")
    }) {
        if (1..=i64::from(MAX_ROT_SHIFT)).contains(&v) {
            shift_candidates.push(v as u16);
        }
    }
    shift_candidates.sort_unstable();
    shift_candidates.dedup();

    let encrypted_total: usize = us_strings.iter().filter(|s| looks_encrypted(s)).count();
    for &shift in &shift_candidates {
        let mut recovered: Vec<RecoveredString> = Vec::new();
        let mut readable_hits: usize = 0;
        for cipher in &us_strings {
            if cipher.is_empty() {
                continue;
            }
            let plain: String = rot_n_decrypt(cipher, shift);
            if looks_readable(&plain) && !looks_encrypted(&plain) && plain != *cipher {
                readable_hits += 1;
                recovered.push(RecoveredString {
                    cipher: cipher.clone(),
                    text: plain,
                });
            }
        }
        if readable_hits >= encrypted_total.max(1) && !recovered.is_empty() {
            result.rot_shift = Some(u32::from(shift));
            result.recovered_strings = recovered;
            break;
        }
    }
    Ok(result)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn homoglyph_unmap_restores_latin_identifier() {
        let plain: &str = "DataConnector";
        let obf: String = plain
            .chars()
            .map(|c: char| match c {
                'a' => '\u{0430}',
                'o' => '\u{043E}',
                'c' => '\u{0441}',
                other => other,
            })
            .collect();
        assert_ne!(obf, plain, "the obfuscated form must contain homoglyphs");
        let unmapped: String = unmap_homoglyph_name(&obf).expect("has homoglyphs");
        assert_eq!(unmapped, plain);
    }

    #[test]
    fn homoglyph_unmap_ignores_pure_latin() {
        assert_eq!(unmap_homoglyph_name("PlainName"), None);
    }

    #[test]
    fn rot_n_inverts_forward_shift() {
        let shift: u16 = 13;
        let units: Vec<u16> = "DataSource=prod;Pwd=secret"
            .encode_utf16()
            .map(|u: u16| u.wrapping_add(shift))
            .collect();
        let cipher: String = String::from_utf16_lossy(&units);
        let recovered: String = rot_n_decrypt(&cipher, shift);
        assert_eq!(recovered, "DataSource=prod;Pwd=secret");
    }
}
