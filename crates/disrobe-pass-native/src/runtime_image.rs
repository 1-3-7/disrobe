use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::entropy::shannon_entropy_bits;
use crate::packers::pe_sections::{PeImage, PeSection, parse_pe_image};

pub const RUNTIME_DECRYPTED_VERDICT: &str = "runtime-decrypted image";

const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const ENCRYPTED_ENTROPY_FLOOR: f64 = 7.9;
const MIN_ENTRY_SECTION_BYTES: usize = 16 * 1024;
const ENTROPY_SAMPLE_WINDOWS: usize = 256;
const ENTROPY_SAMPLE_WINDOW_BYTES: usize = 64 * 1024;
const MAX_REPORTED_SECTIONS: usize = 96;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnbackedSection {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeDecryptedImage {
    pub entry_point_rva: u32,
    pub entry_section: String,
    pub entry_section_raw_bytes: u32,
    pub entry_section_entropy: f64,
    pub unbacked_code: Vec<UnbackedSection>,
    pub unbacked_other: Vec<UnbackedSection>,
}

impl RuntimeDecryptedImage {
    #[must_use]
    pub fn unbacked_code_bytes(&self) -> u64 {
        self.unbacked_code
            .iter()
            .map(|section: &UnbackedSection| u64::from(section.virtual_size))
            .sum()
    }

    #[must_use]
    pub fn summary(&self) -> String {
        let mut text: String = format!(
            "entry point 0x{:X} lies in executable section {} ({} bytes on disk, {:.2} bits/byte); code section(s) ",
            self.entry_point_rva,
            self.entry_section,
            self.entry_section_raw_bytes,
            self.entry_section_entropy
        );
        for (index, section) in self.unbacked_code.iter().enumerate() {
            if index > 0 {
                text.push_str(", ");
            }
            let _ = write!(text, "{} ({} bytes)", section.name, section.virtual_size);
        }
        let _ = write!(
            text,
            " declare {} bytes of code with no bytes on disk",
            self.unbacked_code_bytes()
        );
        if !self.unbacked_other.is_empty() {
            text.push_str("; also unbacked: ");
            for (index, section) in self.unbacked_other.iter().enumerate() {
                if index > 0 {
                    text.push_str(", ");
                }
                let _ = write!(text, "{} ({} bytes)", section.name, section.virtual_size);
            }
        }
        text
    }

    #[must_use]
    pub fn refusal(&self) -> String {
        format!(
            "{RUNTIME_DECRYPTED_VERDICT}: the code exists only after the loader decrypts or decompresses it at run time, so static recovery is refused: {}",
            self.summary()
        )
    }
}

#[must_use]
pub fn detect_runtime_decrypted(bytes: &[u8]) -> Option<RuntimeDecryptedImage> {
    let image: PeImage = parse_pe_image(bytes).ok()?;
    runtime_decrypted_image(&image, bytes)
}

#[must_use]
pub fn runtime_decrypted_image(image: &PeImage, bytes: &[u8]) -> Option<RuntimeDecryptedImage> {
    let entry: &PeSection = image.section_containing_rva(image.entry_point_rva)?;
    if entry.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
        return None;
    }
    let (start, end): (usize, usize) = entry.raw_range(bytes.len())?;
    let raw: &[u8] = bytes.get(start..end)?;
    if raw.len() < MIN_ENTRY_SECTION_BYTES {
        return None;
    }
    let entropy: f64 = sampled_entropy(raw);
    if entropy < ENCRYPTED_ENTROPY_FLOOR {
        return None;
    }
    let mut unbacked_code: Vec<UnbackedSection> = Vec::new();
    let mut unbacked_other: Vec<UnbackedSection> = Vec::new();
    for section in &image.sections {
        if section.virtual_address == entry.virtual_address
            || section.raw_size != 0
            || section.virtual_size == 0
        {
            continue;
        }
        let row: UnbackedSection = UnbackedSection {
            name: String::from_utf8_lossy(section.name_trimmed()).into_owned(),
            virtual_address: section.virtual_address,
            virtual_size: section.virtual_size,
        };
        let code: bool =
            section.characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE) != 0;
        let list: &mut Vec<UnbackedSection> = if code {
            &mut unbacked_code
        } else {
            &mut unbacked_other
        };
        if list.len() < MAX_REPORTED_SECTIONS {
            list.push(row);
        }
    }
    if unbacked_code.is_empty() {
        return None;
    }
    Some(RuntimeDecryptedImage {
        entry_point_rva: image.entry_point_rva,
        entry_section: String::from_utf8_lossy(entry.name_trimmed()).into_owned(),
        entry_section_raw_bytes: entry.raw_size,
        entry_section_entropy: entropy,
        unbacked_code,
        unbacked_other,
    })
}

fn sampled_entropy(raw: &[u8]) -> f64 {
    let budget: usize = ENTROPY_SAMPLE_WINDOWS * ENTROPY_SAMPLE_WINDOW_BYTES;
    if raw.len() <= budget {
        return shannon_entropy_bits(raw);
    }
    let stride: usize = raw.len() / ENTROPY_SAMPLE_WINDOWS;
    let mut sample: Vec<u8> = Vec::with_capacity(budget);
    for window in 0..ENTROPY_SAMPLE_WINDOWS {
        let at: usize = window * stride;
        let stop: usize = at
            .saturating_add(ENTROPY_SAMPLE_WINDOW_BYTES)
            .min(raw.len());
        if let Some(chunk) = raw.get(at..stop) {
            sample.extend_from_slice(chunk);
        }
    }
    shannon_entropy_bits(&sample)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::test_support::{SyntheticSection, pe64_layout};

    const CODE: u32 = 0x6000_0020;
    const DATA: u32 = 0x4000_0040;

    fn noise(len: usize) -> Vec<u8> {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    fn protected_layout(entry_bytes: Vec<u8>) -> Vec<u8> {
        pe64_layout(
            &[
                SyntheticSection::unbacked(*b".text\0\0\0", 0x1000, 0x40_0000, CODE),
                SyntheticSection::unbacked(*b".rdata\0\0", 0x41_0000, 0x8000, DATA),
                SyntheticSection::backed(*b".stub\0\0\0", 0x42_0000, entry_bytes, CODE),
            ],
            0x42_0010,
        )
    }

    #[test]
    fn zero_raw_code_beside_an_encrypted_entry_section_is_named() {
        let bytes: Vec<u8> = protected_layout(noise(0x2_0000));
        let verdict: RuntimeDecryptedImage =
            detect_runtime_decrypted(&bytes).expect("runtime-decrypted layout is named");
        assert_eq!(verdict.entry_section, ".stub");
        assert_eq!(verdict.entry_point_rva, 0x42_0010);
        assert_eq!(
            verdict.unbacked_code,
            vec![UnbackedSection {
                name: ".text".to_owned(),
                virtual_address: 0x1000,
                virtual_size: 0x40_0000,
            }]
        );
        assert_eq!(verdict.unbacked_other.len(), 1);
        assert_eq!(verdict.unbacked_other[0].name, ".rdata");
        assert!(verdict.entry_section_entropy >= ENCRYPTED_ENTROPY_FLOOR);
        let refusal: String = verdict.refusal();
        assert!(refusal.starts_with(RUNTIME_DECRYPTED_VERDICT), "{refusal}");
        assert!(refusal.contains(".text (4194304 bytes)"), "{refusal}");
    }

    #[test]
    fn plain_code_in_the_entry_section_is_not_named() {
        let plain: Vec<u8> = (0..0x2_0000u32).map(|i: u32| (i % 7) as u8).collect();
        assert!(detect_runtime_decrypted(&protected_layout(plain)).is_none());
    }

    #[test]
    fn a_high_entropy_image_with_every_code_section_on_disk_is_not_named() {
        let bytes: Vec<u8> = pe64_layout(
            &[
                SyntheticSection::backed(*b".text\0\0\0", 0x1000, noise(0x2_0000), CODE),
                SyntheticSection::unbacked(*b".bss\0\0\0\0", 0x3_0000, 0x8000, 0xC000_0080),
            ],
            0x1010,
        );
        assert!(detect_runtime_decrypted(&bytes).is_none());
    }
}
