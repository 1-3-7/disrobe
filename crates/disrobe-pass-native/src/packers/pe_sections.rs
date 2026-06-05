use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const DOS_E_LFANEW_OFFSET: usize = 0x3C;
const COFF_HEADER_SIZE: usize = 20;
const SECTION_ENTRY_SIZE: usize = 40;
const PE_MAGIC: &[u8; 4] = b"PE\x00\x00";
const OPT_MAGIC_PE32: u16 = 0x010B;
const OPT_MAGIC_PE32_PLUS: u16 = 0x020B;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeSection {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_pointer: u32,
    pub characteristics: u32,
}

impl PeSection {
    #[must_use]
    pub fn name_trimmed(&self) -> &[u8] {
        let end: usize = self
            .name
            .iter()
            .position(|b: &u8| *b == 0)
            .unwrap_or(self.name.len());
        &self.name[..end]
    }

    #[must_use]
    pub fn name_is(&self, target: &[u8]) -> bool {
        self.name_trimmed() == target
    }

    #[must_use]
    pub fn raw_range(&self, image_len: usize) -> Option<(usize, usize)> {
        let start: usize = self.raw_pointer as usize;
        let end: usize = start.checked_add(self.raw_size as usize)?;
        if end > image_len {
            None
        } else {
            Some((start, end))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeImage {
    pub is_pe32_plus: bool,
    pub entry_point_rva: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub data_directories: Vec<DataDirectory>,
    pub sections: Vec<PeSection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

impl PeImage {
    #[must_use]
    pub fn section_by_name(&self, name: &[u8]) -> Option<&PeSection> {
        self.sections.iter().find(|s: &&PeSection| s.name_is(name))
    }

    #[must_use]
    pub fn section_containing_rva(&self, rva: u32) -> Option<&PeSection> {
        self.sections.iter().find(|s: &&PeSection| {
            let span: u32 = s.virtual_size.max(s.raw_size);
            rva >= s.virtual_address && rva < s.virtual_address.saturating_add(span)
        })
    }
}

pub fn parse_pe_image(bytes: &[u8]) -> Result<PeImage> {
    if bytes.len() < DOS_E_LFANEW_OFFSET + 4 {
        return Err(Error::Truncated {
            needed: DOS_E_LFANEW_OFFSET + 4,
            had: bytes.len(),
        });
    }
    let e_lfanew: usize = read_u32(bytes, DOS_E_LFANEW_OFFSET)? as usize;
    let coff_off: usize = e_lfanew
        .checked_add(4)
        .ok_or_else(|| Error::SignatureDb("PE: e_lfanew overflow".to_owned()))?;
    if coff_off + COFF_HEADER_SIZE > bytes.len() {
        return Err(Error::Truncated {
            needed: coff_off + COFF_HEADER_SIZE,
            had: bytes.len(),
        });
    }
    if &bytes[e_lfanew..e_lfanew + 4] != PE_MAGIC {
        return Err(Error::UnknownFormat);
    }
    let n_sections: usize = read_u16(bytes, coff_off + 2)? as usize;
    let opt_hdr_size: usize = read_u16(bytes, coff_off + 16)? as usize;
    let opt_hdr_off: usize = coff_off + COFF_HEADER_SIZE;
    let opt_magic: u16 = read_u16(bytes, opt_hdr_off)?;
    let is_pe32_plus: bool = match opt_magic {
        OPT_MAGIC_PE32 => false,
        OPT_MAGIC_PE32_PLUS => true,
        _ => return Err(Error::UnknownFormat),
    };
    let entry_point_rva: u32 = read_u32(bytes, opt_hdr_off + 16)?;
    let (image_base, dir_count_off): (u64, usize) = if is_pe32_plus {
        (read_u64(bytes, opt_hdr_off + 24)?, opt_hdr_off + 108)
    } else {
        (
            u64::from(read_u32(bytes, opt_hdr_off + 28)?),
            opt_hdr_off + 92,
        )
    };
    let section_alignment: u32 = read_u32(bytes, opt_hdr_off + 32)?;
    let file_alignment: u32 = read_u32(bytes, opt_hdr_off + 36)?;
    let size_of_image: u32 = read_u32(bytes, opt_hdr_off + 56)?;
    let number_of_dirs: usize = (read_u32(bytes, dir_count_off)? as usize).min(16);
    let dir_table_off: usize = dir_count_off + 4;
    let mut data_directories: Vec<DataDirectory> = Vec::with_capacity(number_of_dirs);
    for i in 0..number_of_dirs {
        let entry: usize = dir_table_off + i * 8;
        if entry + 8 > bytes.len() {
            break;
        }
        data_directories.push(DataDirectory {
            virtual_address: read_u32(bytes, entry)?,
            size: read_u32(bytes, entry + 4)?,
        });
    }
    let sec_table_off: usize = opt_hdr_off + opt_hdr_size;
    let needed: usize = sec_table_off
        .checked_add(
            n_sections
                .checked_mul(SECTION_ENTRY_SIZE)
                .ok_or_else(|| Error::SignatureDb("PE: section count overflow".to_owned()))?,
        )
        .ok_or_else(|| Error::SignatureDb("PE: section table overflow".to_owned()))?;
    if needed > bytes.len() {
        return Err(Error::Truncated {
            needed,
            had: bytes.len(),
        });
    }
    let mut sections: Vec<PeSection> = Vec::with_capacity(n_sections);
    for i in 0..n_sections {
        let off: usize = sec_table_off + i * SECTION_ENTRY_SIZE;
        let mut name: [u8; 8] = [0u8; 8];
        name.copy_from_slice(&bytes[off..off + 8]);
        sections.push(PeSection {
            name,
            virtual_size: read_u32(bytes, off + 8)?,
            virtual_address: read_u32(bytes, off + 12)?,
            raw_size: read_u32(bytes, off + 16)?,
            raw_pointer: read_u32(bytes, off + 20)?,
            characteristics: read_u32(bytes, off + 36)?,
        });
    }
    Ok(PeImage {
        is_pe32_plus,
        entry_point_rva,
        image_base,
        section_alignment,
        file_alignment,
        size_of_image,
        data_directories,
        sections,
    })
}

#[inline]
pub fn read_u16(b: &[u8], off: usize) -> Result<u16> {
    let end: usize = off + 2;
    if end > b.len() {
        return Err(Error::Truncated {
            needed: end,
            had: b.len(),
        });
    }
    Ok(u16::from_le_bytes([b[off], b[off + 1]]))
}

#[inline]
pub fn read_u32(b: &[u8], off: usize) -> Result<u32> {
    let end: usize = off + 4;
    if end > b.len() {
        return Err(Error::Truncated {
            needed: end,
            had: b.len(),
        });
    }
    Ok(u32::from_le_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
    ]))
}

#[inline]
pub fn read_u64(b: &[u8], off: usize) -> Result<u64> {
    let end: usize = off + 8;
    if end > b.len() {
        return Err(Error::Truncated {
            needed: end,
            had: b.len(),
        });
    }
    let mut arr: [u8; 8] = [0u8; 8];
    arr.copy_from_slice(&b[off..off + 8]);
    Ok(u64::from_le_bytes(arr))
}

#[must_use]
pub fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w: &[u8]| w == needle)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn minimal_pe() -> Vec<u8> {
        let mut buf: Vec<u8> = vec![0u8; 0x400];
        buf[0] = b'M';
        buf[1] = b'Z';
        let e_lfanew: u32 = 0x80;
        buf[DOS_E_LFANEW_OFFSET..DOS_E_LFANEW_OFFSET + 4].copy_from_slice(&e_lfanew.to_le_bytes());
        let pe_off: usize = e_lfanew as usize;
        buf[pe_off..pe_off + 4].copy_from_slice(PE_MAGIC);
        let coff_off: usize = pe_off + 4;
        buf[coff_off..coff_off + 2].copy_from_slice(&0x014Cu16.to_le_bytes());
        buf[coff_off + 2..coff_off + 4].copy_from_slice(&1u16.to_le_bytes());
        buf[coff_off + 16..coff_off + 18].copy_from_slice(&0xE0u16.to_le_bytes());
        let opt_off: usize = coff_off + 20;
        buf[opt_off..opt_off + 2].copy_from_slice(&OPT_MAGIC_PE32.to_le_bytes());
        buf[opt_off + 16..opt_off + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt_off + 28..opt_off + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
        buf[opt_off + 32..opt_off + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt_off + 36..opt_off + 40].copy_from_slice(&0x200u32.to_le_bytes());
        let sec_off: usize = opt_off + 0xE0;
        buf[sec_off..sec_off + 5].copy_from_slice(b".text");
        buf[sec_off + 8..sec_off + 12].copy_from_slice(&0x100u32.to_le_bytes());
        buf[sec_off + 12..sec_off + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[sec_off + 16..sec_off + 20].copy_from_slice(&0x200u32.to_le_bytes());
        buf[sec_off + 20..sec_off + 24].copy_from_slice(&0x200u32.to_le_bytes());
        buf
    }

    #[test]
    fn parses_minimal_pe32() {
        let buf: Vec<u8> = minimal_pe();
        let img: PeImage = parse_pe_image(&buf).expect("parse");
        assert!(!img.is_pe32_plus);
        assert_eq!(img.image_base, 0x0040_0000);
        assert_eq!(img.entry_point_rva, 0x1000);
        assert_eq!(img.sections.len(), 1);
        assert!(img.sections[0].name_is(b".text"));
        assert_eq!(img.sections[0].virtual_address, 0x1000);
    }

    #[test]
    fn section_lookup_and_rva_containment() {
        let buf: Vec<u8> = minimal_pe();
        let img: PeImage = parse_pe_image(&buf).expect("parse");
        assert!(img.section_by_name(b".text").is_some());
        assert!(img.section_by_name(b".data").is_none());
        assert!(img.section_containing_rva(0x1050).is_some());
        assert!(img.section_containing_rva(0x9000).is_none());
    }

    #[test]
    fn rejects_non_pe() {
        let buf: Vec<u8> = vec![0u8; 0x100];
        assert!(parse_pe_image(&buf).is_err());
    }

    #[test]
    fn find_subsequence_basic() {
        assert_eq!(find_subsequence(b"hello world", b"world"), Some(6));
        assert_eq!(find_subsequence(b"abc", b"xyz"), None);
    }
}
