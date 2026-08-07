use disrobe_bytes::{
    AddressError, FileOffset, Rva, SectionSpan, Size, align_up_u32, read_u16_le_at, read_u32_le_at,
    read_u64_le_at,
};
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
    pub pointer_to_relocations: u32,
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

    #[must_use]
    pub fn mapped_span(&self) -> SectionSpan {
        SectionSpan::new(
            Rva::new(self.virtual_address),
            Size::new(u64::from(self.virtual_size.max(self.raw_size))),
            FileOffset::new(u64::from(self.raw_pointer)),
            Size::new(u64::from(self.raw_size)),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeImage {
    pub pe_header_offset: u32,
    pub machine: u16,
    pub size_of_optional_header: u16,
    pub coff_characteristics: u16,
    pub is_pe32_plus: bool,
    pub entry_point_rva: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub data_directories: Vec<DataDirectory>,
    pub raw_data_directories: Vec<DataDirectory>,
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

    #[must_use]
    pub fn header_bytes_present(&self, image_len: usize) -> usize {
        (self.size_of_headers as usize).min(image_len)
    }

    #[must_use]
    pub fn rva_is_mapped(&self, rva: u32, image_len: usize) -> bool {
        self.section_containing_rva(rva).is_some()
            || (rva as usize) < self.header_bytes_present(image_len)
    }

    pub fn file_offset_for_rva(
        &self,
        rva: u32,
        image_len: usize,
    ) -> core::result::Result<usize, AddressError> {
        let file_len: Size = Size::try_from(image_len)?;
        let Some(section): Option<&PeSection> = self.section_containing_rva(rva) else {
            let header_offset: usize = rva as usize;
            if header_offset < self.header_bytes_present(image_len) {
                return Ok(header_offset);
            }
            return Err(AddressError::RvaNotMapped { rva: Rva::new(rva) });
        };
        let offset: FileOffset = section.mapped_span().translate(Rva::new(rva))?;
        offset
            .checked_range(Size::new(1), file_len)
            .map(|readable: core::ops::Range<usize>| readable.start)
    }
}

pub fn parse_pe_image(bytes: &[u8]) -> Result<PeImage> {
    if bytes.len() < DOS_E_LFANEW_OFFSET + 4 {
        return Err(Error::Truncated {
            needed: DOS_E_LFANEW_OFFSET + 4,
            had: bytes.len(),
        });
    }
    let pe_header_offset: u32 = read_u32(bytes, DOS_E_LFANEW_OFFSET)?;
    let e_lfanew: usize = pe_header_offset as usize;
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
    let machine: u16 = read_u16(bytes, coff_off)?;
    let n_sections: usize = read_u16(bytes, coff_off + 2)? as usize;
    let size_of_optional_header: u16 = read_u16(bytes, coff_off + 16)?;
    let opt_hdr_size: usize = size_of_optional_header as usize;
    let coff_characteristics: u16 = read_u16(bytes, coff_off + 18)?;
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
    let size_of_headers: u32 = read_u32(bytes, opt_hdr_off + 60)?;
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
            pointer_to_relocations: read_u32(bytes, off + 24)?,
            characteristics: read_u32(bytes, off + 36)?,
        });
    }
    let directory_table_relative: usize = dir_table_off - opt_hdr_off;
    let raw_directory_count: usize =
        (opt_hdr_size.saturating_sub(directory_table_relative) / 8).min(16);
    let mut raw_data_directories: Vec<DataDirectory> = Vec::with_capacity(raw_directory_count);
    for i in 0..raw_directory_count {
        let entry: usize = dir_table_off + i * 8;
        raw_data_directories.push(DataDirectory {
            virtual_address: read_u32(bytes, entry)?,
            size: read_u32(bytes, entry + 4)?,
        });
    }
    Ok(PeImage {
        pe_header_offset,
        machine,
        size_of_optional_header,
        coff_characteristics,
        is_pe32_plus,
        entry_point_rva,
        image_base,
        section_alignment,
        file_alignment,
        size_of_image,
        size_of_headers,
        data_directories,
        raw_data_directories,
        sections,
    })
}

#[inline]
pub fn read_u16(b: &[u8], off: usize) -> Result<u16> {
    let needed: usize = off.saturating_add(2);
    read_u16_le_at(b, off).map_err(|_| Error::Truncated {
        needed,
        had: b.len(),
    })
}

#[inline]
pub fn read_u32(b: &[u8], off: usize) -> Result<u32> {
    let needed: usize = off.saturating_add(4);
    read_u32_le_at(b, off).map_err(|_| Error::Truncated {
        needed,
        had: b.len(),
    })
}

#[inline]
pub fn read_u64(b: &[u8], off: usize) -> Result<u64> {
    let needed: usize = off.saturating_add(8);
    read_u64_le_at(b, off).map_err(|_| Error::Truncated {
        needed,
        had: b.len(),
    })
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

const MEMORY_IMAGE_MAX_FILE_BYTES: usize = 256 * 1024 * 1024;

pub(crate) fn memory_to_file_image(mem_image: &[u8], max_image_ratio: usize) -> Option<Vec<u8>> {
    if mem_image.len() < 0x100 || !mem_image.starts_with(b"MZ") {
        return None;
    }
    let e_lfanew: usize = read_u32(mem_image, DOS_E_LFANEW_OFFSET).ok()? as usize;
    if e_lfanew + 24 > mem_image.len() || mem_image.get(e_lfanew..e_lfanew + 4)? != PE_MAGIC {
        return None;
    }
    let coff: usize = e_lfanew + 4;
    let n_sec: usize = usize::from(read_u16(mem_image, coff + 2).ok()?);
    let opt_hdr_size: u16 = read_u16(mem_image, coff + 16).ok()?;
    let opt: usize = coff + COFF_HEADER_SIZE;
    let file_alignment: u32 = read_u32(mem_image, opt + 36).ok()?.max(0x200);
    let sec_off: usize = opt + opt_hdr_size as usize;
    if sec_off + SECTION_ENTRY_SIZE * n_sec > mem_image.len() {
        return None;
    }
    let headers_raw: u32 = read_u32(mem_image, opt + 60).ok()?.max(file_alignment);
    let mut sections: Vec<(u32, u32, u32, u32)> = Vec::with_capacity(n_sec);
    for i in 0..n_sec {
        let s: usize = sec_off + i * SECTION_ENTRY_SIZE;
        let vs: u32 = read_u32(mem_image, s + 8).ok()?;
        let va: u32 = read_u32(mem_image, s + 12).ok()?;
        let raw_size: u32 = read_u32(mem_image, s + 16).ok()?;
        let raw_ptr: u32 = read_u32(mem_image, s + 20).ok()?;
        let effective_raw: u32 = if raw_size > 0 {
            raw_size
        } else {
            align_up_u32(vs, file_alignment)
        };
        sections.push((va, vs, effective_raw, raw_ptr));
    }
    let total_usize: usize = sections
        .iter()
        .map(|s: &(u32, u32, u32, u32)| (s.2 as usize).saturating_add(s.3 as usize))
        .max()
        .unwrap_or(headers_raw as usize)
        .max(headers_raw as usize);
    let image_ceiling: usize =
        MEMORY_IMAGE_MAX_FILE_BYTES.min(mem_image.len().saturating_mul(max_image_ratio));
    if total_usize > image_ceiling {
        return None;
    }
    let mut out: Vec<u8> = vec![0u8; total_usize];
    let header_copy: usize = (headers_raw as usize).min(mem_image.len());
    out[..header_copy].copy_from_slice(&mem_image[..header_copy]);
    for sec_tuple in &sections {
        let (va, vs, eff_raw, raw_ptr): (u32, u32, u32, u32) = *sec_tuple;
        let src_lo: usize = va as usize;
        let src_hi: usize = src_lo
            .saturating_add(vs.max(eff_raw) as usize)
            .min(mem_image.len());
        let dst_lo: usize = raw_ptr as usize;
        let copy_len: usize = (src_hi.saturating_sub(src_lo)).min(eff_raw as usize);
        if dst_lo + copy_len <= out.len() && src_lo + copy_len <= mem_image.len() {
            out[dst_lo..dst_lo + copy_len].copy_from_slice(&mem_image[src_lo..src_lo + copy_len]);
        }
    }
    Some(out)
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
        buf[coff_off + 18..coff_off + 20].copy_from_slice(&0x0102u16.to_le_bytes());
        let opt_off: usize = coff_off + 20;
        buf[opt_off..opt_off + 2].copy_from_slice(&OPT_MAGIC_PE32.to_le_bytes());
        buf[opt_off + 16..opt_off + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt_off + 28..opt_off + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
        buf[opt_off + 32..opt_off + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt_off + 36..opt_off + 40].copy_from_slice(&0x200u32.to_le_bytes());
        buf[opt_off + 60..opt_off + 64].copy_from_slice(&0x400u32.to_le_bytes());
        buf[opt_off + 104..opt_off + 108].copy_from_slice(&0x3000u32.to_le_bytes());
        buf[opt_off + 108..opt_off + 112].copy_from_slice(&0x80u32.to_le_bytes());
        buf[opt_off + 192..opt_off + 196].copy_from_slice(&0x4000u32.to_le_bytes());
        buf[opt_off + 196..opt_off + 200].copy_from_slice(&0x40u32.to_le_bytes());
        let sec_off: usize = opt_off + 0xE0;
        buf[sec_off..sec_off + 5].copy_from_slice(b".text");
        buf[sec_off + 8..sec_off + 12].copy_from_slice(&0x100u32.to_le_bytes());
        buf[sec_off + 12..sec_off + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[sec_off + 16..sec_off + 20].copy_from_slice(&0x200u32.to_le_bytes());
        buf[sec_off + 20..sec_off + 24].copy_from_slice(&0x200u32.to_le_bytes());
        buf
    }

    fn minimal_pe32_plus() -> Vec<u8> {
        let mut buf: Vec<u8> = vec![0u8; 0x400];
        buf[0..2].copy_from_slice(b"MZ");
        let e_lfanew: u32 = 0x80;
        buf[DOS_E_LFANEW_OFFSET..DOS_E_LFANEW_OFFSET + 4].copy_from_slice(&e_lfanew.to_le_bytes());
        let pe_off: usize = e_lfanew as usize;
        buf[pe_off..pe_off + 4].copy_from_slice(PE_MAGIC);
        let coff_off: usize = pe_off + 4;
        buf[coff_off..coff_off + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        buf[coff_off + 2..coff_off + 4].copy_from_slice(&1u16.to_le_bytes());
        buf[coff_off + 16..coff_off + 18].copy_from_slice(&0xF0u16.to_le_bytes());
        let opt_off: usize = coff_off + COFF_HEADER_SIZE;
        buf[opt_off..opt_off + 2].copy_from_slice(&OPT_MAGIC_PE32_PLUS.to_le_bytes());
        buf[opt_off + 16..opt_off + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt_off + 24..opt_off + 32].copy_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes());
        buf[opt_off + 32..opt_off + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt_off + 36..opt_off + 40].copy_from_slice(&0x200u32.to_le_bytes());
        buf[opt_off + 60..opt_off + 64].copy_from_slice(&0x400u32.to_le_bytes());
        buf[opt_off + 120..opt_off + 124].copy_from_slice(&0x5000u32.to_le_bytes());
        buf[opt_off + 124..opt_off + 128].copy_from_slice(&0x90u32.to_le_bytes());
        buf[opt_off + 208..opt_off + 212].copy_from_slice(&0x6000u32.to_le_bytes());
        buf[opt_off + 212..opt_off + 216].copy_from_slice(&0x50u32.to_le_bytes());
        let sec_off: usize = opt_off + 0xF0;
        buf[sec_off..sec_off + 5].copy_from_slice(b".text");
        buf[sec_off + 8..sec_off + 12].copy_from_slice(&0x100u32.to_le_bytes());
        buf[sec_off + 12..sec_off + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[sec_off + 16..sec_off + 20].copy_from_slice(&0x200u32.to_le_bytes());
        buf[sec_off + 20..sec_off + 24].copy_from_slice(&0x200u32.to_le_bytes());
        buf
    }

    #[test]
    fn parses_minimal_pe_images() {
        let buf: Vec<u8> = minimal_pe();
        let img: PeImage = parse_pe_image(&buf).expect("parse");
        assert!(!img.is_pe32_plus);
        assert_eq!(img.image_base, 0x0040_0000);
        assert_eq!(img.entry_point_rva, 0x1000);
        assert_eq!(img.sections.len(), 1);
        assert!(img.sections[0].name_is(b".text"));
        assert_eq!(img.sections[0].virtual_address, 0x1000);
        assert_eq!(img.pe_header_offset, 0x80);
        assert_eq!(img.machine, 0x014C);
        assert_eq!(img.size_of_optional_header, 0xE0);
        assert_eq!(img.coff_characteristics, 0x0102);
        assert_eq!(img.size_of_headers, 0x400);
        assert!(img.data_directories.is_empty());
        assert_eq!(
            img.raw_data_directories.get(1),
            Some(&DataDirectory {
                virtual_address: 0x3000,
                size: 0x80,
            })
        );
        assert_eq!(
            img.raw_data_directories.get(12),
            Some(&DataDirectory {
                virtual_address: 0x4000,
                size: 0x40,
            })
        );

        let plus_buf: Vec<u8> = minimal_pe32_plus();
        let plus: PeImage = parse_pe_image(&plus_buf).expect("parse PE32+");
        assert!(plus.is_pe32_plus);
        assert_eq!(plus.machine, 0x8664);
        assert_eq!(plus.size_of_optional_header, 0xF0);
        assert_eq!(plus.image_base, 0x0000_0001_4000_0000);
        assert!(plus.data_directories.is_empty());
        assert_eq!(
            plus.raw_data_directories.get(1),
            Some(&DataDirectory {
                virtual_address: 0x5000,
                size: 0x90,
            })
        );
        assert_eq!(
            plus.raw_data_directories.get(12),
            Some(&DataDirectory {
                virtual_address: 0x6000,
                size: 0x50,
            })
        );
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

    #[test]
    fn readers_reject_overflowing_offset_without_panic() {
        let buf: [u8; 16] = [0u8; 16];
        assert!(matches!(
            read_u16(&buf, usize::MAX),
            Err(Error::Truncated { .. })
        ));
        assert!(matches!(
            read_u32(&buf, usize::MAX - 1),
            Err(Error::Truncated { .. })
        ));
        assert!(matches!(
            read_u64(&buf, usize::MAX - 3),
            Err(Error::Truncated { .. })
        ));
        assert!(matches!(read_u16(&buf, 15), Err(Error::Truncated { .. })));
        assert_eq!(read_u16(&buf, 14).unwrap(), 0);
    }
}
