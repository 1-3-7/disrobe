use disrobe_bytes::ByteReader;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const DOS_MAGIC: u16 = 0x5A4D;
pub const NT_SIGNATURE: u32 = 0x0000_4550;
pub const PE32_MAGIC: u16 = 0x010B;
pub const PE32PLUS_MAGIC: u16 = 0x020B;
pub const CLR_DIRECTORY_INDEX: usize = 14;
const SECTION_HEADER_LEN: usize = 40;

#[inline]
const fn section_prealloc(number_of_sections: u16, remaining: usize) -> usize {
    let claimed: usize = number_of_sections as usize;
    let affordable: usize = remaining / SECTION_HEADER_LEN;
    if claimed < affordable {
        claimed
    } else {
        affordable
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PeBitness {
    Pe32,
    Pe32Plus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionHeader {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_pointer: u32,
    pub characteristics: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataDirectory {
    pub rva: u32,
    pub size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeImage {
    pub bitness: PeBitness,
    pub machine: u16,
    pub number_of_sections: u16,
    pub timestamp: u32,
    pub characteristics: u16,
    pub entry_point_rva: u32,
    pub image_base: u64,
    pub data_directories: Vec<DataDirectory>,
    pub sections: Vec<SectionHeader>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClrHeader {
    pub cb: u32,
    pub major_runtime_version: u16,
    pub minor_runtime_version: u16,
    pub metadata: DataDirectory,
    pub flags: u32,
    pub entry_point_token_or_rva: u32,
    pub resources: DataDirectory,
    pub strong_name_signature: DataDirectory,
    pub code_manager_table: DataDirectory,
    pub vtable_fixups: DataDirectory,
    pub export_address_table_jumps: DataDirectory,
    pub managed_native_header: DataDirectory,
}

impl PeImage {
    #[must_use]
    pub fn clr_directory(&self) -> Option<DataDirectory> {
        self.data_directories.get(CLR_DIRECTORY_INDEX).copied()
    }

    #[must_use]
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        for section in &self.sections {
            let start: u32 = section.virtual_address;
            let end: u32 = start.saturating_add(section.virtual_size.max(section.raw_size));
            if rva >= start && rva < end {
                let delta: u32 = rva - start;
                if delta >= section.raw_size {
                    return None;
                }
                let off: u64 = u64::from(section.raw_pointer) + u64::from(delta);
                return usize::try_from(off).ok();
            }
        }
        None
    }

    pub fn slice_at_rva<'a>(&self, image: &'a [u8], rva: u32, len: usize) -> Result<&'a [u8]> {
        let off: usize = self.rva_to_offset(rva).ok_or(Error::Truncated {
            offset: rva as usize,
            needed: len,
            had: 0,
        })?;
        if off.saturating_add(len) > image.len() {
            return Err(Error::Truncated {
                offset: off,
                needed: len,
                had: image.len().saturating_sub(off),
            });
        }
        Ok(&image[off..off + len])
    }

    #[must_use]
    pub fn slice_exact_file_backed_rva<'a>(
        &self,
        image: &'a [u8],
        rva: u32,
        len: usize,
    ) -> Option<&'a [u8]> {
        let length: u32 = u32::try_from(len).ok()?;
        if length == 0 {
            return None;
        }
        let end: u32 = rva.checked_add(length)?;
        let mut matching: Option<&SectionHeader> = None;
        for section in &self.sections {
            let virtual_end: u32 = section
                .virtual_address
                .checked_add(section.virtual_size.max(section.raw_size))?;
            let intersects: bool = rva < virtual_end && end > section.virtual_address;
            if !intersects {
                continue;
            }
            if matching.is_some() {
                return None;
            }
            matching = Some(section);
        }
        let section: &SectionHeader = matching?;
        let raw_end: u32 = section.virtual_address.checked_add(section.raw_size)?;
        if rva < section.virtual_address || end > raw_end {
            return None;
        }
        let delta: u32 = rva.checked_sub(section.virtual_address)?;
        let start: usize =
            usize::try_from(u64::from(section.raw_pointer) + u64::from(delta)).ok()?;
        let file_end: usize = start.checked_add(len)?;
        image.get(start..file_end)
    }

    pub fn slice_at_rva_to_end<'a>(&self, image: &'a [u8], rva: u32) -> Result<&'a [u8]> {
        let off: usize = self.rva_to_offset(rva).ok_or(Error::Truncated {
            offset: rva as usize,
            needed: 0,
            had: 0,
        })?;
        Ok(image.get(off..).unwrap_or(&[]))
    }
}

pub fn parse(bytes: &[u8]) -> Result<PeImage> {
    let mut r: ByteReader<'_> = ByteReader::new(bytes);
    let dos_magic: u16 = r.read_u16_le()?;
    if dos_magic != DOS_MAGIC {
        return Err(Error::BadDosMagic(dos_magic));
    }
    r.seek(0x3C)?;
    let pe_offset: u32 = r.read_u32_le()?;
    r.seek(pe_offset as usize)?;
    let signature: u32 = r.read_u32_le()?;
    if signature & 0x0000_FFFF != NT_SIGNATURE {
        return Err(Error::BadNtSignature(signature));
    }
    let machine: u16 = r.read_u16_le()?;
    let number_of_sections: u16 = r.read_u16_le()?;
    let timestamp: u32 = r.read_u32_le()?;
    let _symbol_table_ptr: u32 = r.read_u32_le()?;
    let _number_of_symbols: u32 = r.read_u32_le()?;
    let size_of_optional_header: u16 = r.read_u16_le()?;
    let characteristics: u16 = r.read_u16_le()?;
    let opt_start: usize = r.position();
    let optional_magic: u16 = r.read_u16_le()?;
    let bitness: PeBitness = match optional_magic {
        PE32_MAGIC => PeBitness::Pe32,
        PE32PLUS_MAGIC => PeBitness::Pe32Plus,
        other => return Err(Error::BadOptionalMagic(other)),
    };
    r.skip(14)?;
    let entry_point_rva: u32 = r.read_u32_le()?;
    let image_base: u64 = match bitness {
        PeBitness::Pe32 => {
            r.skip(8)?;
            u64::from(r.read_u32_le()?)
        }
        PeBitness::Pe32Plus => {
            r.skip(4)?;
            r.read_u64_le()?
        }
    };
    r.skip(40)?;
    let number_of_rva_and_sizes: u32 = match bitness {
        PeBitness::Pe32 => {
            r.skip(20)?;
            r.read_u32_le()?
        }
        PeBitness::Pe32Plus => {
            r.skip(36)?;
            r.read_u32_le()?
        }
    };
    let dir_prealloc: usize = (number_of_rva_and_sizes as usize).min(r.remaining() / 8);
    let mut data_directories: Vec<DataDirectory> = Vec::with_capacity(dir_prealloc);
    for _ in 0..number_of_rva_and_sizes {
        let rva: u32 = r.read_u32_le()?;
        let size: u32 = r.read_u32_le()?;
        data_directories.push(DataDirectory { rva, size });
    }
    let sections_start: usize = opt_start + size_of_optional_header as usize;
    r.seek(sections_start)?;
    let sec_prealloc: usize = section_prealloc(number_of_sections, r.remaining());
    let mut sections: Vec<SectionHeader> = Vec::with_capacity(sec_prealloc);
    for _ in 0..number_of_sections {
        let name_bytes: &[u8] = r.read_bytes(8)?;
        let name: String = String::from_utf8_lossy(
            name_bytes
                .split(|b: &u8| *b == 0)
                .next()
                .unwrap_or(name_bytes),
        )
        .into_owned();
        let virtual_size: u32 = r.read_u32_le()?;
        let virtual_address: u32 = r.read_u32_le()?;
        let raw_size: u32 = r.read_u32_le()?;
        let raw_pointer: u32 = r.read_u32_le()?;
        r.skip(12)?;
        let characteristics_s: u32 = r.read_u32_le()?;
        sections.push(SectionHeader {
            name,
            virtual_size,
            virtual_address,
            raw_size,
            raw_pointer,
            characteristics: characteristics_s,
        });
    }
    Ok(PeImage {
        bitness,
        machine,
        number_of_sections,
        timestamp,
        characteristics,
        entry_point_rva,
        image_base,
        data_directories,
        sections,
    })
}

pub fn parse_clr_header(image: &[u8], pe: &PeImage) -> Result<ClrHeader> {
    let dir: DataDirectory = pe.clr_directory().ok_or(Error::NoClrHeader)?;
    if dir.rva == 0 {
        return Err(Error::NoClrHeader);
    }
    let slice: &[u8] = pe.slice_at_rva(image, dir.rva, dir.size.max(72) as usize)?;
    let mut r: ByteReader<'_> = ByteReader::new(slice);
    let cb: u32 = r.read_u32_le()?;
    let major_runtime_version: u16 = r.read_u16_le()?;
    let minor_runtime_version: u16 = r.read_u16_le()?;
    let metadata: DataDirectory = read_data_dir(&mut r)?;
    let flags: u32 = r.read_u32_le()?;
    let entry_point_token_or_rva: u32 = r.read_u32_le()?;
    let resources: DataDirectory = read_data_dir(&mut r)?;
    let strong_name_signature: DataDirectory = read_data_dir(&mut r)?;
    let code_manager_table: DataDirectory = read_data_dir(&mut r)?;
    let vtable_fixups: DataDirectory = read_data_dir(&mut r)?;
    let export_address_table_jumps: DataDirectory = read_data_dir(&mut r)?;
    let managed_native_header: DataDirectory = read_data_dir(&mut r)?;
    Ok(ClrHeader {
        cb,
        major_runtime_version,
        minor_runtime_version,
        metadata,
        flags,
        entry_point_token_or_rva,
        resources,
        strong_name_signature,
        code_manager_table,
        vtable_fixups,
        export_address_table_jumps,
        managed_native_header,
    })
}

fn read_data_dir(r: &mut ByteReader<'_>) -> Result<DataDirectory> {
    let rva: u32 = r.read_u32_le()?;
    let size: u32 = r.read_u32_le()?;
    Ok(DataDirectory { rva, size })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_pe_input() {
        let err: Error = parse(&[0u8; 64]).expect_err("no dos magic");
        assert!(matches!(err, Error::BadDosMagic(_)));
    }

    #[test]
    fn pe_bitness_const_values_match_spec() {
        assert_eq!(PE32_MAGIC, 0x010B);
        assert_eq!(PE32PLUS_MAGIC, 0x020B);
    }

    #[test]
    fn clr_directory_index_is_fourteen() {
        assert_eq!(CLR_DIRECTORY_INDEX, 14);
    }

    #[test]
    fn rva_to_offset_finds_section() {
        let img: PeImage = PeImage {
            bitness: PeBitness::Pe32,
            machine: 0x14C,
            number_of_sections: 1,
            timestamp: 0,
            characteristics: 0,
            entry_point_rva: 0x2050,
            image_base: 0x40_0000,
            data_directories: vec![],
            sections: vec![SectionHeader {
                name: ".text".to_owned(),
                virtual_size: 0x1000,
                virtual_address: 0x2000,
                raw_size: 0x1000,
                raw_pointer: 0x200,
                characteristics: 0x6000_0020,
            }],
        };
        assert_eq!(img.rva_to_offset(0x2050), Some(0x250));
        assert_eq!(img.rva_to_offset(0x9999), None);
    }

    #[test]
    fn exact_file_backed_rva_slice_rejects_cross_section_and_truncation() {
        let img: PeImage = PeImage {
            bitness: PeBitness::Pe32,
            machine: 0x14C,
            number_of_sections: 2,
            timestamp: 0,
            characteristics: 0,
            entry_point_rva: 0,
            image_base: 0x40_0000,
            data_directories: vec![],
            sections: vec![
                SectionHeader {
                    name: ".data".to_owned(),
                    virtual_size: 4,
                    virtual_address: 0x2000,
                    raw_size: 4,
                    raw_pointer: 0x10,
                    characteristics: 0,
                },
                SectionHeader {
                    name: ".next".to_owned(),
                    virtual_size: 4,
                    virtual_address: 0x2004,
                    raw_size: 4,
                    raw_pointer: 0x20,
                    characteristics: 0,
                },
            ],
        };
        let bytes: Vec<u8> = (0u8..40).collect();
        assert_eq!(
            img.slice_exact_file_backed_rva(&bytes, 0x2001, 3),
            Some(&bytes[0x11..0x14])
        );
        assert_eq!(img.slice_exact_file_backed_rva(&bytes, 0x2001, 4), None);
        assert_eq!(img.slice_exact_file_backed_rva(&bytes, 0x2000, 0), None);
        assert_eq!(
            img.slice_exact_file_backed_rva(&bytes[..0x13], 0x2000, 4),
            None
        );
    }

    #[test]
    fn section_prealloc_caps_to_remaining_input() {
        assert_eq!(section_prealloc(0xFFFF, 0), 0);
        assert_eq!(section_prealloc(0xFFFF, 80), 2);
        assert_eq!(section_prealloc(0xFFFF, 39), 0);
        assert_eq!(section_prealloc(3, 80), 2);
        assert_eq!(section_prealloc(3, 120), 3);
        assert_eq!(section_prealloc(3, 4096), 3);
        assert_eq!(section_prealloc(0, 4096), 0);
    }

    fn crafted_pe_declaring_sections(number_of_sections: u16, tail: usize) -> Vec<u8> {
        let pe_off: usize = 0x80;
        let mut bytes: Vec<u8> = vec![0u8; pe_off + 24 + 96 + tail];
        bytes[0] = 0x4D;
        bytes[1] = 0x5A;
        bytes[0x3C..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
        bytes[pe_off..pe_off + 4].copy_from_slice(&NT_SIGNATURE.to_le_bytes());
        bytes[pe_off + 4..pe_off + 6].copy_from_slice(&0x014Cu16.to_le_bytes());
        bytes[pe_off + 6..pe_off + 8].copy_from_slice(&number_of_sections.to_le_bytes());
        let opt_size: u16 = 96;
        bytes[pe_off + 20..pe_off + 22].copy_from_slice(&opt_size.to_le_bytes());
        let opt_start: usize = pe_off + 24;
        bytes[opt_start..opt_start + 2].copy_from_slice(&PE32_MAGIC.to_le_bytes());
        bytes
    }

    #[test]
    fn giant_section_count_short_buffer_errs_without_panic() {
        let bytes: Vec<u8> = crafted_pe_declaring_sections(0xFFFF, 0);
        let outcome: std::thread::Result<Result<PeImage>> =
            std::panic::catch_unwind(move || parse(&bytes));
        let parsed: Result<PeImage> = outcome.expect("parser must not panic");
        assert!(parsed.is_err(), "declared sections absent from buffer");
    }

    #[test]
    fn well_formed_section_count_still_parses() {
        let mut bytes: Vec<u8> = crafted_pe_declaring_sections(1, SECTION_HEADER_LEN);
        let opt_start: usize = 0x80 + 24;
        let sec_start: usize = opt_start + 96;
        bytes[sec_start..sec_start + 5].copy_from_slice(b".text");
        let img: PeImage = parse(&bytes).expect("one present section parses");
        assert_eq!(img.number_of_sections, 1);
        assert_eq!(img.sections.len(), 1);
        assert_eq!(img.sections[0].name, ".text");
    }
}
