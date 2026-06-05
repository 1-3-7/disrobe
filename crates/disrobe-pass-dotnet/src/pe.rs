use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const DOS_MAGIC: u16 = 0x5A4D;
pub const NT_SIGNATURE: u32 = 0x0000_4550;
pub const PE32_MAGIC: u16 = 0x010B;
pub const PE32PLUS_MAGIC: u16 = 0x020B;
pub const CLR_DIRECTORY_INDEX: usize = 14;

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
}

pub fn parse(bytes: &[u8]) -> Result<PeImage> {
    let mut r: Reader<'_> = Reader::new(bytes);
    let dos_magic: u16 = r.u16_le()?;
    if dos_magic != DOS_MAGIC {
        return Err(Error::BadDosMagic(dos_magic));
    }
    r.seek(0x3C)?;
    let pe_offset: u32 = r.u32_le()?;
    r.seek(pe_offset as usize)?;
    let signature: u32 = r.u32_le()?;
    if signature != NT_SIGNATURE {
        return Err(Error::BadNtSignature(signature));
    }
    let machine: u16 = r.u16_le()?;
    let number_of_sections: u16 = r.u16_le()?;
    let timestamp: u32 = r.u32_le()?;
    let _symbol_table_ptr: u32 = r.u32_le()?;
    let _number_of_symbols: u32 = r.u32_le()?;
    let size_of_optional_header: u16 = r.u16_le()?;
    let characteristics: u16 = r.u16_le()?;
    let opt_start: usize = r.pos;
    let optional_magic: u16 = r.u16_le()?;
    let bitness: PeBitness = match optional_magic {
        PE32_MAGIC => PeBitness::Pe32,
        PE32PLUS_MAGIC => PeBitness::Pe32Plus,
        other => return Err(Error::BadOptionalMagic(other)),
    };
    r.skip(14)?;
    let entry_point_rva: u32 = r.u32_le()?;
    let image_base: u64 = match bitness {
        PeBitness::Pe32 => {
            r.skip(8)?;
            u64::from(r.u32_le()?)
        }
        PeBitness::Pe32Plus => {
            r.skip(4)?;
            r.u64_le()?
        }
    };
    r.skip(40)?;
    let number_of_rva_and_sizes: u32 = match bitness {
        PeBitness::Pe32 => {
            r.skip(20)?;
            r.u32_le()?
        }
        PeBitness::Pe32Plus => {
            r.skip(36)?;
            r.u32_le()?
        }
    };
    let dir_prealloc: usize = (number_of_rva_and_sizes as usize).min(r.remaining() / 8);
    let mut data_directories: Vec<DataDirectory> = Vec::with_capacity(dir_prealloc);
    for _ in 0..number_of_rva_and_sizes {
        let rva: u32 = r.u32_le()?;
        let size: u32 = r.u32_le()?;
        data_directories.push(DataDirectory { rva, size });
    }
    let sections_start: usize = opt_start + size_of_optional_header as usize;
    r.seek(sections_start)?;
    let mut sections: Vec<SectionHeader> = Vec::with_capacity(number_of_sections as usize);
    for _ in 0..number_of_sections {
        let name_bytes: &[u8] = r.take(8)?;
        let name: String = String::from_utf8_lossy(
            name_bytes
                .split(|b: &u8| *b == 0)
                .next()
                .unwrap_or(name_bytes),
        )
        .into_owned();
        let virtual_size: u32 = r.u32_le()?;
        let virtual_address: u32 = r.u32_le()?;
        let raw_size: u32 = r.u32_le()?;
        let raw_pointer: u32 = r.u32_le()?;
        r.skip(12)?;
        let characteristics_s: u32 = r.u32_le()?;
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
    if dir.rva == 0 || dir.size == 0 {
        return Err(Error::NoClrHeader);
    }
    let slice: &[u8] = pe.slice_at_rva(image, dir.rva, dir.size.max(72) as usize)?;
    let mut r: Reader<'_> = Reader::new(slice);
    let cb: u32 = r.u32_le()?;
    let major_runtime_version: u16 = r.u16_le()?;
    let minor_runtime_version: u16 = r.u16_le()?;
    let metadata: DataDirectory = read_data_dir(&mut r)?;
    let flags: u32 = r.u32_le()?;
    let entry_point_token_or_rva: u32 = r.u32_le()?;
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

fn read_data_dir(r: &mut Reader<'_>) -> Result<DataDirectory> {
    let rva: u32 = r.u32_le()?;
    let size: u32 = r.u32_le()?;
    Ok(DataDirectory { rva, size })
}

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    pub(crate) pos: usize,
}

impl<'a> Reader<'a> {
    #[inline]
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    #[inline]
    pub(crate) const fn need(&self, n: usize) -> Result<()> {
        if self.pos.saturating_add(n) > self.bytes.len() {
            return Err(Error::Truncated {
                offset: self.pos,
                needed: n,
                had: self.bytes.len().saturating_sub(self.pos),
            });
        }
        Ok(())
    }

    #[inline]
    pub(crate) const fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    #[inline]
    pub(crate) const fn seek(&mut self, pos: usize) -> Result<()> {
        if pos > self.bytes.len() {
            return Err(Error::Truncated {
                offset: pos,
                needed: 0,
                had: self.bytes.len(),
            });
        }
        self.pos = pos;
        Ok(())
    }

    #[inline]
    pub(crate) fn skip(&mut self, n: usize) -> Result<()> {
        self.need(n)?;
        self.pos += n;
        Ok(())
    }

    #[inline]
    pub(crate) fn u8(&mut self) -> Result<u8> {
        self.need(1)?;
        let v: u8 = self.bytes[self.pos];
        self.pos += 1;
        Ok(v)
    }

    #[inline]
    pub(crate) fn u16_le(&mut self) -> Result<u16> {
        self.need(2)?;
        let v: u16 = u16::from_le_bytes([self.bytes[self.pos], self.bytes[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    #[inline]
    pub(crate) fn u32_le(&mut self) -> Result<u32> {
        self.need(4)?;
        let v: u32 = u32::from_le_bytes([
            self.bytes[self.pos],
            self.bytes[self.pos + 1],
            self.bytes[self.pos + 2],
            self.bytes[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    #[inline]
    pub(crate) fn u64_le(&mut self) -> Result<u64> {
        self.need(8)?;
        let mut buf: [u8; 8] = [0u8; 8];
        buf.copy_from_slice(&self.bytes[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_le_bytes(buf))
    }

    #[inline]
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        self.need(n)?;
        let out: &'a [u8] = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }
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
}
