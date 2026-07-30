use crate::packers::pe_sections::{PeImage, PeSection, parse_pe_image};

pub(super) const MAX_SHORTSTRING_LEN: usize = 255;

const SCN_CNT_CODE: u32 = 0x0000_0020;
const SCN_MEM_EXECUTE: u32 = 0x2000_0000;

pub(super) struct PeView<'a> {
    pub(super) bytes: &'a [u8],
    pub(super) image: PeImage,
}

impl<'a> PeView<'a> {
    pub(super) fn parse(bytes: &'a [u8]) -> Option<Self> {
        let image: PeImage = parse_pe_image(bytes).ok()?;
        Some(Self { bytes, image })
    }

    pub(super) const fn is_64(&self) -> bool {
        self.image.is_pe32_plus
    }

    pub(super) const fn ptr_size(&self) -> usize {
        if self.image.is_pe32_plus { 8 } else { 4 }
    }

    pub(super) const fn image_base(&self) -> u64 {
        self.image.image_base
    }

    pub(super) fn rva_to_off(&self, rva: u32) -> Option<usize> {
        let sec: &PeSection = self.image.section_containing_rva(rva)?;
        let delta: u32 = rva.checked_sub(sec.virtual_address)?;
        if delta >= sec.raw_size {
            return None;
        }
        let off: usize = (sec.raw_pointer as usize).checked_add(delta as usize)?;
        if off <= self.bytes.len() {
            Some(off)
        } else {
            None
        }
    }

    pub(super) fn va_to_off(&self, va: u64) -> Option<usize> {
        let rva: u64 = va.checked_sub(self.image_base())?;
        if rva > u64::from(u32::MAX) {
            return None;
        }
        self.rva_to_off(rva as u32)
    }

    pub(super) fn section_for_va(&self, va: u64) -> Option<&PeSection> {
        let rva: u64 = va.checked_sub(self.image_base())?;
        if rva > u64::from(u32::MAX) {
            return None;
        }
        self.image.section_containing_rva(rva as u32)
    }

    pub(super) fn is_executable_va(&self, va: u64) -> bool {
        self.section_for_va(va)
            .is_some_and(|s: &PeSection| s.characteristics & (SCN_MEM_EXECUTE | SCN_CNT_CODE) != 0)
    }

    pub(super) fn every_mapped_section_is_executable(&self) -> bool {
        let mapped: Vec<&PeSection> = self
            .image
            .sections
            .iter()
            .filter(|s: &&PeSection| s.virtual_size.min(s.raw_size) > 0)
            .collect();
        !mapped.is_empty()
            && mapped
                .iter()
                .all(|s: &&PeSection| s.characteristics & (SCN_MEM_EXECUTE | SCN_CNT_CODE) != 0)
    }

    pub(super) fn read_u16(&self, off: usize) -> Option<u16> {
        let end: usize = off.checked_add(2)?;
        let s: &[u8] = self.bytes.get(off..end)?;
        Some(u16::from_le_bytes([s[0], s[1]]))
    }

    pub(super) fn read_u32(&self, off: usize) -> Option<u32> {
        let end: usize = off.checked_add(4)?;
        let s: &[u8] = self.bytes.get(off..end)?;
        Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    pub(super) fn read_i32(&self, off: usize) -> Option<i32> {
        self.read_u32(off).map(|v: u32| v as i32)
    }

    pub(super) fn read_i16(&self, off: usize) -> Option<i16> {
        self.read_u16(off).map(|v: u16| v as i16)
    }

    pub(super) fn read_u64(&self, off: usize) -> Option<u64> {
        let end: usize = off.checked_add(8)?;
        let s: &[u8] = self.bytes.get(off..end)?;
        Some(u64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    pub(super) fn read_ptr(&self, off: usize) -> Option<u64> {
        if self.is_64() {
            self.read_u64(off)
        } else {
            self.read_u32(off).map(u64::from)
        }
    }

    pub(super) fn read_ptr_at_va(&self, va: u64) -> Option<u64> {
        let off: usize = self.va_to_off(va)?;
        self.read_ptr(off)
    }

    pub(super) fn slice(&self, off: usize, len: usize) -> Option<&'a [u8]> {
        let end: usize = off.checked_add(len)?;
        self.bytes.get(off..end)
    }

    pub(super) fn read_shortstring(&self, off: usize, max_len: usize) -> Option<(String, usize)> {
        let len: usize = *self.bytes.get(off)? as usize;
        if len > max_len {
            return None;
        }
        let start: usize = off.checked_add(1)?;
        let end: usize = start.checked_add(len)?;
        let slice: &[u8] = self.bytes.get(start..end)?;
        Some((String::from_utf8_lossy(slice).into_owned(), 1 + len))
    }
}

pub(super) fn is_plausible_symbol(name: &str) -> bool {
    is_plausible_symbol_of_length(name, 2)
}

pub(super) fn is_plausible_symbol_of_length(name: &str, min_len: usize) -> bool {
    let bytes: &[u8] = name.as_bytes();
    if bytes.len() < min_len || bytes.len() > MAX_SHORTSTRING_LEN {
        return false;
    }
    let first: u8 = bytes[0];
    if first != b'_' && !first.is_ascii_alphabetic() {
        return false;
    }
    bytes
        .iter()
        .all(|b: &u8| *b == b'.' || *b == b'_' || *b == b'$' || b.is_ascii_alphanumeric())
}
