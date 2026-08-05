use std::collections::BTreeMap;

use object::read::macho::{FatArch, FatArch32, FatArch64, MachOFatFile32, MachOFatFile64};
use object::read::{File as ObjFile, Object, ObjectSection};
use object::{Endianness, FileKind, RelocationFlags, RelocationTarget, SectionFlags};

use crate::error::{Error, Result};

const SHF_EXECINSTR: u64 = 0x4;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const MACHO_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const MACHO_SOME_INSTRUCTIONS: u32 = 0x0000_0400;
pub(crate) const MAX_SPANS: usize = 4096;
const MAX_OVERLAP_WALK: usize = 64;
const MAX_FAT_SLICES: usize = 64;

#[derive(Debug, Clone, Copy)]
struct Span {
    va: u64,
    vsize: u64,
    foff: usize,
    fsize: usize,
    exec: bool,
}

#[derive(Debug)]
pub(crate) struct SectionMap<'a> {
    bytes: &'a [u8],
    ptr_size: usize,
    endian: Endianness,
    spans: Vec<Span>,
    span_index: Vec<(u64, u64, usize)>,
    relocs: BTreeMap<u64, u64>,
}

impl<'a> SectionMap<'a> {
    pub(crate) fn build_slices(bytes: &'a [u8]) -> Result<Vec<Self>> {
        let ranges: Vec<(u64, u64)> = fat_slice_ranges(bytes);
        if ranges.is_empty() {
            return Self::build(bytes).map(|map: Self| vec![map]);
        }
        let mut maps: Vec<Self> = Vec::new();
        let mut last_failure: Option<String> = None;
        for (offset, size) in ranges.into_iter().take(MAX_FAT_SLICES) {
            let (Ok(start), Ok(len)): (
                core::result::Result<usize, _>,
                core::result::Result<usize, _>,
            ) = (usize::try_from(offset), usize::try_from(size)) else {
                continue;
            };
            let Some(end) = start.checked_add(len) else {
                continue;
            };
            let Some(slice) = bytes.get(start..end) else {
                continue;
            };
            match Self::build(slice) {
                Ok(map) => maps.push(map),
                Err(Error::NativeParse(detail)) => last_failure = Some(detail),
                Err(other) => return Err(other),
            }
        }
        if maps.is_empty() {
            return Err(Error::NativeParse(last_failure.unwrap_or_else(|| {
                "universal binary declares no slice inside the file".to_owned()
            })));
        }
        Ok(maps)
    }

    pub(crate) fn build(bytes: &'a [u8]) -> Result<Self> {
        let file: ObjFile<'a, &'a [u8]> =
            ObjFile::parse(bytes).map_err(|e| Error::NativeParse(e.to_string()))?;
        let ptr_size: usize = if file.is_64() { 8 } else { 4 };
        let endian: Endianness = file.endianness();
        let mut spans: Vec<Span> = Vec::new();
        for section in file.sections() {
            if spans.len() >= MAX_SPANS {
                break;
            }
            let Some((foff_u64, fsize_u64)) = section.file_range() else {
                continue;
            };
            let va: u64 = section.address();
            let vsize: u64 = section.size();
            if va == 0 || vsize == 0 || fsize_u64 == 0 {
                continue;
            }
            let Ok(foff) = usize::try_from(foff_u64) else {
                continue;
            };
            let Ok(fsize) = usize::try_from(fsize_u64) else {
                continue;
            };
            if foff
                .checked_add(fsize)
                .is_none_or(|end: usize| end > bytes.len())
            {
                continue;
            }
            spans.push(Span {
                va,
                vsize,
                foff,
                fsize,
                exec: section_is_exec(&section.flags()),
            });
        }
        let mut relocs: BTreeMap<u64, u64> = BTreeMap::new();
        if let Some(iter) = file.dynamic_relocations() {
            for (offset, reloc) in iter {
                if reloc_is_relative(&reloc) {
                    relocs.insert(offset, reloc.addend() as u64);
                }
            }
        }
        let span_index: Vec<(u64, u64, usize)> = index_spans(&spans);
        Ok(Self {
            bytes,
            ptr_size,
            endian,
            spans,
            span_index,
            relocs,
        })
    }

    pub(crate) const fn ptr_size(&self) -> usize {
        self.ptr_size
    }

    pub(crate) fn scan_ranges(&self) -> Vec<(u64, u64)> {
        self.spans
            .iter()
            .filter(|span: &&Span| !span.exec)
            .map(|span: &Span| (span.va, span.vsize))
            .collect()
    }

    fn containing(&self, va: u64) -> Option<&Span> {
        let upper: usize = self
            .span_index
            .partition_point(|entry: &(u64, u64, usize)| entry.0 <= va);
        let lower: usize = upper.saturating_sub(MAX_OVERLAP_WALK);
        for entry in self.span_index[lower..upper].iter().rev() {
            let (start, end, idx): (u64, u64, usize) = *entry;
            if va >= start && va < end {
                return self.spans.get(idx);
            }
        }
        None
    }

    fn va_to_off(&self, va: u64) -> Option<usize> {
        let span: &Span = self.containing(va)?;
        let delta: u64 = va.checked_sub(span.va)?;
        let delta_usize: usize = usize::try_from(delta).ok()?;
        if delta_usize >= span.fsize {
            return None;
        }
        span.foff.checked_add(delta_usize)
    }

    pub(crate) fn slice(&self, va: u64, len: usize) -> Option<&'a [u8]> {
        if len == 0 {
            return Some(&self.bytes[0..0]);
        }
        let span: &Span = self.containing(va)?;
        let delta: usize = usize::try_from(va.checked_sub(span.va)?).ok()?;
        let end: usize = delta.checked_add(len)?;
        if end > span.fsize {
            return None;
        }
        let start: usize = span.foff.checked_add(delta)?;
        let abs_end: usize = span.foff.checked_add(end)?;
        self.bytes.get(start..abs_end)
    }

    fn read_raw(&self, va: u64) -> Option<u64> {
        let off: usize = self.va_to_off(va)?;
        let end: usize = off.checked_add(self.ptr_size)?;
        let raw: &[u8] = self.bytes.get(off..end)?;
        Some(match (self.ptr_size, self.endian) {
            (8, Endianness::Little) => u64::from_le_bytes(raw.try_into().ok()?),
            (8, Endianness::Big) => u64::from_be_bytes(raw.try_into().ok()?),
            (4, Endianness::Little) => u64::from(u32::from_le_bytes(raw.try_into().ok()?)),
            (4, Endianness::Big) => u64::from(u32::from_be_bytes(raw.try_into().ok()?)),
            _ => return None,
        })
    }

    pub(crate) fn read_word(&self, va: u64) -> Option<u64> {
        self.read_raw(va)
    }

    pub(crate) fn read_ptr(&self, slot_va: u64) -> Option<u64> {
        self.relocs
            .get(&slot_va)
            .copied()
            .or_else(|| self.read_raw(slot_va))
    }

    #[cfg(test)]
    pub(crate) fn from_single_span(
        bytes: &'a [u8],
        va: u64,
        ptr_size: usize,
        endian: Endianness,
    ) -> Self {
        let span: Span = Span {
            va,
            vsize: bytes.len() as u64,
            foff: 0,
            fsize: bytes.len(),
            exec: false,
        };
        let span_index: Vec<(u64, u64, usize)> = index_spans(std::slice::from_ref(&span));
        Self {
            bytes,
            ptr_size,
            endian,
            spans: vec![span],
            span_index,
            relocs: BTreeMap::new(),
        }
    }
}

fn fat_slice_ranges(bytes: &[u8]) -> Vec<(u64, u64)> {
    match FileKind::parse(bytes) {
        Ok(FileKind::MachOFat32) => MachOFatFile32::parse(bytes).map_or_else(
            |_| Vec::new(),
            |fat: MachOFatFile32<'_>| {
                fat.arches()
                    .iter()
                    .map(|arch: &FatArch32| arch.file_range())
                    .collect()
            },
        ),
        Ok(FileKind::MachOFat64) => MachOFatFile64::parse(bytes).map_or_else(
            |_| Vec::new(),
            |fat: MachOFatFile64<'_>| {
                fat.arches()
                    .iter()
                    .map(|arch: &FatArch64| arch.file_range())
                    .collect()
            },
        ),
        _ => Vec::new(),
    }
}

const fn section_is_exec(flags: &SectionFlags) -> bool {
    match *flags {
        SectionFlags::Elf { sh_flags } => sh_flags & SHF_EXECINSTR != 0,
        SectionFlags::Coff { characteristics } => characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
        SectionFlags::MachO { flags, .. } => {
            flags & (MACHO_PURE_INSTRUCTIONS | MACHO_SOME_INSTRUCTIONS) != 0
        }
        _ => false,
    }
}

fn reloc_is_relative(reloc: &object::Relocation) -> bool {
    matches!(reloc.flags(), RelocationFlags::Elf { .. })
        && matches!(reloc.target(), RelocationTarget::Absolute)
        && !reloc.has_implicit_addend()
}

fn index_spans(spans: &[Span]) -> Vec<(u64, u64, usize)> {
    let mut index: Vec<(u64, u64, usize)> = spans
        .iter()
        .enumerate()
        .map(|(idx, span): (usize, &Span)| (span.va, span.va.saturating_add(span.vsize), idx))
        .collect();
    index.sort_unstable_by_key(|entry: &(u64, u64, usize)| entry.0);
    index
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn containing_matches_linear_reference_at_scale() {
        let spans: Vec<Span> = (0..2000u64)
            .map(|i: u64| Span {
                va: 0x1000 + i * 0x1000,
                vsize: 0x800,
                foff: 0,
                fsize: 0x800,
                exec: false,
            })
            .collect();
        let span_index: Vec<(u64, u64, usize)> = index_spans(&spans);
        let map: SectionMap<'_> = SectionMap {
            bytes: &[],
            ptr_size: 8,
            endian: Endianness::Little,
            spans,
            span_index,
            relocs: BTreeMap::new(),
        };
        for i in 0..2000u64 {
            let base: u64 = 0x1000 + i * 0x1000;
            for probe in [base, base + 0x400, base + 0x7ff, base + 0x800, base + 0x900] {
                let got: Option<u64> = map.containing(probe).map(|span: &Span| span.va);
                let want: Option<u64> = map
                    .spans
                    .iter()
                    .find(|span: &&Span| {
                        probe >= span.va && probe < span.va.saturating_add(span.vsize)
                    })
                    .map(|span: &Span| span.va);
                assert_eq!(got, want, "containing mismatch at {probe:#x}");
            }
        }
    }

    fn push_shdr64(out: &mut Vec<u8>, spec: &[u64; 10]) {
        out.extend_from_slice(&(spec[0] as u32).to_le_bytes());
        out.extend_from_slice(&(spec[1] as u32).to_le_bytes());
        out.extend_from_slice(&spec[2].to_le_bytes());
        out.extend_from_slice(&spec[3].to_le_bytes());
        out.extend_from_slice(&spec[4].to_le_bytes());
        out.extend_from_slice(&spec[5].to_le_bytes());
        out.extend_from_slice(&(spec[6] as u32).to_le_bytes());
        out.extend_from_slice(&(spec[7] as u32).to_le_bytes());
        out.extend_from_slice(&spec[8].to_le_bytes());
        out.extend_from_slice(&spec[9].to_le_bytes());
    }

    fn many_section_elf(section_count: usize) -> Vec<u8> {
        let mut out: Vec<u8> = vec![0u8; 64];
        let data_off: usize = out.len();
        out.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let shstr: &[u8] = b"\0.d\0.shstrtab\0";
        let shstr_off: usize = out.len();
        out.extend_from_slice(shstr);
        while !out.len().is_multiple_of(8) {
            out.push(0);
        }
        let shoff: usize = out.len();

        push_shdr64(&mut out, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        for i in 0..section_count {
            let addr: u64 = 0x1000 + (i as u64) * 0x100;
            push_shdr64(&mut out, &[1, 1, 2, addr, data_off as u64, 8, 0, 0, 1, 0]);
        }
        push_shdr64(
            &mut out,
            &[4, 3, 0, 0, shstr_off as u64, shstr.len() as u64, 0, 0, 1, 0],
        );

        let shnum: u16 = (section_count + 2) as u16;
        let shstrndx: u16 = (section_count + 1) as u16;
        let header: &mut [u8] = &mut out[..64];
        header[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        header[4] = 2;
        header[5] = 1;
        header[6] = 1;
        header[16..18].copy_from_slice(&2u16.to_le_bytes());
        header[18..20].copy_from_slice(&62u16.to_le_bytes());
        header[20..24].copy_from_slice(&1u32.to_le_bytes());
        header[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
        header[52..54].copy_from_slice(&64u16.to_le_bytes());
        header[58..60].copy_from_slice(&64u16.to_le_bytes());
        header[60..62].copy_from_slice(&shnum.to_le_bytes());
        header[62..64].copy_from_slice(&shstrndx.to_le_bytes());
        out
    }

    #[test]
    fn words_are_read_in_the_endianness_the_image_declares() {
        let raw: [u8; 8] = 0x0102_0304_0506_0708u64.to_be_bytes();
        let big: SectionMap<'_> = SectionMap::from_single_span(&raw, 0x1000, 8, Endianness::Big);
        assert_eq!(big.read_word(0x1000), Some(0x0102_0304_0506_0708));
        assert_eq!(big.read_ptr(0x1000), Some(0x0102_0304_0506_0708));
        let little: SectionMap<'_> =
            SectionMap::from_single_span(&raw, 0x1000, 8, Endianness::Little);
        assert_eq!(
            little.read_word(0x1000),
            Some(0x0807_0605_0403_0201),
            "reading a big-endian image little-endian yields a byte-swapped address that resolves \
             to nothing, which is why the endianness must come from the header"
        );
        let big32: SectionMap<'_> = SectionMap::from_single_span(&raw, 0x1000, 4, Endianness::Big);
        assert_eq!(big32.read_word(0x1000), Some(0x0102_0304));
        let little32: SectionMap<'_> =
            SectionMap::from_single_span(&raw, 0x1000, 4, Endianness::Little);
        assert_eq!(little32.read_word(0x1000), Some(0x0403_0201));
    }

    #[test]
    fn a_thin_image_yields_exactly_one_slice() {
        let bytes: Vec<u8> = many_section_elf(4);
        let maps: Vec<SectionMap<'_>> = SectionMap::build_slices(&bytes).unwrap();
        assert_eq!(maps.len(), 1);
        assert_eq!(maps[0].endian, Endianness::Little);
    }

    fn fat32(entries: &[(u32, u32)], body_len: usize) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&0xcafe_babeu32.to_be_bytes());
        out.extend_from_slice(&u32::try_from(entries.len()).unwrap().to_be_bytes());
        for (offset, size) in entries {
            out.extend_from_slice(&0x0100_0007u32.to_be_bytes());
            out.extend_from_slice(&3u32.to_be_bytes());
            out.extend_from_slice(&offset.to_be_bytes());
            out.extend_from_slice(&size.to_be_bytes());
            out.extend_from_slice(&14u32.to_be_bytes());
        }
        out.resize(out.len() + body_len, 0x41);
        out
    }

    #[test]
    fn a_universal_header_pointing_outside_the_file_is_refused_without_panic() {
        for entries in [
            [(0xFFFF_FF00u32, 0x1000u32)].as_slice(),
            [(0x10u32, 0xFFFF_FF00u32)].as_slice(),
            [(0x28u32, 0u32), (0xFFFF_FFFFu32, 0xFFFF_FFFFu32)].as_slice(),
        ] {
            let bytes: Vec<u8> = fat32(entries, 512);
            let err: Error = SectionMap::build_slices(&bytes).expect_err("must refuse");
            assert!(matches!(err, Error::NativeParse(_)), "got {err:?}");
        }
    }

    #[test]
    fn a_universal_arch_count_past_the_file_falls_back_to_a_thin_parse() {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&0xcafe_babeu32.to_be_bytes());
        bytes.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        bytes.resize(256, 0);
        assert!(fat_slice_ranges(&bytes).is_empty());
        let err: Error = SectionMap::build_slices(&bytes).expect_err("must refuse");
        assert!(matches!(err, Error::NativeParse(_)), "got {err:?}");
    }

    #[test]
    fn build_caps_span_count() {
        let bytes: Vec<u8> = many_section_elf(MAX_SPANS + 200);
        let map: SectionMap<'_> = SectionMap::build(&bytes).unwrap();
        assert_eq!(
            map.spans.len(),
            MAX_SPANS,
            "section count must be clamped to MAX_SPANS"
        );
        assert_eq!(
            map.slice(0x1000, 8),
            Some(&[1u8, 2, 3, 4, 5, 6, 7, 8][..]),
            "a retained early section must still resolve after the cap"
        );
    }
}
