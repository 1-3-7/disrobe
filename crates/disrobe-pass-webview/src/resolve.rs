use std::collections::BTreeMap;

use object::read::{File as ObjFile, Object, ObjectSection};
use object::{RelocationFlags, RelocationTarget, SectionFlags};

use crate::error::{Error, Result};

const SHF_EXECINSTR: u64 = 0x4;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const MACHO_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const MACHO_SOME_INSTRUCTIONS: u32 = 0x0000_0400;

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
    spans: Vec<Span>,
    relocs: BTreeMap<u64, u64>,
}

impl<'a> SectionMap<'a> {
    pub(crate) fn build(bytes: &'a [u8]) -> Result<Self> {
        let file: ObjFile<'a, &'a [u8]> =
            ObjFile::parse(bytes).map_err(|e| Error::NativeParse(e.to_string()))?;
        let ptr_size: usize = if file.is_64() { 8 } else { 4 };
        let mut spans: Vec<Span> = Vec::new();
        for section in file.sections() {
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
        Ok(Self {
            bytes,
            ptr_size,
            spans,
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
        self.spans
            .iter()
            .find(|span: &&Span| va >= span.va && va < span.va.saturating_add(span.vsize))
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
        Some(match self.ptr_size {
            8 => u64::from_le_bytes(raw.try_into().ok()?),
            4 => u64::from(u32::from_le_bytes(raw.try_into().ok()?)),
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
