use std::collections::BTreeSet;

use object::Endianness as ObjEndianness;
use object::Object as _;
use object::ObjectSection as _;
use object::ObjectSymbol as _;
use object::read::{File as ObjFile, FileKind};

use crate::debug::{dbg_kv, dbg_line, dbg_section};
use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageKind {
    Pe,
    Elf,
    MachO,
}

#[derive(Debug, Clone)]
pub struct Section<'a> {
    pub name: String,
    pub address: u64,
    pub data: &'a [u8],
    pub mapped_len: u64,
}

#[derive(Debug, Clone)]
pub struct GoImage<'a> {
    pub kind: ImageKind,
    pub endian: Endian,
    pub ptr_size: u8,
    pub sections: Vec<Section<'a>>,
    pub raw: &'a [u8],
    pub symbol_addrs: Vec<(String, u64, u64)>,
    pub flat: bool,
}

const FLAT_IMAGE_BASE: u64 = 0x1000;
const GO_RUNTIME_MARKERS: [&[u8]; 4] = [
    b"runtime.morestack",
    b"\xff Go buildinf:",
    b"runtime.firstmoduledata",
    b"runtime.pclntab",
];
impl<'a> GoImage<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < 64 {
            return Err(Error::InputTooSmall(bytes.len()));
        }
        let Ok(kind_raw): core::result::Result<FileKind, _> = FileKind::parse(bytes) else {
            return Self::parse_flat(bytes);
        };
        let kind: ImageKind = match kind_raw {
            FileKind::Pe32 | FileKind::Pe64 => ImageKind::Pe,
            FileKind::Elf32 | FileKind::Elf64 => ImageKind::Elf,
            FileKind::MachO32 | FileKind::MachO64 => ImageKind::MachO,
            _ => return Self::parse_flat(bytes),
        };
        let file: ObjFile<'a, &'a [u8]> =
            ObjFile::parse(bytes).map_err(|e| Error::ContainerParse(e.to_string()))?;
        let endian: Endian = match file.endianness() {
            ObjEndianness::Little => Endian::Little,
            ObjEndianness::Big => Endian::Big,
        };
        let ptr_size: u8 = if file.is_64() { 8 } else { 4 };
        let mut sections: Vec<Section<'a>> = Vec::new();
        for sec in file.sections() {
            let name: String = sec.name().unwrap_or("").to_owned();
            let data: &'a [u8] = sec.data().unwrap_or(b"");
            let mapped_len: u64 = section_mapped_len(kind, data, sec.size(), sec.align())
                .ok_or_else(|| Error::ContainerParse("invalid mapped section span".to_owned()))?;
            sections.push(Section {
                name,
                address: sec.address(),
                data,
                mapped_len,
            });
        }
        let mut symbol_addrs: Vec<(String, u64, u64)> = Vec::new();
        for sym in file.symbols() {
            let raw_name: &str = sym.name().unwrap_or("");
            if raw_name.is_empty() {
                continue;
            }
            let name: String = normalize_symbol_name(kind, raw_name);
            symbol_addrs.push((name, sym.address(), sym.size()));
        }
        Ok(Self {
            kind,
            endian,
            ptr_size,
            sections,
            raw: bytes,
            symbol_addrs,
            flat: false,
        })
    }

    fn parse_flat(bytes: &'a [u8]) -> Result<Self> {
        dbg_section("go.flat-image");
        dbg_line(|| "no container header (MZ/PE/ELF/MachO): trying headerless go image".to_owned());
        let provisional: Self = Self::flat_with_base(bytes, FLAT_IMAGE_BASE, 8)?;
        let located_off: Option<(usize, u8)> = locate_flat_pclntab_offset(&provisional);
        let (pclntab_off, ptr_size): (Option<usize>, u8) = if let Some((off, ps)) = located_off {
            dbg_line(|| format!("flat pclntab at file-offset {off:#x} ptr_size={ps}"));
            (Some(off), ps)
        } else {
            let hits: usize = marker_hits(bytes);
            dbg_kv("flat_marker_hits", || hits.to_string());
            if hits < 2 {
                dbg_line(|| {
                    "no pclntab and <2 go runtime markers: not a headerless go image".to_owned()
                });
                return Err(Error::UnrecognizedContainer);
            }
            (None, 8)
        };
        let address: u64 = pclntab_off
            .filter(|_| ptr_size == 8)
            .and_then(|off: usize| infer_flat_base(bytes, off))
            .unwrap_or(FLAT_IMAGE_BASE);
        dbg_kv("flat_base", || format!("{address:#x}"));
        Self::flat_with_base(bytes, address, ptr_size)
    }

    fn flat_with_base(bytes: &'a [u8], address: u64, ptr_size: u8) -> Result<Self> {
        let mapped_len: u64 = u64::try_from(bytes.len()).map_err(|_| {
            Error::ContainerParse("flat image exceeds virtual address range".to_owned())
        })?;
        let section: Section<'a> = Section {
            name: ".rdata".to_owned(),
            address,
            data: bytes,
            mapped_len,
        };
        Ok(Self {
            kind: ImageKind::Pe,
            endian: Endian::Little,
            ptr_size,
            sections: vec![section],
            raw: bytes,
            symbol_addrs: Vec::new(),
            flat: true,
        })
    }

    #[must_use]
    pub fn section_by_name(&self, candidates: &[&str]) -> Option<&Section<'a>> {
        for cand in candidates {
            for sec in &self.sections {
                if sec.name == *cand {
                    return Some(sec);
                }
            }
        }
        None
    }

    #[must_use]
    pub fn text_section_base(&self) -> Option<u64> {
        self.section_by_name(&[".text", "__text"])
            .map(|s: &Section<'a>| s.address)
            .filter(|addr: &u64| *addr != 0)
    }

    #[must_use]
    pub fn data_at_va(&self, va: u64, len: usize) -> Option<&'a [u8]> {
        for sec in &self.sections {
            let end: u64 = sec.address.checked_add(sec.data.len() as u64)?;
            if va >= sec.address && va < end {
                let off: usize = usize::try_from(va - sec.address).ok()?;
                if off.checked_add(len)? <= sec.data.len() {
                    return Some(&sec.data[off..off + len]);
                }
            }
        }
        None
    }

    #[must_use]
    pub fn remaining_at_va(&self, va: u64, required: usize) -> Option<usize> {
        let mut current: Option<&Section<'a>> = None;
        for sec in &self.sections {
            let end: u64 = section_end(sec)?;
            if va >= sec.address && va < end {
                if current.is_some() {
                    return None;
                }
                current = Some(sec);
            }
        }
        let mut current: &Section<'a> = current?;
        let mut current_start: u64 = current.address;
        let mut current_end: u64 = section_end(current)?;
        let offset: usize = usize::try_from(va.checked_sub(current_start)?).ok()?;
        let current_len: usize = usize::try_from(current.mapped_len).ok()?;
        let mut available: usize = current_len.checked_sub(offset)?;
        loop {
            for sec in &self.sections {
                if std::ptr::eq(sec, current) || sec.mapped_len == 0 {
                    continue;
                }
                let end: u64 = section_end(sec)?;
                if sec.address < current_end && end > current_start {
                    return None;
                }
            }
            if available >= required {
                return Some(available);
            }
            let mut next: Option<&Section<'a>> = None;
            for sec in &self.sections {
                if sec.address != current_end || sec.mapped_len == 0 {
                    continue;
                }
                if next.is_some() {
                    return None;
                }
                next = Some(sec);
            }
            let Some(next_section): Option<&Section<'a>> = next else {
                return Some(available);
            };
            let next_len: usize = usize::try_from(next_section.mapped_len).ok()?;
            available = available.checked_add(next_len)?;
            current = next_section;
            current_start = current.address;
            current_end = section_end(current)?;
        }
    }

    #[must_use]
    pub fn read_u32(&self, va: u64) -> Option<u32> {
        let arr: [u8; 4] = self.mapped_array_at_va(va)?;
        Some(match self.endian {
            Endian::Little => u32::from_le_bytes(arr),
            Endian::Big => u32::from_be_bytes(arr),
        })
    }

    #[must_use]
    pub fn read_u64(&self, va: u64) -> Option<u64> {
        let arr: [u8; 8] = self.mapped_array_at_va(va)?;
        Some(match self.endian {
            Endian::Little => u64::from_le_bytes(arr),
            Endian::Big => u64::from_be_bytes(arr),
        })
    }

    pub fn read_ptr(&self, va: u64) -> Option<u64> {
        match self.ptr_size {
            4 => self.read_u32(va).map(u64::from),
            8 => self.read_u64(va),
            _ => None,
        }
    }

    fn mapped_array_at_va<const N: usize>(&self, va: u64) -> Option<[u8; N]> {
        let mut bytes: [u8; N] = [0; N];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let offset: u64 = u64::try_from(index).ok()?;
            let byte_va: u64 = va.checked_add(offset)?;
            *byte = self.mapped_byte_at_va(byte_va)?;
        }
        Some(bytes)
    }

    fn mapped_byte_at_va(&self, va: u64) -> Option<u8> {
        let mut value: Option<u8> = None;
        for sec in &self.sections {
            let end: u64 = section_end(sec)?;
            if va < sec.address || va >= end {
                continue;
            }
            if value.is_some() {
                return None;
            }
            let offset: usize = usize::try_from(va.checked_sub(sec.address)?).ok()?;
            value = Some(sec.data.get(offset).copied().map_or(0, |byte: u8| byte));
        }
        value
    }
}

const fn section_end(section: &Section<'_>) -> Option<u64> {
    section.address.checked_add(section.mapped_len)
}

fn section_mapped_len(kind: ImageKind, data: &[u8], virtual_len: u64, align: u64) -> Option<u64> {
    let data_len: u64 = u64::try_from(data.len()).ok()?;
    let size: u64 = data_len.max(virtual_len);
    if kind != ImageKind::Pe || align == 0 {
        return Some(size);
    }
    let remainder: u64 = size % align;
    if remainder == 0 {
        return Some(size);
    }
    size.checked_add(align.checked_sub(remainder)?)
}

fn normalize_symbol_name(kind: ImageKind, raw: &str) -> String {
    if kind == ImageKind::MachO
        && let Some(rest) = raw.strip_prefix('_')
        && (rest.contains('.') || rest.contains('/'))
    {
        return rest.to_owned();
    }
    raw.to_owned()
}

fn locate_flat_pclntab_offset(provisional: &GoImage<'_>) -> Option<(usize, u8)> {
    let located: crate::pclntab::LocatedPclntab<'_> =
        crate::pclntab::locate_pclntab(provisional).ok()?;
    let base: u64 = provisional
        .sections
        .first()
        .map(|s: &Section<'_>| s.address)?;
    let off: usize = usize::try_from(located.header.section_addr.checked_sub(base)?).ok()?;
    Some((off, located.header.ptr_size))
}

const FLAT_PAGE_MASK: u64 = 0xfff;
const FLAT_MIN_BASE: u64 = 0x1_0000;
const FLAT_MAX_BASE: u64 = 1 << 48;
const FLAT_MAX_BASE_CANDIDATES: usize = 64;

const MD_WORD_FTAB_PTR: usize = 1;
const MD_WORD_TEXT: usize = 22;
const MD_WORD_ETEXT: usize = 23;
const MD_WORD_TYPES: usize = 37;
const MD_WORD_ETYPES: usize = 38;

fn infer_flat_base(bytes: &[u8], pclntab_off: usize) -> Option<u64> {
    let span: u64 = bytes.len() as u64;
    let pclntab_off_u64: u64 = pclntab_off as u64;
    let mut candidates: BTreeSet<u64> = BTreeSet::new();
    let mut moduledata_exact: BTreeSet<u64> = BTreeSet::new();
    let mut off: usize = 0;
    while off + 8 <= bytes.len() {
        let value: u64 = read_u64_le(bytes, off);
        if let Some(base) = value.checked_sub(pclntab_off_u64)
            && (FLAT_MIN_BASE..FLAT_MAX_BASE).contains(&base)
            && base & FLAT_PAGE_MASK == 0
            && value < base.saturating_add(span)
        {
            if candidates.len() < FLAT_MAX_BASE_CANDIDATES {
                candidates.insert(base);
            }
            if moduledata_exact.len() < FLAT_MAX_BASE_CANDIDATES
                && moduledata_is_consistent(bytes, off, base, span)
            {
                moduledata_exact.insert(base);
            }
        }
        off += 8;
    }
    dbg_kv("flat_base_candidates", || candidates.len().to_string());
    dbg_kv("flat_base_moduledata_exact", || {
        moduledata_exact.len().to_string()
    });
    if moduledata_exact.len() == 1 {
        dbg_line(|| "base inferred from a single moduledata-consistent slot".to_owned());
        return moduledata_exact.into_iter().next();
    }
    if !moduledata_exact.is_empty() {
        dbg_line(|| "base inferred from the densest moduledata-consistent candidate".to_owned());
        return moduledata_exact
            .into_iter()
            .max_by_key(|&base: &u64| flat_pointer_density(bytes, base, span));
    }
    if candidates.len() == 1 {
        dbg_line(|| "base inferred from a single pclntab-pointer candidate".to_owned());
        return candidates.into_iter().next();
    }
    dbg_line(|| "base inferred from the densest pclntab-pointer candidate".to_owned());
    candidates
        .into_iter()
        .max_by_key(|&base: &u64| flat_pointer_density(bytes, base, span))
}

fn moduledata_is_consistent(bytes: &[u8], md_off: usize, base: u64, span: u64) -> bool {
    let hi: u64 = base.saturating_add(span);
    let word = |index: usize| -> Option<u64> {
        let at: usize = md_off + index * 8;
        (at + 8 <= bytes.len()).then(|| read_u64_le(bytes, at))
    };
    let in_image = |va: u64| -> bool { base <= va && va < hi };
    let Some(ftab_ptr): Option<u64> = word(MD_WORD_FTAB_PTR) else {
        return false;
    };
    let Some(text_va): Option<u64> = word(MD_WORD_TEXT) else {
        return false;
    };
    let Some(etext_va): Option<u64> = word(MD_WORD_ETEXT) else {
        return false;
    };
    let Some(types_va): Option<u64> = word(MD_WORD_TYPES) else {
        return false;
    };
    let Some(etypes_va): Option<u64> = word(MD_WORD_ETYPES) else {
        return false;
    };
    in_image(ftab_ptr)
        && in_image(text_va)
        && text_va < etext_va
        && etext_va <= hi
        && in_image(types_va)
        && types_va < etypes_va
        && etypes_va <= hi
}

fn flat_pointer_density(bytes: &[u8], base: u64, span: u64) -> usize {
    let hi: u64 = base.saturating_add(span);
    let mut resolvable: usize = 0;
    let mut off: usize = 0;
    while off + 8 <= bytes.len() {
        let value: u64 = read_u64_le(bytes, off);
        if value >= base && value < hi {
            resolvable += 1;
        }
        off += 8;
    }
    resolvable
}

#[inline]
fn read_u64_le(bytes: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        bytes[off],
        bytes[off + 1],
        bytes[off + 2],
        bytes[off + 3],
        bytes[off + 4],
        bytes[off + 5],
        bytes[off + 6],
        bytes[off + 7],
    ])
}

fn marker_hits(bytes: &[u8]) -> usize {
    GO_RUNTIME_MARKERS
        .iter()
        .filter(|needle: &&&[u8]| {
            let needle: &[u8] = needle;
            bytes.len() >= needle.len() && bytes.windows(needle.len()).any(|w: &[u8]| w == needle)
        })
        .count()
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{FLAT_MIN_BASE, infer_flat_base};

    #[test]
    fn infer_flat_base_bounds_distinct_candidate_explosion() {
        let pclntab_off: usize = 0x10;
        let slot_count: usize = 200_000;
        let mut bytes: Vec<u8> = Vec::with_capacity(slot_count * 8);
        for i in 0..slot_count as u64 {
            let base: u64 = FLAT_MIN_BASE + i * 0x1000;
            let value: u64 = base + pclntab_off as u64;
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        let start: Instant = Instant::now();
        let inferred: Option<u64> = infer_flat_base(&bytes, pclntab_off);
        let elapsed: Duration = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(5),
            "infer_flat_base must stay bounded under a distinct-base explosion, took {elapsed:?}"
        );
        assert!(
            inferred.is_none_or(|b: u64| (b - FLAT_MIN_BASE).is_multiple_of(0x1000)),
            "an inferred base must be one of the page-aligned candidates"
        );
    }
}
