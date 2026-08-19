use object::Architecture;
use object::Endianness as ObjEndianness;
use object::Object as _;
use object::ObjectSection as _;
use object::ObjectSymbol as _;
use object::read::{File as ObjFile, FileKind};

#[cfg(test)]
use crate::debug::{dbg_kv, dbg_line};
use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Endian {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ImageKind {
    Pe,
    Elf,
    MachO,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CallArchitecture {
    X86,
    X86_64,
    Arm64,
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
    pub(crate) kind: ImageKind,
    pub(crate) endian: Endian,
    pub(crate) ptr_size: u8,
    pub(crate) sections: Vec<Section<'a>>,
    pub(crate) raw: &'a [u8],
    pub(crate) symbol_addrs: Vec<(String, u64, u64)>,
    pub(crate) flat: bool,
}

const GO_RUNTIME_MARKERS: [&[u8]; 4] = [
    b"runtime.morestack",
    b"\xff Go buildinf:",
    b"runtime.firstmoduledata",
    b"runtime.pclntab",
];

impl<'a> GoImage<'a> {
    #[must_use]
    pub const fn kind(&self) -> ImageKind {
        self.kind
    }

    #[must_use]
    pub const fn endian(&self) -> Endian {
        self.endian
    }

    #[must_use]
    pub const fn ptr_size(&self) -> u8 {
        self.ptr_size
    }

    #[must_use]
    pub fn sections(&self) -> &[Section<'a>] {
        &self.sections
    }

    #[must_use]
    pub const fn raw(&self) -> &'a [u8] {
        self.raw
    }

    #[must_use]
    pub fn symbol_addrs(&self) -> &[(String, u64, u64)] {
        &self.symbol_addrs
    }

    #[must_use]
    pub const fn is_flat(&self) -> bool {
        self.flat
    }

    #[must_use]
    pub(crate) fn call_architecture(&self) -> Option<CallArchitecture> {
        let file: ObjFile<'_, &'_ [u8]> = ObjFile::parse(self.raw).ok()?;
        match file.architecture() {
            Architecture::I386 => Some(CallArchitecture::X86),
            Architecture::X86_64 => Some(CallArchitecture::X86_64),
            Architecture::Aarch64 => Some(CallArchitecture::Arm64),
            _ => None,
        }
    }

    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < 64 {
            return Err(Error::InputTooSmall(bytes.len()));
        }
        let Ok(kind_raw): core::result::Result<FileKind, _> = FileKind::parse(bytes) else {
            return Err(headerless_container_error(bytes));
        };
        let kind: ImageKind = match kind_raw {
            FileKind::Pe32 | FileKind::Pe64 => ImageKind::Pe,
            FileKind::Elf32 | FileKind::Elf64 => ImageKind::Elf,
            FileKind::MachO32 | FileKind::MachO64 => ImageKind::MachO,
            _ => return Err(headerless_container_error(bytes)),
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
            let data: &'a [u8] = sec
                .data()
                .map_err(|error| Error::ContainerParse(format!("section {name} data: {error}")))?;
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

fn headerless_container_error(bytes: &[u8]) -> Error {
    if go_runtime_marker_count(bytes) >= 2 {
        Error::HeaderlessEpochUnproven
    } else {
        Error::UnrecognizedContainer
    }
}

fn go_runtime_marker_count(bytes: &[u8]) -> usize {
    GO_RUNTIME_MARKERS
        .iter()
        .filter(|needle: &&&[u8]| {
            let needle: &[u8] = needle;
            bytes.len() >= needle.len() && bytes.windows(needle.len()).any(|w: &[u8]| w == needle)
        })
        .count()
}

#[cfg(test)]
const FLAT_PAGE_MASK: u64 = 0xfff;
#[cfg(test)]
const FLAT_MIN_BASE: u64 = 0x1_0000;
#[cfg(test)]
const FLAT_MAX_BASE: u64 = 1 << 48;
#[cfg(test)]
const FLAT_32_ADDRESS_LIMIT: u64 = 1 << 32;

#[cfg(test)]
const MD_WORD_FUNCNAMETAB_PTR: usize = 1;
#[cfg(test)]
const MD_WORD_FUNCNAMETAB_LEN: usize = 2;
#[cfg(test)]
const MD_WORD_FUNCNAMETAB_CAP: usize = 3;
#[cfg(test)]
const MD_WORD_PCLNTABLE_PTR: usize = 13;
#[cfg(test)]
const MD_WORD_PCLNTABLE_LEN: usize = 14;
#[cfg(test)]
const MD_WORD_PCLNTABLE_CAP: usize = 15;
#[cfg(test)]
const MD_WORD_FTAB_PTR: usize = 16;
#[cfg(test)]
const MD_WORD_FTAB_LEN: usize = 17;
#[cfg(test)]
const MD_WORD_FTAB_CAP: usize = 18;
#[cfg(test)]
const MD_WORD_MIN_PC: usize = 20;
#[cfg(test)]
const MD_WORD_MAX_PC: usize = 21;
#[cfg(test)]
const MD_WORD_TEXT: usize = 22;
#[cfg(test)]
const MD_WORD_ETEXT: usize = 23;

#[cfg(test)]
fn infer_flat_base(
    bytes: &[u8],
    pclntab_off: usize,
    header: &crate::pclntab::PclntabHeader,
) -> Option<u64> {
    if header.version == crate::pclntab::PclntabVersion::Go12 || header.endian != Endian::Little {
        return None;
    }
    let ptr_size: u8 = header.ptr_size;
    let step: usize = match ptr_size {
        4 => 4,
        8 => 8,
        _ => return None,
    };
    let address_limit: u64 = if ptr_size == 4 {
        FLAT_32_ADDRESS_LIMIT
    } else {
        FLAT_MAX_BASE
    };
    let span: u64 = u64::try_from(bytes.len()).ok()?;
    let pclntab_off_u64: u64 = u64::try_from(pclntab_off).ok()?;
    let mut moduledata_base: Option<u64> = None;
    let mut moduledata_ambiguous: bool = false;
    let mut off: usize = 0;
    while off
        .checked_add(step)
        .is_some_and(|end: usize| end <= bytes.len())
    {
        let value: u64 = read_flat_word(bytes, off, ptr_size)?;
        if let Some(base) = value.checked_sub(pclntab_off_u64)
            && (FLAT_MIN_BASE..address_limit).contains(&base)
            && base & FLAT_PAGE_MASK == 0
            && let Some(end) = base.checked_add(span)
            && end <= address_limit
            && value < end
            && moduledata_is_consistent(bytes, off, base, span, pclntab_off_u64, header)
        {
            match moduledata_base {
                None => moduledata_base = Some(base),
                Some(previous) if previous != base => moduledata_ambiguous = true,
                Some(_) => {}
            }
        }
        off = off.checked_add(step)?;
    }
    dbg_kv("flat_base_moduledata_exact", || {
        match (moduledata_base, moduledata_ambiguous) {
            (_, true) => "ambiguous".to_owned(),
            (Some(_), false) => "1".to_owned(),
            (None, false) => "0".to_owned(),
        }
    });
    if moduledata_ambiguous {
        dbg_line(|| "flat base inference rejected ambiguous moduledata candidates".to_owned());
        return None;
    }
    if let Some(base) = moduledata_base {
        dbg_line(|| "base inferred from a single moduledata-consistent slot".to_owned());
        return Some(base);
    }
    dbg_line(|| "flat base inference found no validated moduledata slot".to_owned());
    None
}

#[cfg(test)]
fn moduledata_is_consistent(
    bytes: &[u8],
    md_off: usize,
    base: u64,
    span: u64,
    pclntab_off: u64,
    header: &crate::pclntab::PclntabHeader,
) -> bool {
    let Some(hi): Option<u64> = base.checked_add(span) else {
        return false;
    };
    let ptr_size: u8 = header.ptr_size;
    let step: usize = usize::from(ptr_size);
    let word = |index: usize| -> Option<u64> {
        let delta: usize = index.checked_mul(step)?;
        let at: usize = md_off.checked_add(delta)?;
        read_flat_word(bytes, at, ptr_size)
    };
    let in_image = |va: u64| -> bool { base <= va && va < hi };
    let Some(expected_pclntab): Option<u64> = base.checked_add(pclntab_off) else {
        return false;
    };
    if word(0) != Some(expected_pclntab) {
        return false;
    }
    let Some(funcnametab_ptr): Option<u64> = word(MD_WORD_FUNCNAMETAB_PTR) else {
        return false;
    };
    let Some(funcnametab_len): Option<u64> = word(MD_WORD_FUNCNAMETAB_LEN) else {
        return false;
    };
    let Some(funcnametab_cap): Option<u64> = word(MD_WORD_FUNCNAMETAB_CAP) else {
        return false;
    };
    let Some(pclntable_ptr): Option<u64> = word(MD_WORD_PCLNTABLE_PTR) else {
        return false;
    };
    let Some(pclntable_len): Option<u64> = word(MD_WORD_PCLNTABLE_LEN) else {
        return false;
    };
    let Some(pclntable_cap): Option<u64> = word(MD_WORD_PCLNTABLE_CAP) else {
        return false;
    };
    let Some(ftab_ptr): Option<u64> = word(MD_WORD_FTAB_PTR) else {
        return false;
    };
    let Some(ftab_len): Option<u64> = word(MD_WORD_FTAB_LEN) else {
        return false;
    };
    let Some(ftab_cap): Option<u64> = word(MD_WORD_FTAB_CAP) else {
        return false;
    };
    let Some(min_pc): Option<u64> = word(MD_WORD_MIN_PC) else {
        return false;
    };
    let Some(max_pc): Option<u64> = word(MD_WORD_MAX_PC) else {
        return false;
    };
    let Some(text_va): Option<u64> = word(MD_WORD_TEXT) else {
        return false;
    };
    let Some(etext_va): Option<u64> = word(MD_WORD_ETEXT) else {
        return false;
    };
    let Some(ftab_expected_len): Option<u64> = header.n_funcs.checked_add(1) else {
        return false;
    };
    let Some(ftab_entry_size): Option<u64> = (match header.version {
        crate::pclntab::PclntabVersion::Go116 => u64::from(ptr_size).checked_mul(2),
        crate::pclntab::PclntabVersion::Go118 | crate::pclntab::PclntabVersion::Go120 => Some(8),
        crate::pclntab::PclntabVersion::Go12 => None,
    }) else {
        return false;
    };
    flat_slice_is_consistent(
        funcnametab_ptr,
        funcnametab_len,
        funcnametab_cap,
        1,
        base,
        hi,
    ) && flat_slice_is_consistent(pclntable_ptr, pclntable_len, pclntable_cap, 1, base, hi)
        && ftab_len == ftab_expected_len
        && flat_slice_is_consistent(ftab_ptr, ftab_len, ftab_cap, ftab_entry_size, base, hi)
        && in_image(expected_pclntab)
        && in_image(text_va)
        && text_va <= min_pc
        && min_pc < max_pc
        && max_pc <= etext_va
        && text_va < etext_va
        && etext_va <= hi
        && (header.text_start == 0 || header.text_start == text_va)
}

#[cfg(test)]
const fn flat_slice_is_consistent(
    ptr: u64,
    len: u64,
    cap: u64,
    elem_size: u64,
    base: u64,
    hi: u64,
) -> bool {
    if len > cap || elem_size == 0 {
        return false;
    }
    if cap == 0 {
        return len == 0;
    }
    let Some(span): Option<u64> = cap.checked_mul(elem_size) else {
        return false;
    };
    let Some(end): Option<u64> = ptr.checked_add(span) else {
        return false;
    };
    base <= ptr && ptr < hi && end <= hi
}

#[cfg(test)]
fn read_flat_word(bytes: &[u8], off: usize, ptr_size: u8) -> Option<u64> {
    match ptr_size {
        4 => crate::pclntab::read_u32(bytes, off, Endian::Little)
            .ok()
            .map(u64::from),
        8 => crate::pclntab::read_u64(bytes, off, Endian::Little).ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{
        Endian, FLAT_MIN_BASE, MD_WORD_ETEXT, MD_WORD_FTAB_CAP, MD_WORD_FTAB_LEN, MD_WORD_FTAB_PTR,
        MD_WORD_FUNCNAMETAB_CAP, MD_WORD_FUNCNAMETAB_LEN, MD_WORD_FUNCNAMETAB_PTR, MD_WORD_MAX_PC,
        MD_WORD_MIN_PC, MD_WORD_PCLNTABLE_CAP, MD_WORD_PCLNTABLE_LEN, MD_WORD_PCLNTABLE_PTR,
        MD_WORD_TEXT, infer_flat_base, moduledata_is_consistent,
    };
    use crate::pclntab::{PclntabHeader, PclntabVersion};

    fn set_moduledata_word(bytes: &mut [u8], index: usize, value: u64) {
        let start: usize = index * 8;
        let end: usize = start + 8;
        bytes[start..end].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn go116_64bit_ftab_span_uses_pointer_width() {
        let base: u64 = 0x1_0000;
        let pclntab_off: u64 = 0x100;
        let span: u64 = 0x200;
        let mut bytes: Vec<u8> = vec![0; 0x200];
        let hi: u64 = base + span;
        set_moduledata_word(&mut bytes, 0, base + pclntab_off);
        set_moduledata_word(&mut bytes, MD_WORD_FUNCNAMETAB_PTR, base + 0x100);
        set_moduledata_word(&mut bytes, MD_WORD_FUNCNAMETAB_LEN, 1);
        set_moduledata_word(&mut bytes, MD_WORD_FUNCNAMETAB_CAP, 1);
        set_moduledata_word(&mut bytes, MD_WORD_PCLNTABLE_PTR, base + 0x100);
        set_moduledata_word(&mut bytes, MD_WORD_PCLNTABLE_LEN, 1);
        set_moduledata_word(&mut bytes, MD_WORD_PCLNTABLE_CAP, 1);
        set_moduledata_word(&mut bytes, MD_WORD_FTAB_PTR, hi - 24);
        set_moduledata_word(&mut bytes, MD_WORD_FTAB_LEN, 2);
        set_moduledata_word(&mut bytes, MD_WORD_FTAB_CAP, 2);
        set_moduledata_word(&mut bytes, MD_WORD_MIN_PC, base + 0x10);
        set_moduledata_word(&mut bytes, MD_WORD_MAX_PC, base + 0x20);
        set_moduledata_word(&mut bytes, MD_WORD_TEXT, base + 0x10);
        set_moduledata_word(&mut bytes, MD_WORD_ETEXT, base + 0x30);
        let header: PclntabHeader = PclntabHeader {
            version: PclntabVersion::Go116,
            quantum: 1,
            ptr_size: 8,
            endian: Endian::Little,
            n_funcs: 1,
            n_files: 0,
            text_start: 0,
            funcname_off: 0,
            cu_off: 0,
            filetab_off: 0,
            pctab_off: 0,
            funcdata_off: 0,
            section_addr: 0,
            section_len: bytes.len(),
        };

        assert!(!moduledata_is_consistent(
            &bytes,
            0,
            base,
            span,
            pclntab_off,
            &header,
        ));
    }

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
        let header: PclntabHeader = PclntabHeader {
            version: PclntabVersion::Go120,
            quantum: 1,
            ptr_size: 8,
            endian: Endian::Little,
            n_funcs: 1,
            n_files: 0,
            text_start: 0,
            funcname_off: 0,
            cu_off: 0,
            filetab_off: 0,
            pctab_off: 0,
            funcdata_off: 0,
            section_addr: 0,
            section_len: bytes.len(),
        };
        let start: Instant = Instant::now();
        let inferred: Option<u64> = infer_flat_base(&bytes, pclntab_off, &header);
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
