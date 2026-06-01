use object::Endianness as ObjEndianness;
use object::Object as _;
use object::ObjectSection as _;
use object::ObjectSymbol as _;
use object::read::{File as ObjFile, FileKind};

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
}

#[derive(Debug, Clone)]
pub struct GoImage<'a> {
    pub kind: ImageKind,
    pub endian: Endian,
    pub ptr_size: u8,
    pub sections: Vec<Section<'a>>,
    pub raw: &'a [u8],
    pub symbol_addrs: Vec<(String, u64, u64)>,
}

impl<'a> GoImage<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < 64 {
            return Err(Error::InputTooSmall(bytes.len()));
        }
        let kind_raw: FileKind =
            FileKind::parse(bytes).map_err(|e| Error::ContainerParse(e.to_string()))?;
        let kind: ImageKind = match kind_raw {
            FileKind::Pe32 | FileKind::Pe64 => ImageKind::Pe,
            FileKind::Elf32 | FileKind::Elf64 => ImageKind::Elf,
            FileKind::MachO32 | FileKind::MachO64 => ImageKind::MachO,
            _ => return Err(Error::UnrecognizedContainer),
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
            sections.push(Section {
                name,
                address: sec.address(),
                data,
            });
        }
        let mut symbol_addrs: Vec<(String, u64, u64)> = Vec::new();
        for sym in file.symbols() {
            let raw_name: &str = sym.name().unwrap_or("");
            if raw_name.is_empty() {
                continue;
            }
            symbol_addrs.push((raw_name.to_owned(), sym.address(), sym.size()));
        }
        Ok(Self {
            kind,
            endian,
            ptr_size,
            sections,
            raw: bytes,
            symbol_addrs,
        })
    }

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

    pub fn read_u32(&self, va: u64) -> Option<u32> {
        let buf: &[u8] = self.data_at_va(va, 4)?;
        let arr: [u8; 4] = buf.try_into().ok()?;
        Some(match self.endian {
            Endian::Little => u32::from_le_bytes(arr),
            Endian::Big => u32::from_be_bytes(arr),
        })
    }

    pub fn read_u64(&self, va: u64) -> Option<u64> {
        let buf: &[u8] = self.data_at_va(va, 8)?;
        let arr: [u8; 8] = buf.try_into().ok()?;
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
}

#[allow(dead_code)]
pub(crate) const fn pclntab_section_candidates(kind: ImageKind) -> &'static [&'static str] {
    match kind {
        ImageKind::Pe => &[".gopclntab", ".rdata", ".data", ".text"],
        ImageKind::Elf => &[".gopclntab", ".gopclntab.bss", ".data.rel.ro", ".rodata"],
        ImageKind::MachO => &["__gopclntab", "__rodata", "__DATA,__rodata"],
    }
}
