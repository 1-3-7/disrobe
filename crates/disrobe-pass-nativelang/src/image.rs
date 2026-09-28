use object::Object as _;
use object::ObjectSection as _;
use object::ObjectSymbol as _;
use object::read::{File as ObjFile, FileKind};
use object::{Architecture as ObjArch, ObjectKind, SectionKind, SymbolKind};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImageKind {
    Pe,
    Elf,
    MachO,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CodeArch {
    X86,
    X86_64,
    Aarch64,
    Other,
}

#[derive(Debug, Clone)]
pub struct Section<'a> {
    pub name: String,
    pub address: u64,
    pub kind: SectionKind,
    pub data: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuncSymbol {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub relocatable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FunctionStartSource {
    MachOFunctionStarts,
    PeUnwindTable,
    Export,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FunctionStart {
    pub address: u64,
    pub source: FunctionStartSource,
}

#[derive(Debug, Clone)]
pub struct NativeImage<'a> {
    pub kind: ImageKind,
    pub relocatable: bool,
    pub arch: CodeArch,
    pub ptr_size: u8,
    pub entry: u64,
    pub raw: &'a [u8],
    pub sections: Vec<Section<'a>>,
    pub symbols: Vec<String>,
    pub func_symbols: Vec<FuncSymbol>,
    pub function_starts: Vec<FunctionStart>,
}

const MAX_TABLE_FUNCTION_STARTS: usize = 1 << 20;
const MACHO_LC_SEGMENT_64: u32 = 0x19;
const MACHO_LC_FUNCTION_STARTS: u32 = 0x26;
const MACHO_HEADER_64_LEN: usize = 32;
const PE_RUNTIME_FUNCTION_X64_LEN: usize = 12;
const PE_RUNTIME_FUNCTION_ARM64_LEN: usize = 8;

fn read_u32_le(bytes: &[u8], at: usize) -> Option<u32> {
    let end: usize = at.checked_add(4)?;
    let chunk: [u8; 4] = bytes.get(at..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(chunk))
}

fn read_u64_le(bytes: &[u8], at: usize) -> Option<u64> {
    let end: usize = at.checked_add(8)?;
    let chunk: [u8; 8] = bytes.get(at..end)?.try_into().ok()?;
    Some(u64::from_le_bytes(chunk))
}

fn macho_function_starts(raw: &[u8]) -> Vec<u64> {
    if raw.get(..4) != Some(&[0xCF, 0xFA, 0xED, 0xFE][..]) {
        return Vec::new();
    }
    let Some(command_count): Option<u32> = read_u32_le(raw, 16) else {
        return Vec::new();
    };
    let mut cursor: usize = MACHO_HEADER_64_LEN;
    let mut text_base: Option<u64> = None;
    let mut starts_data: Option<(usize, usize)> = None;
    for _ in 0..command_count {
        let (Some(command), Some(size)): (Option<u32>, Option<u32>) =
            (read_u32_le(raw, cursor), read_u32_le(raw, cursor + 4))
        else {
            break;
        };
        match command {
            MACHO_LC_SEGMENT_64 => {
                let name: &[u8] = raw.get(cursor + 8..cursor + 24).unwrap_or_default();
                if name.split(|byte: &u8| *byte == 0).next() == Some(&b"__TEXT"[..]) {
                    text_base = read_u64_le(raw, cursor + 24);
                }
            }
            MACHO_LC_FUNCTION_STARTS => {
                if let (Some(offset), Some(length)) =
                    (read_u32_le(raw, cursor + 8), read_u32_le(raw, cursor + 12))
                {
                    starts_data = Some((offset as usize, length as usize));
                }
            }
            _ => {}
        }
        let Some(next): Option<usize> = cursor.checked_add(size as usize) else {
            break;
        };
        if size < 8 || next > raw.len() {
            break;
        }
        cursor = next;
    }
    let (Some(mut address), Some((offset, length))): (Option<u64>, Option<(usize, usize)>) =
        (text_base, starts_data)
    else {
        return Vec::new();
    };
    let Some(data): Option<&[u8]> = offset
        .checked_add(length)
        .and_then(|end: usize| raw.get(offset..end))
    else {
        return Vec::new();
    };
    let mut starts: Vec<u64> = Vec::new();
    let mut delta: u64 = 0;
    let mut shift: u32 = 0;
    for byte in data {
        if shift >= 64 {
            break;
        }
        delta |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 != 0 {
            shift += 7;
            continue;
        }
        if delta == 0 || starts.len() >= MAX_TABLE_FUNCTION_STARTS {
            break;
        }
        address = address.saturating_add(delta);
        starts.push(address);
        delta = 0;
        shift = 0;
    }
    starts
}

fn pe_unwind_table_starts(sections: &[Section<'_>], arch: CodeArch, image_base: u64) -> Vec<u64> {
    let entry_len: usize = match arch {
        CodeArch::X86_64 => PE_RUNTIME_FUNCTION_X64_LEN,
        CodeArch::Aarch64 => PE_RUNTIME_FUNCTION_ARM64_LEN,
        CodeArch::X86 | CodeArch::Other => return Vec::new(),
    };
    let Some(pdata): Option<&Section<'_>> = sections
        .iter()
        .find(|section: &&Section<'_>| section.name == ".pdata")
    else {
        return Vec::new();
    };
    pdata
        .data
        .chunks_exact(entry_len)
        .take(MAX_TABLE_FUNCTION_STARTS)
        .filter_map(|entry: &[u8]| read_u32_le(entry, 0))
        .filter(|rva: &u32| *rva != 0)
        .map(|rva: u32| image_base.saturating_add(u64::from(rva)))
        .collect()
}

impl<'a> NativeImage<'a> {
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
        let relocatable: bool = file.kind() == ObjectKind::Relocatable;
        let ptr_size: u8 = if file.is_64() { 8 } else { 4 };
        let arch: CodeArch = match file.architecture() {
            ObjArch::I386 => CodeArch::X86,
            ObjArch::X86_64 | ObjArch::X86_64_X32 => CodeArch::X86_64,
            ObjArch::Aarch64 | ObjArch::Aarch64_Ilp32 => CodeArch::Aarch64,
            _ => CodeArch::Other,
        };
        let entry: u64 = file.entry();
        let mut sections: Vec<Section<'a>> = Vec::new();
        for sec in file.sections() {
            let name: String = sec.name().unwrap_or("").to_owned();
            let data: &'a [u8] = sec.data().unwrap_or(b"");
            sections.push(Section {
                name,
                address: sec.address(),
                kind: sec.kind(),
                data,
            });
        }
        let mut symbols: Vec<String> = Vec::new();
        let mut func_symbols: Vec<FuncSymbol> = Vec::new();
        let mut unsized_symbols: Vec<(String, u64)> = Vec::new();
        for sym in file.symbols() {
            let raw_name: &str = sym.name().unwrap_or("");
            if raw_name.is_empty() {
                continue;
            }
            symbols.push(raw_name.to_owned());
            if sym.kind() != SymbolKind::Text {
                continue;
            }
            let address: u64 = sym.address();
            let resolved: Option<u64> = if relocatable {
                sym.section_index()
                    .and_then(|idx: object::SectionIndex| {
                        file.section_by_index(idx)
                            .ok()
                            .map(|s: object::read::Section<'a, '_, &'a [u8]>| s.address())
                    })
                    .map(|section_addr: u64| section_addr.saturating_add(address))
            } else {
                (address != 0).then_some(address)
            };
            let Some(resolved) = resolved else {
                continue;
            };
            let size: u64 = sym.size();
            if size == 0 {
                unsized_symbols.push((raw_name.to_owned(), resolved));
                continue;
            }
            func_symbols.push(FuncSymbol {
                name: raw_name.to_owned(),
                address: resolved,
                size,
                relocatable,
            });
        }
        let starts: std::collections::BTreeSet<u64> = func_symbols
            .iter()
            .map(|symbol: &FuncSymbol| symbol.address)
            .chain(
                unsized_symbols
                    .iter()
                    .map(|(_, address): &(String, u64)| *address),
            )
            .collect();
        for (name, address) in unsized_symbols {
            let section_end: Option<u64> = sections
                .iter()
                .filter(|section: &&Section<'a>| section.kind == SectionKind::Text)
                .find_map(|section: &Section<'a>| {
                    let end: u64 = section.address.saturating_add(section.data.len() as u64);
                    (section.address <= address && address < end).then_some(end)
                });
            let Some(section_end) = section_end else {
                continue;
            };
            let next_start: u64 = starts
                .range(address.saturating_add(1)..)
                .next()
                .copied()
                .unwrap_or(section_end)
                .min(section_end);
            let size: u64 = next_start.saturating_sub(address);
            if size > 0 {
                func_symbols.push(FuncSymbol {
                    name,
                    address,
                    size,
                    relocatable,
                });
            }
        }
        let table_starts: Vec<u64> = match kind {
            ImageKind::MachO => macho_function_starts(bytes),
            ImageKind::Pe => pe_unwind_table_starts(&sections, arch, file.relative_address_base()),
            ImageKind::Elf => Vec::new(),
        };
        let table_source: FunctionStartSource = if kind == ImageKind::MachO {
            FunctionStartSource::MachOFunctionStarts
        } else {
            FunctionStartSource::PeUnwindTable
        };
        let export_starts: Vec<u64> = file
            .exports()
            .map(|exports: Vec<object::Export<'a>>| {
                exports
                    .iter()
                    .map(|export: &object::Export<'a>| export.address())
                    .collect()
            })
            .unwrap_or_default();
        let in_text = |address: u64| -> bool {
            sections.iter().any(|section: &Section<'a>| {
                section.kind == SectionKind::Text
                    && section.address <= address
                    && address < section.address.saturating_add(section.data.len() as u64)
            })
        };
        let mut seen: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        let function_starts: Vec<FunctionStart> = table_starts
            .into_iter()
            .map(|address: u64| FunctionStart {
                address,
                source: table_source,
            })
            .chain(export_starts.into_iter().map(|address: u64| FunctionStart {
                address,
                source: FunctionStartSource::Export,
            }))
            .filter(|start: &FunctionStart| in_text(start.address) && seen.insert(start.address))
            .take(MAX_TABLE_FUNCTION_STARTS)
            .collect();
        Ok(Self {
            kind,
            relocatable,
            arch,
            ptr_size,
            entry,
            raw: bytes,
            sections,
            symbols,
            func_symbols,
            function_starts,
        })
    }

    #[must_use]
    pub const fn has_symbol_table(&self) -> bool {
        !self.symbols.is_empty()
    }

    #[must_use]
    pub fn section_data(&self, candidates: &[&str]) -> Option<&'a [u8]> {
        for cand in candidates {
            for sec in &self.sections {
                if sec.name == *cand {
                    return Some(sec.data);
                }
            }
        }
        None
    }

    #[must_use]
    pub fn raw_contains(&self, needle: &[u8]) -> bool {
        contains(self.raw, needle)
    }

    #[must_use]
    pub fn text_section(&self) -> Option<&Section<'a>> {
        self.sections
            .iter()
            .find(|s: &&Section<'a>| s.name == ".text" && s.kind == SectionKind::Text)
            .or_else(|| {
                self.sections
                    .iter()
                    .find(|s: &&Section<'a>| s.kind == SectionKind::Text && !s.data.is_empty())
            })
    }

    #[must_use]
    pub fn ascii_strings(&self, min_len: usize) -> Vec<String> {
        ascii_strings(self.raw, min_len)
    }

    #[must_use]
    pub fn ascii_strings_capped(&self, min_len: usize) -> (Vec<String>, bool) {
        ascii_strings_capped(self.raw, min_len)
    }
}

#[must_use]
pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
}

pub const MAX_STRING_SCAN_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_STRING_COUNT: usize = 1 << 20;

#[must_use]
pub fn ascii_strings(buf: &[u8], min_len: usize) -> Vec<String> {
    ascii_strings_capped(buf, min_len).0
}

#[must_use]
pub fn ascii_strings_capped(buf: &[u8], min_len: usize) -> (Vec<String>, bool) {
    const MAX_STRING_LEN: usize = 64 * 1024;
    const MAX_TOTAL_BYTES: usize = 128 * 1024 * 1024;
    fn push_capped(slice: &[u8], out: &mut Vec<String>, total: &mut usize) -> bool {
        if *total >= MAX_TOTAL_BYTES || out.len() >= MAX_STRING_COUNT {
            return false;
        }
        let take: usize = slice.len().min(MAX_STRING_LEN);
        if let Ok(s) = std::str::from_utf8(&slice[..take]) {
            out.push(s.to_owned());
            *total = total.saturating_add(take);
        }
        true
    }
    let window: usize = buf.len().min(MAX_STRING_SCAN_BYTES);
    let mut truncated: bool = buf.len() > MAX_STRING_SCAN_BYTES;
    let scanned: &[u8] = &buf[..window];
    let mut out: Vec<String> = Vec::new();
    let mut total: usize = 0;
    let mut start: usize = 0;
    let mut run: usize = 0;
    for (i, b) in scanned.iter().enumerate() {
        if b.is_ascii_graphic() || *b == b' ' {
            if run == 0 {
                start = i;
            }
            run += 1;
        } else {
            if run >= min_len && !push_capped(&scanned[start..i], &mut out, &mut total) {
                return (out, true);
            }
            run = 0;
        }
    }
    if run >= min_len && !push_capped(&scanned[start..], &mut out, &mut total) {
        truncated = true;
    }
    (out, truncated)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod size_tests {
    use super::*;

    #[test]
    fn mach_o_text_symbols_without_a_size_are_sized_by_the_next_symbol() {
        let path: std::path::PathBuf = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus/native/formats/hello.macho64.o");
        let bytes: Vec<u8> = std::fs::read(&path).expect("read the Mach-O fixture");
        let image: NativeImage<'_> = NativeImage::parse(&bytes).expect("parse the Mach-O fixture");
        let names: Vec<&str> = image
            .func_symbols
            .iter()
            .map(|symbol: &FuncSymbol| symbol.name.as_str())
            .collect();
        assert!(names.contains(&"_disrobe_add"), "{names:?}");
        assert!(names.contains(&"_disrobe_mul"), "{names:?}");
        assert!(
            image
                .func_symbols
                .iter()
                .all(|symbol: &FuncSymbol| symbol.size > 0)
        );
    }
}
