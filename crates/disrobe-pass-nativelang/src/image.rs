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
