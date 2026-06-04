use object::Object as _;
use object::ObjectSection as _;
use object::ObjectSymbol as _;
use object::read::{File as ObjFile, FileKind};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImageKind {
    Pe,
    Elf,
    MachO,
}

#[derive(Debug, Clone)]
pub struct Section<'a> {
    pub name: String,
    pub data: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct NativeImage<'a> {
    pub kind: ImageKind,
    pub ptr_size: u8,
    pub raw: &'a [u8],
    pub sections: Vec<Section<'a>>,
    pub symbols: Vec<String>,
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
        let ptr_size: u8 = if file.is_64() { 8 } else { 4 };
        let mut sections: Vec<Section<'a>> = Vec::new();
        for sec in file.sections() {
            let name: String = sec.name().unwrap_or("").to_owned();
            let data: &'a [u8] = sec.data().unwrap_or(b"");
            sections.push(Section { name, data });
        }
        let mut symbols: Vec<String> = Vec::new();
        for sym in file.symbols() {
            let raw_name: &str = sym.name().unwrap_or("");
            if !raw_name.is_empty() {
                symbols.push(raw_name.to_owned());
            }
        }
        Ok(Self {
            kind,
            ptr_size,
            raw: bytes,
            sections,
            symbols,
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
    pub fn ascii_strings(&self, min_len: usize) -> Vec<String> {
        ascii_strings(self.raw, min_len)
    }
}

#[must_use]
pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w: &[u8]| w == needle)
}

#[must_use]
pub fn ascii_strings(buf: &[u8], min_len: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut start: usize = 0;
    let mut run: usize = 0;
    for (i, b) in buf.iter().enumerate() {
        if b.is_ascii_graphic() || *b == b' ' {
            if run == 0 {
                start = i;
            }
            run += 1;
        } else {
            if run >= min_len
                && let Ok(s) = std::str::from_utf8(&buf[start..i])
            {
                out.push(s.to_owned());
            }
            run = 0;
        }
    }
    if run >= min_len
        && let Ok(s) = std::str::from_utf8(&buf[start..])
    {
        out.push(s.to_owned());
    }
    out
}
