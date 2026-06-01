use std::collections::BTreeMap;
use std::io::Read;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::etf::{self, Term};
use crate::reader::Reader;

const TAG_U: u8 = 0;
const TAGGED_EXT_SIZE_BASE: usize = 2;
const TAGGED_EXT_SIZE_BASE_LARGE: usize = 9;
const TAGGED_EXT_LARGE_THRESHOLD: u8 = 7;

#[derive(Debug, Clone, Copy)]
struct TaggedNumber {
    tag: u8,
    word_value: u64,
    size: usize,
}

fn read_tagged(reader: &mut Reader<'_>) -> Result<TaggedNumber> {
    let len_code: u8 = reader.u8()?;
    let tag: u8 = len_code & 0x07;
    if (len_code & 0x08) == 0 {
        return Ok(TaggedNumber {
            tag,
            word_value: u64::from(len_code >> 4),
            size: 0,
        });
    }
    if (len_code & 0x10) == 0 {
        let extra: u8 = reader.u8()?;
        let value: u64 = (u64::from(len_code >> 5) << 8) | u64::from(extra);
        return Ok(TaggedNumber {
            tag,
            word_value: value,
            size: 0,
        });
    }
    let lc: u8 = len_code >> 5;
    let count: usize = if lc < TAGGED_EXT_LARGE_THRESHOLD {
        usize::from(lc) + TAGGED_EXT_SIZE_BASE
    } else {
        let size_prefix: TaggedNumber = read_tagged(reader)?;
        if size_prefix.tag != TAG_U || size_prefix.size != 0 {
            return Err(Error::BadCompactTerm(reader.position()));
        }
        let unpacked: usize = usize::try_from(size_prefix.word_value)
            .map_err(|_| Error::IntOverflow("tagged extended size"))?;
        unpacked
            .checked_add(TAGGED_EXT_SIZE_BASE_LARGE)
            .ok_or(Error::IntOverflow("tagged extended size"))?
    };
    let data: &[u8] = reader.take(count)?;
    if count <= core::mem::size_of::<u64>() {
        let mut word: u64 = 0;
        for &byte in data {
            word = (word << 8) | u64::from(byte);
        }
        return Ok(TaggedNumber {
            tag,
            word_value: word,
            size: 0,
        });
    }
    Ok(TaggedNumber {
        tag,
        word_value: 0,
        size: count,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomTable {
    pub atoms: Vec<String>,
}

impl AtomTable {
    pub fn parse_utf8(data: &[u8]) -> Result<Self> {
        Self::parse_inner(data, true)
    }

    pub fn parse_latin1(data: &[u8]) -> Result<Self> {
        Self::parse_inner(data, false)
    }

    fn parse_inner(data: &[u8], utf8: bool) -> Result<Self> {
        let mut reader: Reader<'_> = Reader::new(data);
        let count: u32 = reader.u32()?;
        let cap: usize = (count as usize).min(reader.remaining());
        let mut atoms: Vec<String> = Vec::with_capacity(cap);
        for index in 0..count {
            let len: u8 = reader.u8()?;
            let bytes: &[u8] = reader.take(len as usize)?;
            let atom: String = if utf8 {
                core::str::from_utf8(bytes)
                    .map_err(|_| Error::BadAtomUtf8 { index })?
                    .to_owned()
            } else {
                bytes.iter().map(|&b| b as char).collect()
            };
            atoms.push(atom);
        }
        Ok(Self { atoms })
    }

    /// Parses an `AtU8` chunk in either short form (positive `i32` count + `u8`
    /// length prefixes) or OTP-26+ long form (negative `i32` count + tagged-number
    /// length prefixes per `beam_file.c::parse_atom_chunk`).
    pub fn parse_utf8_any(data: &[u8]) -> Result<Self> {
        let mut reader: Reader<'_> = Reader::new(data);
        let signed_count: i32 = reader.i32()?;
        if signed_count >= 0 {
            return Self::parse_inner(data, true);
        }
        let count: u32 = signed_count
            .checked_neg()
            .and_then(|n: i32| u32::try_from(n).ok())
            .ok_or(Error::IntOverflow("AtU8 long-form count"))?;
        let cap: usize = (count as usize).min(reader.remaining());
        let mut atoms: Vec<String> = Vec::with_capacity(cap);
        for _ in 0..count {
            let tagged: TaggedNumber = read_tagged(&mut reader)?;
            if tagged.tag != TAG_U || tagged.size != 0 {
                return Err(Error::BadAtomUtf8 {
                    index: u32::try_from(atoms.len()).unwrap_or(u32::MAX),
                });
            }
            let len: usize = usize::try_from(tagged.word_value)
                .map_err(|_| Error::IntOverflow("AtU8 long-form length"))?;
            let bytes: &[u8] = reader.take(len)?;
            let atom: String = core::str::from_utf8(bytes)
                .map_err(|_| Error::BadAtomUtf8 {
                    index: u32::try_from(atoms.len()).unwrap_or(u32::MAX),
                })?
                .to_owned();
            atoms.push(atom);
        }
        Ok(Self { atoms })
    }

    #[must_use]
    pub fn get(&self, index: u32) -> Option<&str> {
        if index == 0 {
            return None;
        }
        let i: usize = (index as usize).checked_sub(1)?;
        self.atoms.get(i).map(String::as_str)
    }

    pub fn require(&self, index: u32) -> Result<&str> {
        #[allow(clippy::cast_possible_truncation)]
        self.get(index)
            .ok_or(Error::BadAtomIndex(index, self.atoms.len() as u32))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.atoms.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.atoms.is_empty()
    }

    #[must_use]
    pub fn module_name(&self) -> Option<&str> {
        self.get(1)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeChunk {
    pub sub_size: u32,
    pub instruction_set: u32,
    pub opcode_max: u32,
    pub num_labels: u32,
    pub num_functions: u32,
    pub code: Vec<u8>,
}

impl CodeChunk {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut reader: Reader<'_> = Reader::new(data);
        let sub_size: u32 = reader.u32()?;
        if (sub_size as usize) + 4 > data.len() {
            return Err(Error::BadCodeHeader(sub_size, data.len()));
        }
        let instruction_set: u32 = reader.u32()?;
        let opcode_max: u32 = reader.u32()?;
        let num_labels: u32 = reader.u32()?;
        let num_functions: u32 = reader.u32()?;
        let header_consumed: usize = 4 + sub_size as usize;
        reader.seek(header_consumed)?;
        let code: Vec<u8> = data[header_consumed..].to_vec();
        Ok(Self {
            sub_size,
            instruction_set,
            opcode_max,
            num_labels,
            num_functions,
            code,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringTable {
    pub bytes: Vec<u8>,
}

impl StringTable {
    #[must_use]
    pub fn parse(data: &[u8]) -> Self {
        Self {
            bytes: data.to_vec(),
        }
    }

    #[must_use]
    pub fn slice(&self, offset: usize, len: usize) -> Option<&[u8]> {
        let end: usize = offset.checked_add(len)?;
        self.bytes.get(offset..end)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportEntry {
    pub function_atom_index: u32,
    pub arity: u32,
    pub label: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportEntry {
    pub module_atom_index: u32,
    pub function_atom_index: u32,
    pub arity: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalEntry {
    pub function_atom_index: u32,
    pub arity: u32,
    pub label: u32,
}

pub fn parse_export_table(data: &[u8]) -> Result<Vec<ExportEntry>> {
    let mut reader: Reader<'_> = Reader::new(data);
    let count: u32 = reader.u32()?;
    let cap: usize = (count as usize).min(reader.remaining() / 12 + 1);
    let mut out: Vec<ExportEntry> = Vec::with_capacity(cap);
    for _ in 0..count {
        let function_atom_index: u32 = reader.u32()?;
        let arity: u32 = reader.u32()?;
        let label: u32 = reader.u32()?;
        out.push(ExportEntry {
            function_atom_index,
            arity,
            label,
        });
    }
    Ok(out)
}

pub fn parse_import_table(data: &[u8]) -> Result<Vec<ImportEntry>> {
    let mut reader: Reader<'_> = Reader::new(data);
    let count: u32 = reader.u32()?;
    let cap: usize = (count as usize).min(reader.remaining() / 12 + 1);
    let mut out: Vec<ImportEntry> = Vec::with_capacity(cap);
    for _ in 0..count {
        let module_atom_index: u32 = reader.u32()?;
        let function_atom_index: u32 = reader.u32()?;
        let arity: u32 = reader.u32()?;
        out.push(ImportEntry {
            module_atom_index,
            function_atom_index,
            arity,
        });
    }
    Ok(out)
}

pub fn parse_local_table(data: &[u8]) -> Result<Vec<LocalEntry>> {
    let mut reader: Reader<'_> = Reader::new(data);
    let count: u32 = reader.u32()?;
    let cap: usize = (count as usize).min(reader.remaining() / 12 + 1);
    let mut out: Vec<LocalEntry> = Vec::with_capacity(cap);
    for _ in 0..count {
        let function_atom_index: u32 = reader.u32()?;
        let arity: u32 = reader.u32()?;
        let label: u32 = reader.u32()?;
        out.push(LocalEntry {
            function_atom_index,
            arity,
            label,
        });
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttrChunk {
    pub term: Term,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompileInfoChunk {
    pub term: Term,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DbgiChunk {
    pub term: Term,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DocsChunk {
    pub term: Term,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LiteralChunk {
    pub literals: Vec<Term>,
}

impl LiteralChunk {
    /// Parses a `LitT` chunk. OTP-26 and earlier always zlib-deflate the payload
    /// after a `u32` uncompressed-size header. OTP-28+ replaced the format with
    /// a zero-valued header followed by the raw uncompressed `count + (size, etf)`
    /// stream; this loader transparently handles both encodings.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut reader: Reader<'_> = Reader::new(data);
        let uncompressed_size: u32 = reader.u32()?;
        let rest: &[u8] = reader.take(reader.remaining())?;
        let inflated: Vec<u8> = if uncompressed_size == 0 {
            rest.to_vec()
        } else {
            let cap: usize = (uncompressed_size as usize).min(rest.len().saturating_mul(64));
            let mut out: Vec<u8> = Vec::with_capacity(cap);
            let mut decoder: flate2::read::ZlibDecoder<&[u8]> =
                flate2::read::ZlibDecoder::new(rest);
            decoder
                .read_to_end(&mut out)
                .map_err(|e: std::io::Error| Error::Zlib("LitT", e.to_string()))?;
            out
        };
        let mut inner: Reader<'_> = Reader::new(&inflated);
        let count: u32 = inner.u32()?;
        let cap: usize = (count as usize).min(inner.remaining());
        let mut literals: Vec<Term> = Vec::with_capacity(cap);
        for _ in 0..count {
            let size: u32 = inner.u32()?;
            let payload: &[u8] = inner.take(size as usize)?;
            literals.push(etf::decode_etf(payload)?);
        }
        Ok(Self { literals })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineChunk {
    pub version: u32,
    pub flags: u32,
    pub num_instrs: u32,
    pub num_lines: u32,
    pub num_filenames: u32,
    pub filenames: Vec<String>,
    pub items: Vec<LineItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineItem {
    pub filename_index: u32,
    pub line: u32,
}

impl LineChunk {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut reader: Reader<'_> = Reader::new(data);
        let version: u32 = reader.u32()?;
        let flags: u32 = reader.u32()?;
        let num_instrs: u32 = reader.u32()?;
        let num_lines: u32 = reader.u32()?;
        let num_filenames: u32 = reader.u32()?;
        let cap_items: usize = (num_lines as usize).min(reader.remaining());
        let mut items: Vec<LineItem> = Vec::with_capacity(cap_items);
        let mut current_filename: u32 = 1;
        while (items.len() as u32) < num_lines {
            let (tag, value): (u8, u32) = crate::disasm::decode_compact_simple(&mut reader)?;
            if tag == crate::disasm::TAG_ATOM {
                current_filename = value;
            } else {
                items.push(LineItem {
                    filename_index: current_filename,
                    line: value,
                });
            }
        }
        let cap_filenames: usize = (num_filenames as usize).min(reader.remaining());
        let mut filenames: Vec<String> = Vec::with_capacity(cap_filenames);
        for _ in 0..num_filenames {
            let len: u16 = reader.u16()?;
            let bytes: &[u8] = reader.take(len as usize)?;
            let name: String = core::str::from_utf8(bytes)
                .map_err(|_| Error::BadAtomUtf8 { index: 0 })?
                .to_owned();
            filenames.push(name);
        }
        Ok(Self {
            version,
            flags,
            num_instrs,
            num_lines,
            num_filenames,
            filenames,
            items,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunEntry {
    pub function_atom_index: u32,
    pub arity: u32,
    pub label: u32,
    pub index: u32,
    pub num_free: u32,
    pub old_uniq: u32,
}

pub fn parse_fun_table(data: &[u8]) -> Result<Vec<FunEntry>> {
    let mut reader: Reader<'_> = Reader::new(data);
    let count: u32 = reader.u32()?;
    let cap: usize = (count as usize).min(reader.remaining() / 24 + 1);
    let mut out: Vec<FunEntry> = Vec::with_capacity(cap);
    for _ in 0..count {
        let function_atom_index: u32 = reader.u32()?;
        let arity: u32 = reader.u32()?;
        let label: u32 = reader.u32()?;
        let index: u32 = reader.u32()?;
        let num_free: u32 = reader.u32()?;
        let old_uniq: u32 = reader.u32()?;
        out.push(FunEntry {
            function_atom_index,
            arity,
            label,
            index,
            num_free,
            old_uniq,
        });
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Chunks {
    pub atoms: AtomTable,
    pub code: Option<CodeChunk>,
    pub strings: Option<StringTable>,
    pub attributes: Option<AttrChunk>,
    pub compile_info: Option<CompileInfoChunk>,
    pub dbgi: Option<DbgiChunk>,
    pub docs: Option<DocsChunk>,
    pub exports: Vec<ExportEntry>,
    pub imports: Vec<ImportEntry>,
    pub locals: Vec<LocalEntry>,
    pub literals: Option<LiteralChunk>,
    pub line: Option<LineChunk>,
    pub funs: Vec<FunEntry>,
    pub other: BTreeMap<String, Vec<u8>>,
}
