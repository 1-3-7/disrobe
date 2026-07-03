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
const ATOM_ENTRY_MIN_SIZE: usize = 1;
const EXPORT_ENTRY_SIZE: usize = 12;
const IMPORT_ENTRY_SIZE: usize = 12;
const LOCAL_ENTRY_SIZE: usize = 12;
const LITERAL_ENTRY_MIN_SIZE: usize = 4;
const LINE_ITEM_MIN_SIZE: usize = 1;
const LINE_FILENAME_MIN_SIZE: usize = 2;
const FUN_ENTRY_SIZE: usize = 24;

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

fn checked_table_count(
    table: &'static str,
    count: u32,
    available: usize,
    min_record_size: usize,
) -> Result<usize> {
    let count_usize: usize = usize::try_from(count).map_err(|_| Error::TableCountTooLarge {
        table,
        count,
        available,
        min_record_size,
    })?;
    let max_records: usize = available / min_record_size;
    if count_usize > max_records {
        return Err(Error::TableCountTooLarge {
            table,
            count,
            available,
            min_record_size,
        });
    }
    Ok(count_usize)
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
        let cap: usize =
            checked_table_count("Atom", count, reader.remaining(), ATOM_ENTRY_MIN_SIZE)?;
        let mut atoms: Vec<String> = Vec::with_capacity(cap);
        for _ in 0..cap {
            let len: u8 = reader.u8()?;
            let bytes: &[u8] = reader.take(usize::from(len))?;
            let atom: String = if utf8 {
                String::from_utf8_lossy(bytes).into_owned()
            } else {
                bytes.iter().map(|&b| b as char).collect()
            };
            atoms.push(atom);
        }
        Ok(Self { atoms })
    }

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
        let cap: usize =
            checked_table_count("AtU8", count, reader.remaining(), ATOM_ENTRY_MIN_SIZE)?;
        let mut atoms: Vec<String> = Vec::with_capacity(cap);
        for _ in 0..cap {
            let tagged: TaggedNumber = read_tagged(&mut reader)?;
            if tagged.tag != TAG_U || tagged.size != 0 {
                let index: u32 = atoms.len() as u32;
                return Err(Error::BadAtomUtf8 { index });
            }
            let len: usize = usize::try_from(tagged.word_value)
                .map_err(|_| Error::IntOverflow("AtU8 long-form length"))?;
            let bytes: &[u8] = reader.take(len)?;
            let atom: String = String::from_utf8_lossy(bytes).into_owned();
            atoms.push(atom);
        }
        Ok(Self { atoms })
    }

    #[must_use]
    pub fn get(&self, index: u32) -> Option<&str> {
        if index == 0 {
            return None;
        }
        let i: usize = usize::try_from(index).ok()?.checked_sub(1)?;
        self.atoms.get(i).map(String::as_str)
    }

    pub fn require(&self, index: u32) -> Result<&str> {
        let len: u32 = u32::try_from(self.atoms.len()).unwrap_or(u32::MAX);
        self.get(index).ok_or(Error::BadAtomIndex(index, len))
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
        let sub_size_usize: usize =
            usize::try_from(sub_size).map_err(|_| Error::BadCodeHeader(sub_size, data.len()))?;
        let header_consumed: usize = sub_size_usize
            .checked_add(4)
            .ok_or(Error::IntOverflow("Code sub-header size"))?;
        if header_consumed > data.len() {
            return Err(Error::BadCodeHeader(sub_size, data.len()));
        }
        let instruction_set: u32 = reader.u32()?;
        let opcode_max: u32 = reader.u32()?;
        let num_labels: u32 = reader.u32()?;
        let num_functions: u32 = reader.u32()?;
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

pub(crate) const MAX_FUN_ARITY: u32 = 1024;

pub fn parse_export_table(data: &[u8]) -> Result<Vec<ExportEntry>> {
    let mut reader: Reader<'_> = Reader::new(data);
    let count: u32 = reader.u32()?;
    let cap: usize = checked_table_count("ExpT", count, reader.remaining(), EXPORT_ENTRY_SIZE)?;
    let mut out: Vec<ExportEntry> = Vec::with_capacity(cap);
    for _ in 0..cap {
        let function_atom_index: u32 = reader.u32()?;
        let arity: u32 = reader.u32()?.min(MAX_FUN_ARITY);
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
    let cap: usize = checked_table_count("ImpT", count, reader.remaining(), IMPORT_ENTRY_SIZE)?;
    let mut out: Vec<ImportEntry> = Vec::with_capacity(cap);
    for _ in 0..cap {
        let module_atom_index: u32 = reader.u32()?;
        let function_atom_index: u32 = reader.u32()?;
        let arity: u32 = reader.u32()?.min(MAX_FUN_ARITY);
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
    let cap: usize = checked_table_count("LocT", count, reader.remaining(), LOCAL_ENTRY_SIZE)?;
    let mut out: Vec<LocalEntry> = Vec::with_capacity(cap);
    for _ in 0..cap {
        let function_atom_index: u32 = reader.u32()?;
        let arity: u32 = reader.u32()?.min(MAX_FUN_ARITY);
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

const MAX_LITT_INFLATE: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LiteralChunk {
    pub literals: Vec<Term>,
}

impl LiteralChunk {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut reader: Reader<'_> = Reader::new(data);
        let uncompressed_size: u32 = reader.u32()?;
        let rest: &[u8] = reader.take(reader.remaining())?;
        let inflated: Vec<u8> = if uncompressed_size == 0 {
            rest.to_vec()
        } else {
            let uncompressed_size_usize: usize =
                usize::try_from(uncompressed_size).map_err(|_| {
                    Error::Zlib(
                        "LitT",
                        "uncompressed size exceeds platform bounds".to_owned(),
                    )
                })?;
            let cap: usize = uncompressed_size_usize
                .min(rest.len().saturating_mul(64))
                .min(MAX_LITT_INFLATE);
            let mut out: Vec<u8> = Vec::with_capacity(cap);
            let decoder: flate2::read::ZlibDecoder<&[u8]> = flate2::read::ZlibDecoder::new(rest);
            decoder
                .take(MAX_LITT_INFLATE as u64 + 1)
                .read_to_end(&mut out)
                .map_err(|e: std::io::Error| Error::Zlib("LitT", e.to_string()))?;
            if out.len() > MAX_LITT_INFLATE || out.len() != uncompressed_size_usize {
                return Err(Error::Zlib("LitT", "uncompressed size mismatch".to_owned()));
            }
            out
        };
        let mut inner: Reader<'_> = Reader::new(&inflated);
        let count: u32 = inner.u32()?;
        let cap: usize =
            checked_table_count("LitT", count, inner.remaining(), LITERAL_ENTRY_MIN_SIZE)?;
        let mut literals: Vec<Term> = Vec::with_capacity(cap);
        for _ in 0..cap {
            let size: u32 = inner.u32()?;
            let size_usize: usize =
                usize::try_from(size).map_err(|_| Error::IntOverflow("LitT literal size"))?;
            let payload: &[u8] = inner.take(size_usize)?;
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
        let cap_items: usize =
            checked_table_count("Line", num_lines, reader.remaining(), LINE_ITEM_MIN_SIZE)?;
        let mut items: Vec<LineItem> = Vec::with_capacity(cap_items);
        let mut current_filename: u32 = 1;
        while items.len() < cap_items {
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
        let cap_filenames: usize = checked_table_count(
            "Line filenames",
            num_filenames,
            reader.remaining(),
            LINE_FILENAME_MIN_SIZE,
        )?;
        let mut filenames: Vec<String> = Vec::with_capacity(cap_filenames);
        for _ in 0..cap_filenames {
            let len: u16 = reader.u16()?;
            let bytes: &[u8] = reader.take(usize::from(len))?;
            let name: String = String::from_utf8_lossy(bytes).into_owned();
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
    let cap: usize = checked_table_count("FunT", count, reader.remaining(), FUN_ENTRY_SIZE)?;
    let mut out: Vec<FunEntry> = Vec::with_capacity(cap);
    for _ in 0..cap {
        let function_atom_index: u32 = reader.u32()?;
        let arity: u32 = reader.u32()?.min(MAX_FUN_ARITY);
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
