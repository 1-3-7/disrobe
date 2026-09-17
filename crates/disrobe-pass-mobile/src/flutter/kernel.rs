use serde::{Deserialize, Serialize};

use crate::debug::{dbg_kv, dbg_section};
use crate::error::{Error, Result};

pub const DART_KERNEL_MAGIC: u32 = 0x90ab_cdef;

const KERNEL_HEADER_MIN: usize = 8;

const COMPONENT_INDEX_FIXED_FIELDS: usize = 8;

const PROCEDURE_TAG: u8 = 6;

const CLASS_TAG: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KernelProcedureKind {
    Method,
    Getter,
    Setter,
    Operator,
    Factory,
    Unknown,
}

impl KernelProcedureKind {
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        match raw {
            0 => Self::Method,
            1 => Self::Getter,
            2 => Self::Setter,
            3 => Self::Operator,
            4 => Self::Factory,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelProcedure {
    pub name: String,
    pub kind: KernelProcedureKind,
    pub is_private: bool,
    pub is_abstract: bool,
    pub start_offset: usize,
    pub end_offset: usize,
    pub recovered_source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelClass {
    pub name: String,
    pub is_abstract: bool,
    pub fields: Vec<String>,
    pub procedures: Vec<KernelProcedure>,
    pub recovered_source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelLibrary {
    pub name: Option<String>,
    pub import_uri: Option<String>,
    pub file_uri: Option<String>,
    pub classes: Vec<KernelClass>,
    pub procedures: Vec<KernelProcedure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelSource {
    pub uri: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartKernel {
    pub format_version: u32,
    pub string_count: usize,
    pub libraries: Vec<KernelLibrary>,
    pub sources: Vec<KernelSource>,
    pub class_count: usize,
    pub procedure_count: usize,
    pub field_count: usize,
    pub bodies_recovered: usize,
}

#[must_use]
pub fn is_dart_kernel(bytes: &[u8]) -> bool {
    bytes.len() >= 4
        && u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) == DART_KERNEL_MAGIC
}

struct Cursor<'data> {
    bytes: &'data [u8],
    pos: usize,
}

impl<'data> Cursor<'data> {
    const fn at(bytes: &'data [u8], pos: usize) -> Self {
        Self { bytes, pos }
    }

    fn read_byte(&mut self) -> Option<u8> {
        let b: u8 = *self.bytes.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn read_uint(&mut self) -> Option<u64> {
        let b0: u8 = *self.bytes.get(self.pos)?;
        if b0 & 0x80 == 0 {
            self.pos += 1;
            return Some(u64::from(b0));
        }
        if b0 & 0x40 == 0 {
            let b1: u8 = *self.bytes.get(self.pos + 1)?;
            self.pos += 2;
            return Some((u64::from(b0 & 0x3f) << 8) | u64::from(b1));
        }
        let b1: u8 = *self.bytes.get(self.pos + 1)?;
        let b2: u8 = *self.bytes.get(self.pos + 2)?;
        let b3: u8 = *self.bytes.get(self.pos + 3)?;
        self.pos += 4;
        Some(
            (u64::from(b0 & 0x3f) << 24)
                | (u64::from(b1) << 16)
                | (u64::from(b2) << 8)
                | u64::from(b3),
        )
    }

    fn read_byte_list(&mut self) -> Option<&'data [u8]> {
        let len: usize = usize::try_from(self.read_uint()?).ok()?;
        let end: usize = self.pos.checked_add(len)?;
        let slice: &[u8] = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn skip_uint_list(&mut self) -> Option<()> {
        let count: u64 = self.read_uint()?;
        for _ in 0..count {
            self.read_uint()?;
        }
        Some(())
    }
}

const MEMBER_TABLE_CAP: usize = 1 << 20;

struct MemberTable {
    count: usize,
    start: usize,
}

#[must_use]
fn read_be_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let slice: &[u8] = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn member_table_from_count(bytes: &[u8], count_field_at: usize) -> Option<MemberTable> {
    let count: usize = usize::try_from(read_be_u32(bytes, count_field_at)?).ok()?;
    if count > MEMBER_TABLE_CAP {
        return None;
    }
    let table_bytes: usize = count.checked_add(1)?.checked_mul(4)?;
    let start: usize = count_field_at.checked_sub(table_bytes)?;
    Some(MemberTable { count, start })
}

fn member_table(bytes: &[u8], member_block_end: usize) -> Option<MemberTable> {
    member_table_from_count(bytes, member_block_end.checked_sub(4)?)
}

struct StringTable {
    strings: Vec<String>,
}

impl StringTable {
    fn parse(bytes: &[u8], offset: usize) -> Option<Self> {
        let mut cursor: Cursor<'_> = Cursor::at(bytes, offset);
        let count: usize = usize::try_from(cursor.read_uint()?).ok()?;
        let remaining: usize = bytes.len().saturating_sub(cursor.pos);
        if count > remaining || count > MEMBER_TABLE_CAP {
            return None;
        }
        let mut end_offsets: Vec<usize> = Vec::with_capacity(count.min(1 << 16));
        for _ in 0..count {
            end_offsets.push(usize::try_from(cursor.read_uint()?).ok()?);
        }
        let data_start: usize = cursor.pos;
        let mut strings: Vec<String> = Vec::with_capacity(end_offsets.len());
        let mut prev: usize = 0;
        for end in end_offsets {
            if end < prev {
                return None;
            }
            let from: usize = data_start.checked_add(prev)?;
            let to: usize = data_start.checked_add(end)?;
            let slice: &[u8] = bytes.get(from..to)?;
            strings.push(String::from_utf8_lossy(slice).into_owned());
            prev = end;
        }
        Some(Self { strings })
    }

    fn get(&self, index: usize) -> Option<&str> {
        self.strings.get(index).map(String::as_str)
    }
}

struct ComponentIndex {
    source_table_offset: usize,
    string_table_offset: usize,
    library_offsets: Vec<usize>,
}

fn parse_component_index(bytes: &[u8]) -> Option<ComponentIndex> {
    let n: usize = bytes.len();
    if n < 16 {
        return None;
    }
    let library_count: usize = usize::try_from(read_be_u32(bytes, n - 8)?).ok()?;
    if library_count > (1 << 24) {
        return None;
    }
    let library_offsets_bytes: usize = (library_count + 1).checked_mul(4)?;
    let library_offsets_start: usize = (n - 8).checked_sub(library_offsets_bytes)?;
    let mut library_offsets: Vec<usize> = Vec::with_capacity(library_count + 1);
    for i in 0..=library_count {
        let off: usize =
            usize::try_from(read_be_u32(bytes, library_offsets_start + i * 4)?).ok()?;
        library_offsets.push(off);
    }
    let fixed_block_start: usize = library_offsets_start
        .checked_sub(4)?
        .checked_sub(COMPONENT_INDEX_FIXED_FIELDS * 4)?;
    let source_table_offset: usize =
        usize::try_from(read_be_u32(bytes, fixed_block_start)?).ok()?;
    let string_table_offset: usize =
        usize::try_from(read_be_u32(bytes, fixed_block_start + 6 * 4)?).ok()?;
    Some(ComponentIndex {
        source_table_offset,
        string_table_offset,
        library_offsets,
    })
}

fn parse_sources(bytes: &[u8], offset: usize) -> Vec<KernelSource> {
    let mut out: Vec<KernelSource> = Vec::new();
    let Some(length): Option<usize> =
        read_be_u32(bytes, offset).and_then(|v: u32| usize::try_from(v).ok())
    else {
        return out;
    };
    let mut cursor: Cursor<'_> = Cursor::at(bytes, offset + 4);
    for _ in 0..length {
        let Some(uri): Option<&[u8]> = cursor.read_byte_list() else {
            break;
        };
        let Some(source): Option<&[u8]> = cursor.read_byte_list() else {
            break;
        };
        if cursor.skip_uint_list().is_none() {
            break;
        }
        let Some(_import): Option<&[u8]> = cursor.read_byte_list() else {
            break;
        };
        if cursor.skip_uint_list().is_none() {
            break;
        }
        out.push(KernelSource {
            uri: String::from_utf8_lossy(uri).into_owned(),
            text: String::from_utf8_lossy(source).into_owned(),
        });
    }
    out
}

#[must_use]
fn source_slice(
    sources: &[KernelSource],
    start_plus_one: u64,
    end_plus_one: u64,
) -> Option<String> {
    if start_plus_one == 0 || end_plus_one == 0 || end_plus_one <= start_plus_one {
        return None;
    }
    let start: usize = usize::try_from(start_plus_one - 1).ok()?;
    let end: usize = usize::try_from(end_plus_one - 1).ok()?;
    for source in sources {
        let text_bytes: &[u8] = source.text.as_bytes();
        if end <= text_bytes.len() && start < end {
            let slice: &[u8] = &text_bytes[start..end];
            return Some(String::from_utf8_lossy(slice).into_owned());
        }
    }
    None
}

struct NodeReader<'a, 'data> {
    cursor: Cursor<'data>,
    strings: &'a StringTable,
}

impl NodeReader<'_, '_> {
    fn read_name(&mut self) -> Option<(String, bool)> {
        let index: usize = usize::try_from(self.cursor.read_uint()?).ok()?;
        let raw: &str = self.strings.get(index).unwrap_or("");
        let is_private: bool = raw.starts_with('_');
        if is_private {
            self.cursor.read_uint()?;
        }
        Some((raw.to_owned(), is_private))
    }

    fn read_string_ref(&mut self) -> Option<String> {
        let index: usize = usize::try_from(self.cursor.read_uint()?).ok()?;
        Some(self.strings.get(index).unwrap_or("").to_owned())
    }
}

fn parse_procedure(
    bytes: &[u8],
    offset: usize,
    strings: &StringTable,
    sources: &[KernelSource],
) -> Option<KernelProcedure> {
    let mut reader: NodeReader<'_, '_> = NodeReader {
        cursor: Cursor::at(bytes, offset),
        strings,
    };
    let tag: u8 = reader.cursor.read_byte()?;
    if tag != PROCEDURE_TAG {
        return None;
    }
    reader.cursor.read_uint()?;
    reader.cursor.read_uint()?;
    let start_fo: u64 = reader.cursor.read_uint()?;
    let _file_fo: u64 = reader.cursor.read_uint()?;
    let end_fo: u64 = reader.cursor.read_uint()?;
    let kind_raw: u8 = reader.cursor.read_byte()?;
    let _stub_kind: u8 = reader.cursor.read_byte()?;
    let flags: u64 = reader.cursor.read_uint()?;
    let (name, is_private): (String, bool) = reader.read_name()?;
    let recovered_source: Option<String> = source_slice(sources, start_fo, end_fo);
    Some(KernelProcedure {
        name,
        kind: KernelProcedureKind::from_raw(kind_raw),
        is_private,
        is_abstract: flags & 0x01 == 0,
        start_offset: usize::try_from(start_fo.saturating_sub(1)).unwrap_or(0),
        end_offset: usize::try_from(end_fo.saturating_sub(1)).unwrap_or(0),
        recovered_source,
    })
}

fn extract_field_names(class_source: &str) -> Vec<String> {
    let mut fields: Vec<String> = Vec::new();
    let mut brace_depth: i32 = 0;
    for raw_line in class_source.lines() {
        let line: &str = raw_line.trim();
        let opens: i32 = line.matches('{').count() as i32;
        let closes: i32 = line.matches('}').count() as i32;
        let starts_at_depth_one: bool = brace_depth == 1;
        brace_depth += opens - closes;
        if !starts_at_depth_one || !line.ends_with(';') {
            continue;
        }
        if line.contains('(') || line.contains("=>") {
            continue;
        }
        if let Some(name) = field_name_from_declaration(line)
            && !fields.contains(&name)
        {
            fields.push(name);
        }
    }
    fields
}

#[must_use]
fn field_name_from_declaration(line: &str) -> Option<String> {
    let trimmed: &str = line.trim_end_matches(';').trim();
    let head: &str = trimmed.split('=').next().unwrap_or(trimmed).trim();
    let mut tokens: Vec<&str> = head.split_whitespace().collect::<Vec<&str>>();
    for keyword in ["static", "final", "const", "late", "covariant"] {
        while tokens.first() == Some(&keyword) {
            tokens.remove(0);
        }
    }
    if tokens.len() < 2 {
        return None;
    }
    let candidate: &str = tokens.last()?;
    let valid: bool = candidate.chars().enumerate().all(|(i, c): (usize, char)| {
        if i == 0 {
            c.is_ascii_alphabetic() || c == '_'
        } else {
            c.is_ascii_alphanumeric() || c == '_'
        }
    });
    if valid && !candidate.is_empty() {
        Some(candidate.to_owned())
    } else {
        None
    }
}

fn member_offsets(bytes: &[u8], member_block_end: usize) -> Option<Vec<usize>> {
    let table: MemberTable = member_table(bytes, member_block_end)?;
    let mut out: Vec<usize> = Vec::with_capacity(table.count);
    for i in 0..table.count {
        let at: usize = table.start.checked_add(i.checked_mul(4)?)?;
        out.push(usize::try_from(read_be_u32(bytes, at)?).ok()?);
    }
    Some(out)
}

fn parse_class(
    bytes: &[u8],
    start: usize,
    end: usize,
    strings: &StringTable,
    sources: &[KernelSource],
) -> Option<KernelClass> {
    let mut reader: NodeReader<'_, '_> = NodeReader {
        cursor: Cursor::at(bytes, start),
        strings,
    };
    let tag: u8 = reader.cursor.read_byte()?;
    if tag != CLASS_TAG {
        return None;
    }
    reader.cursor.read_uint()?;
    reader.cursor.read_uint()?;
    let start_fo: u64 = reader.cursor.read_uint()?;
    let _file_fo: u64 = reader.cursor.read_uint()?;
    let end_fo: u64 = reader.cursor.read_uint()?;
    let flags: u8 = reader.cursor.read_byte()?;
    let name: String = reader.read_string_ref()?;

    let procedures: Vec<KernelProcedure> = member_offsets(bytes, end)
        .map(|offsets: Vec<usize>| {
            offsets
                .into_iter()
                .filter_map(|o: usize| parse_procedure(bytes, o, strings, sources))
                .collect::<Vec<KernelProcedure>>()
        })
        .unwrap_or_default();

    let recovered_source: Option<String> = source_slice(sources, start_fo, end_fo);
    let fields: Vec<String> = recovered_source
        .as_deref()
        .map(extract_field_names)
        .unwrap_or_default();

    Some(KernelClass {
        name,
        is_abstract: flags & 0x01 != 0,
        fields,
        procedures,
        recovered_source,
    })
}

fn parse_library(
    bytes: &[u8],
    start: usize,
    end: usize,
    strings: &StringTable,
    sources: &[KernelSource],
) -> Option<KernelLibrary> {
    if end <= start || end > bytes.len() {
        return None;
    }
    let mut reader: NodeReader<'_, '_> = NodeReader {
        cursor: Cursor::at(bytes, start),
        strings,
    };
    let _flags: u8 = reader.cursor.read_byte()?;
    reader.cursor.read_uint()?;
    reader.cursor.read_uint()?;
    reader.cursor.read_uint()?;
    let name_index: usize = usize::try_from(reader.cursor.read_uint()?).ok()?;
    let name: Option<String> = strings
        .get(name_index)
        .filter(|s: &&str| !s.is_empty())
        .map(str::to_owned);
    let file_uri_index: usize = usize::try_from(reader.cursor.read_uint()?).ok()?;
    let file_uri: Option<String> = strings
        .get(file_uri_index)
        .filter(|s: &&str| !s.is_empty())
        .map(str::to_owned);

    let proc_table: MemberTable = member_table(bytes, end)?;
    let mut procedures: Vec<KernelProcedure> = Vec::with_capacity(proc_table.count);
    for i in 0..proc_table.count {
        let at: usize = proc_table.start.checked_add(i.checked_mul(4)?)?;
        if let Some(off) = read_be_u32(bytes, at).and_then(|v: u32| usize::try_from(v).ok())
            && let Some(proc) = parse_procedure(bytes, off, strings, sources)
        {
            procedures.push(proc);
        }
    }

    let class_count_field_at: usize = proc_table.start.checked_sub(4)?;
    let class_table: MemberTable = member_table_from_count(bytes, class_count_field_at)?;
    let class_offset_count: usize = class_table.count.checked_add(1)?;
    let mut class_offsets: Vec<usize> = Vec::with_capacity(class_offset_count);
    for i in 0..class_offset_count {
        let at: usize = class_table.start.checked_add(i.checked_mul(4)?)?;
        let off: usize = read_be_u32(bytes, at).and_then(|v: u32| usize::try_from(v).ok())?;
        class_offsets.push(off);
    }
    let mut classes: Vec<KernelClass> = Vec::with_capacity(class_table.count);
    for window in class_offsets.windows(2) {
        if let Some(class) = parse_class(bytes, window[0], window[1], strings, sources) {
            classes.push(class);
        }
    }

    Some(KernelLibrary {
        name,
        import_uri: None,
        file_uri,
        classes,
        procedures,
    })
}

pub fn parse_kernel(bytes: &[u8]) -> Result<DartKernel> {
    dbg_section("dart.kernel");
    if bytes.len() < KERNEL_HEADER_MIN || !is_dart_kernel(bytes) {
        return Err(Error::DartKernelBadMagic);
    }
    let format_version: u32 =
        read_be_u32(bytes, 4).ok_or(Error::DartKernelSection("kernel-version"))?;
    dbg_kv("format_version", || format_version.to_string());
    let index: ComponentIndex =
        parse_component_index(bytes).ok_or(Error::DartKernelSection("component-index"))?;
    let strings: StringTable = StringTable::parse(bytes, index.string_table_offset)
        .ok_or(Error::DartKernelSection("string-table"))?;
    let sources: Vec<KernelSource> = parse_sources(bytes, index.source_table_offset);

    let mut libraries: Vec<KernelLibrary> = Vec::new();
    for window in index.library_offsets.windows(2) {
        if let Some(library) = parse_library(bytes, window[0], window[1], &strings, &sources) {
            libraries.push(library);
        }
    }

    let mut class_count: usize = 0;
    let mut procedure_count: usize = 0;
    let mut field_count: usize = 0;
    let mut bodies_recovered: usize = 0;
    for library in &libraries {
        class_count += library.classes.len();
        for proc in &library.procedures {
            procedure_count += 1;
            if proc.recovered_source.is_some() {
                bodies_recovered += 1;
            }
        }
        for class in &library.classes {
            field_count += class.fields.len();
            for proc in &class.procedures {
                procedure_count += 1;
                if proc.recovered_source.is_some() {
                    bodies_recovered += 1;
                }
            }
        }
    }

    dbg_kv("libraries", || libraries.len().to_string());
    dbg_kv("classes", || class_count.to_string());
    dbg_kv("procedures", || procedure_count.to_string());
    dbg_kv("bodies_recovered", || bodies_recovered.to_string());

    Ok(DartKernel {
        format_version,
        string_count: strings.strings.len(),
        libraries,
        sources,
        class_count,
        procedure_count,
        field_count,
        bodies_recovered,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn encode_uint(value: u64) -> Vec<u8> {
        if value < 0x80 {
            vec![value as u8]
        } else if value < 0x4000 {
            vec![0x80 | ((value >> 8) as u8), (value & 0xff) as u8]
        } else {
            vec![
                0xc0 | ((value >> 24) as u8),
                ((value >> 16) & 0xff) as u8,
                ((value >> 8) & 0xff) as u8,
                (value & 0xff) as u8,
            ]
        }
    }

    #[test]
    fn uint_round_trip_one_two_four_bytes() {
        for value in [0u64, 1, 127, 128, 16_383, 16_384, 1_000_000, (1 << 30) - 1] {
            let encoded: Vec<u8> = encode_uint(value);
            let mut cursor: Cursor<'_> = Cursor::at(&encoded, 0);
            assert_eq!(cursor.read_uint(), Some(value), "round trip {value}");
            assert_eq!(cursor.pos, encoded.len(), "consumed all bytes for {value}");
        }
    }

    #[test]
    fn magic_detection() {
        let mut bytes: Vec<u8> = vec![0x90, 0xab, 0xcd, 0xef];
        bytes.extend_from_slice(&[0, 0, 0, 130]);
        assert!(is_dart_kernel(&bytes));
        bytes[0] = 0x00;
        assert!(!is_dart_kernel(&bytes));
    }

    #[test]
    fn string_table_round_trip() {
        let mut buf: Vec<u8> = Vec::new();
        let entries: [&str; 3] = ["", "Widget", "build"];
        buf.extend_from_slice(&encode_uint(entries.len() as u64));
        let mut running: u64 = 0;
        for e in entries {
            running += e.len() as u64;
            buf.extend_from_slice(&encode_uint(running));
        }
        for e in entries {
            buf.extend_from_slice(e.as_bytes());
        }
        let table: StringTable = StringTable::parse(&buf, 0).expect("parse string table");
        assert_eq!(table.get(0), Some(""));
        assert_eq!(table.get(1), Some("Widget"));
        assert_eq!(table.get(2), Some("build"));
    }

    #[test]
    fn string_table_rejects_huge_count_before_allocating() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&encode_uint((1 << 30) - 1));
        buf.extend_from_slice(b"three");
        assert!(
            StringTable::parse(&buf, 0).is_none(),
            "a billion-entry count over a seven-byte buffer must be rejected, not allocated"
        );
    }

    #[test]
    fn string_table_huge_count_propagates_to_bounded_error() {
        let mut buf: Vec<u8> = vec![0x90, 0xab, 0xcd, 0xef, 0, 0, 0, 1];
        let table_offset: usize = buf.len();
        buf.extend_from_slice(&encode_uint((1 << 30) - 1));
        buf.extend_from_slice(b"payload");
        let err: Error = StringTable::parse(&buf, table_offset)
            .map_or(Error::DartKernelSection("string-table"), |_| {
                Error::DartKernelBadMagic
            });
        assert!(
            matches!(err, Error::DartKernelSection("string-table")),
            "huge count must surface as the bounded string-table section error, got {err:?}"
        );
    }

    #[test]
    fn member_table_rejects_count_over_cap() {
        let mut bytes: Vec<u8> = vec![0; 8];
        bytes.extend_from_slice(&(MEMBER_TABLE_CAP as u32 + 1).to_be_bytes());
        assert!(member_table(&bytes, bytes.len()).is_none());
    }

    #[test]
    fn parse_library_rejects_oversized_member_table_count() {
        let mut bytes: Vec<u8> = vec![0, 0, 0, 0, 0, 0];
        bytes.extend_from_slice(&(MEMBER_TABLE_CAP as u32 + 1).to_be_bytes());
        let strings: StringTable = StringTable {
            strings: vec![String::new()],
        };
        let sources: Vec<KernelSource> = Vec::new();
        assert!(parse_library(&bytes, 0, bytes.len(), &strings, &sources).is_none());
    }

    #[test]
    fn source_slice_subtracts_offset_encoding() {
        let sources: Vec<KernelSource> = vec![KernelSource {
            uri: "file:///a.dart".to_owned(),
            text: "int f() => 1;".to_owned(),
        }];
        let slice: String = source_slice(&sources, 1, 7).expect("slice present");
        assert_eq!(slice, "int f(");
        assert!(source_slice(&sources, 0, 7).is_none());
        assert!(source_slice(&sources, 7, 7).is_none());
    }

    #[test]
    fn non_kernel_bytes_rejected() {
        let err: Error = parse_kernel(&[0u8; 64]).expect_err("must reject");
        assert!(matches!(err, Error::DartKernelBadMagic));
    }

    #[test]
    fn field_extractor_recovers_declarations_not_methods() {
        let src: &str = "class InventoryItem {\n  final String skuLabel;\n  final int quantityOnHand;\n  final double unitPriceUsd;\n\n  const InventoryItem(this.skuLabel, this.quantityOnHand, this.unitPriceUsd);\n\n  double extendedValue() => quantityOnHand * unitPriceUsd;\n\n  bool get isBackordered => quantityOnHand <= 0;\n}";
        let fields: Vec<String> = extract_field_names(src);
        assert_eq!(
            fields,
            vec![
                "skuLabel".to_owned(),
                "quantityOnHand".to_owned(),
                "unitPriceUsd".to_owned()
            ],
            "must recover exactly the three instance fields, not constructors/methods/getters"
        );
    }

    #[test]
    fn field_extractor_ignores_local_variables_in_method_bodies() {
        let src: &str = "class C {\n  int total;\n  void run() {\n    int local = 0;\n    var other = 1;\n  }\n}";
        let fields: Vec<String> = extract_field_names(src);
        assert_eq!(
            fields,
            vec!["total".to_owned()],
            "locals at brace depth 2 must not be treated as fields"
        );
    }

    #[test]
    fn member_offsets_short_block_does_not_underflow() {
        let bytes: Vec<u8> = vec![0u8; 64];
        for end in 0..=4usize {
            assert!(
                member_offsets(&bytes, end).is_none(),
                "member_offsets must reject block-end {end} without panicking"
            );
        }
    }

    #[test]
    fn parse_library_and_class_reject_short_end_offsets() {
        let bytes: Vec<u8> = vec![0u8; 64];
        let strings: StringTable = StringTable {
            strings: Vec::new(),
        };
        let sources: Vec<KernelSource> = Vec::new();
        for end in 0..4usize {
            assert!(
                parse_library(&bytes, 0, end, &strings, &sources).is_none(),
                "parse_library must reject end {end} without underflow panic"
            );
            assert!(
                parse_class(&bytes, 0, end, &strings, &sources).is_none(),
                "parse_class must reject end {end} without underflow panic"
            );
        }
    }
}
