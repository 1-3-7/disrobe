use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use disrobe_core::debug::DebugLog;

use crate::util::{find_subslice, pe_data_section_ranges};

const QUALNAME_FLAG: u64 = 0x1;
const FREE_VARS_FLAG: u64 = 0x2;
const KW_ONLY_FLAG: u64 = 0x4;
const POS_ONLY_FLAG: u64 = 0x8;
const KIND_MASK: u64 = 0x30;

const MAX_DEPTH: usize = 200;
const MAX_NAME_LEN: usize = 200;
const MIN_CHUNK_SIZE: u64 = 2;
const MAX_CHUNK_COUNT: u64 = 200_000;
const SIZE_SLACK: i64 = 8;
const MAX_VALUE_BYTES: usize = 64 * 1024 * 1024;
const MAX_CHUNK_BYTES: u64 = 64 * 1024 * 1024;
const MAX_STORED_LAST_WEIGHT: usize = 4096;
const MAX_PREVIOUS_CLONE_WEIGHT: usize = 128 * 1024;
const MAX_WIDE_SCAN_BYTES: usize = 256 * 1024 * 1024;
const MAX_TABLE_HEADER_HINTS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkValueLayout {
    ModernVarint,
    LegacyFixed32,
    LegacyFixed64,
}

impl ChunkValueLayout {
    const fn label(self) -> &'static str {
        match self {
            Self::ModernVarint => "modern-varint",
            Self::LegacyFixed32 => "legacy-fixed32",
            Self::LegacyFixed64 => "legacy-fixed64",
        }
    }

    const fn is_modern(self) -> bool {
        matches!(self, Self::ModernVarint)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CodeKind {
    Function,
    Generator,
    Coroutine,
    AsyncGenerator,
}

impl CodeKind {
    const fn from_flags(flags: u64) -> Self {
        match flags & KIND_MASK {
            0x10 => Self::Generator,
            0x20 => Self::Coroutine,
            0x30 => Self::AsyncGenerator,
            _ => Self::Function,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeObjectMeta {
    pub name: String,
    pub qualname: Option<String>,
    pub filename: Option<String>,
    pub firstlineno: u32,
    pub argcount: u32,
    pub kwonlyargcount: u32,
    pub posonlyargcount: u32,
    pub varnames: Vec<String>,
    pub freevars: Vec<String>,
    pub kind: CodeKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ConstItem {
    Str {
        value: String,
    },
    AnnotationDict {
        params: Vec<(String, String)>,
        ret: Option<String>,
    },
    StrTuple {
        items: Vec<String>,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleConstants {
    pub name: String,
    pub blob_offset: u64,
    pub chunk_size: u32,
    pub value_count: u32,
    pub ordered_strings: Vec<String>,
    pub ordered_items: Vec<ConstItem>,
    pub strings: BTreeSet<String>,
    pub ints: BTreeSet<i64>,
    pub float_count: usize,
    pub byte_blobs: usize,
    pub code_objects: Vec<CodeObjectMeta>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NuitkaConstants {
    pub modules: Vec<ModuleConstants>,
    pub region_offset: u64,
    pub region_len: u64,
}

impl NuitkaConstants {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    #[must_use]
    pub fn module_names(&self) -> Vec<String> {
        self.modules
            .iter()
            .map(|m: &ModuleConstants| m.name.clone())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Value {
    None,
    Bool(bool),
    Int(i64),
    BigInt,
    Float(f64),
    Complex,
    Str(String),
    Bytes(usize),
    Seq(Vec<Self>),
    Mapping(Vec<Self>),
    Builtin(String),
    Code(Box<CodeObjectMeta>),
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    last: Option<Value>,
    last_weight: usize,
    previous_clone_weight: usize,
    layout: ChunkValueLayout,
}

impl<'a> Reader<'a> {
    const fn new(buf: &'a [u8], pos: usize, layout: ChunkValueLayout) -> Self {
        Self {
            buf,
            pos,
            last: None,
            last_weight: 0,
            previous_clone_weight: 0,
            layout,
        }
    }

    fn u8(&mut self) -> Option<u8> {
        let byte: u8 = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(byte)
    }

    fn varint(&mut self) -> Option<u64> {
        let mut value: u64 = 0;
        let mut shift: u32 = 0;
        loop {
            if shift >= 64 {
                return None;
            }
            let byte: u8 = self.u8()?;
            value |= u64::from(byte & 0x7F) << shift;
            if byte & 0x80 == 0 {
                return Some(value);
            }
            shift += 7;
        }
    }

    fn i32(&mut self) -> Option<i32> {
        let raw: &[u8] = self.buf.get(self.pos..self.pos + 4)?;
        self.pos += 4;
        Some(i32::from_le_bytes(raw.try_into().ok()?))
    }

    fn i64(&mut self) -> Option<i64> {
        let raw: &[u8] = self.buf.get(self.pos..self.pos + 8)?;
        self.pos += 8;
        Some(i64::from_le_bytes(raw.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        let raw: &[u8] = self.buf.get(self.pos..self.pos + 8)?;
        self.pos += 8;
        Some(u64::from_le_bytes(raw.try_into().ok()?))
    }

    fn length(&mut self) -> Option<u64> {
        match self.layout {
            ChunkValueLayout::ModernVarint => self.varint(),
            ChunkValueLayout::LegacyFixed32 | ChunkValueLayout::LegacyFixed64 => {
                u64::try_from(self.i32()?).ok()
            }
        }
    }

    fn bounded_len(&mut self) -> Option<usize> {
        let len: usize = usize::try_from(self.length()?).ok()?;
        if len > MAX_VALUE_BYTES || len > self.buf.len().saturating_sub(self.pos) {
            return None;
        }
        Some(len)
    }

    fn zstr(&mut self) -> Option<String> {
        let rel: usize = self
            .buf
            .get(self.pos..)?
            .iter()
            .position(|&b: &u8| b == 0)?;
        let slice: &[u8] = self.buf.get(self.pos..self.pos + rel)?;
        let text: String = String::from_utf8_lossy(slice).into_owned();
        self.pos += rel + 1;
        Some(text)
    }

    fn value(&mut self, depth: usize) -> Option<Value> {
        if depth > MAX_DEPTH {
            return None;
        }
        let tag: u8 = self.u8()?;
        let value: Value = self.value_body(tag, depth)?;
        if tag != 0x70 {
            let weight: usize = value_weight(&value)?;
            if weight <= MAX_STORED_LAST_WEIGHT {
                self.last = Some(value.clone());
                self.last_weight = weight;
            } else {
                self.last = None;
                self.last_weight = 0;
            }
        }
        Some(value)
    }

    fn value_body(&mut self, tag: u8, depth: usize) -> Option<Value> {
        match tag {
            0x70 => {
                self.previous_clone_weight =
                    self.previous_clone_weight.checked_add(self.last_weight)?;
                if self.previous_clone_weight > MAX_PREVIOUS_CLONE_WEIGHT {
                    return None;
                }
                Some(self.last.as_ref()?.clone())
            }
            0x6E => Some(Value::None),
            0x74 => Some(Value::Bool(true)),
            0x46 => Some(Value::Bool(false)),
            0x73 => Some(Value::Str(String::new())),
            0x54 | 0x4C | 0x53 | 0x50 => {
                let count: u64 = self.length()?;
                self.sequence(count, depth)
            }
            0x44 => {
                let count: u64 = self.length()?;
                if count > MAX_CHUNK_COUNT / 2 {
                    return None;
                }
                let mut items: Vec<Value> = Vec::new();
                for _ in 0..count.saturating_mul(2) {
                    items.push(self.value(depth + 1)?);
                }
                Some(Value::Mapping(items))
            }
            0x69 | 0x6C | 0x49 | 0x71 => Some(Value::Int(self.integer(tag)?)),
            0x67 => self.big_int(true),
            0x47 if self.layout.is_modern() => self.big_int(false),
            0x41 | 0x47 => {
                let origin: Value = self.value(depth + 1)?;
                let _ = self.value(depth + 1)?;
                Some(origin)
            }
            0x66 => {
                let raw: &[u8] = self.buf.get(self.pos..self.pos + 8)?;
                let bytes: [u8; 8] = raw.try_into().ok()?;
                self.pos += 8;
                Some(Value::Float(f64::from_le_bytes(bytes)))
            }
            0x5A => {
                self.u8()?;
                Some(Value::Float(f64::NAN))
            }
            0x6A => {
                let _ = self.buf.get(self.pos..self.pos + 16)?;
                self.pos += 16;
                Some(Value::Complex)
            }
            0x4A => {
                self.u8()?;
                Some(Value::Complex)
            }
            0x77 => {
                let byte: u8 = self.u8()?;
                Some(Value::Str(String::from_utf8_lossy(&[byte]).into_owned()))
            }
            0x76 => {
                let len: usize = self.bounded_len()?;
                let slice: &[u8] = self.buf.get(self.pos..self.pos + len)?;
                let text: String = String::from_utf8_lossy(slice).into_owned();
                self.pos += len;
                Some(Value::Str(text))
            }
            0x75 | 0x61 => Some(Value::Str(self.zstr()?)),
            0x64 => {
                self.u8()?;
                Some(Value::Bytes(1))
            }
            0x62 | 0x42 | 0x58 => {
                let len: usize = self.bounded_len()?;
                let _ = self.buf.get(self.pos..self.pos + len)?;
                self.pos += len;
                Some(Value::Bytes(len))
            }
            0x63 => {
                let rel: usize = self
                    .buf
                    .get(self.pos..)?
                    .iter()
                    .position(|&b: &u8| b == 0)?;
                self.pos += rel + 1;
                Some(Value::Bytes(rel))
            }
            0x3A | 0x3B => self.sequence(3, depth),
            0x4D | 0x51 => {
                self.u8()?;
                Some(Value::Builtin(String::new()))
            }
            0x4F | 0x45 => Some(Value::Builtin(self.zstr()?)),
            0x48 => self.value(depth + 1),
            0x43 => Some(Value::Code(Box::new(self.code_object(depth)?))),
            _ => None,
        }
    }

    fn integer(&mut self, tag: u8) -> Option<i64> {
        match self.layout {
            ChunkValueLayout::ModernVarint => {
                let value: u64 = self.varint()?;
                let signed: i64 = i64::try_from(value).ok()?;
                Some(if matches!(tag, 0x49 | 0x71) {
                    -signed
                } else {
                    signed
                })
            }
            ChunkValueLayout::LegacyFixed32 => match tag {
                0x71 => self.i64(),
                _ => Some(i64::from(self.i32()?)),
            },
            ChunkValueLayout::LegacyFixed64 => self.i64(),
        }
    }

    fn big_int(&mut self, signed_by_prefix: bool) -> Option<Value> {
        match self.layout {
            ChunkValueLayout::ModernVarint => {
                let digits: u64 = self.varint()?;
                for _ in 0..digits {
                    self.varint()?;
                }
                Some(Value::BigInt)
            }
            ChunkValueLayout::LegacyFixed32 | ChunkValueLayout::LegacyFixed64 => {
                if signed_by_prefix {
                    self.u8()?;
                }
                let digits: u64 = self.length()?;
                if digits > MAX_CHUNK_COUNT {
                    return None;
                }
                for _ in 0..digits {
                    self.u64()?;
                }
                Some(Value::BigInt)
            }
        }
    }

    fn sequence(&mut self, count: u64, depth: usize) -> Option<Value> {
        if count > MAX_CHUNK_COUNT {
            return None;
        }
        let mut items: Vec<Value> = Vec::with_capacity(usize::try_from(count).ok()?.min(4096));
        for _ in 0..count {
            items.push(self.value(depth + 1)?);
        }
        Some(Value::Seq(items))
    }

    fn code_object(&mut self, depth: usize) -> Option<CodeObjectMeta> {
        let flags: u64 = self.varint()?;
        let name: Value = self.value(depth + 1)?;
        let name_str: String = value_as_str(&name).unwrap_or_default();
        let firstlineno: u32 = u32::try_from(self.varint()?).ok()?.saturating_add(1);
        let varnames: Value = self.value(depth + 1)?;
        let argcount: u32 = u32::try_from(self.varint()?).ok()?;
        let qualname: Option<String> = if flags & QUALNAME_FLAG != 0 {
            value_as_str(&self.value(depth + 1)?).map(|stored: String| {
                if name_str.is_empty() {
                    stored
                } else {
                    format!("{stored}.{name_str}")
                }
            })
        } else {
            None
        };
        let freevars: Vec<String> = if flags & FREE_VARS_FLAG != 0 {
            value_as_strings(&self.value(depth + 1)?)
        } else {
            Vec::new()
        };
        let kwonlyargcount: u32 = if flags & KW_ONLY_FLAG != 0 {
            u32::try_from(self.varint()?).ok()?.saturating_add(1)
        } else {
            0
        };
        let posonlyargcount: u32 = if flags & POS_ONLY_FLAG != 0 {
            u32::try_from(self.varint()?).ok()?.saturating_add(1)
        } else {
            0
        };
        Some(CodeObjectMeta {
            name: name_str,
            qualname,
            filename: None,
            firstlineno,
            argcount,
            kwonlyargcount,
            posonlyargcount,
            varnames: value_as_strings(&varnames),
            freevars,
            kind: CodeKind::from_flags(flags),
        })
    }
}

fn value_as_str(value: &Value) -> Option<String> {
    match value {
        Value::Str(s) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

fn value_as_strings(value: &Value) -> Vec<String> {
    match value {
        Value::Seq(items) => items.iter().filter_map(value_as_str).collect(),
        _ => Vec::new(),
    }
}

fn value_weight(value: &Value) -> Option<usize> {
    match value {
        Value::None
        | Value::Bool(_)
        | Value::Int(_)
        | Value::BigInt
        | Value::Float(_)
        | Value::Complex
        | Value::Bytes(_) => Some(1),
        Value::Str(s) | Value::Builtin(s) => s.len().checked_add(1),
        Value::Seq(items) | Value::Mapping(items) => {
            let mut total: usize = 1;
            for item in items {
                total = total.checked_add(value_weight(item)?)?;
            }
            Some(total)
        }
        Value::Code(code) => {
            let mut total: usize = 1usize
                .checked_add(code.name.len())?
                .checked_add(code.qualname.as_ref().map_or(0, String::len))?
                .checked_add(code.filename.as_ref().map_or(0, String::len))?;
            for item in code.varnames.iter().chain(code.freevars.iter()) {
                total = total.checked_add(item.len())?;
            }
            Some(total)
        }
    }
}

#[derive(Default)]
struct ModuleCollector {
    ordered_strings: Vec<String>,
    ordered_items: Vec<ConstItem>,
    strings: BTreeSet<String>,
    ints: BTreeSet<i64>,
    float_count: usize,
    byte_blobs: usize,
    code_objects: Vec<CodeObjectMeta>,
}

impl ModuleCollector {
    fn collect_top_level(&mut self, value: &Value) {
        if let Some(item) = const_item(value) {
            self.ordered_items.push(item);
        }
        self.collect(value);
    }

    fn collect(&mut self, value: &Value) {
        match value {
            Value::Str(s) => {
                if !s.is_empty() {
                    self.ordered_strings.push(s.clone());
                    self.strings.insert(s.clone());
                }
            }
            Value::Int(i) => {
                self.ints.insert(*i);
            }
            Value::Float(_) => self.float_count += 1,
            Value::Bytes(_) => self.byte_blobs += 1,
            Value::Builtin(name) => {
                if !name.is_empty() {
                    self.ordered_strings.push(name.clone());
                    self.strings.insert(name.clone());
                }
            }
            Value::Seq(items) | Value::Mapping(items) => {
                for item in items {
                    self.collect(item);
                }
            }
            Value::Code(code) => {
                if let Some(qn) = &code.qualname {
                    self.strings.insert(qn.clone());
                }
                self.strings.insert(code.name.clone());
                for vn in &code.varnames {
                    self.strings.insert(vn.clone());
                }
                self.code_objects.push((**code).clone());
            }
            Value::None | Value::Bool(_) | Value::BigInt | Value::Complex => {}
        }
    }
}

fn const_item(value: &Value) -> Option<ConstItem> {
    match value {
        Value::Str(s) if !s.is_empty() => Some(ConstItem::Str { value: s.clone() }),
        Value::Mapping(items) => annotation_dict(items),
        Value::Seq(items) => {
            let strings: Vec<String> = items.iter().filter_map(value_as_str).collect();
            (strings.len() == items.len() && !strings.is_empty())
                .then_some(ConstItem::StrTuple { items: strings })
        }
        _ => None,
    }
}

fn annotation_dict(items: &[Value]) -> Option<ConstItem> {
    if items.is_empty() || !items.len().is_multiple_of(2) {
        return None;
    }
    let pair_count: usize = items.len() / 2;
    let (keys, values): (&[Value], &[Value]) = items.split_at(pair_count);
    let mut params: Vec<(String, String)> = Vec::new();
    let mut ret: Option<String> = None;
    for (key, value) in keys.iter().zip(values.iter()) {
        let key_str: String = value_as_str(key)?;
        if !is_identifier(&key_str) {
            return None;
        }
        let type_str: String = annotation_to_str(value)?;
        if key_str == "return" {
            ret = Some(type_str);
        } else {
            params.push((key_str, type_str));
        }
    }
    ret.as_ref()?;
    Some(ConstItem::AnnotationDict { params, ret })
}

fn annotation_to_str(value: &Value) -> Option<String> {
    match value {
        Value::Str(s) if is_type_annotation(s) => Some(s.clone()),
        Value::Builtin(s) if !s.is_empty() => Some(s.clone()),
        Value::None => Some("None".to_owned()),
        _ => None,
    }
}

fn is_type_annotation(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 120
        && s.chars()
            .next()
            .is_some_and(|c: char| c.is_ascii_alphabetic() || c == '_')
        && s.chars().all(|c: char| {
            c.is_ascii_alphanumeric()
                || matches!(c, '_' | '.' | '[' | ']' | ',' | ' ' | '|' | '(' | ')')
        })
}

fn is_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .next()
            .is_some_and(|c: char| c.is_ascii_alphabetic() || c == '_')
        && s.chars()
            .all(|c: char| c.is_ascii_alphanumeric() || c == '_')
}

struct ParsedChunk {
    module: ModuleConstants,
    next: usize,
    layout: ChunkValueLayout,
    slack: u64,
}

fn try_chunk(buf: &[u8], pos: usize) -> Option<ParsedChunk> {
    let mut best: Option<ParsedChunk> = None;
    for layout in [
        ChunkValueLayout::ModernVarint,
        ChunkValueLayout::LegacyFixed32,
        ChunkValueLayout::LegacyFixed64,
    ] {
        if let Some(parsed) = try_chunk_with_layout(buf, pos, layout)
            && best
                .as_ref()
                .is_none_or(|candidate: &ParsedChunk| parsed.slack < candidate.slack)
        {
            best = Some(parsed);
        }
    }
    best
}

fn try_chunk_with_layout(buf: &[u8], pos: usize, layout: ChunkValueLayout) -> Option<ParsedChunk> {
    let name_end: usize = buf.get(pos..)?.iter().position(|&b: &u8| b == 0)? + pos;
    let name_bytes: &[u8] = buf.get(pos..name_end)?;
    if name_bytes.is_empty()
        || name_bytes.len() > MAX_NAME_LEN
        || !name_bytes.iter().all(|&b: &u8| (0x20..0x7F).contains(&b))
    {
        return None;
    }
    let after: usize = name_end + 1;
    let size_bytes: &[u8] = buf.get(after..after + 4)?;
    let size: u64 = u64::from(u32::from_le_bytes(size_bytes.try_into().ok()?));
    let max_size: u64 = u64::try_from(buf.len().checked_sub(after + 4)?).ok()?;
    if size < MIN_CHUNK_SIZE || size > max_size || size > MAX_CHUNK_BYTES {
        return None;
    }
    let payload_start: usize = after + 4;
    let count_bytes: &[u8] = buf.get(payload_start..payload_start + 2)?;
    let count: u64 = u64::from(u16::from_le_bytes(count_bytes.try_into().ok()?));
    if count == 0 || count > MAX_CHUNK_COUNT {
        return None;
    }

    let mut reader: Reader<'_> = Reader::new(buf, payload_start + 2, layout);
    let mut collector: ModuleCollector = ModuleCollector::default();
    for _ in 0..count {
        let value: Value = reader.value(0)?;
        collector.collect_top_level(&value);
    }
    let consumed: i64 = i64::try_from(reader.pos.checked_sub(payload_start)?).ok()?;
    let expected: i64 = i64::try_from(size).ok()?;
    let slack: u64 = consumed.abs_diff(expected);
    if slack > u64::try_from(SIZE_SLACK).ok()? {
        return None;
    }

    let module: ModuleConstants = ModuleConstants {
        name: String::from_utf8_lossy(name_bytes).into_owned(),
        blob_offset: u64::try_from(pos).ok()?,
        chunk_size: u32::try_from(size).ok()?,
        value_count: u32::try_from(count).ok()?,
        ordered_strings: collector.ordered_strings,
        ordered_items: collector.ordered_items,
        strings: collector.strings,
        ints: collector.ints,
        float_count: collector.float_count,
        byte_blobs: collector.byte_blobs,
        code_objects: collector.code_objects,
    };
    Some(ParsedChunk {
        module,
        next: payload_start + usize::try_from(size).ok()?,
        layout,
        slack,
    })
}

fn chunk_qualifies(module: &ModuleConstants) -> bool {
    !module.code_objects.is_empty() || module.strings.len() >= 2
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConstantsUnparsedReason {
    NoPlaintextTable,
    LoaderMarkerPresent,
    TableHeaderPresent,
    WideScanSkipped,
}

pub(crate) fn constants_unparsed_reason(image: &[u8]) -> ConstantsUnparsedReason {
    let ranges: Vec<(usize, usize)> = primary_scan_ranges(image);
    if table_header_hints(image, &ranges) > 0 {
        return ConstantsUnparsedReason::TableHeaderPresent;
    }
    if full_scan_fallback_allowed(image, &ranges)
        && table_header_hints(image, &[(0usize, image.len())]) > 0
    {
        return ConstantsUnparsedReason::TableHeaderPresent;
    }
    if full_scan_fallback_skipped(image, &ranges) {
        return ConstantsUnparsedReason::WideScanSkipped;
    }
    if find_subslice(image, b"loadConstantsBlob").is_some()
        || find_subslice(image, b"createGlobalConstants").is_some()
        || find_subslice(image, b"constant_bin").is_some()
    {
        return ConstantsUnparsedReason::LoaderMarkerPresent;
    }
    ConstantsUnparsedReason::NoPlaintextTable
}

fn primary_scan_ranges(image: &[u8]) -> Vec<(usize, usize)> {
    pe_data_section_ranges(image).unwrap_or_else(|| vec![(0usize, image.len())])
}

fn full_scan_fallback_allowed(image: &[u8], ranges: &[(usize, usize)]) -> bool {
    !is_full_range(image, ranges) && image.len() <= MAX_WIDE_SCAN_BYTES
}

fn full_scan_fallback_skipped(image: &[u8], ranges: &[(usize, usize)]) -> bool {
    !is_full_range(image, ranges) && image.len() > MAX_WIDE_SCAN_BYTES
}

fn is_full_range(image: &[u8], ranges: &[(usize, usize)]) -> bool {
    matches!(ranges, [(0, end)] if *end == image.len())
}

fn table_header_hints(image: &[u8], ranges: &[(usize, usize)]) -> usize {
    let mut hints: usize = 0usize;
    for &(range_start, range_end) in ranges {
        let mut pos: usize = range_start;
        while pos < range_end && hints < MAX_TABLE_HEADER_HINTS {
            if plausible_table_header(image, pos).is_some() {
                hints += 1;
            }
            pos += 1;
        }
    }
    hints
}

fn plausible_table_header(buf: &[u8], pos: usize) -> Option<()> {
    let name_end: usize = buf.get(pos..)?.iter().position(|&b: &u8| b == 0)? + pos;
    let name_bytes: &[u8] = buf.get(pos..name_end)?;
    if name_bytes.is_empty()
        || name_bytes.len() > MAX_NAME_LEN
        || !name_bytes.iter().all(|&b: &u8| (0x20..0x7F).contains(&b))
    {
        return None;
    }
    let after: usize = name_end + 1;
    let size_bytes: &[u8] = buf.get(after..after + 4)?;
    let size: u64 = u64::from(u32::from_le_bytes(size_bytes.try_into().ok()?));
    let payload_start: usize = after + 4;
    let max_size: u64 = u64::try_from(buf.len().checked_sub(payload_start)?).ok()?;
    if size < MIN_CHUNK_SIZE || size > max_size || size > MAX_CHUNK_BYTES {
        return None;
    }
    let count_bytes: &[u8] = buf.get(payload_start..payload_start + 2)?;
    let count: u64 = u64::from(u16::from_le_bytes(count_bytes.try_into().ok()?));
    if count == 0 || count > MAX_CHUNK_COUNT {
        return None;
    }
    Some(())
}

fn scan_ranges(
    image: &[u8],
    ranges: &[(usize, usize)],
    dbg: &DebugLog,
    modules: &mut Vec<ModuleConstants>,
    first_offset: &mut Option<usize>,
    last_end: &mut usize,
) {
    for &(range_start, range_end) in ranges {
        let mut pos: usize = range_start;
        while pos < range_end {
            match try_chunk(image, pos) {
                Some(parsed) if chunk_qualifies(&parsed.module) => {
                    dbg.line(|| {
                        format!(
                            "chunk [{}] layout={} off={:#x} size={} count={} strings={} code_objects={}",
                            parsed.module.name,
                            parsed.layout.label(),
                            parsed.module.blob_offset,
                            parsed.module.chunk_size,
                            parsed.module.value_count,
                            parsed.module.strings.len(),
                            parsed.module.code_objects.len()
                        )
                    });
                    first_offset.get_or_insert(pos);
                    *last_end = parsed.next;
                    modules.push(parsed.module);
                    pos = parsed.next.max(pos + 1);
                }
                _ => pos += 1,
            }
        }
    }
}

#[must_use]
pub fn parse_constants(image: &[u8]) -> NuitkaConstants {
    let dbg: DebugLog = DebugLog::for_scope("nuitka");
    dbg.section("const-blob");
    let ranges: Vec<(usize, usize)> = primary_scan_ranges(image);
    dbg.kv("scan_ranges", || ranges.len().to_string());

    let mut modules: Vec<ModuleConstants> = Vec::new();
    let mut first_offset: Option<usize> = None;
    let mut last_end: usize = 0;

    scan_ranges(
        image,
        &ranges,
        &dbg,
        &mut modules,
        &mut first_offset,
        &mut last_end,
    );

    if modules.is_empty() && full_scan_fallback_allowed(image, &ranges) {
        dbg.line(|| "primary ranges produced no chunks; widening to full-image scan".to_owned());
        scan_ranges(
            image,
            &[(0usize, image.len())],
            &dbg,
            &mut modules,
            &mut first_offset,
            &mut last_end,
        );
    } else if modules.is_empty() && full_scan_fallback_skipped(image, &ranges) {
        dbg.line(|| "full-image fallback skipped by bounded scan cap".to_owned());
    }

    let (region_offset, region_len): (u64, u64) = first_offset.map_or((0, 0), |start: usize| {
        (
            u64::try_from(start).unwrap_or(0),
            u64::try_from(last_end.saturating_sub(start)).unwrap_or(0),
        )
    });
    dbg.kv("modules", || modules.len().to_string());
    if modules.is_empty() {
        dbg.line(|| {
            "no chunk self-validated under modern varint or legacy fixed-width grammars".to_owned()
        });
    }

    NuitkaConstants {
        modules,
        region_offset,
        region_len,
    }
}

#[must_use]
pub fn constants_unparsable(image: &[u8]) -> bool {
    parse_constants(image).is_empty()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn corpus_standalone() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus/python/nuitka/real/sample_app-standalone.exe")
    }

    const QUALNAME_BLOB: &[u8] = include_bytes!("../tests/fixtures/qualname_codeobjects.bin");

    #[test]
    fn code_object_qualname_reconstructs_full_dotted_path() {
        let constants: NuitkaConstants = parse_constants(QUALNAME_BLOB);
        let module: &ModuleConstants = constants
            .modules
            .iter()
            .find(|m: &&ModuleConstants| m.name == "codetest")
            .expect("codetest chunk recovered");
        let by_name = |needle: &str| -> &CodeObjectMeta {
            module
                .code_objects
                .iter()
                .find(|c: &&CodeObjectMeta| c.name == needle)
                .unwrap_or_else(|| panic!("code object {needle} recovered"))
        };

        let method: &CodeObjectMeta = by_name("method");
        assert_eq!(
            method.qualname.as_deref(),
            Some("Outer.method"),
            "Nuitka stores qualname with the trailing name stripped; the runtime concatenates \
             stored + '.' + name, so the partial 'Outer' must be completed to 'Outer.method'"
        );

        let deep: &CodeObjectMeta = by_name("deep");
        assert_eq!(deep.qualname.as_deref(), Some("Outer.deep"));

        let only: &CodeObjectMeta = by_name("only");
        assert_eq!(
            only.qualname, None,
            "qualname == name carries no qualname flag and must not fabricate one"
        );
    }

    fn varint_bytes(mut value: u64) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        while value >= 128 {
            out.push(((value & 0x7F) | 0x80) as u8);
            value >>= 7;
        }
        out.push(value as u8);
        out
    }

    fn sized_chunk(name: &str, payload: Vec<u8>) -> Vec<u8> {
        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(name.as_bytes());
        blob.push(0);
        blob.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        blob.extend(payload);
        blob
    }

    fn counted_chunk(name: &str, count: u16, values: Vec<u8>) -> Vec<u8> {
        let mut payload: Vec<u8> = count.to_le_bytes().to_vec();
        payload.extend(values);
        sized_chunk(name, payload)
    }

    fn modern_text(text: &str) -> Vec<u8> {
        let mut out: Vec<u8> = vec![0x76];
        out.extend(varint_bytes(text.len() as u64));
        out.extend_from_slice(text.as_bytes());
        out
    }

    fn legacy_text(text: &str) -> Vec<u8> {
        let mut out: Vec<u8> = vec![0x76];
        out.extend_from_slice(&(text.len() as i32).to_le_bytes());
        out.extend_from_slice(text.as_bytes());
        out
    }

    fn legacy_ztext(text: &str) -> Vec<u8> {
        let mut out: Vec<u8> = vec![0x75];
        out.extend_from_slice(text.as_bytes());
        out.push(0);
        out
    }

    fn minimal_pe_with_outside_chunk(chunk: &[u8]) -> Vec<u8> {
        let chunk_offset: usize = 0x180;
        let mut image: Vec<u8> = vec![0u8; chunk_offset + chunk.len() + 0x20];
        image[0..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff: usize = 0x84;
        image[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        image[coff + 16..coff + 18].copy_from_slice(&0u16.to_le_bytes());
        let section: usize = coff + 20;
        image[section..section + 5].copy_from_slice(b".data");
        image[section + 16..section + 20].copy_from_slice(&0x20u32.to_le_bytes());
        image[section + 20..section + 24].copy_from_slice(&0x100u32.to_le_bytes());
        image[section + 36..section + 40].copy_from_slice(&0x40u32.to_le_bytes());
        image[chunk_offset..chunk_offset + chunk.len()].copy_from_slice(chunk);
        image
    }

    #[test]
    fn legacy_fixed32_roundtrips_disrobes_own_encoding() {
        let mut values: Vec<u8> = legacy_text("alpha");
        let mut tuple: Vec<u8> = vec![0x54];
        tuple.extend_from_slice(&2i32.to_le_bytes());
        tuple.extend(legacy_ztext("beta"));
        tuple.push(0x6C);
        tuple.extend_from_slice(&42i32.to_le_bytes());
        values.extend(tuple);

        let constants: NuitkaConstants = parse_constants(&counted_chunk("legacy32", 2, values));
        let module: &ModuleConstants = constants
            .modules
            .iter()
            .find(|m: &&ModuleConstants| m.name == "legacy32")
            .expect("legacy32 module recovered");

        assert!(module.strings.contains("alpha"));
        assert!(module.strings.contains("beta"));
        assert!(module.ints.contains(&42));
        assert_eq!(module.value_count, 2);
    }

    #[test]
    fn legacy_fixed64_roundtrips_disrobes_own_encoding() {
        let mut values: Vec<u8> = legacy_text("wide");
        values.extend(legacy_ztext("counter"));
        values.push(0x6C);
        values.extend_from_slice(&4_294_967_296i64.to_le_bytes());

        let constants: NuitkaConstants = parse_constants(&counted_chunk("legacy64", 3, values));
        let module: &ModuleConstants = constants
            .modules
            .iter()
            .find(|m: &&ModuleConstants| m.name == "legacy64")
            .expect("legacy64 module recovered");

        assert!(module.strings.contains("wide"));
        assert!(module.strings.contains("counter"));
        assert!(module.ints.contains(&4_294_967_296i64));
    }

    #[test]
    fn pe_full_image_fallback_recovers_chunk_outside_data_sections() {
        let mut values: Vec<u8> = modern_text("alpha");
        values.extend(modern_text("beta"));
        let chunk: Vec<u8> = counted_chunk("outside", 2, values);
        let image: Vec<u8> = minimal_pe_with_outside_chunk(&chunk);

        let constants: NuitkaConstants = parse_constants(&image);
        let names: Vec<String> = constants.module_names();

        assert!(names.iter().any(|name: &String| name == "outside"));
        assert_eq!(constants.region_offset, 0x180);
    }

    #[test]
    fn unparsed_reason_splits_rejected_table_from_absence() {
        let rejected: Vec<u8> = counted_chunk("broken", 1, vec![0xff, 0, 0, 0]);
        assert!(parse_constants(&rejected).is_empty());
        assert_eq!(
            constants_unparsed_reason(&rejected),
            ConstantsUnparsedReason::TableHeaderPresent
        );

        let marker: &[u8] = b"prefix loadConstantsBlob suffix";
        assert_eq!(
            constants_unparsed_reason(marker),
            ConstantsUnparsedReason::LoaderMarkerPresent
        );

        assert_eq!(
            constants_unparsed_reason(b"plain noise"),
            ConstantsUnparsedReason::NoPlaintextTable
        );
    }

    #[test]
    fn huge_declared_length_is_rejected_without_oom() {
        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(b"mod\0");
        blob.extend_from_slice(&64u32.to_le_bytes());
        blob.extend_from_slice(&1u16.to_le_bytes());
        blob.push(0x76);
        blob.extend(varint_bytes(238_319_529));
        blob.extend_from_slice(&[0x41u8; 16]);
        let result: NuitkaConstants = parse_constants(&blob);
        assert!(
            result.is_empty(),
            "a 238MB declared length over a tiny buffer must be rejected, not allocated"
        );
    }

    #[test]
    fn chunk_size_over_hard_cap_is_rejected() {
        let mut blob: Vec<u8> = vec![0u8; 1024];
        blob[0] = b'm';
        blob[1] = 0;
        let huge: u32 = (MAX_CHUNK_BYTES + 1) as u32;
        blob[2..6].copy_from_slice(&huge.to_le_bytes());
        assert!(try_chunk(&blob, 0).is_none());
    }

    #[test]
    fn previous_reference_to_large_value_is_rejected() {
        let large_items: usize = MAX_STORED_LAST_WEIGHT + 1;
        let repeated: usize = 16;
        let mut value: Vec<u8> = vec![0x4C];
        value.extend(varint_bytes((repeated + 1) as u64));
        value.push(0x4C);
        value.extend(varint_bytes(large_items as u64));
        value.extend(std::iter::repeat_n(0x6Eu8, large_items));
        value.extend(std::iter::repeat_n(0x70u8, repeated));

        let mut payload: Vec<u8> = 1u16.to_le_bytes().to_vec();
        payload.extend(value);

        let mut blob: Vec<u8> = b"mod\0".to_vec();
        blob.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        blob.extend(payload);
        assert!(try_chunk(&blob, 0).is_none());
    }

    #[test]
    fn varint_round_trips_multibyte() {
        let encoded: Vec<u8> = varint_bytes(300);
        let mut reader: Reader<'_> = Reader::new(&encoded, 0, ChunkValueLayout::ModernVarint);
        assert_eq!(reader.varint(), Some(300));
    }

    #[test]
    fn rejects_noise() {
        let noise: Vec<u8> = vec![0xFFu8; 512];
        assert!(parse_constants(&noise).is_empty());
    }

    #[test]
    fn empty_image_is_empty() {
        assert!(parse_constants(&[]).is_empty());
    }

    #[test]
    fn recovers_real_standalone_modules_and_functions() {
        let path: std::path::PathBuf = corpus_standalone();
        if !path.is_file() {
            eprintln!(
                "skipping: real nuitka corpus exe absent at {}",
                path.display()
            );
            return;
        }
        let image: Vec<u8> = std::fs::read(&path).expect("read corpus exe");
        let constants: NuitkaConstants = parse_constants(&image);
        let names: Vec<String> = constants.module_names();
        for expected in [
            "sample_app",
            "sample_app.core",
            "sample_app.cli",
            "sample_app.models",
            "sample_app.utils",
            "__main__",
        ] {
            assert!(
                names.iter().any(|n: &String| n == expected),
                "module {expected} not recovered; got {names:?}"
            );
        }
        let all_strings: BTreeSet<String> = constants
            .modules
            .iter()
            .flat_map(|m: &ModuleConstants| m.strings.iter().cloned())
            .collect();
        for func in [
            "compute_checksum",
            "transform_pipeline",
            "normalize_scores",
            "magic_sum",
            "deposit",
            "withdraw",
            "apply_interest",
            "clamp",
        ] {
            assert!(
                all_strings.contains(func),
                "function name {func} not recovered"
            );
        }
        assert!(
            all_strings
                .iter()
                .any(|s: &String| s.contains("Adler-32-style checksum")),
            "known docstring not recovered"
        );
    }
}
