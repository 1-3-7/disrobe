use serde::{Deserialize, Serialize};

use crate::yarv::opcodes::{TsKind, YarvOpcode, YarvVersion};
use crate::yarv::reader::YarvBinaryHeader;

pub(crate) const IBF_OBJECT_LIST_ENTRY_CAP: u32 = 1_048_576;
pub(crate) const IBF_STRING_LEN_CAP: usize = 16 * 1024 * 1024;
pub(crate) const IBF_ARRAY_LEN_CAP: usize = 1_048_576;
const IBF_FLOAT_ALIGN: usize = 8;
const IBF_MAX_INSNS_PER_ISEQ: usize = 1_048_576;
const IBF_MAX_ISEQ_BODIES: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IbfObjectKind {
    String,
    Symbol,
    Array,
    Bignum,
    Float,
    Regexp,
    Hash,
    Range,
    Class,
    Object,
    Complex,
    Rational,
    Nil,
    True,
    False,
    Fixnum,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IbfObject {
    pub index: u32,
    pub offset: u32,
    pub kind: IbfObjectKind,
    pub literal: Option<String>,
    pub element_count: Option<u32>,

    pub elements: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct YarvIbfInstruction {
    pub pc: u32,
    pub opcode: u32,
    pub mnemonic: String,
    pub operands: Vec<YarvOperand>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "value")]
pub enum YarvOperand {
    Literal(String),

    StrLiteral(String),

    SymLiteral(String),

    NumLiteral(String),

    ObjectRef(u32),

    IseqRef(u32),

    Id(String),

    Offset(u32),

    Num(u64),

    Builtin(String),

    Call {
        method: String,
        argc: u32,
        flags: u32,
    },
}

#[derive(Debug, Clone)]
struct CallEntry {
    method: Option<String>,
    argc: u32,
    flags: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CatchType {
    Rescue,
    Ensure,
    Retry,
    Break,
    Redo,
    Next,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct YarvCatchEntry {
    pub catch_type: CatchType,
    pub start_pc: u32,
    pub end_pc: u32,
    pub cont_pc: u32,
    pub handler_iseq: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct YarvIseqBody {
    pub index: u32,
    pub offset: u32,
    pub iseq_size: u32,
    pub instructions: Vec<YarvIbfInstruction>,

    pub local_table: Vec<Option<String>>,

    pub param_lead_num: u32,

    pub param_size: u32,

    pub param_flags: u64,

    pub param_opt_num: u32,

    pub param_rest_start: u32,

    pub param_block_start: u32,

    pub catch_entries: Vec<YarvCatchEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IbfImage {
    pub iseq_offsets: Vec<u32>,
    pub objects: Vec<IbfObject>,
    pub iseqs: Vec<YarvIseqBody>,
    pub recovered_literal_count: u32,
    pub recovered_instruction_count: u32,
}

#[inline]
const fn ntz_u8(c: u8) -> u32 {
    if c == 0 { 8 } else { c.trailing_zeros() }
}

#[inline]
#[allow(clippy::many_single_char_names)]
pub(crate) fn read_small_value(bytes: &[u8], pos: usize) -> Option<(u64, usize)> {
    let c: u8 = *bytes.get(pos)?;
    let n: usize = if c & 1 == 1 {
        1
    } else if c == 0 {
        9
    } else {
        (ntz_u8(c) as usize) + 1
    };
    let end: usize = pos.checked_add(n)?;
    if end > bytes.len() {
        return None;
    }
    let mut x: u64 = if n >= 9 {
        0
    } else {
        u64::from(c) >> (n as u32)
    };
    let mut i: usize = 1;
    while i < n {
        let b: u8 = *bytes.get(pos + i)?;
        x = (x << 8) | u64::from(b);
        i += 1;
    }
    Some((x, end))
}

#[inline]
fn read_u32_le(bytes: &[u8], pos: usize) -> Option<u32> {
    let slice: &[u8] = bytes.get(pos..pos.checked_add(4)?)?;
    let arr: [u8; 4] = slice.try_into().ok()?;
    Some(u32::from_le_bytes(arr))
}

const fn classify_tag(tag: u8) -> IbfObjectKind {
    match tag & 0x1f {
        0x01 => IbfObjectKind::Object,
        0x02 => IbfObjectKind::Class,
        0x04 => IbfObjectKind::Float,
        0x05 => IbfObjectKind::String,
        0x06 => IbfObjectKind::Regexp,
        0x07 => IbfObjectKind::Array,
        0x08 => IbfObjectKind::Hash,
        0x09 => IbfObjectKind::Range,
        0x0a => IbfObjectKind::Bignum,
        0x0e => IbfObjectKind::Complex,
        0x0f => IbfObjectKind::Rational,
        0x11 => IbfObjectKind::Nil,
        0x12 => IbfObjectKind::True,
        0x13 => IbfObjectKind::False,
        0x14 => IbfObjectKind::Symbol,
        0x15 => IbfObjectKind::Fixnum,
        _ => IbfObjectKind::Unknown,
    }
}

#[inline]
const fn fixnum_value(raw: u64) -> i64 {
    (raw as i64) >> 1
}

fn render_float_literal(value: f64) -> String {
    if value.is_nan() {
        return "(0.0 / 0.0)".to_owned();
    }
    if value.is_infinite() {
        return if value > 0.0 {
            "(1.0 / 0.0)".to_owned()
        } else {
            "(-1.0 / 0.0)".to_owned()
        };
    }
    let mut text: String = format!("{value:?}");
    if !text.contains(['.', 'e', 'E']) {
        text.push_str(".0");
    }
    text
}

pub(crate) fn ruby_dq_body(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out: String = String::with_capacity(s.len() + 2);
    let mut chars: core::iter::Peekable<core::str::Chars<'_>> = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '#' => match chars.peek() {
                Some('{' | '$' | '@') => out.push_str("\\#"),
                _ => out.push('#'),
            },
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                let byte: usize = c as usize;
                out.push('\\');
                out.push('x');
                out.push(HEX[(byte >> 4) & 0xf] as char);
                out.push(HEX[byte & 0xf] as char);
            }
            c => out.push(c),
        }
    }
    out
}

pub(crate) fn ruby_string_literal(s: &str) -> String {
    format!("\"{}\"", ruby_dq_body(s))
}

const fn unknown_ibf_object(index: u32, offset: u32) -> IbfObject {
    IbfObject {
        index,
        offset,
        kind: IbfObjectKind::Unknown,
        literal: None,
        element_count: None,
        elements: Vec::new(),
    }
}

fn capped_usize(raw: u64, cap: usize) -> Option<usize> {
    let value: usize = usize::try_from(raw).ok()?;
    (value <= cap).then_some(value)
}

fn checked_slice(bytes: &[u8], pos: usize, len: usize) -> Option<(&[u8], usize)> {
    let end: usize = pos.checked_add(len)?;
    let slice: &[u8] = bytes.get(pos..end)?;
    Some((slice, end))
}

fn decode_object(bytes: &[u8], index: u32, offset: u32) -> IbfObject {
    let off: usize = offset as usize;
    let Some(tag): Option<u8> = bytes.get(off).copied() else {
        return unknown_ibf_object(index, offset);
    };
    let kind: IbfObjectKind = classify_tag(tag);
    let Some(after_tag): Option<usize> = off.checked_add(1) else {
        return unknown_ibf_object(index, offset);
    };
    let mut literal: Option<String> = None;
    let mut element_count: Option<u32> = None;
    let mut elements: Vec<u32> = Vec::new();
    match kind {
        IbfObjectKind::String | IbfObjectKind::Symbol => {
            if let Some((_enc, p1)) = read_small_value(bytes, after_tag)
                && let Some((len, p2)) = read_small_value(bytes, p1)
                && let Some(len_usize) = capped_usize(len, IBF_STRING_LEN_CAP)
                && let Some((slice, _)) = checked_slice(bytes, p2, len_usize)
            {
                literal = Some(String::from_utf8_lossy(slice).into_owned());
            }
        }
        IbfObjectKind::Array => {
            if let Some((count, mut ep)) = read_small_value(bytes, after_tag) {
                let capped: u32 =
                    u32::try_from(count.min(IBF_ARRAY_LEN_CAP as u64)).unwrap_or(u32::MAX);
                element_count = Some(capped);
                elements.reserve((capped as usize).min(64));
                for _ in 0..capped {
                    let Some((elem, next)): Option<(u64, usize)> = read_small_value(bytes, ep)
                    else {
                        break;
                    };
                    elements.push(u32::try_from(elem).unwrap_or(u32::MAX));
                    ep = next;
                }
            }
        }
        IbfObjectKind::Fixnum => {
            if let Some((raw, _)) = read_small_value(bytes, after_tag) {
                literal = Some(fixnum_value(raw).to_string());
            }
        }
        IbfObjectKind::Float => {
            if let Some(body) = after_tag.checked_next_multiple_of(IBF_FLOAT_ALIGN)
                && let Some((slice, _)) = checked_slice(bytes, body, 8)
                && let Ok(bits) = <[u8; 8]>::try_from(slice)
            {
                literal = Some(render_float_literal(f64::from_le_bytes(bits)));
            }
        }
        IbfObjectKind::Range => {
            if let Some((excl, beg, end)) = decode_range_fields(bytes, off) {
                element_count = Some(excl);
                elements.push(beg);
                elements.push(end);
            }
        }
        IbfObjectKind::Hash => {
            if let Some((pair_count, mut ep)) = read_small_value(bytes, after_tag) {
                let pairs: u32 =
                    u32::try_from(pair_count.min(IBF_ARRAY_LEN_CAP as u64)).unwrap_or(u32::MAX);
                let ref_count: u32 = pairs.saturating_mul(2);
                element_count = Some(ref_count);
                elements.reserve((ref_count as usize).min(128));
                for _ in 0..ref_count {
                    let Some((elem, next)): Option<(u64, usize)> = read_small_value(bytes, ep)
                    else {
                        break;
                    };
                    elements.push(u32::try_from(elem).unwrap_or(u32::MAX));
                    ep = next;
                }
            }
        }
        IbfObjectKind::Regexp => {
            if let Some(&option) = bytes.get(after_tag)
                && let Some(src_pos) = after_tag.checked_add(1)
                && let Some((src_index, _)) = read_small_value(bytes, src_pos)
            {
                element_count = Some(u32::from(option));
                elements.push(u32::try_from(src_index).unwrap_or(u32::MAX));
            }
        }
        IbfObjectKind::Nil => literal = Some("nil".to_owned()),
        IbfObjectKind::True => literal = Some("true".to_owned()),
        IbfObjectKind::False => literal = Some("false".to_owned()),
        _ => {}
    }
    IbfObject {
        index,
        offset,
        kind,
        literal,
        element_count,
        elements,
    }
}

fn read_i32_le(bytes: &[u8], pos: usize) -> Option<i32> {
    let slice: &[u8] = bytes.get(pos..pos.checked_add(4)?)?;
    let arr: [u8; 4] = slice.try_into().ok()?;
    Some(i32::from_le_bytes(arr))
}

fn decode_range_fields(bytes: &[u8], offset: usize) -> Option<(u32, u32, u32)> {
    for long_width in [4usize, 8usize] {
        let align: usize = long_width;
        let aligned: usize = offset.checked_add(1)?.div_ceil(align).checked_mul(align)?;
        for base in [aligned, offset.checked_add(align)?] {
            let class_index: i32 = read_i32_le(bytes, base)?;
            let len: i32 = read_i32_le(bytes, base.checked_add(long_width)?)?;
            if class_index != 0 || len != 3 {
                continue;
            }
            let beg: i32 = read_i32_le(bytes, base.checked_add(long_width.checked_mul(2)?)?)?;
            let end: i32 = read_i32_le(bytes, base.checked_add(long_width.checked_mul(3)?)?)?;
            let excl: i32 = read_i32_le(bytes, base.checked_add(long_width.checked_mul(4)?)?)?;
            if beg < 0 || end < 0 || !matches!(excl, 0 | 1) {
                continue;
            }
            let beg_idx: u32 = u32::try_from(beg).ok()?;
            let end_idx: u32 = u32::try_from(end).ok()?;
            return Some((u32::try_from(excl).ok()?, beg_idx, end_idx));
        }
    }
    None
}

fn resolve_regexp_literals(objects: &mut [IbfObject], recovered: &mut u32) {
    let sources: Vec<Option<String>> = objects
        .iter()
        .map(|o| {
            if o.kind == IbfObjectKind::Regexp {
                o.elements
                    .first()
                    .and_then(|&src| objects.get(src as usize))
                    .filter(|s| s.kind == IbfObjectKind::String)
                    .and_then(|s| s.literal.clone())
            } else {
                None
            }
        })
        .collect();
    for (obj, src) in objects.iter_mut().zip(sources) {
        if let Some(src) = src
            && obj.literal.is_none()
            && !src.contains(['\n', '\r'])
        {
            let flags: String = regexp_flag_suffix(obj.element_count.unwrap_or(0));
            obj.literal = Some(format!("/{}/{}", escape_regexp_slashes(&src), flags));
            *recovered = recovered.saturating_add(1);
        }
    }
}

fn regexp_flag_suffix(option: u32) -> String {
    const IGNORECASE: u32 = 1;
    const EXTENDED: u32 = 2;
    const MULTILINE: u32 = 4;
    const NOENCODING: u32 = 32;
    let mut out: String = String::with_capacity(4);
    if option & MULTILINE != 0 {
        out.push('m');
    }
    if option & IGNORECASE != 0 {
        out.push('i');
    }
    if option & EXTENDED != 0 {
        out.push('x');
    }
    if option & NOENCODING != 0 {
        out.push('n');
    }
    out
}

fn element_literal_text(obj: &IbfObject) -> Option<String> {
    let lit: &str = obj.literal.as_deref()?;
    let rendered: String = match obj.kind {
        IbfObjectKind::String => ruby_string_literal(lit),
        IbfObjectKind::Symbol => format!(":{}", symbol_element_text(lit)),
        _ => lit.to_owned(),
    };
    Some(rendered)
}

fn symbol_element_text(name: &str) -> String {
    let simple: bool = !name.is_empty()
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '?' || c == '!' || c == '=');
    let operatorish: bool = matches!(
        name,
        "+" | "-"
            | "*"
            | "/"
            | "%"
            | "**"
            | "<<"
            | ">>"
            | "<"
            | ">"
            | "<="
            | ">="
            | "<=>"
            | "=="
            | "==="
            | "!="
            | "=~"
            | "!~"
            | "&"
            | "|"
            | "^"
            | "~"
            | "!"
            | "[]"
            | "[]="
            | "+@"
            | "-@"
    );
    if simple || operatorish {
        name.to_owned()
    } else {
        ruby_string_literal(name)
    }
}

fn resolve_array_literals(objects: &mut [IbfObject], recovered: &mut u32) {
    let rendered: Vec<Option<String>> = objects
        .iter()
        .map(|obj| match obj.kind {
            IbfObjectKind::Array if obj.literal.is_none() => render_array_literal(objects, obj),
            IbfObjectKind::Hash if obj.literal.is_none() => render_hash_literal(objects, obj),
            IbfObjectKind::Range if obj.literal.is_none() => render_range_literal(objects, obj),
            _ => None,
        })
        .collect();
    for (obj, text) in objects.iter_mut().zip(rendered) {
        if let Some(text) = text {
            obj.literal = Some(text);
            *recovered = recovered.saturating_add(1);
        }
    }
}

fn render_array_literal(objects: &[IbfObject], obj: &IbfObject) -> Option<String> {
    let mut parts: Vec<String> = Vec::with_capacity(obj.elements.len());
    for &elem in &obj.elements {
        let referenced: &IbfObject = objects.get(elem as usize)?;
        parts.push(element_literal_text(referenced)?);
    }
    Some(format!("[{}]", parts.join(", ")))
}

fn render_range_literal(objects: &[IbfObject], obj: &IbfObject) -> Option<String> {
    let &[beg_idx, end_idx]: &[u32; 2] = obj.elements.first_chunk::<2>()?;
    let beg: &IbfObject = objects.get(beg_idx as usize)?;
    let end: &IbfObject = objects.get(end_idx as usize)?;
    let beg_text: String = if beg.kind == IbfObjectKind::Nil {
        String::new()
    } else {
        element_literal_text(beg)?
    };
    let end_text: String = if end.kind == IbfObjectKind::Nil {
        String::new()
    } else {
        element_literal_text(end)?
    };
    let dots: &str = if obj.element_count == Some(1) {
        "..."
    } else {
        ".."
    };
    Some(format!("({beg_text}{dots}{end_text})"))
}

fn render_hash_literal(objects: &[IbfObject], obj: &IbfObject) -> Option<String> {
    if obj.elements.is_empty() {
        return Some("{}".to_owned());
    }
    if !obj.elements.len().is_multiple_of(2) {
        return None;
    }
    let mut pairs: Vec<String> = Vec::with_capacity(obj.elements.len() / 2);
    for chunk in obj.elements.chunks_exact(2) {
        let key: &IbfObject = objects.get(chunk[0] as usize)?;
        let value: &IbfObject = objects.get(chunk[1] as usize)?;
        let value_text: String = element_literal_text(value)?;
        if key.kind == IbfObjectKind::Symbol {
            let name: &str = key.literal.as_deref()?;
            pairs.push(format!("{}: {value_text}", symbol_element_text(name)));
        } else {
            pairs.push(format!("{} => {value_text}", element_literal_text(key)?));
        }
    }
    Some(format!("{{ {} }}", pairs.join(", ")))
}

fn escape_regexp_slashes(src: &str) -> String {
    let mut out: String = String::with_capacity(src.len() + 4);
    let mut prev_backslash: bool = false;
    for ch in src.chars() {
        if ch == '/' && !prev_backslash {
            out.push('\\');
        }
        out.push(ch);
        prev_backslash = ch == '\\' && !prev_backslash;
    }
    out
}

struct ObjectTable<'a> {
    objects: &'a [IbfObject],
}

impl ObjectTable<'_> {
    fn literal(&self, index: u64) -> Option<&str> {
        usize::try_from(index)
            .ok()
            .and_then(|i| self.objects.get(i))
            .and_then(|o| o.literal.as_deref())
    }

    fn typed_literal(&self, index: u64) -> Option<(&str, IbfObjectKind)> {
        let obj: &IbfObject = usize::try_from(index)
            .ok()
            .and_then(|i| self.objects.get(i))?;
        let lit: &str = obj.literal.as_deref()?;
        Some((lit, obj.kind))
    }
}

const BODY_READ_PARAM_FLAGS: usize = 4;
const BODY_READ_PARAM_SIZE: usize = 5;
const BODY_READ_PARAM_LEAD_NUM: usize = 6;
const BODY_READ_PARAM_OPT_NUM: usize = 7;
const BODY_READ_PARAM_REST_START: usize = 8;
const BODY_READ_PARAM_BLOCK_START: usize = 11;
const BODY_READ_CATCH_TABLE_SIZE: usize = 27;
const BODY_READ_CATCH_TABLE_OFFSET: usize = 28;
const BODY_READ_LOCAL_TABLE_OFFSET: usize = 26;
const BODY_READ_CI_ENTRIES_OFFSET: usize = 32;
const BODY_READ_LOCAL_TABLE_SIZE: usize = 35;
const BODY_READ_CI_SIZE: usize = 40;
const BODY_HEADER_READS: usize = 41;
const IBF_MAX_CI_ENTRIES: usize = 1_048_576;
const IBF_MAX_LOCALS: usize = 65_536;
const IBF_MAX_CATCH_ENTRIES: usize = 65_536;

struct BodyHeader {
    iseq_size: usize,
    bytecode_offset: usize,
    bytecode_size: usize,
    param_flags: u64,
    param_size: u32,
    param_lead_num: u32,
    param_opt_num: u32,
    param_rest_start: u32,
    param_block_start: u32,
    local_table_offset: Option<usize>,
    local_table_size: usize,
    ci_entries_offset: Option<usize>,
    ci_size: usize,
    catch_table_offset: Option<usize>,
    catch_table_size: usize,
}

fn parse_body_header(
    bytes: &[u8],
    body_offset: usize,
    ci_layout_known: bool,
) -> Option<BodyHeader> {
    let mut pos: usize = body_offset;
    let mut iseq_size: usize = 0;
    let mut bytecode_offset: usize = 0;
    let mut bytecode_size: usize = 0;
    let mut param_flags: u64 = 0;
    let mut param_size: u32 = 0;
    let mut param_lead_num: u32 = 0;
    let mut param_opt_num: u32 = 0;
    let mut param_rest_start: u32 = 0;
    let mut param_block_start: u32 = 0;
    let mut local_table_offset: Option<usize> = None;
    let mut local_table_size: usize = 0;
    let mut ci_entries_offset: Option<usize> = None;
    let mut ci_size: usize = 0;
    let mut catch_table_offset: Option<usize> = None;
    let mut catch_table_size: usize = 0;
    let reads: usize = if ci_layout_known {
        BODY_HEADER_READS
    } else {
        4
    };
    for read_idx in 0..reads {
        let (raw, next): (u64, usize) = read_small_value(bytes, pos)?;
        match read_idx {
            1 => iseq_size = usize::try_from(raw).ok()?.min(IBF_MAX_INSNS_PER_ISEQ),
            2 => {
                let rel: usize = usize::try_from(raw).ok()?;
                bytecode_offset = body_offset.checked_sub(rel)?;
            }
            3 => bytecode_size = usize::try_from(raw).ok()?,
            BODY_READ_PARAM_FLAGS => param_flags = raw,
            BODY_READ_PARAM_SIZE => {
                param_size = raw.min(IBF_MAX_LOCALS as u64) as u32;
            }
            BODY_READ_PARAM_LEAD_NUM => {
                param_lead_num = raw.min(IBF_MAX_LOCALS as u64) as u32;
            }
            BODY_READ_PARAM_OPT_NUM => {
                param_opt_num = raw.min(IBF_MAX_LOCALS as u64) as u32;
            }
            BODY_READ_PARAM_REST_START => {
                param_rest_start = raw.min(IBF_MAX_LOCALS as u64) as u32;
            }
            BODY_READ_PARAM_BLOCK_START => {
                param_block_start = raw.min(IBF_MAX_LOCALS as u64) as u32;
            }
            BODY_READ_LOCAL_TABLE_OFFSET => {
                let rel: usize = usize::try_from(raw).ok()?;
                local_table_offset = body_offset.checked_sub(rel);
            }
            BODY_READ_CATCH_TABLE_SIZE => {
                catch_table_size = usize::try_from(raw).ok()?.min(IBF_MAX_CATCH_ENTRIES);
            }
            BODY_READ_CATCH_TABLE_OFFSET => {
                let rel: usize = usize::try_from(raw).ok()?;
                catch_table_offset = body_offset.checked_sub(rel);
            }
            BODY_READ_CI_ENTRIES_OFFSET => {
                let rel: usize = usize::try_from(raw).ok()?;
                ci_entries_offset = body_offset.checked_sub(rel);
            }
            BODY_READ_LOCAL_TABLE_SIZE => {
                local_table_size = usize::try_from(raw).ok()?.min(IBF_MAX_LOCALS);
            }
            BODY_READ_CI_SIZE => ci_size = usize::try_from(raw).ok()?.min(IBF_MAX_CI_ENTRIES),
            _ => {}
        }
        pos = next;
    }
    Some(BodyHeader {
        iseq_size,
        bytecode_offset,
        bytecode_size,
        param_flags,
        param_size,
        param_lead_num,
        param_opt_num,
        param_rest_start,
        param_block_start,
        local_table_offset,
        local_table_size,
        ci_entries_offset,
        ci_size,
        catch_table_offset,
        catch_table_size,
    })
}

fn parse_local_table(
    bytes: &[u8],
    objects: &ObjectTable<'_>,
    offset: usize,
    size: usize,
) -> Vec<Option<String>> {
    let aligned: usize = offset.div_ceil(4).saturating_mul(4);
    let mut names: Vec<Option<String>> = Vec::with_capacity(size.min(4096));
    for i in 0..size {
        let at: usize = match aligned.checked_add(i.wrapping_mul(8)) {
            Some(at) => at,
            None => break,
        };
        let Some(id_index): Option<u32> = read_u32_le(bytes, at) else {
            break;
        };
        names.push(objects.literal(u64::from(id_index)).map(str::to_owned));
    }
    names
}

fn parse_ci_entries(
    bytes: &[u8],
    objects: &ObjectTable<'_>,
    offset: usize,
    count: usize,
) -> Vec<CallEntry> {
    let mut entries: Vec<CallEntry> = Vec::with_capacity(count.min(4096));
    let mut pos: usize = offset;
    for _ in 0..count {
        let Some((mid_index, p1)): Option<(u64, usize)> = read_small_value(bytes, pos) else {
            break;
        };
        if mid_index == u64::MAX || (mid_index as i64) == -1 {
            entries.push(CallEntry {
                method: None,
                argc: 0,
                flags: 0,
            });
            pos = p1;
            continue;
        }
        let Some((flag, p2)): Option<(u64, usize)> = read_small_value(bytes, p1) else {
            break;
        };
        let Some((argc, p3)): Option<(u64, usize)> = read_small_value(bytes, p2) else {
            break;
        };
        let Some((kwlen, p4)): Option<(u64, usize)> = read_small_value(bytes, p3) else {
            break;
        };
        let mut np: usize = p4;
        for _ in 0..kwlen.min(IBF_ARRAY_LEN_CAP as u64) {
            match read_small_value(bytes, np) {
                Some((_kw, n)) => np = n,
                None => break,
            }
        }
        entries.push(CallEntry {
            method: objects.literal(mid_index).map(str::to_owned),
            argc: u32::try_from(argc).unwrap_or(u32::MAX),
            flags: u32::try_from(flag).unwrap_or(0),
        });
        pos = np;
    }
    entries
}

const fn classify_catch_type(raw: u64) -> CatchType {
    match raw >> 1 {
        1 => CatchType::Rescue,
        2 => CatchType::Ensure,
        3 => CatchType::Retry,
        4 => CatchType::Break,
        5 => CatchType::Redo,
        6 => CatchType::Next,
        _ => CatchType::Unknown,
    }
}

fn parse_catch_table(bytes: &[u8], offset: usize, count: usize) -> Vec<YarvCatchEntry> {
    let mut entries: Vec<YarvCatchEntry> = Vec::with_capacity(count.min(4096));
    let mut pos: usize = offset;
    for _ in 0..count {
        let Some((iseq_index, p1)): Option<(u64, usize)> = read_small_value(bytes, pos) else {
            break;
        };
        let Some((ty, p2)): Option<(u64, usize)> = read_small_value(bytes, p1) else {
            break;
        };
        let Some((start, p3)): Option<(u64, usize)> = read_small_value(bytes, p2) else {
            break;
        };
        let Some((end, p4)): Option<(u64, usize)> = read_small_value(bytes, p3) else {
            break;
        };
        let Some((cont, p5)): Option<(u64, usize)> = read_small_value(bytes, p4) else {
            break;
        };
        let Some((_sp, p6)): Option<(u64, usize)> = read_small_value(bytes, p5) else {
            break;
        };
        let handler_iseq: Option<u32> = (iseq_index != 0 && iseq_index != u64::MAX)
            .then(|| u32::try_from(iseq_index).unwrap_or(u32::MAX));
        entries.push(YarvCatchEntry {
            catch_type: classify_catch_type(ty),
            start_pc: u32::try_from(start).unwrap_or(u32::MAX),
            end_pc: u32::try_from(end).unwrap_or(u32::MAX),
            cont_pc: u32::try_from(cont).unwrap_or(u32::MAX),
            handler_iseq,
        });
        pos = p6;
    }
    entries
}

#[allow(clippy::too_many_lines)]
fn decode_iseq_body(
    bytes: &[u8],
    table: &[YarvOpcode],
    objects: &ObjectTable<'_>,
    body_offset: u32,
    index: u32,
    ci_layout_known: bool,
) -> Option<YarvIseqBody> {
    let start: usize = body_offset as usize;
    let header: BodyHeader = parse_body_header(bytes, start, ci_layout_known)?;

    let calls: Vec<CallEntry> = match header.ci_entries_offset {
        Some(ci_off) if ci_off <= bytes.len() && header.ci_size > 0 => {
            parse_ci_entries(bytes, objects, ci_off, header.ci_size)
        }
        _ => Vec::new(),
    };

    let local_table: Vec<Option<String>> = match header.local_table_offset {
        Some(lt_off) if lt_off <= bytes.len() && header.local_table_size > 0 => {
            parse_local_table(bytes, objects, lt_off, header.local_table_size)
        }
        _ => Vec::new(),
    };

    let catch_entries: Vec<YarvCatchEntry> = match header.catch_table_offset {
        Some(ct_off) if ct_off <= bytes.len() && header.catch_table_size > 0 => {
            parse_catch_table(bytes, ct_off, header.catch_table_size)
        }
        _ => Vec::new(),
    };

    let bytecode_end: usize = header
        .bytecode_offset
        .checked_add(header.bytecode_size)?
        .min(bytes.len());
    if header.bytecode_offset > bytes.len() {
        return Some(YarvIseqBody {
            index,
            offset: body_offset,
            iseq_size: u32::try_from(header.iseq_size).unwrap_or(u32::MAX),
            instructions: Vec::new(),
            local_table,
            param_lead_num: header.param_lead_num,
            param_size: header.param_size,
            param_flags: header.param_flags,
            param_opt_num: header.param_opt_num,
            param_rest_start: header.param_rest_start,
            param_block_start: header.param_block_start,
            catch_entries,
        });
    }

    let mut instructions: Vec<YarvIbfInstruction> = Vec::with_capacity(header.iseq_size.min(4096));
    let mut rp: usize = header.bytecode_offset;
    let mut decoded: usize = 0;
    let mut call_cursor: usize = 0;
    'decode: while rp < bytecode_end && decoded <= header.iseq_size {
        let insn_pc: usize = rp.saturating_sub(header.bytecode_offset);
        let Some((op, after_op)): Option<(u64, usize)> = read_small_value(bytes, rp) else {
            break;
        };
        rp = after_op;
        let Some(op_idx): Option<usize> = usize::try_from(op).ok() else {
            break;
        };
        let Some(spec): Option<&YarvOpcode> = table.get(op_idx) else {
            break;
        };
        let mut operands: Vec<YarvOperand> = Vec::with_capacity(spec.operands.len());
        for kind in spec.operands {
            let operand: YarvOperand = match kind {
                TsKind::CallData => {
                    let entry: Option<&CallEntry> = calls.get(call_cursor);
                    call_cursor += 1;
                    match entry {
                        Some(CallEntry {
                            method: Some(name),
                            argc,
                            flags,
                        }) => YarvOperand::Call {
                            method: name.clone(),
                            argc: *argc,
                            flags: *flags,
                        },
                        Some(CallEntry {
                            method: None,
                            argc,
                            flags,
                        }) => YarvOperand::Call {
                            method: "(call)".to_owned(),
                            argc: *argc,
                            flags: *flags,
                        },
                        None => YarvOperand::Num(0),
                    }
                }
                TsKind::Builtin => {
                    let Some((_bidx, p1)): Option<(u64, usize)> = read_small_value(bytes, rp)
                    else {
                        break 'decode;
                    };
                    let Some((blen, p2)): Option<(u64, usize)> = read_small_value(bytes, p1) else {
                        break 'decode;
                    };
                    let Some(blen_usize): Option<usize> = capped_usize(blen, IBF_STRING_LEN_CAP)
                    else {
                        break 'decode;
                    };
                    let Some((name_slice, name_end)): Option<(&[u8], usize)> =
                        checked_slice(bytes, p2, blen_usize)
                    else {
                        break 'decode;
                    };
                    let name: String = String::from_utf8_lossy(name_slice).into_owned();
                    rp = name_end;
                    YarvOperand::Builtin(name)
                }
                TsKind::Variable => break,
                _ => {
                    let Some((raw, next)): Option<(u64, usize)> = read_small_value(bytes, rp)
                    else {
                        break 'decode;
                    };
                    rp = next;
                    resolve_operand(*kind, raw, objects)
                }
            };
            operands.push(operand);
        }
        instructions.push(YarvIbfInstruction {
            pc: u32::try_from(insn_pc).unwrap_or(u32::MAX),
            opcode: op_idx as u32,
            mnemonic: spec.mnemonic.to_owned(),
            operands,
        });
        decoded += 1 + spec.operands.len();
    }

    Some(YarvIseqBody {
        index,
        offset: body_offset,
        iseq_size: u32::try_from(header.iseq_size).unwrap_or(u32::MAX),
        instructions,
        local_table,
        param_lead_num: header.param_lead_num,
        param_size: header.param_size,
        param_flags: header.param_flags,
        param_opt_num: header.param_opt_num,
        param_rest_start: header.param_rest_start,
        param_block_start: header.param_block_start,
        catch_entries,
    })
}

fn resolve_operand(kind: TsKind, raw: u64, objects: &ObjectTable<'_>) -> YarvOperand {
    let ref_index: u32 = u32::try_from(raw).unwrap_or(u32::MAX);
    match kind {
        TsKind::Value | TsKind::CdHash | TsKind::Ic => objects.typed_literal(raw).map_or_else(
            || YarvOperand::ObjectRef(ref_index),
            |(lit, kind)| match kind {
                IbfObjectKind::Fixnum
                | IbfObjectKind::Float
                | IbfObjectKind::Regexp
                | IbfObjectKind::Nil
                | IbfObjectKind::True
                | IbfObjectKind::False
                | IbfObjectKind::Array
                | IbfObjectKind::Hash
                | IbfObjectKind::Range => YarvOperand::NumLiteral(lit.to_owned()),
                IbfObjectKind::String => YarvOperand::StrLiteral(lit.to_owned()),
                IbfObjectKind::Symbol => YarvOperand::SymLiteral(lit.to_owned()),
                _ => YarvOperand::Literal(lit.to_owned()),
            },
        ),
        TsKind::Id => objects.literal(raw).map_or_else(
            || YarvOperand::ObjectRef(ref_index),
            |name| YarvOperand::Id(name.to_owned()),
        ),
        TsKind::Iseq => YarvOperand::IseqRef(ref_index),
        TsKind::Offset => YarvOperand::Offset(raw as u32),
        _ => YarvOperand::Num(raw),
    }
}

pub(crate) fn parse_image(
    bytes: &[u8],
    header: &YarvBinaryHeader,
    version: YarvVersion,
) -> IbfImage {
    let total: usize = bytes.len();
    let iseq_base: usize = header.iseq_list_offset as usize;
    let obj_base: usize = header.global_object_list_offset as usize;
    let iseq_n: usize = (header.iseq_list_size.min(IBF_OBJECT_LIST_ENTRY_CAP) as usize)
        .min(table_entries_available(total, iseq_base));
    let obj_n: usize = (header
        .global_object_list_size
        .min(IBF_OBJECT_LIST_ENTRY_CAP) as usize)
        .min(table_entries_available(total, obj_base));

    let mut iseq_offsets: Vec<u32> = Vec::with_capacity(iseq_n.min(4096));
    for i in 0..iseq_n {
        let at: usize = match iseq_base.checked_add(i.wrapping_mul(4)) {
            Some(at) => at,
            None => break,
        };
        let Some(v): Option<u32> = read_u32_le(bytes, at) else {
            break;
        };
        iseq_offsets.push(v);
    }

    let mut objects: Vec<IbfObject> = Vec::with_capacity(obj_n.min(4096));
    let mut recovered_literal_count: u32 = 0;
    for i in 0..obj_n {
        let at: usize = match obj_base.checked_add(i.wrapping_mul(4)) {
            Some(at) => at,
            None => break,
        };
        let Some(obj_off): Option<u32> = read_u32_le(bytes, at) else {
            break;
        };
        let index: u32 = u32::try_from(i).unwrap_or(u32::MAX);
        if (obj_off as usize) >= total {
            objects.push(IbfObject {
                index,
                offset: obj_off,
                kind: IbfObjectKind::Unknown,
                literal: None,
                element_count: None,
                elements: Vec::new(),
            });
            continue;
        }
        let obj: IbfObject = decode_object(bytes, index, obj_off);
        if obj.literal.is_some() {
            recovered_literal_count += 1;
        }
        objects.push(obj);
    }

    resolve_regexp_literals(&mut objects, &mut recovered_literal_count);
    resolve_array_literals(&mut objects, &mut recovered_literal_count);

    let mut iseqs: Vec<YarvIseqBody> = Vec::new();
    let mut recovered_instruction_count: u32 = 0;
    if let Some(table) = version.opcode_table() {
        let ci_layout_known: bool = version.major == 3 && version.minor >= 3;
        let obj_table: ObjectTable<'_> = ObjectTable { objects: &objects };
        let limit: usize = iseq_offsets.len().min(IBF_MAX_ISEQ_BODIES);
        for (i, &body_off) in iseq_offsets.iter().take(limit).enumerate() {
            if (body_off as usize) >= total {
                continue;
            }
            let index: u32 = u32::try_from(i).unwrap_or(u32::MAX);
            if let Some(body) =
                decode_iseq_body(bytes, table, &obj_table, body_off, index, ci_layout_known)
            {
                recovered_instruction_count = recovered_instruction_count
                    .saturating_add(u32::try_from(body.instructions.len()).unwrap_or(u32::MAX));
                iseqs.push(body);
            }
        }
    }

    IbfImage {
        iseq_offsets,
        objects,
        iseqs,
        recovered_literal_count,
        recovered_instruction_count,
    }
}

#[inline]
const fn table_entries_available(total: usize, base: usize) -> usize {
    if base >= total { 0 } else { (total - base) / 4 }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::yarv::reader::read_header;

    #[test]
    fn truncated_body_keeps_leading_instructions_instead_of_dropping_whole_iseq() {
        let img_bytes: [u8; 47] = [
            0x59, 0x41, 0x52, 0x42, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x2f, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x2b, 0x00, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x01, 0x01, 0x37, 0x01, 0x21, 0x07,
            0x87, 0x27, 0x00, 0x00, 0x00,
        ];
        let header: YarvBinaryHeader = read_header(&img_bytes).expect("header");
        let version: YarvVersion = YarvVersion::new(header.major, header.minor);
        let image: IbfImage = parse_image(&img_bytes, &header, version);
        assert_eq!(image.iseq_offsets.len(), 1);
        assert_eq!(
            image.iseqs.len(),
            1,
            "body must survive a mid-instruction end"
        );
        let body: &YarvIseqBody = &image.iseqs[0];
        assert!(
            !body.instructions.is_empty(),
            "leading instructions must be retained, not discarded with the whole body"
        );
        assert_eq!(body.instructions[0].mnemonic, "nop");
    }

    #[test]
    fn invalid_table_offsets_do_not_reserve_declared_counts() {
        let bytes: [u8; 36] = [0; 36];
        let header: YarvBinaryHeader = YarvBinaryHeader {
            magic: *b"YARB",
            major: 3,
            minor: 2,
            size: 36,
            extra_size: 0,
            iseq_list_size: u32::MAX,
            global_object_list_size: u32::MAX,
            iseq_list_offset: u32::MAX,
            global_object_list_offset: u32::MAX,
        };
        let version: YarvVersion = YarvVersion::new(header.major, header.minor);
        let image: IbfImage = parse_image(&bytes, &header, version);
        assert!(image.iseq_offsets.is_empty());
        assert!(image.objects.is_empty());
    }

    #[test]
    fn small_value_single_byte_odd_flag() {
        let bytes: [u8; 1] = [0x17];
        let (v, next): (u64, usize) = read_small_value(&bytes, 0).expect("decode");
        assert_eq!(v, 11);
        assert_eq!(next, 1);
    }

    #[test]
    fn small_value_two_byte_continuation() {
        let bytes: [u8; 2] = [0x02, 0x40];
        let (v, next): (u64, usize) = read_small_value(&bytes, 0).expect("decode");
        assert_eq!(v, 0x40);
        assert_eq!(next, 2);
    }

    #[test]
    fn local_table_resolves_object_indices_to_symbol_names() {
        let objects: Vec<IbfObject> = vec![
            IbfObject {
                index: 0,
                offset: 0,
                kind: IbfObjectKind::Nil,
                literal: None,
                element_count: None,
                elements: Vec::new(),
            },
            IbfObject {
                index: 1,
                offset: 0,
                kind: IbfObjectKind::Symbol,
                literal: Some("count".to_owned()),
                element_count: None,
                elements: Vec::new(),
            },
            IbfObject {
                index: 2,
                offset: 0,
                kind: IbfObjectKind::Symbol,
                literal: Some("name".to_owned()),
                element_count: None,
                elements: Vec::new(),
            },
        ];
        let table: ObjectTable<'_> = ObjectTable { objects: &objects };
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&2u64.to_le_bytes());
        bytes.extend_from_slice(&1u64.to_le_bytes());
        let names: Vec<Option<String>> = parse_local_table(&bytes, &table, 0, 2);
        assert_eq!(
            names,
            vec![Some("name".to_owned()), Some("count".to_owned())]
        );
    }

    #[test]
    fn local_table_hidden_slot_is_none() {
        let objects: Vec<IbfObject> = vec![IbfObject {
            index: 0,
            offset: 0,
            kind: IbfObjectKind::Fixnum,
            literal: None,
            element_count: None,
            elements: Vec::new(),
        }];
        let table: ObjectTable<'_> = ObjectTable { objects: &objects };
        let bytes: [u8; 8] = 0u64.to_le_bytes();
        let names: Vec<Option<String>> = parse_local_table(&bytes, &table, 0, 1);
        assert_eq!(names, vec![None]);
    }

    #[test]
    fn catch_table_decodes_rescue_entry() {
        let int2fix_rescue: u64 = (1 << 1) | 1;
        let fields: [u64; 6] = [2, int2fix_rescue, 0, 6, 7, 0];
        let mut bytes: Vec<u8> = Vec::new();
        for f in fields {
            bytes.extend_from_slice(&dump_small_value(f));
        }
        let entries: Vec<YarvCatchEntry> = parse_catch_table(&bytes, 0, 1);
        assert_eq!(entries.len(), 1);
        let entry: &YarvCatchEntry = &entries[0];
        assert_eq!(entry.catch_type, CatchType::Rescue);
        assert_eq!(entry.start_pc, 0);
        assert_eq!(entry.end_pc, 6);
        assert_eq!(entry.cont_pc, 7);
        assert_eq!(entry.handler_iseq, Some(2));
    }

    #[test]
    fn float_literals_round_trip_as_ruby_source() {
        assert_eq!(render_float_literal(0.299), "0.299");
        assert_eq!(render_float_literal(1.0), "1.0");
        assert_eq!(render_float_literal(2.71), "2.71");
        assert_eq!(render_float_literal(-2.5), "-2.5");
        assert_eq!(render_float_literal(f64::INFINITY), "(1.0 / 0.0)");
        assert_eq!(render_float_literal(f64::NEG_INFINITY), "(-1.0 / 0.0)");
        assert_eq!(render_float_literal(f64::NAN), "(0.0 / 0.0)");
    }

    #[test]
    fn ruby_string_literal_escapes_so_it_reparses_to_the_same_bytes() {
        assert_eq!(ruby_string_literal("plain"), "\"plain\"");
        assert_eq!(ruby_dq_body("a#{b}c"), "a\\#{b}c");
        assert_eq!(
            ruby_dq_body("ivar #@a global #$b cvar #@@c"),
            "ivar \\#@a global \\#$b cvar \\#@@c"
        );
        assert_eq!(ruby_dq_body("trailing #"), "trailing #");
        assert_eq!(ruby_dq_body("hash #x mid"), "hash #x mid");
        assert_eq!(ruby_dq_body("\u{0}7"), "\\x007");
        assert_eq!(ruby_dq_body("\u{1}\u{1f}"), "\\x01\\x1F");
        assert_eq!(ruby_dq_body("\u{7f}"), "\\x7F");
        assert_eq!(ruby_dq_body("a\tb\nc\rd"), "a\\tb\\nc\\rd");
        assert_eq!(ruby_dq_body("quote \" back \\"), "quote \\\" back \\\\");
        assert_eq!(ruby_dq_body("caf\u{e9}"), "caf\u{e9}");
    }

    #[test]
    fn decode_object_recovers_float_literal() {
        let mut bytes: Vec<u8> = vec![0x04];
        bytes.resize(IBF_FLOAT_ALIGN, 0);
        bytes.extend_from_slice(&0.299_f64.to_le_bytes());
        let obj: IbfObject = decode_object(&bytes, 0, 0);
        assert_eq!(obj.kind, IbfObjectKind::Float);
        assert_eq!(obj.literal.as_deref(), Some("0.299"));
    }

    #[test]
    fn regexp_escapes_inner_slashes() {
        assert_eq!(escape_regexp_slashes("^/api/v"), "^\\/api\\/v");
        assert_eq!(escape_regexp_slashes("a\\/b"), "a\\/b");
        assert_eq!(escape_regexp_slashes("plain"), "plain");
    }

    #[test]
    fn regexp_literal_resolves_from_source_string() {
        let mut objects: Vec<IbfObject> = vec![
            IbfObject {
                index: 0,
                offset: 0,
                kind: IbfObjectKind::Regexp,
                literal: None,
                element_count: None,
                elements: vec![1],
            },
            IbfObject {
                index: 1,
                offset: 0,
                kind: IbfObjectKind::String,
                literal: Some("\\Aregex".to_owned()),
                element_count: None,
                elements: Vec::new(),
            },
        ];
        let mut recovered: u32 = 0;
        resolve_regexp_literals(&mut objects, &mut recovered);
        assert_eq!(objects[0].literal.as_deref(), Some("/\\Aregex/"));
        assert_eq!(recovered, 1);
    }

    #[test]
    fn regexp_flag_suffix_matches_ruby_inspect_order() {
        assert_eq!(regexp_flag_suffix(0), "");
        assert_eq!(regexp_flag_suffix(1), "i");
        assert_eq!(regexp_flag_suffix(2), "x");
        assert_eq!(regexp_flag_suffix(4), "m");
        assert_eq!(regexp_flag_suffix(7), "mix");
        assert_eq!(regexp_flag_suffix(32), "n");
        assert_eq!(regexp_flag_suffix(16), "");
        assert_eq!(regexp_flag_suffix(1 | 4 | 32), "min");
    }

    #[test]
    fn regexp_literal_preserves_option_flags() {
        fn resolved(option: u32) -> Option<String> {
            let mut objects: Vec<IbfObject> = vec![
                IbfObject {
                    index: 0,
                    offset: 0,
                    kind: IbfObjectKind::Regexp,
                    literal: None,
                    element_count: Some(option),
                    elements: vec![1],
                },
                IbfObject {
                    index: 1,
                    offset: 0,
                    kind: IbfObjectKind::String,
                    literal: Some("abc".to_owned()),
                    element_count: None,
                    elements: Vec::new(),
                },
            ];
            let mut recovered: u32 = 0;
            resolve_regexp_literals(&mut objects, &mut recovered);
            objects[0].literal.clone()
        }
        assert_eq!(resolved(1).as_deref(), Some("/abc/i"));
        assert_eq!(resolved(4).as_deref(), Some("/abc/m"));
        assert_eq!(resolved(2).as_deref(), Some("/abc/x"));
        assert_eq!(resolved(7).as_deref(), Some("/abc/mix"));
        assert_eq!(resolved(32).as_deref(), Some("/abc/n"));
        assert_eq!(resolved(0).as_deref(), Some("/abc/"));
    }

    #[test]
    fn regexp_decode_captures_option_byte() {
        let mut bytes: Vec<u8> = vec![0x06, 0x01];
        bytes.extend_from_slice(&dump_small_value(9));
        let obj: IbfObject = decode_object(&bytes, 0, 0);
        assert_eq!(obj.kind, IbfObjectKind::Regexp);
        assert_eq!(obj.element_count, Some(1));
        assert_eq!(obj.elements.first().copied(), Some(9));
    }

    #[test]
    fn fixnum_object_decodes_to_numeric_literal() {
        let mut bytes: Vec<u8> = vec![0x00; 4];
        bytes.push(0x35);
        bytes.extend_from_slice(&dump_small_value((2 << 1) | 1));
        let obj: IbfObject = decode_object(&bytes, 0, 4);
        assert_eq!(obj.kind, IbfObjectKind::Fixnum);
        assert_eq!(obj.literal.as_deref(), Some("2"));
    }

    #[test]
    fn catch_table_null_handler_is_none() {
        let int2fix_retry: u64 = (3 << 1) | 1;
        let fields: [u64; 6] = [0, int2fix_retry, 6, 7, 0, 0];
        let mut bytes: Vec<u8> = Vec::new();
        for f in fields {
            bytes.extend_from_slice(&dump_small_value(f));
        }
        let entries: Vec<YarvCatchEntry> = parse_catch_table(&bytes, 0, 1);
        assert_eq!(entries[0].catch_type, CatchType::Retry);
        assert_eq!(entries[0].handler_iseq, None);
    }

    #[test]
    fn small_value_roundtrip_against_dump_formula() {
        for value in [0u64, 1, 63, 64, 127, 128, 16_383, 16_384, 1_000_000] {
            let encoded: Vec<u8> = dump_small_value(value);
            let (decoded, used): (u64, usize) =
                read_small_value(&encoded, 0).expect("decode roundtrip");
            assert_eq!(decoded, value, "value {value}");
            assert_eq!(used, encoded.len(), "length {value}");
        }
    }

    #[test]
    fn small_value_rejects_truncated_continuation() {
        let bytes: [u8; 1] = [0x02];
        assert!(read_small_value(&bytes, 0).is_none());
    }

    #[test]
    fn decode_string_object_recovers_literal() {
        let mut bytes: Vec<u8> = vec![0x00; 4];
        bytes.push(0x45);
        bytes.push(0x03);
        bytes.push(0x17);
        bytes.extend_from_slice(b"hello world");
        let obj: IbfObject = decode_object(&bytes, 0, 4);
        assert_eq!(obj.kind, IbfObjectKind::String);
        assert_eq!(obj.literal.as_deref(), Some("hello world"));
    }

    #[test]
    fn out_of_bounds_string_len_is_safe() {
        let bytes: Vec<u8> = vec![
            0x45, 0x03, 0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];
        let obj: IbfObject = decode_object(&bytes, 0, 0);
        assert!(obj.literal.is_none());
    }

    #[test]
    fn out_of_bounds_object_offset_is_unknown() {
        let bytes: [u8; 1] = [0x11];
        let obj: IbfObject = decode_object(&bytes, 7, 128);
        assert_eq!(obj.kind, IbfObjectKind::Unknown);
        assert!(obj.literal.is_none());
        assert!(obj.elements.is_empty());
    }

    #[test]
    fn builtin_operand_rejects_oversized_name() {
        let mut bytecode: Vec<u8> = Vec::new();
        bytecode.extend_from_slice(&dump_small_value(0));
        bytecode.extend_from_slice(&dump_small_value(7));
        let oversized_len: u64 = u64::try_from(IBF_STRING_LEN_CAP).expect("string cap") + 1;
        bytecode.extend_from_slice(&dump_small_value(oversized_len));
        let body: YarvIseqBody = decode_single_builtin_bytecode(&bytecode);
        assert!(body.instructions.is_empty());
    }

    #[test]
    fn builtin_operand_decodes_bounded_name() {
        let mut bytecode: Vec<u8> = Vec::new();
        bytecode.extend_from_slice(&dump_small_value(0));
        bytecode.extend_from_slice(&dump_small_value(7));
        bytecode.extend_from_slice(&dump_small_value(3));
        bytecode.extend_from_slice(b"jit");
        let body: YarvIseqBody = decode_single_builtin_bytecode(&bytecode);
        assert_eq!(body.instructions.len(), 1);
        assert_eq!(
            body.instructions[0].operands,
            vec![YarvOperand::Builtin("jit".to_owned())]
        );
    }

    fn leaf(index: u32, kind: IbfObjectKind, literal: Option<&str>) -> IbfObject {
        IbfObject {
            index,
            offset: 0,
            kind,
            literal: literal.map(ToOwned::to_owned),
            element_count: None,
            elements: Vec::new(),
        }
    }

    #[test]
    fn immediates_decode_to_keyword_literals() {
        assert_eq!(decode_object(&[0x11], 0, 0).literal.as_deref(), Some("nil"));
        assert_eq!(
            decode_object(&[0x12], 0, 0).literal.as_deref(),
            Some("true")
        );
        assert_eq!(
            decode_object(&[0x13], 0, 0).literal.as_deref(),
            Some("false")
        );
        assert_eq!(classify_tag(0x09), IbfObjectKind::Range);
    }

    #[test]
    fn array_literal_resolves_from_element_indices() {
        let mut objects: Vec<IbfObject> = vec![
            IbfObject {
                index: 0,
                offset: 0,
                kind: IbfObjectKind::Array,
                literal: None,
                element_count: Some(3),
                elements: vec![1, 2, 3],
            },
            leaf(1, IbfObjectKind::Fixnum, Some("2")),
            leaf(2, IbfObjectKind::String, Some("hi")),
            leaf(3, IbfObjectKind::Symbol, Some("ok")),
        ];
        let mut recovered: u32 = 0;
        resolve_array_literals(&mut objects, &mut recovered);
        assert_eq!(objects[0].literal.as_deref(), Some("[2, \"hi\", :ok]"));
        assert_eq!(recovered, 1);
    }

    #[test]
    fn hash_literal_resolves_symbol_keys_and_values() {
        let mut objects: Vec<IbfObject> = vec![
            IbfObject {
                index: 0,
                offset: 0,
                kind: IbfObjectKind::Hash,
                literal: None,
                element_count: Some(4),
                elements: vec![1, 2, 3, 4],
            },
            leaf(1, IbfObjectKind::Symbol, Some("timeout")),
            leaf(2, IbfObjectKind::Fixnum, Some("30")),
            leaf(3, IbfObjectKind::Symbol, Some("debug")),
            leaf(4, IbfObjectKind::False, Some("false")),
        ];
        let mut recovered: u32 = 0;
        resolve_array_literals(&mut objects, &mut recovered);
        assert_eq!(
            objects[0].literal.as_deref(),
            Some("{ timeout: 30, debug: false }")
        );
    }

    #[test]
    fn empty_hash_literal_renders_braces() {
        let mut objects: Vec<IbfObject> = vec![IbfObject {
            index: 0,
            offset: 0,
            kind: IbfObjectKind::Hash,
            literal: None,
            element_count: Some(0),
            elements: Vec::new(),
        }];
        let mut recovered: u32 = 0;
        resolve_array_literals(&mut objects, &mut recovered);
        assert_eq!(objects[0].literal.as_deref(), Some("{}"));
    }

    #[test]
    fn range_literal_resolves_inclusive_exclusive_and_endless() {
        let mut objects: Vec<IbfObject> = vec![
            IbfObject {
                index: 0,
                offset: 0,
                kind: IbfObjectKind::Range,
                literal: None,
                element_count: Some(0),
                elements: vec![3, 4],
            },
            IbfObject {
                index: 1,
                offset: 0,
                kind: IbfObjectKind::Range,
                literal: None,
                element_count: Some(1),
                elements: vec![3, 4],
            },
            IbfObject {
                index: 2,
                offset: 0,
                kind: IbfObjectKind::Range,
                literal: None,
                element_count: Some(0),
                elements: vec![3, 5],
            },
            leaf(3, IbfObjectKind::Fixnum, Some("1")),
            leaf(4, IbfObjectKind::Fixnum, Some("10")),
            leaf(5, IbfObjectKind::Nil, Some("nil")),
        ];
        let mut recovered: u32 = 0;
        resolve_array_literals(&mut objects, &mut recovered);
        assert_eq!(objects[0].literal.as_deref(), Some("(1..10)"));
        assert_eq!(objects[1].literal.as_deref(), Some("(1...10)"));
        assert_eq!(objects[2].literal.as_deref(), Some("(1..)"));
    }

    fn decode_single_builtin_bytecode(bytecode: &[u8]) -> YarvIseqBody {
        let mut bytes: Vec<u8> = bytecode.to_vec();
        let body_offset: u32 = u32::try_from(bytes.len()).expect("body offset");
        let bytecode_size: u64 = u64::try_from(bytecode.len()).expect("bytecode size");
        for raw in [0u64, 1, u64::from(body_offset), bytecode_size] {
            bytes.extend_from_slice(&dump_small_value(raw));
        }
        let opcodes: [YarvOpcode; 1] = [YarvOpcode {
            mnemonic: "builtin",
            operands: &[TsKind::Builtin],
        }];
        let objects: Vec<IbfObject> = Vec::new();
        let object_table: ObjectTable<'_> = ObjectTable { objects: &objects };
        decode_iseq_body(&bytes, &opcodes, &object_table, body_offset, 0, false).expect("body")
    }

    fn dump_small_value(mut x: u64) -> Vec<u8> {
        let max_len: usize = 9;
        let mut bytes: Vec<u8> = vec![0u8; max_len];
        let mut n: u32 = 0;
        while (n as usize) < 8 && (x >> (7 - n)) != 0 {
            bytes[max_len - 1 - n as usize] = x as u8;
            n += 1;
            x >>= 8;
        }
        x <<= 1;
        x |= 1;
        x <<= n;
        bytes[max_len - 1 - n as usize] = x as u8;
        n += 1;
        bytes.split_off(max_len - n as usize)
    }
}
