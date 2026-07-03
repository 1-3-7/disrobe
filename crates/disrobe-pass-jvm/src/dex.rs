use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const DEX_MAGIC_PREFIX: [u8; 4] = [b'd', b'e', b'x', b'\n'];
pub const DEX_ENDIAN_TAG: u32 = 0x1234_5678;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DexVersion {
    V035,
    V037,
    V038,
    V039,
    V040,
    V041,
}

impl DexVersion {
    #[inline]
    #[must_use]
    pub const fn from_ascii(version: [u8; 3]) -> Option<Self> {
        match &version {
            b"035" => Some(Self::V035),
            b"037" => Some(Self::V037),
            b"038" => Some(Self::V038),
            b"039" => Some(Self::V039),
            b"040" => Some(Self::V040),
            b"041" => Some(Self::V041),
            _ => None,
        }
    }

    #[inline]
    #[must_use]
    pub const fn android_marketing(self) -> &'static str {
        match self {
            Self::V035 => "Android 1.0 .. 6.0 (API 1 .. 23)",
            Self::V037 => "Android 7.0 (API 24, default-methods)",
            Self::V038 => "Android 8.0 (API 26, invoke-polymorphic)",
            Self::V039 => "Android 9.0 (API 28, const-method-handle)",
            Self::V040 => "Android 10 .. 13 (API 29 .. 33)",
            Self::V041 => "Android 14 .. 16 (API 34 .. 36, hidden API)",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexHeader {
    pub version: DexVersion,
    pub checksum: u32,
    pub signature: [u8; 20],
    pub file_size: u32,
    pub header_size: u32,
    pub endian_tag: u32,
    pub link_size: u32,
    pub link_off: u32,
    pub map_off: u32,
    pub string_ids_size: u32,
    pub string_ids_off: u32,
    pub type_ids_size: u32,
    pub type_ids_off: u32,
    pub proto_ids_size: u32,
    pub proto_ids_off: u32,
    pub field_ids_size: u32,
    pub field_ids_off: u32,
    pub method_ids_size: u32,
    pub method_ids_off: u32,
    pub class_defs_size: u32,
    pub class_defs_off: u32,
    pub data_size: u32,
    pub data_off: u32,
}

pub fn parse_header(bytes: &[u8]) -> Result<DexHeader> {
    if bytes.len() < 0x70 {
        return Err(Error::Truncated {
            offset: 0,
            needed: 0x70,
            had: bytes.len(),
        });
    }
    let mut magic: [u8; 8] = [0u8; 8];
    magic.copy_from_slice(&bytes[..8]);
    let magic_intact: bool = magic[..4] == DEX_MAGIC_PREFIX && magic[7] == 0;
    let structurally_valid: bool = disrobe_binfmt::structural::validate_dex(bytes);
    if !magic_intact && !structurally_valid {
        return Err(Error::BadDexMagic(magic));
    }
    let version_bytes: [u8; 3] = [magic[4], magic[5], magic[6]];
    let version: DexVersion = match DexVersion::from_ascii(version_bytes) {
        Some(v) => v,
        None if structurally_valid => DexVersion::V035,
        None => return Err(Error::UnsupportedDexVersion(version_bytes)),
    };
    let checksum: u32 = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let mut signature: [u8; 20] = [0u8; 20];
    signature.copy_from_slice(&bytes[12..32]);
    let read_u32 = |o: usize| -> u32 {
        u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]])
    };
    let endian_tag: u32 = read_u32(40);
    if endian_tag != DEX_ENDIAN_TAG {
        return Err(Error::BadDexEndian(endian_tag));
    }
    Ok(DexHeader {
        version,
        checksum,
        signature,
        file_size: read_u32(32),
        header_size: read_u32(36),
        endian_tag,
        link_size: read_u32(44),
        link_off: read_u32(48),
        map_off: read_u32(52),
        string_ids_size: read_u32(56),
        string_ids_off: read_u32(60),
        type_ids_size: read_u32(64),
        type_ids_off: read_u32(68),
        proto_ids_size: read_u32(72),
        proto_ids_off: read_u32(76),
        field_ids_size: read_u32(80),
        field_ids_off: read_u32(84),
        method_ids_size: read_u32(88),
        method_ids_off: read_u32(92),
        class_defs_size: read_u32(96),
        class_defs_off: read_u32(100),
        data_size: read_u32(104),
        data_off: read_u32(108),
    })
}

fn read_uleb128(bytes: &[u8], off: usize) -> Result<(u32, usize)> {
    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    let mut cursor: usize = off;
    loop {
        if cursor >= bytes.len() {
            return Err(Error::Truncated {
                offset: cursor,
                needed: 1,
                had: 0,
            });
        }
        let b: u8 = bytes[cursor];
        cursor += 1;
        result |= u32::from(b & 0x7F) << shift;
        if (b & 0x80) == 0 {
            break;
        }
        shift += 7;
        if shift >= 32 {
            return Err(Error::BadDexEndian(0));
        }
    }
    Ok((result, cursor))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtoId {
    pub shorty: String,
    pub return_type: String,
    pub parameters: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldId {
    pub class: String,
    pub type_name: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodId {
    pub class: String,
    pub proto: ProtoId,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexFile {
    pub header: DexHeader,
    pub strings: Vec<String>,
    pub type_names: Vec<String>,
    pub class_descriptors: Vec<String>,
    pub proto_ids: Vec<ProtoId>,
    pub field_ids: Vec<FieldId>,
    pub method_ids: Vec<MethodId>,
}

#[inline]
fn cap_hint(declared: u32, total_len: usize) -> usize {
    (declared as usize).min(total_len)
}

#[inline]
fn count_cap(declared: u32, record_stride: usize, total_len: usize) -> usize {
    let max_records: usize = total_len / record_stride.max(1) + 1;
    (declared as usize).min(max_records)
}

struct WalkBudget {
    members: usize,
    insn_words: usize,
}

impl WalkBudget {
    #[inline]
    const fn new(header: &DexHeader, total_len: usize) -> Self {
        Self {
            members: (header.field_ids_size as usize + header.method_ids_size as usize)
                .saturating_add(1),
            insn_words: total_len,
        }
    }

    #[inline]
    const fn spent(&self) -> bool {
        self.members == 0
    }
}

pub fn parse(bytes: &[u8]) -> Result<DexFile> {
    let header: DexHeader = parse_header(bytes)?;
    let mut strings: Vec<String> =
        Vec::with_capacity(cap_hint(header.string_ids_size, bytes.len()));
    for i in 0..count_cap(header.string_ids_size, 4, bytes.len()) {
        let id_off: usize = header.string_ids_off as usize + i * 4;
        if id_off + 4 > bytes.len() {
            break;
        }
        let data_off: u32 = u32::from_le_bytes([
            bytes[id_off],
            bytes[id_off + 1],
            bytes[id_off + 2],
            bytes[id_off + 3],
        ]);
        let data_off_usize: usize = data_off as usize;
        if data_off_usize >= bytes.len() {
            break;
        }
        let (size, after_leb): (u32, usize) = read_uleb128(bytes, data_off_usize)?;
        let end: usize = after_leb + size as usize;
        if end > bytes.len() {
            break;
        }
        let raw: &[u8] = &bytes[after_leb..end];
        let decoded: String = decode_mutf8_lossy(raw);
        strings.push(decoded);
    }
    let mut type_names: Vec<String> =
        Vec::with_capacity(cap_hint(header.type_ids_size, bytes.len()));
    for i in 0..count_cap(header.type_ids_size, 4, bytes.len()) {
        let id_off: usize = header.type_ids_off as usize + i * 4;
        if id_off + 4 > bytes.len() {
            break;
        }
        let descriptor_idx: u32 = u32::from_le_bytes([
            bytes[id_off],
            bytes[id_off + 1],
            bytes[id_off + 2],
            bytes[id_off + 3],
        ]);
        let idx: usize = descriptor_idx as usize;
        if idx < strings.len() {
            type_names.push(strings[idx].clone());
        } else {
            type_names.push(String::new());
        }
    }
    let mut class_descriptors: Vec<String> =
        Vec::with_capacity(cap_hint(header.class_defs_size, bytes.len()));
    let class_def_size: usize = 32;
    for i in 0..count_cap(header.class_defs_size, class_def_size, bytes.len()) {
        let cd_off: usize = header.class_defs_off as usize + i * class_def_size;
        if cd_off + 4 > bytes.len() {
            break;
        }
        let class_idx: u32 = u32::from_le_bytes([
            bytes[cd_off],
            bytes[cd_off + 1],
            bytes[cd_off + 2],
            bytes[cd_off + 3],
        ]);
        let idx: usize = class_idx as usize;
        if idx < type_names.len() {
            class_descriptors.push(type_names[idx].clone());
        }
    }
    let proto_ids: Vec<ProtoId> = parse_proto_ids(bytes, &header, &strings, &type_names);
    let field_ids: Vec<FieldId> = parse_field_ids(bytes, &header, &strings, &type_names);
    let method_ids: Vec<MethodId> =
        parse_method_ids(bytes, &header, &strings, &type_names, &proto_ids);
    Ok(DexFile {
        header,
        strings,
        type_names,
        class_descriptors,
        proto_ids,
        field_ids,
        method_ids,
    })
}

#[inline]
fn read_u16_at(bytes: &[u8], o: usize) -> Option<u16> {
    bytes
        .get(o..o + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

#[inline]
fn read_u32_at(bytes: &[u8], o: usize) -> Option<u32> {
    bytes
        .get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn type_at(type_names: &[String], idx: usize) -> String {
    type_names.get(idx).cloned().unwrap_or_default()
}

fn string_at(strings: &[String], idx: usize) -> String {
    strings.get(idx).cloned().unwrap_or_default()
}

fn parse_type_list(
    bytes: &[u8],
    off: u32,
    type_names: &[String],
    budget: &mut usize,
) -> Vec<String> {
    if off == 0 {
        return Vec::new();
    }
    let base: usize = off as usize;
    let Some(size): Option<u32> = read_u32_at(bytes, base) else {
        return Vec::new();
    };
    let entries: usize = (size as usize).min(*budget);
    if base + 4 + entries * 2 > bytes.len() {
        return Vec::new();
    }
    *budget -= entries;
    let mut out: Vec<String> = Vec::with_capacity(entries);
    for i in 0..entries {
        let entry_off: usize = base + 4 + i * 2;
        let Some(type_idx): Option<u16> = read_u16_at(bytes, entry_off) else {
            break;
        };
        out.push(type_at(type_names, usize::from(type_idx)));
    }
    out
}

fn parse_proto_ids(
    bytes: &[u8],
    header: &DexHeader,
    strings: &[String],
    type_names: &[String],
) -> Vec<ProtoId> {
    let base: usize = header.proto_ids_off as usize;
    let count: usize = count_cap(header.proto_ids_size, 12, bytes.len());
    let mut budget: usize = bytes.len();
    let mut out: Vec<ProtoId> = Vec::with_capacity(count.min(bytes.len()));
    for i in 0..count {
        let entry: usize = base + i * 12;
        let (Some(shorty_idx), Some(return_type_idx), Some(params_off)): (
            Option<u32>,
            Option<u32>,
            Option<u32>,
        ) = (
            read_u32_at(bytes, entry),
            read_u32_at(bytes, entry + 4),
            read_u32_at(bytes, entry + 8),
        ) else {
            break;
        };
        out.push(ProtoId {
            shorty: string_at(strings, shorty_idx as usize),
            return_type: type_at(type_names, return_type_idx as usize),
            parameters: parse_type_list(bytes, params_off, type_names, &mut budget),
        });
    }
    out
}

fn parse_field_ids(
    bytes: &[u8],
    header: &DexHeader,
    strings: &[String],
    type_names: &[String],
) -> Vec<FieldId> {
    let base: usize = header.field_ids_off as usize;
    let count: usize = count_cap(header.field_ids_size, 8, bytes.len());
    let mut out: Vec<FieldId> = Vec::with_capacity(count.min(bytes.len()));
    for i in 0..count {
        let entry: usize = base + i * 8;
        let (Some(class_idx), Some(type_idx), Some(name_idx)): (
            Option<u16>,
            Option<u16>,
            Option<u32>,
        ) = (
            read_u16_at(bytes, entry),
            read_u16_at(bytes, entry + 2),
            read_u32_at(bytes, entry + 4),
        ) else {
            break;
        };
        out.push(FieldId {
            class: type_at(type_names, usize::from(class_idx)),
            type_name: type_at(type_names, usize::from(type_idx)),
            name: string_at(strings, name_idx as usize),
        });
    }
    out
}

fn parse_method_ids(
    bytes: &[u8],
    header: &DexHeader,
    strings: &[String],
    type_names: &[String],
    proto_ids: &[ProtoId],
) -> Vec<MethodId> {
    let base: usize = header.method_ids_off as usize;
    let count: usize = count_cap(header.method_ids_size, 8, bytes.len());
    let mut out: Vec<MethodId> = Vec::with_capacity(count.min(bytes.len()));
    for i in 0..count {
        let entry: usize = base + i * 8;
        let (Some(class_idx), Some(proto_idx), Some(name_idx)): (
            Option<u16>,
            Option<u16>,
            Option<u32>,
        ) = (
            read_u16_at(bytes, entry),
            read_u16_at(bytes, entry + 2),
            read_u32_at(bytes, entry + 4),
        ) else {
            break;
        };
        out.push(MethodId {
            class: type_at(type_names, usize::from(class_idx)),
            proto: proto_ids
                .get(usize::from(proto_idx))
                .cloned()
                .unwrap_or(ProtoId {
                    shorty: String::new(),
                    return_type: String::new(),
                    parameters: Vec::new(),
                }),
            name: string_at(strings, name_idx as usize),
        });
    }
    out
}

fn decode_mutf8_lossy(raw: &[u8]) -> String {
    let mut out: String = String::with_capacity(raw.len());
    let mut i: usize = 0;
    while i < raw.len() {
        let b1: u8 = raw[i];
        if b1 == 0 {
            break;
        }
        if b1 < 0x80 {
            out.push(b1 as char);
            i += 1;
        } else if (b1 & 0xE0) == 0xC0 && i + 1 < raw.len() {
            let b2: u8 = raw[i + 1];
            let cp: u32 = (u32::from(b1 & 0x1F) << 6) | u32::from(b2 & 0x3F);
            if let Some(ch) = char::from_u32(cp) {
                out.push(ch);
            }
            i += 2;
        } else if (b1 & 0xF0) == 0xE0 && i + 2 < raw.len() {
            let b2: u8 = raw[i + 1];
            let b3: u8 = raw[i + 2];
            let cp: u32 =
                (u32::from(b1 & 0x0F) << 12) | (u32::from(b2 & 0x3F) << 6) | u32::from(b3 & 0x3F);
            if (0xD800..=0xDBFF).contains(&cp) && i + 5 < raw.len() && raw[i + 3] == 0xED {
                let c5: u8 = raw[i + 4];
                let c6: u8 = raw[i + 5];
                let low: u32 = 0xD000 | (u32::from(c5 & 0x3F) << 6) | u32::from(c6 & 0x3F);
                if (0xDC00..=0xDFFF).contains(&low) {
                    let combined: u32 = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                    if let Some(ch) = char::from_u32(combined) {
                        out.push(ch);
                    }
                    i += 6;
                    continue;
                }
            }
            if let Some(ch) = char::from_u32(cp) {
                out.push(ch);
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TryItem {
    pub start_addr: u32,
    pub insn_count: u16,
    pub handlers: Vec<(Option<String>, u32)>,
    pub catch_all: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeItem {
    pub method_name: String,
    pub method_descriptor: String,
    pub class: String,
    pub is_direct: bool,
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub insns: Vec<u16>,
    pub tries: Vec<TryItem>,
    pub param_names: Vec<Option<String>>,
}

fn read_sleb128(bytes: &[u8], off: usize) -> Result<(i32, usize)> {
    let mut result: i32 = 0;
    let mut shift: u32 = 0;
    let mut cursor: usize = off;
    loop {
        if cursor >= bytes.len() {
            return Err(Error::Truncated {
                offset: cursor,
                needed: 1,
                had: 0,
            });
        }
        let b: u8 = bytes[cursor];
        cursor += 1;
        result |= i32::from(b & 0x7F) << shift;
        shift += 7;
        if (b & 0x80) == 0 {
            if shift < 32 && (b & 0x40) != 0 {
                result |= -(1i32 << shift);
            }
            break;
        }
        if shift >= 32 {
            break;
        }
    }
    Ok((result, cursor))
}

type ParsedCode = (u16, u16, u16, Vec<u16>, Vec<TryItem>, Vec<Option<String>>);
type ParsedHandlers = (Vec<(Option<String>, u32)>, Option<u32>);

fn parse_debug_param_names(
    bytes: &[u8],
    debug_off: usize,
    strings: &[String],
) -> Vec<Option<String>> {
    if debug_off == 0 || debug_off >= bytes.len() {
        return Vec::new();
    }
    let Ok((_line_start, after_line)): Result<(u32, usize)> = read_uleb128(bytes, debug_off) else {
        return Vec::new();
    };
    let Ok((params_size, mut cursor)): Result<(u32, usize)> = read_uleb128(bytes, after_line)
    else {
        return Vec::new();
    };
    let max_params: usize = (params_size as usize).min(bytes.len().saturating_sub(cursor));
    let mut names: Vec<Option<String>> = Vec::with_capacity(max_params);
    for _ in 0..max_params {
        let Ok((name_idx_p1, next)): Result<(u32, usize)> = read_uleb128(bytes, cursor) else {
            break;
        };
        cursor = next;
        if name_idx_p1 == 0 {
            names.push(None);
        } else {
            names.push(strings.get((name_idx_p1 - 1) as usize).cloned());
        }
    }
    names
}

fn parse_code_item(
    bytes: &[u8],
    code_off: usize,
    type_names: &[String],
    strings: &[String],
    budget: &mut WalkBudget,
) -> Option<ParsedCode> {
    if code_off + 16 > bytes.len() {
        return None;
    }
    let registers_size: u16 = read_u16_at(bytes, code_off)?;
    let ins_size: u16 = read_u16_at(bytes, code_off + 2)?;
    let outs_size: u16 = read_u16_at(bytes, code_off + 4)?;
    let tries_size: u16 = read_u16_at(bytes, code_off + 6)?;
    let debug_info_off: usize = read_u32_at(bytes, code_off + 8)? as usize;
    let insns_size: usize = read_u32_at(bytes, code_off + 12)? as usize;
    if insns_size > budget.insn_words {
        return None;
    }
    budget.insn_words -= insns_size;
    let insns_off: usize = code_off + 16;
    if insns_off + insns_size * 2 > bytes.len() {
        return None;
    }
    let mut insns: Vec<u16> = Vec::with_capacity(insns_size);
    for k in 0..insns_size {
        insns.push(read_u16_at(bytes, insns_off + k * 2)?);
    }
    let mut tries: Vec<TryItem> = Vec::new();
    if tries_size > 0 {
        let mut after_insns: usize = insns_off + insns_size * 2;
        if insns_size % 2 == 1 {
            after_insns += 2;
        }
        let tries_off: usize = after_insns;
        let handlers_base: usize = tries_off + usize::from(tries_size) * 8;
        if handlers_base > bytes.len() || usize::from(tries_size) > budget.insn_words {
            return None;
        }
        budget.insn_words -= usize::from(tries_size);
        let mut raw_tries: Vec<(u32, u16, u16)> = Vec::with_capacity(usize::from(tries_size));
        for t in 0..usize::from(tries_size) {
            let entry: usize = tries_off + t * 8;
            let start_addr: u32 = read_u32_at(bytes, entry)?;
            let insn_count: u16 = read_u16_at(bytes, entry + 4)?;
            let handler_off: u16 = read_u16_at(bytes, entry + 6)?;
            raw_tries.push((start_addr, insn_count, handler_off));
        }
        for (start_addr, insn_count, handler_off) in raw_tries {
            let abs: usize = handlers_base + usize::from(handler_off);
            let (handlers, catch_all): (Vec<(Option<String>, u32)>, Option<u32>) =
                parse_encoded_catch_handler(bytes, abs, type_names, budget).unwrap_or_default();
            tries.push(TryItem {
                start_addr,
                insn_count,
                handlers,
                catch_all,
            });
        }
    }
    let param_names: Vec<Option<String>> = parse_debug_param_names(bytes, debug_info_off, strings);
    Some((
        registers_size,
        ins_size,
        outs_size,
        insns,
        tries,
        param_names,
    ))
}

fn parse_encoded_catch_handler(
    bytes: &[u8],
    off: usize,
    type_names: &[String],
    budget: &mut WalkBudget,
) -> Option<ParsedHandlers> {
    let (size, mut cursor): (i32, usize) = read_sleb128(bytes, off).ok()?;
    let mut handlers: Vec<(Option<String>, u32)> = Vec::new();
    let count: usize = (size.unsigned_abs() as usize)
        .min(bytes.len().saturating_sub(cursor))
        .min(budget.insn_words);
    budget.insn_words -= count;
    for _ in 0..count {
        let (type_idx, n1): (u32, usize) = read_uleb128(bytes, cursor).ok()?;
        let (addr, n2): (u32, usize) = read_uleb128(bytes, n1).ok()?;
        let catch_type: Option<String> = type_names.get(type_idx as usize).cloned();
        handlers.push((catch_type, addr));
        cursor = n2;
    }
    let catch_all: Option<u32> = if size <= 0 {
        let (addr, _n): (u32, usize) = read_uleb128(bytes, cursor).ok()?;
        Some(addr)
    } else {
        None
    };
    Some((handlers, catch_all))
}

#[must_use]
pub fn parse_code_items(dex: &DexFile, bytes: &[u8]) -> Vec<CodeItem> {
    let header: &DexHeader = &dex.header;
    let class_defs_off: usize = header.class_defs_off as usize;
    let mut out: Vec<CodeItem> = Vec::new();
    let mut budget: WalkBudget = WalkBudget::new(header, bytes.len());
    for ci in 0..count_cap(header.class_defs_size, 32, bytes.len()) {
        let base: usize = class_defs_off + ci * 32;
        let Some(class_idx): Option<u32> = read_u32_at(bytes, base) else {
            break;
        };
        let class_name: String = type_at(&dex.type_names, class_idx as usize);
        let Some(class_data_off): Option<u32> = read_u32_at(bytes, base + 24) else {
            continue;
        };
        if class_data_off == 0 {
            continue;
        }
        if budget.spent() {
            break;
        }
        walk_class_data(
            dex,
            bytes,
            class_data_off as usize,
            &class_name,
            &mut out,
            &mut budget,
        );
    }
    out
}

fn walk_class_data(
    dex: &DexFile,
    bytes: &[u8],
    class_data_off: usize,
    class_name: &str,
    out: &mut Vec<CodeItem>,
    budget: &mut WalkBudget,
) {
    let Ok((static_fields, n1)): Result<(u32, usize)> = read_uleb128(bytes, class_data_off) else {
        return;
    };
    let Ok((instance_fields, n2)): Result<(u32, usize)> = read_uleb128(bytes, n1) else {
        return;
    };
    let Ok((direct_methods, n3)): Result<(u32, usize)> = read_uleb128(bytes, n2) else {
        return;
    };
    let Ok((virtual_methods, n4)): Result<(u32, usize)> = read_uleb128(bytes, n3) else {
        return;
    };
    let after_static: usize = skip_encoded_fields(bytes, n4, static_fields, budget);
    let after_instance: usize = skip_encoded_fields(bytes, after_static, instance_fields, budget);
    let after_direct: usize = walk_encoded_methods(
        dex,
        bytes,
        after_instance,
        direct_methods,
        class_name,
        true,
        out,
        budget,
    );
    let _after_virtual: usize = walk_encoded_methods(
        dex,
        bytes,
        after_direct,
        virtual_methods,
        class_name,
        false,
        out,
        budget,
    );
}

fn skip_encoded_fields(bytes: &[u8], mut o: usize, count: u32, budget: &mut WalkBudget) -> usize {
    let bounded: usize = (count as usize).min(budget.members);
    for _ in 0..bounded {
        let Ok((_idx_diff, n1)): Result<(u32, usize)> = read_uleb128(bytes, o) else {
            return o;
        };
        let Ok((_access, n2)): Result<(u32, usize)> = read_uleb128(bytes, n1) else {
            return n1;
        };
        o = n2;
        budget.members = budget.members.saturating_sub(1);
    }
    o
}

fn walk_encoded_methods(
    dex: &DexFile,
    bytes: &[u8],
    mut o: usize,
    count: u32,
    class_name: &str,
    is_direct: bool,
    out: &mut Vec<CodeItem>,
    budget: &mut WalkBudget,
) -> usize {
    let mut method_idx: u32 = 0;
    let bounded: u32 = count.min(budget.members as u32);
    for k in 0..bounded {
        let Ok((idx_diff, n1)): Result<(u32, usize)> = read_uleb128(bytes, o) else {
            return o;
        };
        let Ok((_access, n2)): Result<(u32, usize)> = read_uleb128(bytes, n1) else {
            return n1;
        };
        let Ok((code_off, n3)): Result<(u32, usize)> = read_uleb128(bytes, n2) else {
            return n2;
        };
        budget.members = budget.members.saturating_sub(1);
        method_idx = if k == 0 {
            idx_diff
        } else {
            method_idx + idx_diff
        };
        if code_off != 0
            && let Some(parsed) = parse_code_item(
                bytes,
                code_off as usize,
                &dex.type_names,
                &dex.strings,
                budget,
            )
        {
            let (registers_size, ins_size, outs_size, insns, tries, param_names): ParsedCode =
                parsed;
            let method: Option<&MethodId> = dex.method_ids.get(method_idx as usize);
            let method_name: String = method.map(|m| m.name.clone()).unwrap_or_default();
            let method_descriptor: String = method
                .map(|m| {
                    let params: String = m.proto.parameters.concat();
                    format!("({params}){}", m.proto.return_type)
                })
                .unwrap_or_default();
            out.push(CodeItem {
                method_name,
                method_descriptor,
                class: class_name.to_owned(),
                is_direct,
                registers_size,
                ins_size,
                outs_size,
                insns,
                tries,
                param_names,
            });
        }
        o = n3;
    }
    o
}

pub const ACC_NATIVE: u32 = 0x0100;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeMethod {
    pub class: String,
    pub method: String,
    pub descriptor: String,
    pub jni_short_symbol: String,
    pub jni_long_symbol: String,
}

#[must_use]
pub fn extract_native_methods(dex: &DexFile, bytes: &[u8]) -> Vec<NativeMethod> {
    let header: &DexHeader = &dex.header;
    let class_defs_off: usize = header.class_defs_off as usize;
    let mut out: Vec<NativeMethod> = Vec::new();
    let mut budget: WalkBudget = WalkBudget::new(header, bytes.len());
    for ci in 0..count_cap(header.class_defs_size, 32, bytes.len()) {
        let base: usize = class_defs_off + ci * 32;
        let Some(class_idx): Option<u32> = read_u32_at(bytes, base) else {
            break;
        };
        let class_name: String = type_at(&dex.type_names, class_idx as usize);
        let Some(class_data_off): Option<u32> = read_u32_at(bytes, base + 24) else {
            continue;
        };
        if class_data_off == 0 {
            continue;
        }
        if budget.spent() {
            break;
        }
        collect_native_methods(
            dex,
            bytes,
            class_data_off as usize,
            &class_name,
            &mut out,
            &mut budget,
        );
    }
    out
}

fn collect_native_methods(
    dex: &DexFile,
    bytes: &[u8],
    class_data_off: usize,
    class_name: &str,
    out: &mut Vec<NativeMethod>,
    budget: &mut WalkBudget,
) {
    let Ok((static_fields, n1)): Result<(u32, usize)> = read_uleb128(bytes, class_data_off) else {
        return;
    };
    let Ok((instance_fields, n2)): Result<(u32, usize)> = read_uleb128(bytes, n1) else {
        return;
    };
    let Ok((direct_methods, n3)): Result<(u32, usize)> = read_uleb128(bytes, n2) else {
        return;
    };
    let Ok((virtual_methods, n4)): Result<(u32, usize)> = read_uleb128(bytes, n3) else {
        return;
    };
    let after_static: usize = skip_encoded_fields(bytes, n4, static_fields, budget);
    let after_instance: usize = skip_encoded_fields(bytes, after_static, instance_fields, budget);
    let after_direct: usize = scan_native_methods(
        dex,
        bytes,
        after_instance,
        direct_methods,
        class_name,
        out,
        budget,
    );
    let _after_virtual: usize = scan_native_methods(
        dex,
        bytes,
        after_direct,
        virtual_methods,
        class_name,
        out,
        budget,
    );
}

fn scan_native_methods(
    dex: &DexFile,
    bytes: &[u8],
    mut o: usize,
    count: u32,
    class_name: &str,
    out: &mut Vec<NativeMethod>,
    budget: &mut WalkBudget,
) -> usize {
    let mut method_idx: u32 = 0;
    let bounded: u32 = count.min(budget.members as u32);
    for k in 0..bounded {
        let Ok((idx_diff, n1)): Result<(u32, usize)> = read_uleb128(bytes, o) else {
            return o;
        };
        let Ok((access, n2)): Result<(u32, usize)> = read_uleb128(bytes, n1) else {
            return n1;
        };
        let Ok((_code_off, n3)): Result<(u32, usize)> = read_uleb128(bytes, n2) else {
            return n2;
        };
        budget.members = budget.members.saturating_sub(1);
        method_idx = if k == 0 {
            idx_diff
        } else {
            method_idx + idx_diff
        };
        if access & ACC_NATIVE != 0
            && let Some(method) = dex.method_ids.get(method_idx as usize)
        {
            let descriptor: String = {
                let params: String = method.proto.parameters.concat();
                format!("({params}){}", method.proto.return_type)
            };
            let (short, long): (String, String) =
                jni_symbols(class_name, &method.name, &method.proto.parameters);
            out.push(NativeMethod {
                class: class_name.to_owned(),
                method: method.name.clone(),
                descriptor,
                jni_short_symbol: short,
                jni_long_symbol: long,
            });
        }
        o = n3;
    }
    o
}

fn jni_mangle(segment: &str) -> String {
    let mut out: String = String::with_capacity(segment.len() + 8);
    for ch in segment.chars() {
        match ch {
            '_' => out.push_str("_1"),
            ';' => out.push_str("_2"),
            '[' => out.push_str("_3"),
            '/' | '.' => out.push('_'),
            c if c.is_ascii_alphanumeric() => out.push(c),
            c => {
                use std::fmt::Write as _;
                let _ = write!(out, "_0{:04x}", c as u32);
            }
        }
    }
    out
}

fn jni_symbols(class_descriptor: &str, method: &str, params: &[String]) -> (String, String) {
    let internal: &str = class_descriptor
        .strip_prefix('L')
        .and_then(|s: &str| s.strip_suffix(';'))
        .unwrap_or(class_descriptor);
    let mangled_class: String = jni_mangle(internal);
    let mangled_method: String = jni_mangle(method);
    let short: String = format!("Java_{mangled_class}_{mangled_method}");
    let mangled_args: String = jni_mangle(&params.concat());
    let long: String = format!("{short}__{mangled_args}");
    (short, long)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiDex {
    pub files: Vec<DexFile>,
}

pub fn parse_multi_dex(named: &[(&str, &[u8])]) -> Result<MultiDex> {
    let mut files: Vec<DexFile> = Vec::with_capacity(named.len());
    for (_name, bytes) in named {
        files.push(parse(bytes)?);
    }
    Ok(MultiDex { files })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_magic() {
        let bytes: [u8; 0x70] = [0u8; 0x70];
        let err: Error = parse_header(&bytes).expect_err("bad magic");
        assert!(matches!(err, Error::BadDexMagic(_)));
    }

    #[test]
    fn dex_version_table_complete() {
        for v in [b"035", b"037", b"038", b"039", b"040", b"041"] {
            assert!(DexVersion::from_ascii(*v).is_some());
        }
        assert!(DexVersion::from_ascii(*b"099").is_none());
    }

    #[test]
    fn uleb128_single_byte() {
        let (v, n): (u32, usize) = read_uleb128(&[0x42], 0).expect("uleb");
        assert_eq!(v, 0x42);
        assert_eq!(n, 1);
    }

    #[test]
    fn uleb128_two_bytes() {
        let (v, n): (u32, usize) = read_uleb128(&[0xE5, 0x8E, 0x26], 0).expect("uleb");
        assert_eq!(v, 624485);
        assert_eq!(n, 3);
    }

    #[test]
    fn mutf8_lossy_decodes_supplementary_pair() {
        let bytes: [u8; 6] = [0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80];
        let s: String = decode_mutf8_lossy(&bytes);
        assert_eq!(s, "\u{1F600}");
    }

    #[test]
    fn mutf8_lossy_stops_at_embedded_null() {
        let bytes: [u8; 3] = [b'a', 0x00, b'b'];
        let s: String = decode_mutf8_lossy(&bytes);
        assert_eq!(s, "a");
    }
}
