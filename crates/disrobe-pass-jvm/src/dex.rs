use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const DEX_NO_INDEX: u32 = 0xFFFF_FFFF;

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
    let mut value: u32 = 0;
    for index in 0..5 {
        let cursor: usize = off.checked_add(index).ok_or(Error::BadBytecode {
            offset: off,
            reason: "DEX uleb128 offset overflow",
        })?;
        let Some(byte): Option<u8> = bytes.get(cursor).copied() else {
            return Err(Error::Truncated {
                offset: cursor,
                needed: 1,
                had: 0,
            });
        };
        if index == 4 && (byte & 0x80 != 0 || byte & 0xF0 != 0) {
            return Err(Error::BadBytecode {
                offset: cursor,
                reason: "DEX uleb128 exceeds 32 bits",
            });
        }
        value |= u32::from(byte & 0x7F) << (index * 7);
        if byte & 0x80 == 0 {
            return Ok((value, cursor + 1));
        }
    }
    Err(Error::BadBytecode {
        offset: off,
        reason: "unterminated DEX uleb128",
    })
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
    pub class_super_descriptors: BTreeMap<String, String>,
    pub proto_ids: Vec<ProtoId>,
    pub field_ids: Vec<FieldId>,
    pub method_ids: Vec<MethodId>,
    pub call_site_ids_size: usize,
    pub method_handles_size: usize,
}

#[inline]
fn count_cap(declared: u32, record_stride: usize, total_len: usize) -> usize {
    let max_records: usize = total_len / record_stride.max(1) + 1;
    (declared as usize).min(max_records)
}

fn declared_table_count(
    bytes: &[u8],
    offset: u32,
    count: u32,
    stride: usize,
    reason: &'static str,
) -> Result<usize> {
    let table_offset: usize = offset as usize;
    let declared: usize = count as usize;
    let table_size: usize = declared.checked_mul(stride).ok_or(Error::BadBytecode {
        offset: table_offset,
        reason,
    })?;
    let table_end: usize = table_offset
        .checked_add(table_size)
        .ok_or(Error::BadBytecode {
            offset: table_offset,
            reason,
        })?;
    if table_end > bytes.len() {
        return Err(Error::BadBytecode {
            offset: table_offset,
            reason,
        });
    }
    Ok(declared)
}

fn parse_extended_pool_sizes(bytes: &[u8], header: &DexHeader) -> Result<(usize, usize)> {
    if header.map_off == 0 {
        return Ok((0, 0));
    }
    let map_offset: usize = header.map_off as usize;
    let map_size: u32 = required_u32_at(bytes, map_offset)?;
    let entries_offset: usize = map_offset.checked_add(4).ok_or(Error::BadBytecode {
        offset: map_offset,
        reason: "DEX map offset overflow",
    })?;
    let entry_count: usize = declared_table_count(
        bytes,
        u32::try_from(entries_offset).map_err(|_| Error::BadBytecode {
            offset: map_offset,
            reason: "DEX map offset is out of range",
        })?,
        map_size,
        12,
        "DEX map list is out of range",
    )?;
    let mut call_site_ids_size: Option<usize> = None;
    let mut method_handles_size: Option<usize> = None;
    for index in 0..entry_count {
        let entry_offset: usize = entries_offset
            .checked_add(index.checked_mul(12).ok_or(Error::BadBytecode {
                offset: entries_offset,
                reason: "DEX map entry offset overflow",
            })?)
            .ok_or(Error::BadBytecode {
                offset: entries_offset,
                reason: "DEX map entry offset overflow",
            })?;
        let item_type: u16 = required_u16_at(bytes, entry_offset)?;
        let unused: u16 = required_u16_at(bytes, entry_offset + 2)?;
        let item_size: u32 = required_u32_at(bytes, entry_offset + 4)?;
        let item_offset: u32 = required_u32_at(bytes, entry_offset + 8)?;
        if unused != 0 {
            return Err(Error::BadBytecode {
                offset: entry_offset + 2,
                reason: "DEX map entry has nonzero reserved data",
            });
        }
        let (slot, stride, reason): (&mut Option<usize>, usize, &'static str) = match item_type {
            0x0007 => (
                &mut call_site_ids_size,
                4,
                "DEX call-site identifier table is out of range",
            ),
            0x0008 => (
                &mut method_handles_size,
                8,
                "DEX method-handle table is out of range",
            ),
            _ => continue,
        };
        if slot.is_some() || !item_offset.is_multiple_of(4) {
            return Err(Error::BadBytecode {
                offset: entry_offset,
                reason: "DEX extended pool map entry is invalid",
            });
        }
        let count: usize = declared_table_count(bytes, item_offset, item_size, stride, reason)?;
        if item_type == 0x0007 {
            for item_index in 0..count {
                let offset: usize = item_offset as usize + item_index * stride;
                let data_offset: u32 = required_u32_at(bytes, offset)?;
                if data_offset == 0 || data_offset as usize >= bytes.len() {
                    return Err(Error::BadBytecode {
                        offset,
                        reason: "DEX call-site data offset is out of range",
                    });
                }
            }
        } else {
            for item_index in 0..count {
                let offset: usize = item_offset as usize + item_index * stride;
                let handle_type: u16 = required_u16_at(bytes, offset)?;
                let first_unused: u16 = required_u16_at(bytes, offset + 2)?;
                let member_index: u16 = required_u16_at(bytes, offset + 4)?;
                let second_unused: u16 = required_u16_at(bytes, offset + 6)?;
                let pool_size: u32 = match handle_type {
                    0..=3 => header.field_ids_size,
                    4..=8 => header.method_ids_size,
                    _ => {
                        return Err(Error::BadBytecode {
                            offset,
                            reason: "DEX method-handle type is invalid",
                        });
                    }
                };
                if first_unused != 0 || second_unused != 0 || u32::from(member_index) >= pool_size {
                    return Err(Error::BadBytecode {
                        offset,
                        reason: "DEX method-handle item is invalid",
                    });
                }
            }
        }
        *slot = Some(count);
    }
    Ok((
        call_site_ids_size.unwrap_or(0),
        method_handles_size.unwrap_or(0),
    ))
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
    let string_count: usize = declared_table_count(
        bytes,
        header.string_ids_off,
        header.string_ids_size,
        4,
        "DEX string identifier table is out of range",
    )?;
    let mut strings: Vec<String> = Vec::with_capacity(string_count.min(bytes.len()));
    for i in 0..string_count {
        let id_off: usize = header.string_ids_off as usize + i * 4;
        let data_off: u32 = required_u32_at(bytes, id_off)?;
        let data_off_usize: usize = data_off as usize;
        if data_off_usize >= bytes.len() {
            return Err(Error::BadBytecode {
                offset: id_off,
                reason: "DEX string data offset is out of range",
            });
        }
        let decoded: String = parse_string_data(bytes, data_off_usize)?;
        strings.push(decoded);
    }
    let type_count: usize = declared_table_count(
        bytes,
        header.type_ids_off,
        header.type_ids_size,
        4,
        "DEX type identifier table is out of range",
    )?;
    let mut type_names: Vec<String> = Vec::with_capacity(type_count.min(bytes.len()));
    for i in 0..type_count {
        let id_off: usize = header.type_ids_off as usize + i * 4;
        let descriptor_idx: u32 = required_u32_at(bytes, id_off)?;
        let idx: usize = descriptor_idx as usize;
        let descriptor: String = strings.get(idx).cloned().ok_or(Error::BadBytecode {
            offset: id_off,
            reason: "DEX type descriptor string index is out of range",
        })?;
        type_names.push(descriptor);
    }
    let class_count: usize = declared_table_count(
        bytes,
        header.class_defs_off,
        header.class_defs_size,
        32,
        "DEX class definition table is out of range",
    )?;
    let mut class_descriptors: Vec<String> = Vec::with_capacity(class_count.min(bytes.len()));
    let mut class_super_descriptors: BTreeMap<String, String> = BTreeMap::new();
    let class_def_size: usize = 32;
    for i in 0..class_count {
        let cd_off: usize = header.class_defs_off as usize + i * class_def_size;
        let class_idx: u32 = required_u32_at(bytes, cd_off)?;
        let superclass_idx: u32 = required_u32_at(bytes, cd_off + 8)?;
        let idx: usize = class_idx as usize;
        let class_name: String = type_names.get(idx).cloned().ok_or(Error::BadBytecode {
            offset: cd_off,
            reason: "DEX class type index is out of range",
        })?;
        if superclass_idx != DEX_NO_INDEX {
            let super_name: String =
                type_names
                    .get(superclass_idx as usize)
                    .cloned()
                    .ok_or(Error::BadBytecode {
                        offset: cd_off + 8,
                        reason: "DEX superclass type index is out of range",
                    })?;
            class_super_descriptors.insert(class_name.clone(), super_name);
        }
        class_descriptors.push(class_name);
    }
    let proto_ids: Vec<ProtoId> = parse_proto_ids(bytes, &header, &strings, &type_names)?;
    let field_ids: Vec<FieldId> = parse_field_ids(bytes, &header, &strings, &type_names)?;
    let method_ids: Vec<MethodId> =
        parse_method_ids(bytes, &header, &strings, &type_names, &proto_ids)?;
    let (call_site_ids_size, method_handles_size): (usize, usize) =
        parse_extended_pool_sizes(bytes, &header)?;
    Ok(DexFile {
        header,
        strings,
        type_names,
        class_descriptors,
        class_super_descriptors,
        proto_ids,
        field_ids,
        method_ids,
        call_site_ids_size,
        method_handles_size,
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

fn parse_type_list(
    bytes: &[u8],
    off: u32,
    type_names: &[String],
    budget: &mut usize,
) -> Result<Vec<String>> {
    if off == 0 {
        return Ok(Vec::new());
    }
    let base: usize = off as usize;
    let size: u32 = required_u32_at(bytes, base)?;
    let entries: usize = size as usize;
    if entries > *budget {
        return Err(Error::BadBytecode {
            offset: base,
            reason: "DEX type list budget exceeded",
        });
    }
    let entries_size: usize = entries.checked_mul(2).ok_or(Error::BadBytecode {
        offset: base,
        reason: "DEX type list size overflow",
    })?;
    let entries_end: usize = base
        .checked_add(4)
        .and_then(|start: usize| start.checked_add(entries_size))
        .ok_or(Error::BadBytecode {
            offset: base,
            reason: "DEX type list size overflow",
        })?;
    if entries_end > bytes.len() {
        return Err(Error::BadBytecode {
            offset: base,
            reason: "DEX type list is truncated",
        });
    }
    *budget -= entries;
    let mut out: Vec<String> = Vec::with_capacity(entries);
    for i in 0..entries {
        let entry_off: usize = base + 4 + i * 2;
        let type_idx: u16 = required_u16_at(bytes, entry_off)?;
        let type_name: String =
            type_names
                .get(usize::from(type_idx))
                .cloned()
                .ok_or(Error::BadBytecode {
                    offset: entry_off,
                    reason: "DEX type list index is out of range",
                })?;
        out.push(type_name);
    }
    Ok(out)
}

fn parse_proto_ids(
    bytes: &[u8],
    header: &DexHeader,
    strings: &[String],
    type_names: &[String],
) -> Result<Vec<ProtoId>> {
    let base: usize = header.proto_ids_off as usize;
    let count: usize = declared_table_count(
        bytes,
        header.proto_ids_off,
        header.proto_ids_size,
        12,
        "DEX prototype identifier table is out of range",
    )?;
    let mut budget: usize = bytes.len();
    let mut out: Vec<ProtoId> = Vec::with_capacity(count.min(bytes.len()));
    for i in 0..count {
        let entry: usize = base + i * 12;
        let shorty_idx: u32 = required_u32_at(bytes, entry)?;
        let return_type_idx: u32 = required_u32_at(bytes, entry + 4)?;
        let params_off: u32 = required_u32_at(bytes, entry + 8)?;
        let shorty: String =
            strings
                .get(shorty_idx as usize)
                .cloned()
                .ok_or(Error::BadBytecode {
                    offset: entry,
                    reason: "DEX prototype shorty index is out of range",
                })?;
        let return_type: String =
            type_names
                .get(return_type_idx as usize)
                .cloned()
                .ok_or(Error::BadBytecode {
                    offset: entry + 4,
                    reason: "DEX prototype return type index is out of range",
                })?;
        out.push(ProtoId {
            shorty,
            return_type,
            parameters: parse_type_list(bytes, params_off, type_names, &mut budget)?,
        });
    }
    Ok(out)
}

fn parse_field_ids(
    bytes: &[u8],
    header: &DexHeader,
    strings: &[String],
    type_names: &[String],
) -> Result<Vec<FieldId>> {
    let base: usize = header.field_ids_off as usize;
    let count: usize = declared_table_count(
        bytes,
        header.field_ids_off,
        header.field_ids_size,
        8,
        "DEX field identifier table is out of range",
    )?;
    let mut out: Vec<FieldId> = Vec::with_capacity(count.min(bytes.len()));
    for i in 0..count {
        let entry: usize = base + i * 8;
        let class_idx: u16 = required_u16_at(bytes, entry)?;
        let type_idx: u16 = required_u16_at(bytes, entry + 2)?;
        let name_idx: u32 = required_u32_at(bytes, entry + 4)?;
        let class: String =
            type_names
                .get(usize::from(class_idx))
                .cloned()
                .ok_or(Error::BadBytecode {
                    offset: entry,
                    reason: "DEX field class index is out of range",
                })?;
        let type_name: String =
            type_names
                .get(usize::from(type_idx))
                .cloned()
                .ok_or(Error::BadBytecode {
                    offset: entry + 2,
                    reason: "DEX field type index is out of range",
                })?;
        let name: String = strings
            .get(name_idx as usize)
            .cloned()
            .ok_or(Error::BadBytecode {
                offset: entry + 4,
                reason: "DEX field name index is out of range",
            })?;
        out.push(FieldId {
            class,
            type_name,
            name,
        });
    }
    Ok(out)
}

fn parse_method_ids(
    bytes: &[u8],
    header: &DexHeader,
    strings: &[String],
    type_names: &[String],
    proto_ids: &[ProtoId],
) -> Result<Vec<MethodId>> {
    let base: usize = header.method_ids_off as usize;
    let count: usize = declared_table_count(
        bytes,
        header.method_ids_off,
        header.method_ids_size,
        8,
        "DEX method identifier table is out of range",
    )?;
    let mut out: Vec<MethodId> = Vec::with_capacity(count.min(bytes.len()));
    for i in 0..count {
        let entry: usize = base + i * 8;
        let class_idx: u16 = required_u16_at(bytes, entry)?;
        let proto_idx: u16 = required_u16_at(bytes, entry + 2)?;
        let name_idx: u32 = required_u32_at(bytes, entry + 4)?;
        let class: String =
            type_names
                .get(usize::from(class_idx))
                .cloned()
                .ok_or(Error::BadBytecode {
                    offset: entry,
                    reason: "DEX method class index is out of range",
                })?;
        let proto: ProtoId =
            proto_ids
                .get(usize::from(proto_idx))
                .cloned()
                .ok_or(Error::BadBytecode {
                    offset: entry + 2,
                    reason: "DEX method prototype index is out of range",
                })?;
        let name: String = strings
            .get(name_idx as usize)
            .cloned()
            .ok_or(Error::BadBytecode {
                offset: entry + 4,
                reason: "DEX method name index is out of range",
            })?;
        out.push(MethodId { class, proto, name });
    }
    Ok(out)
}

fn decode_mutf8(raw: &[u8], base_offset: usize) -> Result<String> {
    let mut out: String = String::with_capacity(raw.len());
    let mut i: usize = 0;
    while i < raw.len() {
        let b1: u8 = raw[i];
        if (1..=0x7F).contains(&b1) {
            out.push(b1 as char);
            i += 1;
            continue;
        }
        if (0xC0..=0xDF).contains(&b1) {
            let Some(b2): Option<u8> = raw.get(i + 1).copied() else {
                return Err(Error::BadBytecode {
                    offset: base_offset + i,
                    reason: "DEX string has truncated MUTF-8",
                });
            };
            if b2 & 0xC0 != 0x80 {
                return Err(Error::BadBytecode {
                    offset: base_offset + i + 1,
                    reason: "DEX string has an invalid MUTF-8 continuation",
                });
            }
            let cp: u32 = (u32::from(b1 & 0x1F) << 6) | u32::from(b2 & 0x3F);
            if cp == 0 {
                out.push('\0');
            } else if cp < 0x80 {
                return Err(Error::BadBytecode {
                    offset: base_offset + i,
                    reason: "DEX string has an overlong MUTF-8 sequence",
                });
            } else {
                let ch: char = char::from_u32(cp).ok_or(Error::BadBytecode {
                    offset: base_offset + i,
                    reason: "DEX string has an invalid MUTF-8 scalar",
                })?;
                out.push(ch);
            }
            i += 2;
            continue;
        }
        if (0xE0..=0xEF).contains(&b1) {
            let Some(pair): Option<&[u8]> = raw.get(i + 1..i + 3) else {
                return Err(Error::BadBytecode {
                    offset: base_offset + i,
                    reason: "DEX string has truncated MUTF-8",
                });
            };
            let b2: u8 = pair[0];
            let b3: u8 = pair[1];
            if b2 & 0xC0 != 0x80 || b3 & 0xC0 != 0x80 {
                return Err(Error::BadBytecode {
                    offset: base_offset + i,
                    reason: "DEX string has an invalid MUTF-8 continuation",
                });
            }
            let cp: u32 =
                (u32::from(b1 & 0x0F) << 12) | (u32::from(b2 & 0x3F) << 6) | u32::from(b3 & 0x3F);
            if cp < 0x800 {
                return Err(Error::BadBytecode {
                    offset: base_offset + i,
                    reason: "DEX string has an overlong MUTF-8 sequence",
                });
            }
            if (0xD800..=0xDBFF).contains(&cp) {
                let Some(low_bytes): Option<&[u8]> = raw.get(i + 3..i + 6) else {
                    return Err(Error::BadBytecode {
                        offset: base_offset + i,
                        reason: "DEX string has an unpaired MUTF-8 surrogate",
                    });
                };
                let low_lead: u8 = low_bytes[0];
                let low_second: u8 = low_bytes[1];
                let low_third: u8 = low_bytes[2];
                if low_lead != 0xED || low_second & 0xC0 != 0x80 || low_third & 0xC0 != 0x80 {
                    return Err(Error::BadBytecode {
                        offset: base_offset + i + 3,
                        reason: "DEX string has an unpaired MUTF-8 surrogate",
                    });
                }
                let low: u32 = (u32::from(low_lead & 0x0F) << 12)
                    | (u32::from(low_second & 0x3F) << 6)
                    | u32::from(low_third & 0x3F);
                if !(0xDC00..=0xDFFF).contains(&low) {
                    return Err(Error::BadBytecode {
                        offset: base_offset + i + 3,
                        reason: "DEX string has an unpaired MUTF-8 surrogate",
                    });
                }
                let combined: u32 = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                let ch: char = char::from_u32(combined).ok_or(Error::BadBytecode {
                    offset: base_offset + i,
                    reason: "DEX string has an invalid MUTF-8 scalar",
                })?;
                out.push(ch);
                i += 6;
                continue;
            }
            if (0xDC00..=0xDFFF).contains(&cp) {
                return Err(Error::BadBytecode {
                    offset: base_offset + i,
                    reason: "DEX string has an unpaired MUTF-8 surrogate",
                });
            }
            let ch: char = char::from_u32(cp).ok_or(Error::BadBytecode {
                offset: base_offset + i,
                reason: "DEX string has an invalid MUTF-8 scalar",
            })?;
            out.push(ch);
            i += 3;
            continue;
        }
        return Err(Error::BadBytecode {
            offset: base_offset + i,
            reason: "DEX string has an invalid MUTF-8 leading byte",
        });
    }
    Ok(out)
}

fn parse_string_data(bytes: &[u8], offset: usize) -> Result<String> {
    let (declared_utf16_size, data_start): (u32, usize) = read_uleb128(bytes, offset)?;
    let data: &[u8] = bytes.get(data_start..).ok_or(Error::BadBytecode {
        offset: data_start,
        reason: "DEX string data offset is out of range",
    })?;
    let Some(terminator): Option<usize> = data.iter().position(|byte: &u8| *byte == 0) else {
        return Err(Error::BadBytecode {
            offset: data_start,
            reason: "DEX string data is not null terminated",
        });
    };
    let raw: &[u8] = &data[..terminator];
    let decoded: String = decode_mutf8(raw, data_start)?;
    let decoded_utf16_size: usize = decoded.encode_utf16().count();
    let declared_utf16_size: usize =
        usize::try_from(declared_utf16_size).map_err(|_| Error::BadBytecode {
            offset,
            reason: "DEX string UTF-16 size is out of range",
        })?;
    if decoded_utf16_size != declared_utf16_size {
        return Err(Error::BadBytecode {
            offset,
            reason: "DEX string UTF-16 size does not match its data",
        });
    }
    Ok(decoded)
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

#[derive(Debug)]
pub enum DexCodeState {
    Absent,
    Decoded(usize),
    Refused(Error),
}

#[derive(Debug)]
pub struct DexMethodCode {
    pub method_index: u32,
    pub class: String,
    pub method_name: String,
    pub method_descriptor: String,
    pub access_flags: u32,
    pub is_direct: bool,
    pub code_offset: u32,
    pub state: DexCodeState,
}

#[derive(Debug)]
pub struct DexCodeTail {
    pub class: String,
    pub error: Error,
}

#[derive(Debug)]
pub struct CodeItemsReport {
    decoded: Vec<CodeItem>,
    methods: Vec<DexMethodCode>,
    unrecovered_tail: Option<DexCodeTail>,
}

impl CodeItemsReport {
    #[must_use]
    pub fn decoded(&self) -> &[CodeItem] {
        &self.decoded
    }

    #[must_use]
    pub fn methods(&self) -> &[DexMethodCode] {
        &self.methods
    }

    #[must_use]
    pub const fn unrecovered_tail(&self) -> Option<&DexCodeTail> {
        self.unrecovered_tail.as_ref()
    }

    #[must_use]
    pub fn first_error(&self) -> Option<&Error> {
        self.methods
            .iter()
            .find_map(|method: &DexMethodCode| match &method.state {
                DexCodeState::Refused(error) => Some(error),
                DexCodeState::Absent | DexCodeState::Decoded(_) => None,
            })
            .or_else(|| {
                self.unrecovered_tail
                    .as_ref()
                    .map(|tail: &DexCodeTail| &tail.error)
            })
    }

    #[must_use]
    pub fn is_fully_decoded(&self) -> bool {
        self.first_error().is_none()
    }

    #[must_use]
    pub fn error_count(&self) -> usize {
        let method_errors: usize = self
            .methods
            .iter()
            .filter(|method: &&DexMethodCode| matches!(&method.state, DexCodeState::Refused(_)))
            .count();
        method_errors + usize::from(self.unrecovered_tail.is_some())
    }

    pub fn into_complete(self) -> Result<Vec<CodeItem>> {
        let Self {
            decoded,
            methods,
            unrecovered_tail,
        }: Self = self;
        let first_method_error: Option<Error> =
            methods
                .into_iter()
                .find_map(|method: DexMethodCode| match method.state {
                    DexCodeState::Refused(error) => Some(error),
                    DexCodeState::Absent | DexCodeState::Decoded(_) => None,
                });
        let method_result: Result<()> =
            first_method_error.map_or(Ok(()), |error: Error| Err(error));
        method_result?;
        let tail_result: Result<()> =
            unrecovered_tail.map_or(Ok(()), |tail: DexCodeTail| Err(tail.error));
        tail_result?;
        Ok(decoded)
    }

    #[must_use]
    pub fn into_partial_decoded(self) -> Vec<CodeItem> {
        self.decoded
    }
}

fn read_sleb128(bytes: &[u8], off: usize) -> Result<(i32, usize)> {
    let mut value: i64 = 0;
    for index in 0..5 {
        let cursor: usize = off.checked_add(index).ok_or(Error::BadBytecode {
            offset: off,
            reason: "DEX sleb128 offset overflow",
        })?;
        let Some(byte): Option<u8> = bytes.get(cursor).copied() else {
            return Err(Error::Truncated {
                offset: cursor,
                needed: 1,
                had: 0,
            });
        };
        let payload: u8 = byte & 0x7F;
        if index == 4 && (byte & 0x80 != 0 || !matches!(payload & 0x70, 0x00 | 0x70)) {
            return Err(Error::BadBytecode {
                offset: cursor,
                reason: "DEX sleb128 exceeds 32 bits",
            });
        }
        value |= i64::from(payload) << (index * 7);
        if byte & 0x80 == 0 {
            let used_bits: usize = (index + 1) * 7;
            if byte & 0x40 != 0 {
                value |= -1_i64 << used_bits;
            }
            let decoded: i32 = i32::try_from(value).map_err(|_| Error::BadBytecode {
                offset: cursor,
                reason: "DEX sleb128 exceeds 32 bits",
            })?;
            return Ok((decoded, cursor + 1));
        }
    }
    Err(Error::BadBytecode {
        offset: off,
        reason: "unterminated DEX sleb128",
    })
}

type ParsedCode = (u16, u16, u16, Vec<u16>, Vec<TryItem>, Vec<Option<String>>);
type CatchHandlers = Vec<(Option<String>, u32)>;
type HandlerSet = (CatchHandlers, Option<u32>);
type ParsedHandlers = (CatchHandlers, Option<u32>, usize);

fn parse_debug_param_names(
    bytes: &[u8],
    debug_off: usize,
    data_start: usize,
    registers_size: u16,
    type_names: &[String],
    strings: &[String],
) -> Result<Vec<Option<String>>> {
    if debug_off == 0 {
        return Ok(Vec::new());
    }
    if debug_off < data_start || debug_off >= bytes.len() {
        return Err(Error::BadBytecode {
            offset: debug_off,
            reason: "DEX debug info offset is outside the data section",
        });
    }
    let (_, after_line): (u32, usize) = read_uleb128(bytes, debug_off)?;
    let (params_size_raw, mut cursor): (u32, usize) = read_uleb128(bytes, after_line)?;
    let params_size: usize = usize::try_from(params_size_raw).map_err(|_| Error::BadBytecode {
        offset: after_line,
        reason: "DEX debug parameter count is out of range",
    })?;
    if params_size > bytes.len().saturating_sub(cursor) {
        return Err(Error::BadBytecode {
            offset: cursor,
            reason: "DEX debug parameter budget exceeded",
        });
    }
    let mut names: Vec<Option<String>> = Vec::with_capacity(params_size);
    for _ in 0..params_size {
        let (name_idx_p1, next): (u32, usize) = read_uleb128(bytes, cursor)?;
        cursor = next;
        if name_idx_p1 == 0 {
            names.push(None);
        } else {
            let name_index: usize =
                usize::try_from(name_idx_p1 - 1).map_err(|_| Error::BadBytecode {
                    offset: cursor,
                    reason: "DEX debug parameter name index is out of range",
                })?;
            let Some(name): Option<&String> = strings.get(name_index) else {
                return Err(Error::BadBytecode {
                    offset: cursor,
                    reason: "DEX debug parameter name index is out of range",
                });
            };
            names.push(Some(name.clone()));
        }
    }
    loop {
        let Some(opcode): Option<u8> = bytes.get(cursor).copied() else {
            return Err(Error::Truncated {
                offset: cursor,
                needed: 1,
                had: 0,
            });
        };
        cursor += 1;
        match opcode {
            0x00 => break,
            0x01 => {
                let (_, next): (u32, usize) = read_uleb128(bytes, cursor)?;
                cursor = next;
            }
            0x02 => {
                let (_, next): (i32, usize) = read_sleb128(bytes, cursor)?;
                cursor = next;
            }
            0x03 | 0x04 => {
                let (register, after_register): (u32, usize) = read_uleb128(bytes, cursor)?;
                if register >= u32::from(registers_size) {
                    return Err(Error::BadBytecode {
                        offset: cursor,
                        reason: "DEX debug register is out of range",
                    });
                }
                let (name_idx_p1, after_name): (u32, usize) = read_uleb128(bytes, after_register)?;
                validate_debug_index(
                    name_idx_p1,
                    strings.len(),
                    after_register,
                    "DEX debug name index is out of range",
                )?;
                let (type_idx_p1, after_type): (u32, usize) = read_uleb128(bytes, after_name)?;
                validate_debug_index(
                    type_idx_p1,
                    type_names.len(),
                    after_name,
                    "DEX debug type index is out of range",
                )?;
                cursor = after_type;
                if opcode == 0x04 {
                    let (signature_idx_p1, after_signature): (u32, usize) =
                        read_uleb128(bytes, cursor)?;
                    validate_debug_index(
                        signature_idx_p1,
                        strings.len(),
                        cursor,
                        "DEX debug signature index is out of range",
                    )?;
                    cursor = after_signature;
                }
            }
            0x05 | 0x06 => {
                let (register, next): (u32, usize) = read_uleb128(bytes, cursor)?;
                if register >= u32::from(registers_size) {
                    return Err(Error::BadBytecode {
                        offset: cursor,
                        reason: "DEX debug register is out of range",
                    });
                }
                cursor = next;
            }
            0x07 | 0x08 => {}
            0x09 => {
                let (name_idx_p1, next): (u32, usize) = read_uleb128(bytes, cursor)?;
                validate_debug_index(
                    name_idx_p1,
                    strings.len(),
                    cursor,
                    "DEX debug file index is out of range",
                )?;
                cursor = next;
            }
            _ => {}
        }
    }
    Ok(names)
}

fn validate_debug_index(
    encoded_index: u32,
    len: usize,
    offset: usize,
    reason: &'static str,
) -> Result<()> {
    if encoded_index == 0 {
        return Ok(());
    }
    let index: usize =
        usize::try_from(encoded_index - 1).map_err(|_| Error::BadBytecode { offset, reason })?;
    if index >= len {
        return Err(Error::BadBytecode { offset, reason });
    }
    Ok(())
}

const fn dex_truncated(bytes: &[u8], offset: usize, needed: usize) -> Error {
    Error::Truncated {
        offset,
        needed,
        had: bytes.len().saturating_sub(offset),
    }
}

fn required_u16_at(bytes: &[u8], offset: usize) -> Result<u16> {
    read_u16_at(bytes, offset).ok_or_else(|| dex_truncated(bytes, offset, 2))
}

fn required_u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    read_u32_at(bytes, offset).ok_or_else(|| dex_truncated(bytes, offset, 4))
}

fn checked_dex_add(offset: usize, amount: usize, reason: &'static str) -> Result<usize> {
    offset
        .checked_add(amount)
        .ok_or(Error::BadBytecode { offset, reason })
}

fn checked_dex_mul(value: usize, factor: usize, offset: usize) -> Result<usize> {
    value.checked_mul(factor).ok_or(Error::BadBytecode {
        offset,
        reason: "DEX code item size overflow",
    })
}

fn require_dex_range(bytes: &[u8], offset: usize, length: usize) -> Result<usize> {
    let end: usize = checked_dex_add(offset, length, "DEX code item range overflow")?;
    if end > bytes.len() {
        return Err(dex_truncated(bytes, offset, length));
    }
    Ok(end)
}

fn parse_code_item(
    bytes: &[u8],
    code_off: usize,
    data_start: usize,
    type_names: &[String],
    strings: &[String],
    budget: &mut WalkBudget,
) -> Result<ParsedCode> {
    if !code_off.is_multiple_of(4) {
        return Err(Error::BadBytecode {
            offset: code_off,
            reason: "unaligned DEX code item",
        });
    }
    let insns_off: usize = require_dex_range(bytes, code_off, 16)?;
    let registers_size: u16 = required_u16_at(bytes, code_off)?;
    let ins_size_offset: usize = checked_dex_add(code_off, 2, "DEX code header overflow")?;
    let outs_size_offset: usize = checked_dex_add(code_off, 4, "DEX code header overflow")?;
    let tries_size_offset: usize = checked_dex_add(code_off, 6, "DEX code header overflow")?;
    let debug_offset: usize = checked_dex_add(code_off, 8, "DEX code header overflow")?;
    let size_offset: usize = checked_dex_add(code_off, 12, "DEX code header overflow")?;
    let ins_size: u16 = required_u16_at(bytes, ins_size_offset)?;
    if registers_size < ins_size {
        return Err(Error::BadBytecode {
            offset: code_off,
            reason: "DEX register count is smaller than incoming register count",
        });
    }
    let outs_size: u16 = required_u16_at(bytes, outs_size_offset)?;
    let tries_size: u16 = required_u16_at(bytes, tries_size_offset)?;
    let debug_info_off: usize = required_u32_at(bytes, debug_offset)? as usize;
    let insns_size: usize = required_u32_at(bytes, size_offset)? as usize;
    if insns_size > budget.insn_words {
        return Err(Error::BadBytecode {
            offset: code_off,
            reason: "DEX instruction budget exceeded",
        });
    }
    let insns_bytes: usize = checked_dex_mul(insns_size, 2, insns_off)?;
    let after_insns_unaligned: usize = require_dex_range(bytes, insns_off, insns_bytes)?;
    budget.insn_words -= insns_size;
    let mut insns: Vec<u16> = Vec::with_capacity(insns_size);
    for index in 0..insns_size {
        let byte_delta: usize = checked_dex_mul(index, 2, insns_off)?;
        let entry: usize =
            checked_dex_add(insns_off, byte_delta, "DEX instruction offset overflow")?;
        insns.push(required_u16_at(bytes, entry)?);
    }
    crate::dalvik::validate_method(&insns, insns_off)?;
    let mut tries: Vec<TryItem> = Vec::new();
    if tries_size > 0 {
        let padding: usize = if insns_size % 2 == 1 { 2 } else { 0 };
        if padding != 0 && required_u16_at(bytes, after_insns_unaligned)? != 0 {
            return Err(Error::BadBytecode {
                offset: after_insns_unaligned,
                reason: "nonzero DEX code item padding",
            });
        }
        let tries_off: usize = checked_dex_add(
            after_insns_unaligned,
            padding,
            "DEX try table offset overflow",
        )?;
        let try_count: usize = usize::from(tries_size);
        if try_count > budget.insn_words {
            return Err(Error::BadBytecode {
                offset: tries_off,
                reason: "DEX try table budget exceeded",
            });
        }
        let tries_bytes: usize = checked_dex_mul(try_count, 8, tries_off)?;
        let handlers_base: usize = require_dex_range(bytes, tries_off, tries_bytes)?;
        budget.insn_words -= try_count;
        let mut raw_tries: Vec<(u32, u16, u16)> = Vec::with_capacity(try_count);
        let mut previous_end: usize = 0;
        for index in 0..try_count {
            let byte_delta: usize = checked_dex_mul(index, 8, tries_off)?;
            let entry: usize = checked_dex_add(tries_off, byte_delta, "DEX try offset overflow")?;
            let count_offset: usize = checked_dex_add(entry, 4, "DEX try offset overflow")?;
            let handler_offset: usize = checked_dex_add(entry, 6, "DEX try offset overflow")?;
            let start_addr: u32 = required_u32_at(bytes, entry)?;
            let insn_count: u16 = required_u16_at(bytes, count_offset)?;
            let handler_off: u16 = required_u16_at(bytes, handler_offset)?;
            let start: usize = usize::try_from(start_addr).map_err(|_| Error::BadBytecode {
                offset: entry,
                reason: "DEX try start is out of range",
            })?;
            let end: usize =
                start
                    .checked_add(usize::from(insn_count))
                    .ok_or(Error::BadBytecode {
                        offset: entry,
                        reason: "DEX try range overflow",
                    })?;
            if insn_count == 0 || end > insns_size {
                return Err(Error::BadBytecode {
                    offset: entry,
                    reason: "DEX try range is out of bounds",
                });
            }
            if index > 0 && start < previous_end {
                return Err(Error::BadBytecode {
                    offset: entry,
                    reason: "DEX try table is out of order or overlapping",
                });
            }
            previous_end = end;
            raw_tries.push((start_addr, insn_count, handler_off));
        }
        let (handler_count_raw, mut handler_cursor): (u32, usize) =
            read_uleb128(bytes, handlers_base)?;
        let handler_count: usize =
            usize::try_from(handler_count_raw).map_err(|_| Error::BadBytecode {
                offset: handlers_base,
                reason: "DEX catch handler count is out of range",
            })?;
        let remaining_handler_bytes: usize = bytes.len().saturating_sub(handler_cursor);
        if handler_count > budget.insn_words || handler_count > remaining_handler_bytes / 2 {
            return Err(Error::BadBytecode {
                offset: handlers_base,
                reason: "DEX catch handler list budget exceeded",
            });
        }
        budget.insn_words -= handler_count;
        let mut parsed_handlers: BTreeMap<usize, HandlerSet> = BTreeMap::new();
        for _ in 0..handler_count {
            let relative_offset: usize =
                handler_cursor
                    .checked_sub(handlers_base)
                    .ok_or(Error::BadBytecode {
                        offset: handler_cursor,
                        reason: "DEX catch handler offset underflow",
                    })?;
            let (handlers, catch_all, next): ParsedHandlers =
                parse_encoded_catch_handler(bytes, handler_cursor, type_names, insns_size, budget)?;
            parsed_handlers.insert(relative_offset, (handlers, catch_all));
            handler_cursor = next;
        }
        for (start_addr, insn_count, handler_off) in raw_tries {
            let Some((handlers, catch_all)): Option<&HandlerSet> =
                parsed_handlers.get(&usize::from(handler_off))
            else {
                return Err(Error::BadBytecode {
                    offset: handlers_base,
                    reason: "DEX try handler offset does not target a handler",
                });
            };
            tries.push(TryItem {
                start_addr,
                insn_count,
                handlers: handlers.clone(),
                catch_all: *catch_all,
            });
        }
    }
    let param_names: Vec<Option<String>> = parse_debug_param_names(
        bytes,
        debug_info_off,
        data_start,
        registers_size,
        type_names,
        strings,
    )?;
    Ok((
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
    insns_size: usize,
    budget: &mut WalkBudget,
) -> Result<ParsedHandlers> {
    let (size, mut cursor): (i32, usize) = read_sleb128(bytes, off)?;
    let count: usize = size.unsigned_abs() as usize;
    let remaining: usize = bytes.len().saturating_sub(cursor);
    let encoded_limit: usize = remaining / 2;
    let representation_size: usize = std::mem::size_of::<(Option<String>, u32)>().max(1);
    let representation_limit: usize = bytes.len() / representation_size;
    if count > budget.insn_words || count > encoded_limit || count > representation_limit {
        return Err(Error::BadBytecode {
            offset: off,
            reason: "DEX catch handler budget exceeded",
        });
    }
    budget.insn_words -= count;
    let mut handlers: Vec<(Option<String>, u32)> = Vec::new();
    let mut type_name_bytes: usize = 0;
    for _ in 0..count {
        let (type_idx, after_type): (u32, usize) = read_uleb128(bytes, cursor)?;
        let (address, after_address): (u32, usize) = read_uleb128(bytes, after_type)?;
        let Some(catch_type): Option<&String> = type_names.get(type_idx as usize) else {
            return Err(Error::BadBytecode {
                offset: cursor,
                reason: "DEX catch type index is out of range",
            });
        };
        type_name_bytes =
            type_name_bytes
                .checked_add(catch_type.len())
                .ok_or(Error::BadBytecode {
                    offset: cursor,
                    reason: "DEX catch type budget overflow",
                })?;
        if type_name_bytes > bytes.len() {
            return Err(Error::BadBytecode {
                offset: cursor,
                reason: "DEX catch type budget exceeded",
            });
        }
        let handler_address: usize = usize::try_from(address).map_err(|_| Error::BadBytecode {
            offset: after_type,
            reason: "DEX catch handler address is out of range",
        })?;
        if handler_address >= insns_size {
            return Err(Error::BadBytecode {
                offset: after_type,
                reason: "DEX catch handler address is out of bounds",
            });
        }
        handlers.push((Some(catch_type.clone()), address));
        cursor = after_address;
    }
    let catch_all: Option<u32> = if size <= 0 {
        let (address, next): (u32, usize) = read_uleb128(bytes, cursor)?;
        let handler_address: usize = usize::try_from(address).map_err(|_| Error::BadBytecode {
            offset: cursor,
            reason: "DEX catch-all address is out of range",
        })?;
        if handler_address >= insns_size {
            return Err(Error::BadBytecode {
                offset: cursor,
                reason: "DEX catch-all address is out of bounds",
            });
        }
        cursor = next;
        Some(address)
    } else {
        None
    };
    Ok((handlers, catch_all, cursor))
}

fn require_pool_index(
    index: Option<u32>,
    pool_len: usize,
    offset: usize,
    reason: &'static str,
) -> Result<()> {
    let Some(raw_index): Option<u32> = index else {
        return Err(Error::BadBytecode { offset, reason });
    };
    let index: usize =
        usize::try_from(raw_index).map_err(|_| Error::BadBytecode { offset, reason })?;
    if index >= pool_len {
        return Err(Error::BadBytecode { offset, reason });
    }
    Ok(())
}

const fn supports_dex_038(version: DexVersion) -> bool {
    matches!(
        version,
        DexVersion::V038 | DexVersion::V039 | DexVersion::V040 | DexVersion::V041
    )
}

const fn supports_dex_039(version: DexVersion) -> bool {
    matches!(
        version,
        DexVersion::V039 | DexVersion::V040 | DexVersion::V041
    )
}

const fn require_dex_feature(supported: bool, offset: usize, reason: &'static str) -> Result<()> {
    if !supported {
        return Err(Error::BadBytecode { offset, reason });
    }
    Ok(())
}

fn validate_code_references(insns: &[u16], dex: &DexFile, insns_offset: usize) -> Result<()> {
    let decoded: Vec<crate::dalvik::DalvikInsn> = crate::dalvik::decode_method(insns);
    for insn in decoded {
        let unit_offset: usize = usize::try_from(insn.pc).map_err(|_| Error::BadBytecode {
            offset: insns_offset,
            reason: "DEX instruction offset is out of range",
        })?;
        let byte_delta: usize = checked_dex_mul(unit_offset, 2, insns_offset)?;
        let offset: usize =
            checked_dex_add(insns_offset, byte_delta, "DEX instruction offset overflow")?;
        match insn.op {
            0x1A | 0x1B => require_pool_index(
                insn.index,
                dex.strings.len(),
                offset,
                "DEX string index is out of range",
            )?,
            0x1C | 0x1F | 0x20 | 0x22..=0x25 => require_pool_index(
                insn.index,
                dex.type_names.len(),
                offset,
                "DEX type index is out of range",
            )?,
            0x52..=0x6D => require_pool_index(
                insn.index,
                dex.field_ids.len(),
                offset,
                "DEX field index is out of range",
            )?,
            0x6E..=0x72 | 0x74..=0x78 => require_pool_index(
                insn.index,
                dex.method_ids.len(),
                offset,
                "DEX method index is out of range",
            )?,
            0xFA | 0xFB => {
                require_dex_feature(
                    supports_dex_038(dex.header.version),
                    offset,
                    "DEX invoke-polymorphic requires version 038 or later",
                )?;
                require_pool_index(
                    insn.index,
                    dex.method_ids.len(),
                    offset,
                    "DEX method index is out of range",
                )?;
            }
            0xFC | 0xFD => {
                require_dex_feature(
                    supports_dex_038(dex.header.version),
                    offset,
                    "DEX invoke-custom requires version 038 or later",
                )?;
                require_pool_index(
                    insn.index,
                    dex.call_site_ids_size,
                    offset,
                    "DEX call-site index is out of range",
                )?;
            }
            0xFE => {
                require_dex_feature(
                    supports_dex_039(dex.header.version),
                    offset,
                    "DEX const-method-handle requires version 039 or later",
                )?;
                require_pool_index(
                    insn.index,
                    dex.method_handles_size,
                    offset,
                    "DEX method-handle index is out of range",
                )?;
            }
            0xFF => {
                require_dex_feature(
                    supports_dex_039(dex.header.version),
                    offset,
                    "DEX const-method-type requires version 039 or later",
                )?;
                require_pool_index(
                    insn.index,
                    dex.proto_ids.len(),
                    offset,
                    "DEX prototype index is out of range",
                )?;
            }
            _ => {}
        }
        if matches!(insn.op, 0xFA | 0xFB) {
            let proto_unit: usize = unit_offset.checked_add(3).ok_or(Error::BadBytecode {
                offset,
                reason: "DEX prototype index offset overflow",
            })?;
            let proto_index: Option<u32> = insns.get(proto_unit).copied().map(u32::from);
            require_pool_index(
                proto_index,
                dex.proto_ids.len(),
                offset,
                "DEX prototype index is out of range",
            )?;
        }
    }
    Ok(())
}

#[must_use]
pub fn parse_code_items(dex: &DexFile, bytes: &[u8]) -> CodeItemsReport {
    let header: &DexHeader = &dex.header;
    let class_defs_off: usize = header.class_defs_off as usize;
    let mut decoded: Vec<CodeItem> = Vec::new();
    let mut methods: Vec<DexMethodCode> = Vec::new();
    let mut unrecovered_tail: Option<DexCodeTail> = None;
    let data_start: usize = header.data_off as usize;
    let data_size: usize = header.data_size as usize;
    let data_end: usize = match data_start.checked_add(data_size) {
        Some(end) if end <= bytes.len() => end,
        _ => {
            return CodeItemsReport {
                decoded,
                methods,
                unrecovered_tail: Some(DexCodeTail {
                    class: String::new(),
                    error: Error::BadBytecode {
                        offset: data_start,
                        reason: "DEX data section is out of range",
                    },
                }),
            };
        }
    };
    let class_count: usize = count_cap(header.class_defs_size, 32, bytes.len());
    let mut budget: WalkBudget = WalkBudget::new(header, bytes.len());
    for class_ordinal in 0..class_count {
        let class_delta: usize = match checked_dex_mul(class_ordinal, 32, class_defs_off) {
            Ok(delta) => delta,
            Err(error) => {
                unrecovered_tail = Some(DexCodeTail {
                    class: String::new(),
                    error,
                });
                break;
            }
        };
        let base: usize =
            match checked_dex_add(class_defs_off, class_delta, "DEX class offset overflow") {
                Ok(offset) => offset,
                Err(error) => {
                    unrecovered_tail = Some(DexCodeTail {
                        class: String::new(),
                        error,
                    });
                    break;
                }
            };
        let class_idx: u32 = match required_u32_at(bytes, base) {
            Ok(index) => index,
            Err(error) => {
                unrecovered_tail = Some(DexCodeTail {
                    class: String::new(),
                    error,
                });
                break;
            }
        };
        let Some(class_name): Option<String> = dex.type_names.get(class_idx as usize).cloned()
        else {
            unrecovered_tail = Some(DexCodeTail {
                class: String::new(),
                error: Error::BadBytecode {
                    offset: base,
                    reason: "DEX class index out of range",
                },
            });
            break;
        };
        let data_field: usize =
            match checked_dex_add(base, 24, "DEX class data field offset overflow") {
                Ok(offset) => offset,
                Err(error) => {
                    unrecovered_tail = Some(DexCodeTail {
                        class: class_name,
                        error,
                    });
                    break;
                }
            };
        let class_data_off: u32 = match required_u32_at(bytes, data_field) {
            Ok(offset) => offset,
            Err(error) => {
                unrecovered_tail = Some(DexCodeTail {
                    class: class_name,
                    error,
                });
                break;
            }
        };
        if class_data_off == 0 {
            continue;
        }
        let class_data_offset: usize = class_data_off as usize;
        if !(data_start..data_end).contains(&class_data_offset) {
            unrecovered_tail = Some(DexCodeTail {
                class: class_name,
                error: Error::BadBytecode {
                    offset: class_data_offset,
                    reason: "DEX class data offset is outside the data section",
                },
            });
            break;
        }
        if budget.spent() {
            unrecovered_tail = Some(DexCodeTail {
                class: class_name,
                error: Error::BadBytecode {
                    offset: class_data_off as usize,
                    reason: "DEX class data budget exceeded",
                },
            });
            break;
        }
        let walked: Result<()> = {
            let mut context: CodeWalk<'_> = CodeWalk {
                dex,
                bytes: &bytes[..data_end],
                decoded: &mut decoded,
                methods: &mut methods,
                budget: &mut budget,
                data_start,
                data_end,
                seen_method_indices: BTreeSet::new(),
            };
            walk_class_data(&mut context, class_data_offset, &class_name)
        };
        match walked {
            Ok(()) => {}
            Err(error_value) => {
                let error: Error = error_value;
                unrecovered_tail = Some(DexCodeTail {
                    class: class_name,
                    error,
                });
                break;
            }
        }
    }
    if unrecovered_tail.is_none() && class_count < header.class_defs_size as usize {
        unrecovered_tail = Some(DexCodeTail {
            class: String::new(),
            error: Error::BadBytecode {
                offset: class_defs_off,
                reason: "DEX class definition budget exceeded",
            },
        });
    }
    CodeItemsReport {
        decoded,
        methods,
        unrecovered_tail,
    }
}

struct CodeWalk<'a> {
    dex: &'a DexFile,
    bytes: &'a [u8],
    decoded: &'a mut Vec<CodeItem>,
    methods: &'a mut Vec<DexMethodCode>,
    budget: &'a mut WalkBudget,
    data_start: usize,
    data_end: usize,
    seen_method_indices: BTreeSet<u32>,
}

fn walk_class_data(
    context: &mut CodeWalk<'_>,
    class_data_off: usize,
    class_name: &str,
) -> Result<()> {
    let (static_fields, after_static_count): (u32, usize) =
        read_uleb128(context.bytes, class_data_off)?;
    let (instance_fields, after_instance_count): (u32, usize) =
        read_uleb128(context.bytes, after_static_count)?;
    let (direct_methods, after_direct_count): (u32, usize) =
        read_uleb128(context.bytes, after_instance_count)?;
    let (virtual_methods, members_start): (u32, usize) =
        read_uleb128(context.bytes, after_direct_count)?;
    let after_static: usize = skip_encoded_fields(
        context.bytes,
        members_start,
        static_fields,
        &context.dex.field_ids,
        class_name,
        context.budget,
    )?;
    let after_instance: usize = skip_encoded_fields(
        context.bytes,
        after_static,
        instance_fields,
        &context.dex.field_ids,
        class_name,
        context.budget,
    )?;
    let after_direct: usize =
        walk_encoded_methods(context, after_instance, direct_methods, class_name, true)?;
    let _: usize = walk_encoded_methods(context, after_direct, virtual_methods, class_name, false)?;
    Ok(())
}

fn skip_encoded_fields(
    bytes: &[u8],
    mut offset: usize,
    count: u32,
    fields: &[FieldId],
    class_name: &str,
    budget: &mut WalkBudget,
) -> Result<usize> {
    let requested: usize = count as usize;
    let bounded: usize = requested.min(budget.members);
    let mut field_idx: u32 = 0;
    for ordinal in 0..bounded {
        let (idx_diff, after_index): (u32, usize) = read_uleb128(bytes, offset)?;
        if ordinal > 0 && idx_diff == 0 {
            return Err(Error::BadBytecode {
                offset,
                reason: "DEX field indices are not strictly increasing",
            });
        }
        field_idx = field_idx.checked_add(idx_diff).ok_or(Error::BadBytecode {
            offset,
            reason: "DEX field index overflow",
        })?;
        let Some(field): Option<&FieldId> = fields.get(field_idx as usize) else {
            return Err(Error::BadBytecode {
                offset,
                reason: "DEX field index out of range",
            });
        };
        if field.class != class_name {
            return Err(Error::BadBytecode {
                offset,
                reason: "DEX field owner does not match class data",
            });
        }
        let (_, after_access): (u32, usize) = read_uleb128(bytes, after_index)?;
        offset = after_access;
        budget.members -= 1;
    }
    if bounded < requested {
        return Err(Error::BadBytecode {
            offset,
            reason: "DEX field budget exceeded",
        });
    }
    Ok(offset)
}

fn walk_encoded_methods(
    context: &mut CodeWalk<'_>,
    mut offset: usize,
    count: u32,
    class_name: &str,
    is_direct: bool,
) -> Result<usize> {
    let requested: usize = count as usize;
    let bounded: usize = requested.min(context.budget.members);
    let mut method_idx: u32 = 0;
    for ordinal in 0..bounded {
        let (idx_diff, after_index): (u32, usize) = read_uleb128(context.bytes, offset)?;
        if ordinal > 0 && idx_diff == 0 {
            return Err(Error::BadBytecode {
                offset,
                reason: "DEX method indices are not strictly increasing",
            });
        }
        let (access_flags, after_access): (u32, usize) = read_uleb128(context.bytes, after_index)?;
        let (code_offset, next): (u32, usize) = read_uleb128(context.bytes, after_access)?;
        context.budget.members -= 1;
        method_idx = method_idx.checked_add(idx_diff).ok_or(Error::BadBytecode {
            offset,
            reason: "DEX method index overflow",
        })?;
        if !context.seen_method_indices.insert(method_idx) {
            return Err(Error::BadBytecode {
                offset,
                reason: "DEX method index is duplicated in class data",
            });
        }
        let Some(method): Option<&MethodId> = context.dex.method_ids.get(method_idx as usize)
        else {
            return Err(Error::BadBytecode {
                offset,
                reason: "DEX method index out of range",
            });
        };
        if method.class != class_name {
            return Err(Error::BadBytecode {
                offset,
                reason: "DEX method owner does not match class data",
            });
        }
        let method_name: String = method.name.clone();
        let parameters: String = method.proto.parameters.concat();
        let method_descriptor: String = format!("({parameters}){}", method.proto.return_type);
        let bodyless: bool = access_flags & (ACC_NATIVE | ACC_ABSTRACT) != 0;
        let state: DexCodeState = if code_offset == 0 && bodyless {
            DexCodeState::Absent
        } else if code_offset == 0 {
            DexCodeState::Refused(Error::BadBytecode {
                offset,
                reason: "concrete DEX method has no code item",
            })
        } else if bodyless {
            DexCodeState::Refused(Error::BadBytecode {
                offset,
                reason: "Code item is present on a bodyless declaration",
            })
        } else {
            let code_item_offset: usize = code_offset as usize;
            if !(context.data_start..context.data_end).contains(&code_item_offset) {
                return Err(Error::BadBytecode {
                    offset,
                    reason: "DEX code item offset is outside the data section",
                });
            }
            match parse_code_item(
                context.bytes,
                code_item_offset,
                context.data_start,
                &context.dex.type_names,
                &context.dex.strings,
                context.budget,
            ) {
                Ok(parsed) => {
                    let (
                        registers_size,
                        ins_size,
                        outs_size,
                        insns,
                        tries,
                        param_names,
                    ): ParsedCode = parsed;
                    match validate_code_references(&insns, context.dex, code_item_offset + 16) {
                        Ok(()) => {
                            let item_index: usize = context.decoded.len();
                            context.decoded.push(CodeItem {
                                method_name: method_name.clone(),
                                method_descriptor: method_descriptor.clone(),
                                class: class_name.to_owned(),
                                is_direct,
                                registers_size,
                                ins_size,
                                outs_size,
                                insns,
                                tries,
                                param_names,
                            });
                            DexCodeState::Decoded(item_index)
                        }
                        Err(error) => DexCodeState::Refused(error),
                    }
                }
                Err(error) => DexCodeState::Refused(error),
            }
        };
        context.methods.push(DexMethodCode {
            method_index: method_idx,
            class: class_name.to_owned(),
            method_name,
            method_descriptor,
            access_flags,
            is_direct,
            code_offset,
            state,
        });
        offset = next;
    }
    if bounded < requested {
        return Err(Error::BadBytecode {
            offset,
            reason: "DEX method budget exceeded",
        });
    }
    Ok(offset)
}

pub const ACC_NATIVE: u32 = 0x0100;
pub const ACC_ABSTRACT: u32 = 0x0400;

pub const ACC_STATIC: u32 = 0x0008;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeMethod {
    pub class: String,
    pub method: String,
    pub descriptor: String,
    pub jni_short_symbol: String,
    pub jni_long_symbol: String,
    pub is_static: bool,
}

pub fn extract_native_methods(dex: &DexFile, bytes: &[u8]) -> Result<Vec<NativeMethod>> {
    let header: &DexHeader = &dex.header;
    let class_defs_off: usize = header.class_defs_off as usize;
    let mut out: Vec<NativeMethod> = Vec::new();
    let mut budget: WalkBudget = WalkBudget::new(header, bytes.len());
    let class_count: usize = declared_table_count(
        bytes,
        header.class_defs_off,
        header.class_defs_size,
        32,
        "DEX class definition table is out of range",
    )?;
    for ci in 0..class_count {
        let base: usize = class_defs_off
            .checked_add(ci.checked_mul(32).ok_or(Error::BadBytecode {
                offset: class_defs_off,
                reason: "DEX class definition offset overflow",
            })?)
            .ok_or(Error::BadBytecode {
                offset: class_defs_off,
                reason: "DEX class definition offset overflow",
            })?;
        let class_idx: u32 = required_u32_at(bytes, base)?;
        let class_name: String =
            dex.type_names
                .get(class_idx as usize)
                .cloned()
                .ok_or(Error::BadBytecode {
                    offset: base,
                    reason: "DEX class type index is out of range",
                })?;
        let class_data_off: u32 = required_u32_at(bytes, base + 24)?;
        if class_data_off == 0 {
            continue;
        }
        if budget.spent() {
            return Err(Error::BadBytecode {
                offset: base,
                reason: "DEX native method scan budget exceeded",
            });
        }
        collect_native_methods(
            dex,
            bytes,
            class_data_off as usize,
            &class_name,
            &mut out,
            &mut budget,
        )?;
    }
    Ok(out)
}

fn collect_native_methods(
    dex: &DexFile,
    bytes: &[u8],
    class_data_off: usize,
    class_name: &str,
    out: &mut Vec<NativeMethod>,
    budget: &mut WalkBudget,
) -> Result<()> {
    let (static_fields, n1): (u32, usize) = read_uleb128(bytes, class_data_off)?;
    let (instance_fields, n2): (u32, usize) = read_uleb128(bytes, n1)?;
    let (direct_methods, n3): (u32, usize) = read_uleb128(bytes, n2)?;
    let (virtual_methods, n4): (u32, usize) = read_uleb128(bytes, n3)?;
    let after_static: usize =
        skip_encoded_fields(bytes, n4, static_fields, &dex.field_ids, class_name, budget)?;
    let after_instance: usize = skip_encoded_fields(
        bytes,
        after_static,
        instance_fields,
        &dex.field_ids,
        class_name,
        budget,
    )?;
    let after_direct: usize = scan_native_methods(
        dex,
        bytes,
        after_instance,
        direct_methods,
        class_name,
        out,
        budget,
    )?;
    let _: usize = scan_native_methods(
        dex,
        bytes,
        after_direct,
        virtual_methods,
        class_name,
        out,
        budget,
    )?;
    Ok(())
}

fn scan_native_methods(
    dex: &DexFile,
    bytes: &[u8],
    mut o: usize,
    count: u32,
    class_name: &str,
    out: &mut Vec<NativeMethod>,
    budget: &mut WalkBudget,
) -> Result<usize> {
    let mut method_idx: u32 = 0;
    let requested: usize = count as usize;
    if requested > budget.members {
        return Err(Error::BadBytecode {
            offset: o,
            reason: "DEX native method scan budget exceeded",
        });
    }
    for k in 0..count {
        let (idx_diff, n1): (u32, usize) = read_uleb128(bytes, o)?;
        let (access, n2): (u32, usize) = read_uleb128(bytes, n1)?;
        let (_, n3): (u32, usize) = read_uleb128(bytes, n2)?;
        budget.members = budget.members.saturating_sub(1);
        method_idx = if k == 0 {
            idx_diff
        } else {
            method_idx.checked_add(idx_diff).ok_or(Error::BadBytecode {
                offset: o,
                reason: "DEX native method index overflow",
            })?
        };
        let method: &MethodId =
            dex.method_ids
                .get(method_idx as usize)
                .ok_or(Error::BadBytecode {
                    offset: o,
                    reason: "DEX native method index is out of range",
                })?;
        if access & ACC_NATIVE != 0 {
            let descriptor: String = {
                let params: String = method.proto.parameters.concat();
                format!("({params}){}", method.proto.return_type)
            };
            let (short, long): (String, String) =
                jni_symbols(class_name, &method.name, &method.proto.parameters.concat());
            out.push(NativeMethod {
                class: class_name.to_owned(),
                method: method.name.clone(),
                descriptor,
                jni_short_symbol: short,
                jni_long_symbol: long,
                is_static: access & ACC_STATIC != 0,
            });
        }
        o = n3;
    }
    Ok(o)
}

pub(crate) fn jni_mangle(segment: &str) -> String {
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
                let mut buf: [u16; 2] = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    let _ = write!(out, "_0{unit:04x}");
                }
            }
        }
    }
    out
}

pub(crate) fn jni_symbols(
    class_descriptor: &str,
    method: &str,
    arg_descriptor: &str,
) -> (String, String) {
    let internal: &str = class_descriptor
        .strip_prefix('L')
        .and_then(|s: &str| s.strip_suffix(';'))
        .unwrap_or(class_descriptor);
    let mangled_class: String = jni_mangle(internal);
    let mangled_method: String = jni_mangle(method);
    let short: String = format!("Java_{mangled_class}_{mangled_method}");
    let mangled_args: String = jni_mangle(arg_descriptor);
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
#[allow(clippy::expect_used)]
pub(crate) fn partial_code_failure_fixture() -> (DexFile, Vec<u8>) {
    use crate::dex_builder::{ClassDef, DexBuilder, EncodedMethod, MethodRef, ProtoRef};

    let mut builder: DexBuilder = DexBuilder::new();
    let methods: Vec<EncodedMethod> = ["a", "b"]
        .into_iter()
        .map(|name: &str| EncodedMethod {
            method: MethodRef {
                class: "Lcom/disrobe/Partial;".to_owned(),
                proto: ProtoRef {
                    return_type: "V".to_owned(),
                    params: Vec::new(),
                },
                name: name.to_owned(),
            },
            access_flags: 0x0001,
            is_direct: false,
            registers_size: 1,
            ins_size: 0,
            outs_size: 0,
            insns: vec![0x000E],
            relocations: Vec::new(),
        })
        .collect();
    builder.add_class(ClassDef {
        class: "Lcom/disrobe/Partial;".to_owned(),
        super_class: "Ljava/lang/Object;".to_owned(),
        access_flags: 0x0001,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: Vec::new(),
        virtual_methods: methods,
    });
    let mut bytes: Vec<u8> = builder.build();
    let dex: DexFile = parse(&bytes).expect("partial code fixture parses");
    let class_data_field: usize = dex.header.class_defs_off as usize + 24;
    let class_data_offset: usize =
        required_u32_at(&bytes, class_data_field).expect("class data offset") as usize;
    let (_, after_static): (u32, usize) =
        read_uleb128(&bytes, class_data_offset).expect("static field count");
    let (_, after_instance): (u32, usize) =
        read_uleb128(&bytes, after_static).expect("instance field count");
    let (_, after_direct): (u32, usize) =
        read_uleb128(&bytes, after_instance).expect("direct method count");
    let (_, mut cursor): (u32, usize) =
        read_uleb128(&bytes, after_direct).expect("virtual method count");
    let mut code_offsets: Vec<usize> = Vec::new();
    for _ in 0..2 {
        let (_, after_index): (u32, usize) = read_uleb128(&bytes, cursor).expect("method index");
        let (_, after_access): (u32, usize) =
            read_uleb128(&bytes, after_index).expect("method access");
        let (code_offset, next): (u32, usize) =
            read_uleb128(&bytes, after_access).expect("method code offset");
        code_offsets.push(code_offset as usize);
        cursor = next;
    }
    let malformed: usize = code_offsets[1] + 12;
    bytes[malformed..malformed + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    (dex, bytes)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn code_item_with_tries(tries: &[(u32, u16, u16)]) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        let tries_size: u16 = u16::try_from(tries.len()).expect("try count fits u16");
        bytes.extend_from_slice(&tries_size.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&0x0000_u16.to_le_bytes());
        bytes.extend_from_slice(&0x000E_u16.to_le_bytes());
        for (start, count, handler_offset) in tries {
            bytes.extend_from_slice(&start.to_le_bytes());
            bytes.extend_from_slice(&count.to_le_bytes());
            bytes.extend_from_slice(&handler_offset.to_le_bytes());
        }
        bytes.extend_from_slice(&[0x01, 0x00, 0x00]);
        bytes
    }

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
    fn uleb128_refuses_five_byte_overflow_and_continuation() {
        for bytes in [
            [0xFF, 0xFF, 0xFF, 0xFF, 0x10],
            [0x80, 0x80, 0x80, 0x80, 0x80],
        ] {
            let parsed: Result<(u32, usize)> = read_uleb128(&bytes, 0);
            assert!(matches!(parsed, Err(Error::BadBytecode { .. })));
        }
    }

    #[test]
    fn sleb128_refuses_five_byte_overflow_and_continuation() {
        for bytes in [
            [0xFF, 0xFF, 0xFF, 0xFF, 0x6F],
            [0x80, 0x80, 0x80, 0x80, 0x80],
        ] {
            let parsed: Result<(i32, usize)> = read_sleb128(&bytes, 0);
            assert!(matches!(parsed, Err(Error::BadBytecode { .. })));
        }
    }

    #[test]
    fn malformed_catch_handler_is_refused() {
        let mut budget: WalkBudget = WalkBudget {
            members: 1,
            insn_words: 4,
        };
        let parsed: Result<ParsedHandlers> =
            parse_encoded_catch_handler(&[0x01], 0, &[], 1, &mut budget);
        assert!(parsed.is_err());
    }

    #[test]
    fn out_of_range_catch_type_is_refused() {
        let mut budget: WalkBudget = WalkBudget {
            members: 1,
            insn_words: 4,
        };
        let parsed: Result<ParsedHandlers> =
            parse_encoded_catch_handler(&[0x01, 0x00, 0x00], 0, &[], 1, &mut budget);
        assert!(parsed.is_err());
    }

    #[test]
    fn misaligned_code_item_is_refused() {
        let mut budget: WalkBudget = WalkBudget {
            members: 1,
            insn_words: 4,
        };
        let parsed: Result<ParsedCode> = parse_code_item(&[0; 20], 1, 0, &[], &[], &mut budget);
        assert!(matches!(parsed, Err(Error::BadBytecode { .. })));
    }

    #[test]
    fn nonzero_code_item_padding_is_refused() {
        let mut bytes: Vec<u8> = vec![0; 28];
        bytes[6..8].copy_from_slice(&1u16.to_le_bytes());
        bytes[12..16].copy_from_slice(&1u32.to_le_bytes());
        bytes[16..18].copy_from_slice(&0x000E_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&1u16.to_le_bytes());
        let mut budget: WalkBudget = WalkBudget {
            members: 1,
            insn_words: 4,
        };
        let parsed: Result<ParsedCode> = parse_code_item(&bytes, 0, 0, &[], &[], &mut budget);
        assert!(matches!(parsed, Err(Error::BadBytecode { .. })));
    }

    #[test]
    fn try_handler_offset_must_target_declared_handler() {
        let bytes: Vec<u8> = code_item_with_tries(&[(0, 1, 0)]);
        let mut budget: WalkBudget = WalkBudget {
            members: 4,
            insn_words: 16,
        };
        let type_names: Vec<String> = vec!["java/lang/Exception".to_owned()];
        let parsed: Result<ParsedCode> =
            parse_code_item(&bytes, 0, 0, &type_names, &[], &mut budget);
        assert!(matches!(parsed, Err(Error::BadBytecode { .. })));
    }

    #[test]
    fn declared_try_handler_offset_decodes() {
        let bytes: Vec<u8> = code_item_with_tries(&[(0, 1, 1)]);
        let mut budget: WalkBudget = WalkBudget {
            members: 4,
            insn_words: 16,
        };
        let parsed: ParsedCode =
            parse_code_item(&bytes, 0, 0, &[], &[], &mut budget).expect("valid try handler");
        assert_eq!(parsed.4.len(), 1);
        assert_eq!(parsed.4[0].catch_all, Some(0));
    }

    #[test]
    fn try_table_must_be_ordered_and_nonoverlapping() {
        for tries in [vec![(1, 1, 1), (0, 1, 1)], vec![(0, 2, 1), (1, 1, 1)]] {
            let bytes: Vec<u8> = code_item_with_tries(&tries);
            let mut budget: WalkBudget = WalkBudget {
                members: 4,
                insn_words: 16,
            };
            let parsed: Result<ParsedCode> = parse_code_item(&bytes, 0, 0, &[], &[], &mut budget);
            assert!(matches!(parsed, Err(Error::BadBytecode { .. })));
        }
    }

    #[test]
    fn mutf8_decodes_supplementary_pair() {
        let bytes: [u8; 6] = [0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80];
        let s: String = decode_mutf8(&bytes, 0).expect("valid supplementary pair");
        assert_eq!(s, "\u{1F600}");
    }

    #[test]
    fn mutf8_rejects_embedded_null() {
        let bytes: [u8; 3] = [b'a', 0x00, b'b'];
        assert!(decode_mutf8(&bytes, 0).is_err());
    }

    #[test]
    fn string_data_uses_utf16_size_instead_of_byte_length() {
        let bytes: [u8; 4] = [0x01, 0xC3, 0xA9, 0x00];
        let decoded: String = parse_string_data(&bytes, 0).expect("valid string data");
        assert_eq!(decoded, "\u{e9}");
    }

    #[test]
    fn string_data_requires_terminator_and_matching_utf16_size() {
        let unterminated: [u8; 2] = [0x01, b'a'];
        assert!(parse_string_data(&unterminated, 0).is_err());

        let wrong_size: [u8; 3] = [0x02, b'a', 0x00];
        assert!(parse_string_data(&wrong_size, 0).is_err());
    }

    #[test]
    fn string_data_rejects_malformed_mutf8() {
        let bad_leading_byte: [u8; 3] = [0x00, 0x80, 0x00];
        assert!(parse_string_data(&bad_leading_byte, 0).is_err());

        let bad_continuation: [u8; 4] = [0x01, 0xC2, b'A', 0x00];
        assert!(parse_string_data(&bad_continuation, 0).is_err());

        let overlong_ascii: [u8; 4] = [0x01, 0xC1, 0x81, 0x00];
        assert!(parse_string_data(&overlong_ascii, 0).is_err());

        let lone_surrogate: [u8; 5] = [0x01, 0xED, 0xA0, 0x80, 0x00];
        assert!(parse_string_data(&lone_surrogate, 0).is_err());
    }

    #[test]
    fn extended_pool_sizes_come_from_the_map_list() {
        let header: DexHeader = DexHeader {
            version: DexVersion::V038,
            checksum: 0,
            signature: [0; 20],
            file_size: 128,
            header_size: 0x70,
            endian_tag: DEX_ENDIAN_TAG,
            link_size: 0,
            link_off: 0,
            map_off: 16,
            string_ids_size: 0,
            string_ids_off: 0,
            type_ids_size: 0,
            type_ids_off: 0,
            proto_ids_size: 0,
            proto_ids_off: 0,
            field_ids_size: 1,
            field_ids_off: 0,
            method_ids_size: 1,
            method_ids_off: 0,
            class_defs_size: 0,
            class_defs_off: 0,
            data_size: 0,
            data_off: 0,
        };
        let mut bytes: Vec<u8> = vec![0; 128];
        bytes[16..20].copy_from_slice(&2u32.to_le_bytes());
        bytes[20..22].copy_from_slice(&0x0007u16.to_le_bytes());
        bytes[24..28].copy_from_slice(&1u32.to_le_bytes());
        bytes[28..32].copy_from_slice(&64u32.to_le_bytes());
        bytes[32..34].copy_from_slice(&0x0008u16.to_le_bytes());
        bytes[36..40].copy_from_slice(&1u32.to_le_bytes());
        bytes[40..44].copy_from_slice(&68u32.to_le_bytes());
        bytes[64..68].copy_from_slice(&96u32.to_le_bytes());
        let sizes: (usize, usize) =
            parse_extended_pool_sizes(&bytes, &header).expect("valid extended pools");
        assert_eq!(sizes, (1, 1));
    }
}
