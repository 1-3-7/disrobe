use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::debug::{dbg_kv, dbg_line, dbg_section};
use crate::error::{Error, Result};

pub mod bigint;
pub mod builtins;
pub mod decompile;
pub mod literals;
pub mod regex;
pub mod structure;

pub use bigint::{bigint_literal, recover_bigints};
pub use builtins::{builtin_name, is_template_object_builtin};
pub use decompile::{
    DeclineCount, DecompileReport, DecompiledFunction, decompile_function, decompile_module,
    disassemble_function_instructions,
};
pub use literals::{BufferKind, LiteralValue, decode_literals};
pub use regex::{RecoveredRegExp, recover_regexp, recover_regexps};
pub use structure::StructureDecline;

pub const HERMES_MAGIC: u64 = 0x1f19_03c1_03bc_1fc6;
pub const HERMES_MAGIC_LE_BYTES: [u8; 8] = HERMES_MAGIC.to_le_bytes();

pub const HERMES_MIN_VERSION: u32 = 60;
pub const HERMES_MAX_VERSION: u32 = 96;
pub const HERMES_LIFT_VERSION: u32 = 96;

const SMALL_STRING_INVALID_LENGTH: u32 = 0xff;
const HERMES_HEADER_TOTAL_SIZE: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HermesStringKind {
    String,
    Identifier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HermesHeader {
    pub version: u32,
    pub source_hash: [u8; 20],
    pub file_length: u32,
    pub global_code_index: u32,
    pub function_count: u32,
    pub string_kind_count: u32,
    pub identifier_count: u32,
    pub string_count: u32,
    pub overflow_string_count: u32,
    pub string_storage_size: u32,
    pub big_int_count: u32,
    pub big_int_storage_size: u32,
    pub reg_exp_count: u32,
    pub reg_exp_storage_size: u32,
    pub array_buffer_size: u32,
    pub obj_key_buffer_size: u32,
    pub obj_value_buffer_size: u32,
    pub segment_id: u32,
    pub cjs_module_count: u32,
    pub function_source_count: u32,
    pub debug_info_offset: u32,
    pub flags: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmallFunctionHeader {
    pub offset: u32,
    pub param_count: u32,
    pub bytecode_size_bytes: u32,
    pub function_name_id: u32,
    pub info_offset: u32,
    pub frame_size: u32,
    pub env_size: u32,
    pub highest_read_cache_index: u8,
    pub highest_write_cache_index: u8,
    pub prohibit_invoke: u8,
    pub strict_mode: bool,
    pub has_exception_handler: bool,
    pub has_debug_info: bool,
    pub overflowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HermesModule {
    pub header: HermesHeader,
    pub functions: Vec<SmallFunctionHeader>,
    pub identifiers: Vec<String>,
    pub strings: Vec<String>,
    pub string_kinds: Vec<HermesStringKind>,
    pub overflow_resolved: usize,
    pub utf16_strings: usize,
    pub raw_bytecode_size: usize,
    #[serde(skip)]
    pub array_buffer: Vec<u8>,
    #[serde(skip)]
    pub obj_key_buffer: Vec<u8>,
    #[serde(skip)]
    pub obj_value_buffer: Vec<u8>,
    pub big_int_table: Vec<BigIntTableEntry>,
    #[serde(skip)]
    pub big_int_storage: Vec<u8>,
    pub reg_exp_table: Vec<RegExpTableEntry>,
    #[serde(skip)]
    pub reg_exp_storage: Vec<u8>,
    #[serde(skip)]
    pub raw_image: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegExpTableEntry {
    pub offset: u32,
    pub length: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BigIntTableEntry {
    pub offset: u32,
    pub length: u32,
}

impl HermesModule {
    #[must_use]
    pub fn string_by_global_id(&self, global_id: u32) -> Option<&str> {
        let id: usize = usize::try_from(global_id).ok()?;
        if id < self.identifiers.len() {
            return self.identifiers.get(id).map(String::as_str);
        }
        self.strings
            .get(id - self.identifiers.len())
            .map(String::as_str)
    }

    #[must_use]
    pub fn function_code(&self, index: usize) -> &[u8] {
        let Some(f): Option<&SmallFunctionHeader> = self.functions.get(index) else {
            return &[];
        };
        let Some(start): Option<usize> = usize::try_from(f.offset).ok() else {
            return &[];
        };
        let Some(length): Option<usize> = usize::try_from(f.bytecode_size_bytes).ok() else {
            return &[];
        };
        let Some(end): Option<usize> = start.checked_add(length) else {
            return &[];
        };
        self.raw_image.get(start..end).unwrap_or(&[])
    }
}

pub fn parse(bytes: &[u8]) -> Result<HermesModule> {
    dbg_section("hermes.parse");
    let header: HermesHeader = parse_header(bytes)?;
    dbg_kv("hbc.version", || header.version.to_string());
    dbg_kv("hbc.function_count", || header.function_count.to_string());
    dbg_kv("hbc.string_count", || header.string_count.to_string());
    dbg_kv("hbc.identifier_count", || {
        header.identifier_count.to_string()
    });
    dbg_kv("hbc.reg_exp_count", || header.reg_exp_count.to_string());
    if header.version < HERMES_MIN_VERSION || header.version > HERMES_MAX_VERSION {
        dbg_line(|| {
            format!(
                "wall: hbc version {} outside supported [{HERMES_MIN_VERSION}, {HERMES_MAX_VERSION}]",
                header.version
            )
        });
        return Err(Error::HermesUnsupportedVersion(header.version));
    }
    reject_oversized_header_counts(&header, bytes.len())?;
    let header_size: usize = header_size_for_version(header.version);
    let mut cursor: usize = header_size;
    cursor = align_up(cursor, 4);
    let function_count: usize = header_field_usize(header.function_count, bytes.len())?;
    let string_kind_count: usize = header_field_usize(header.string_kind_count, bytes.len())?;
    let identifier_count: usize = header_field_usize(header.identifier_count, bytes.len())?;
    let string_count: usize = header_field_usize(header.string_count, bytes.len())?;
    let overflow_string_count: usize =
        header_field_usize(header.overflow_string_count, bytes.len())?;
    let string_storage_size: usize = header_field_usize(header.string_storage_size, bytes.len())?;
    let array_buffer_size: usize = header_field_usize(header.array_buffer_size, bytes.len())?;
    let obj_key_buffer_size: usize = header_field_usize(header.obj_key_buffer_size, bytes.len())?;
    let obj_value_buffer_size: usize =
        header_field_usize(header.obj_value_buffer_size, bytes.len())?;
    let big_int_count: usize = header_field_usize(header.big_int_count, bytes.len())?;
    let big_int_storage_size: usize = header_field_usize(header.big_int_storage_size, bytes.len())?;
    let reg_exp_count: usize = header_field_usize(header.reg_exp_count, bytes.len())?;
    let reg_exp_storage_size: usize = header_field_usize(header.reg_exp_storage_size, bytes.len())?;
    let functions: Vec<SmallFunctionHeader> =
        parse_small_function_table(bytes, &mut cursor, function_count)?;
    cursor = align_up(cursor, 4);
    let string_kinds: Vec<HermesStringKind> =
        parse_string_kind_table(bytes, &mut cursor, string_kind_count, string_count)?;
    cursor = align_up(cursor, 4);
    skip_identifier_hash_table(bytes, &mut cursor, identifier_count);
    cursor = align_up(cursor, 4);
    let small_entries: Vec<SmallStringTableRaw> =
        parse_small_string_table(bytes, &mut cursor, string_count)?;
    cursor = align_up(cursor, 4);
    let overflow_entries: Vec<(u32, u32)> =
        parse_overflow_string_table(bytes, &mut cursor, overflow_string_count)?;
    cursor = align_up(cursor, 4);
    let storage_offset: usize = cursor;
    let storage_end: usize =
        storage_offset
            .checked_add(string_storage_size)
            .ok_or(Error::HermesStringOob {
                offset: storage_offset,
                length: string_storage_size,
                storage: bytes.len(),
            })?;
    if storage_end > bytes.len() {
        return Err(Error::HermesStringOob {
            offset: storage_offset,
            length: string_storage_size,
            storage: bytes.len(),
        });
    }
    let storage: &[u8] = &bytes[storage_offset..storage_end];
    let identifier_cutoff: usize = identifier_count;
    let identifier_cap: usize = identifier_cutoff.min(small_entries.len());
    let mut identifiers: Vec<String> = Vec::with_capacity(identifier_cap);
    let mut strings: Vec<String> =
        Vec::with_capacity(small_entries.len().saturating_sub(identifier_cutoff));
    let mut overflow_resolved: usize = 0;
    let mut utf16_strings: usize = 0;
    for (idx, entry) in small_entries.iter().enumerate() {
        let resolved: ResolvedString = resolve_entry(entry, &overflow_entries)?;
        if resolved.from_overflow {
            overflow_resolved += 1;
        }
        let byte_len: usize = if resolved.is_utf16 {
            utf16_strings += 1;
            let length_chars: usize =
                usize::try_from(resolved.length_chars).map_err(|_| Error::HermesStringOob {
                    offset: usize::try_from(resolved.offset).unwrap_or(usize::MAX),
                    length: usize::MAX,
                    storage: storage.len(),
                })?;
            length_chars
                .checked_mul(2)
                .ok_or_else(|| Error::HermesStringOob {
                    offset: usize::try_from(resolved.offset).unwrap_or(usize::MAX),
                    length: usize::MAX,
                    storage: storage.len(),
                })?
        } else {
            usize::try_from(resolved.length_chars).map_err(|_| Error::HermesStringOob {
                offset: usize::try_from(resolved.offset).unwrap_or(usize::MAX),
                length: usize::MAX,
                storage: storage.len(),
            })?
        };
        let off_usize: usize =
            usize::try_from(resolved.offset).map_err(|_| Error::HermesStringOob {
                offset: usize::MAX,
                length: byte_len,
                storage: storage.len(),
            })?;
        let end: usize = off_usize
            .checked_add(byte_len)
            .ok_or(Error::HermesStringOob {
                offset: off_usize,
                length: byte_len,
                storage: storage.len(),
            })?;
        if end > storage.len() {
            return Err(Error::HermesStringOob {
                offset: off_usize,
                length: byte_len,
                storage: storage.len(),
            });
        }
        let slice: &[u8] = &storage[off_usize..end];
        let decoded: String = if resolved.is_utf16 {
            decode_utf16_le_lossy(slice)
        } else {
            decode_utf8_lossy_ascii(slice)
        };
        if idx < identifier_cutoff {
            identifiers.push(decoded);
        } else {
            strings.push(decoded);
        }
    }
    let raw_bytecode_size: usize = bytes.len().saturating_sub(header_size);

    let mut buffer_cursor: usize = align_up(storage_end, 4);
    let array_buffer: Vec<u8> = take_buffer(bytes, &mut buffer_cursor, array_buffer_size)?;
    buffer_cursor = align_up(buffer_cursor, 4);
    let obj_key_buffer: Vec<u8> = take_buffer(bytes, &mut buffer_cursor, obj_key_buffer_size)?;
    buffer_cursor = align_up(buffer_cursor, 4);
    let obj_value_buffer: Vec<u8> = take_buffer(bytes, &mut buffer_cursor, obj_value_buffer_size)?;
    buffer_cursor = align_up(buffer_cursor, 4);
    let (big_int_table, big_int_storage): (Vec<BigIntTableEntry>, Vec<u8>) = parse_big_int_section(
        bytes,
        &mut buffer_cursor,
        big_int_count,
        big_int_storage_size,
    )?;
    let (reg_exp_table, reg_exp_storage): (Vec<RegExpTableEntry>, Vec<u8>) = parse_reg_exp_section(
        bytes,
        &mut buffer_cursor,
        reg_exp_count,
        reg_exp_storage_size,
    )?;

    dbg_kv("hbc.string_storage_offset", || storage_offset.to_string());
    dbg_kv("hbc.overflow_resolved", || overflow_resolved.to_string());
    dbg_kv("hbc.utf16_strings", || utf16_strings.to_string());
    dbg_kv("hbc.reg_exp_table_len", || reg_exp_table.len().to_string());
    dbg_kv("hbc.raw_bytecode_size", || raw_bytecode_size.to_string());

    Ok(HermesModule {
        header,
        functions,
        identifiers,
        strings,
        string_kinds,
        overflow_resolved,
        utf16_strings,
        raw_bytecode_size,
        array_buffer,
        obj_key_buffer,
        obj_value_buffer,
        big_int_table,
        big_int_storage,
        reg_exp_table,
        reg_exp_storage,
        raw_image: bytes.to_vec(),
    })
}

fn take_buffer(bytes: &[u8], cursor: &mut usize, size: usize) -> Result<Vec<u8>> {
    let start: usize = *cursor;
    let Some(end): Option<usize> = start.checked_add(size) else {
        *cursor = bytes.len();
        return Err(Error::HermesHeaderCountsExceedInput {
            declared: usize::MAX,
            available: bytes.len(),
        });
    };
    if end > bytes.len() {
        *cursor = bytes.len();
        return Err(Error::HermesHeaderCountsExceedInput {
            declared: end,
            available: bytes.len(),
        });
    }
    *cursor = end;
    Ok(bytes[start..end].to_vec())
}

fn parse_big_int_section(
    bytes: &[u8],
    cursor: &mut usize,
    big_int_count: usize,
    big_int_storage_size: usize,
) -> Result<(Vec<BigIntTableEntry>, Vec<u8>)> {
    const BIGINT_TABLE_ENTRY_SIZE: usize = 8;
    let Some(table_bytes): Option<usize> = big_int_count.checked_mul(BIGINT_TABLE_ENTRY_SIZE)
    else {
        *cursor = bytes.len();
        return Err(Error::HermesHeaderCountsExceedInput {
            declared: usize::MAX,
            available: bytes.len(),
        });
    };
    let Some(table_end): Option<usize> = cursor.checked_add(table_bytes) else {
        *cursor = bytes.len();
        return Err(Error::HermesHeaderCountsExceedInput {
            declared: usize::MAX,
            available: bytes.len(),
        });
    };
    if table_end > bytes.len() {
        *cursor = bytes.len();
        return Err(Error::HermesHeaderCountsExceedInput {
            declared: table_end,
            available: bytes.len(),
        });
    }
    let mut table: Vec<BigIntTableEntry> = Vec::with_capacity(big_int_count);
    for i in 0..big_int_count {
        let base: usize = *cursor + i * BIGINT_TABLE_ENTRY_SIZE;
        let offset: u32 = u32::from_le_bytes(slice_4(bytes, base));
        let length: u32 = u32::from_le_bytes(slice_4(bytes, base + 4));
        table.push(BigIntTableEntry { offset, length });
    }
    *cursor = table_end;
    *cursor = align_up(*cursor, 4);
    let storage: Vec<u8> = take_buffer(bytes, cursor, big_int_storage_size)?;
    *cursor = align_up(*cursor, 4);
    Ok((table, storage))
}

fn parse_reg_exp_section(
    bytes: &[u8],
    cursor: &mut usize,
    reg_exp_count: usize,
    reg_exp_storage_size: usize,
) -> Result<(Vec<RegExpTableEntry>, Vec<u8>)> {
    const REGEXP_TABLE_ENTRY_SIZE: usize = 8;
    let Some(table_bytes): Option<usize> = reg_exp_count.checked_mul(REGEXP_TABLE_ENTRY_SIZE)
    else {
        *cursor = bytes.len();
        return Err(Error::HermesHeaderCountsExceedInput {
            declared: usize::MAX,
            available: bytes.len(),
        });
    };
    let Some(table_end): Option<usize> = cursor.checked_add(table_bytes) else {
        *cursor = bytes.len();
        return Err(Error::HermesHeaderCountsExceedInput {
            declared: usize::MAX,
            available: bytes.len(),
        });
    };
    if table_end > bytes.len() {
        *cursor = bytes.len();
        return Err(Error::HermesHeaderCountsExceedInput {
            declared: table_end,
            available: bytes.len(),
        });
    }
    let mut table: Vec<RegExpTableEntry> = Vec::with_capacity(reg_exp_count);
    for i in 0..reg_exp_count {
        let base: usize = *cursor + i * REGEXP_TABLE_ENTRY_SIZE;
        let offset: u32 = u32::from_le_bytes(slice_4(bytes, base));
        let length: u32 = u32::from_le_bytes(slice_4(bytes, base + 4));
        table.push(RegExpTableEntry { offset, length });
    }
    *cursor = table_end;
    *cursor = align_up(*cursor, 4);
    let storage: Vec<u8> = take_buffer(bytes, cursor, reg_exp_storage_size)?;
    Ok((table, storage))
}

const SMALL_FUNCTION_HEADER_SIZE: usize = 16;
const STRING_KIND_ENTRY_SIZE: usize = 4;
const SMALL_STRING_ENTRY_SIZE: usize = 4;
const OVERFLOW_STRING_ENTRY_SIZE: usize = 8;
const IDENTIFIER_HASH_ENTRY_SIZE: usize = 4;

fn header_field_usize(value: u32, available: usize) -> Result<usize> {
    usize::try_from(value).map_err(|_| Error::HermesHeaderCountsExceedInput {
        declared: usize::MAX,
        available,
    })
}

fn reject_oversized_header_counts(header: &HermesHeader, available: usize) -> Result<()> {
    let declared: usize =
        checked_declared_size(header).ok_or(Error::HermesHeaderCountsExceedInput {
            declared: usize::MAX,
            available,
        })?;
    if declared > available {
        return Err(Error::HermesHeaderCountsExceedInput {
            declared,
            available,
        });
    }
    Ok(())
}

fn checked_declared_size(header: &HermesHeader) -> Option<usize> {
    let function_count: usize = usize::try_from(header.function_count).ok()?;
    let string_kind_count: usize = usize::try_from(header.string_kind_count).ok()?;
    let identifier_count: usize = usize::try_from(header.identifier_count).ok()?;
    let string_count: usize = usize::try_from(header.string_count).ok()?;
    let overflow_string_count: usize = usize::try_from(header.overflow_string_count).ok()?;
    let string_storage_size: usize = usize::try_from(header.string_storage_size).ok()?;
    let big_int_count: usize = usize::try_from(header.big_int_count).ok()?;
    let big_int_storage_size: usize = usize::try_from(header.big_int_storage_size).ok()?;
    let reg_exp_count: usize = usize::try_from(header.reg_exp_count).ok()?;
    let reg_exp_storage_size: usize = usize::try_from(header.reg_exp_storage_size).ok()?;
    let array_buffer_size: usize = usize::try_from(header.array_buffer_size).ok()?;
    let obj_key_buffer_size: usize = usize::try_from(header.obj_key_buffer_size).ok()?;
    let obj_value_buffer_size: usize = usize::try_from(header.obj_value_buffer_size).ok()?;
    let functions: usize = function_count.checked_mul(SMALL_FUNCTION_HEADER_SIZE)?;
    let kinds: usize = string_kind_count.checked_mul(STRING_KIND_ENTRY_SIZE)?;
    let identifiers: usize = identifier_count.checked_mul(IDENTIFIER_HASH_ENTRY_SIZE)?;
    let strings: usize = string_count.checked_mul(SMALL_STRING_ENTRY_SIZE)?;
    let overflow: usize = overflow_string_count.checked_mul(OVERFLOW_STRING_ENTRY_SIZE)?;
    let big_int_table: usize = big_int_count.checked_mul(8)?;
    let reg_exp_table: usize = reg_exp_count.checked_mul(8)?;
    functions
        .checked_add(kinds)?
        .checked_add(identifiers)?
        .checked_add(strings)?
        .checked_add(overflow)?
        .checked_add(string_storage_size)?
        .checked_add(array_buffer_size)?
        .checked_add(obj_key_buffer_size)?
        .checked_add(obj_value_buffer_size)?
        .checked_add(big_int_table)?
        .checked_add(big_int_storage_size)?
        .checked_add(reg_exp_table)?
        .checked_add(reg_exp_storage_size)
}

struct ResolvedString {
    offset: u32,
    length_chars: u32,
    is_utf16: bool,
    from_overflow: bool,
}

fn resolve_entry(entry: &SmallStringTableRaw, overflow: &[(u32, u32)]) -> Result<ResolvedString> {
    if entry.length == SMALL_STRING_INVALID_LENGTH {
        let index: usize = usize::try_from(entry.offset).map_err(|_| Error::HermesStringOob {
            offset: usize::MAX,
            length: 0,
            storage: overflow.len(),
        })?;
        let (off, len): (u32, u32) = *overflow.get(index).ok_or(Error::HermesStringOob {
            offset: index,
            length: 0,
            storage: overflow.len(),
        })?;
        Ok(ResolvedString {
            offset: off,
            length_chars: len,
            is_utf16: entry.is_utf16,
            from_overflow: true,
        })
    } else {
        Ok(ResolvedString {
            offset: entry.offset,
            length_chars: entry.length,
            is_utf16: entry.is_utf16,
            from_overflow: false,
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct SmallStringTableRaw {
    is_utf16: bool,
    offset: u32,
    length: u32,
}

pub fn parse_header(bytes: &[u8]) -> Result<HermesHeader> {
    const MIN_HEADER: usize = 128;
    if bytes.len() < MIN_HEADER {
        return Err(Error::HermesTruncated {
            need: MIN_HEADER,
            got: bytes.len(),
        });
    }
    let magic: u64 = u64::from_le_bytes(slice_8(bytes, 0));
    if magic != HERMES_MAGIC {
        return Err(Error::HermesBadMagic(magic));
    }
    let version: u32 = u32::from_le_bytes(slice_4(bytes, 8));
    let mut source_hash: [u8; 20] = [0u8; 20];
    source_hash.copy_from_slice(&bytes[12..32]);
    let file_length: u32 = u32::from_le_bytes(slice_4(bytes, 32));
    let global_code_index: u32 = u32::from_le_bytes(slice_4(bytes, 36));
    let function_count: u32 = u32::from_le_bytes(slice_4(bytes, 40));
    let string_kind_count: u32 = u32::from_le_bytes(slice_4(bytes, 44));
    let identifier_count: u32 = u32::from_le_bytes(slice_4(bytes, 48));
    let string_count: u32 = u32::from_le_bytes(slice_4(bytes, 52));
    let overflow_string_count: u32 = u32::from_le_bytes(slice_4(bytes, 56));
    let string_storage_size: u32 = u32::from_le_bytes(slice_4(bytes, 60));
    let mut cursor: usize = 64;
    let (big_int_count, big_int_storage_size): (u32, u32) = if version >= 87 {
        let bc: u32 = u32::from_le_bytes(slice_4(bytes, cursor));
        cursor += 4;
        let bs: u32 = u32::from_le_bytes(slice_4(bytes, cursor));
        cursor += 4;
        (bc, bs)
    } else {
        (0, 0)
    };
    let reg_exp_count: u32 = u32::from_le_bytes(slice_4(bytes, cursor));
    cursor += 4;
    let reg_exp_storage_size: u32 = u32::from_le_bytes(slice_4(bytes, cursor));
    cursor += 4;
    let array_buffer_size: u32 = u32::from_le_bytes(slice_4(bytes, cursor));
    cursor += 4;
    let obj_key_buffer_size: u32 = u32::from_le_bytes(slice_4(bytes, cursor));
    cursor += 4;
    let obj_value_buffer_size: u32 = u32::from_le_bytes(slice_4(bytes, cursor));
    cursor += 4;
    let segment_id: u32 = u32::from_le_bytes(slice_4(bytes, cursor));
    cursor += 4;
    let cjs_module_count: u32 = u32::from_le_bytes(slice_4(bytes, cursor));
    cursor += 4;
    let function_source_count: u32 = if version >= 84 {
        let fsc: u32 = u32::from_le_bytes(slice_4(bytes, cursor));
        cursor += 4;
        fsc
    } else {
        0
    };
    let debug_info_offset: u32 = u32::from_le_bytes(slice_4(bytes, cursor));
    cursor += 4;
    let flags: u8 = bytes[cursor];
    Ok(HermesHeader {
        version,
        source_hash,
        file_length,
        global_code_index,
        function_count,
        string_kind_count,
        identifier_count,
        string_count,
        overflow_string_count,
        string_storage_size,
        big_int_count,
        big_int_storage_size,
        reg_exp_count,
        reg_exp_storage_size,
        array_buffer_size,
        obj_key_buffer_size,
        obj_value_buffer_size,
        segment_id,
        cjs_module_count,
        function_source_count,
        debug_info_offset,
        flags,
    })
}

#[must_use]
pub const fn header_size_for_version(_version: u32) -> usize {
    HERMES_HEADER_TOTAL_SIZE
}

struct ResolvedFunctionFields {
    offset: u32,
    param_count: u32,
    bytecode_size_bytes: u32,
    function_name_id: u32,
    info_offset: u32,
    frame_size: u32,
    env_size: u32,
    highest_read_cache_index: u8,
    highest_write_cache_index: u8,
}

fn resolve_large_function_header(bytes: &[u8], base: usize) -> Option<ResolvedFunctionFields> {
    const LARGE_HEADER_SIZE: usize = 30;
    let end: usize = base.checked_add(LARGE_HEADER_SIZE)?;
    if end > bytes.len() {
        return None;
    }
    Some(ResolvedFunctionFields {
        offset: u32::from_le_bytes(slice_4(bytes, base)),
        param_count: u32::from_le_bytes(slice_4(bytes, base + 4)),
        bytecode_size_bytes: u32::from_le_bytes(slice_4(bytes, base + 8)),
        function_name_id: u32::from_le_bytes(slice_4(bytes, base + 12)),
        info_offset: u32::from_le_bytes(slice_4(bytes, base + 16)),
        frame_size: u32::from_le_bytes(slice_4(bytes, base + 20)),
        env_size: u32::from_le_bytes(slice_4(bytes, base + 24)),
        highest_read_cache_index: bytes[base + 28],
        highest_write_cache_index: bytes[base + 29],
    })
}

fn parse_small_function_table(
    bytes: &[u8],
    cursor: &mut usize,
    count: usize,
) -> Result<Vec<SmallFunctionHeader>> {
    const SFH_SIZE: usize = 16;
    let need: usize = count
        .checked_mul(SFH_SIZE)
        .ok_or(Error::HermesFunctionOob { index: 0, count })?;
    let table_end: usize = cursor
        .checked_add(need)
        .ok_or(Error::HermesFunctionOob { index: 0, count })?;
    if bytes.len() < table_end {
        return Err(Error::HermesFunctionOob { index: 0, count });
    }
    let mut out: Vec<SmallFunctionHeader> = Vec::with_capacity(count);
    for i in 0..count {
        let base: usize = *cursor + i * SFH_SIZE;
        let word0: u32 = u32::from_le_bytes(slice_4(bytes, base));
        let word1: u32 = u32::from_le_bytes(slice_4(bytes, base + 4));
        let word2: u32 = u32::from_le_bytes(slice_4(bytes, base + 8));
        let word3: u32 = u32::from_le_bytes(slice_4(bytes, base + 12));
        let offset: u32 = word0 & 0x01ff_ffff;
        let param_count: u32 = word0 >> 25;
        let bytecode_size_bytes: u32 = word1 & 0x0000_7fff;
        let function_name_id_lo: u32 = (word1 >> 15) & 0x0001_ffff;
        let info_offset: u32 = word2 & 0x01ff_ffff;
        let frame_size: u32 = word2 >> 25;
        let env_size: u32 = word3 & 0x0000_00ff;
        let highest_read_cache_index: u8 = ((word3 >> 8) & 0xff) as u8;
        let highest_write_cache_index: u8 = ((word3 >> 16) & 0xff) as u8;
        let flag_byte: u8 = ((word3 >> 24) & 0xff) as u8;
        let prohibit_invoke: u8 = flag_byte & 0b0000_0011;
        let strict_mode: bool = (flag_byte & 0b0000_0100) != 0;
        let has_exception_handler: bool = (flag_byte & 0b0000_1000) != 0;
        let has_debug_info: bool = (flag_byte & 0b0001_0000) != 0;
        let overflowed: bool = (flag_byte & 0b0010_0000) != 0;
        let resolved: ResolvedFunctionFields = if overflowed {
            let large_offset_raw: u64 = (u64::from(info_offset) << 16) | u64::from(offset);
            let large_offset: usize = usize::try_from(large_offset_raw)
                .map_err(|_| Error::HermesFunctionOob { index: i, count })?;
            resolve_large_function_header(bytes, large_offset).unwrap_or(ResolvedFunctionFields {
                offset,
                param_count,
                bytecode_size_bytes,
                function_name_id: function_name_id_lo,
                info_offset,
                frame_size,
                env_size,
                highest_read_cache_index,
                highest_write_cache_index,
            })
        } else {
            ResolvedFunctionFields {
                offset,
                param_count,
                bytecode_size_bytes,
                function_name_id: function_name_id_lo,
                info_offset,
                frame_size,
                env_size,
                highest_read_cache_index,
                highest_write_cache_index,
            }
        };
        out.push(SmallFunctionHeader {
            offset: resolved.offset,
            param_count: resolved.param_count,
            bytecode_size_bytes: resolved.bytecode_size_bytes,
            function_name_id: resolved.function_name_id,
            info_offset: resolved.info_offset,
            frame_size: resolved.frame_size,
            env_size: resolved.env_size,
            highest_read_cache_index: resolved.highest_read_cache_index,
            highest_write_cache_index: resolved.highest_write_cache_index,
            prohibit_invoke,
            strict_mode,
            has_exception_handler,
            has_debug_info,
            overflowed,
        });
    }
    *cursor = table_end;
    Ok(out)
}

fn parse_string_kind_table(
    bytes: &[u8],
    cursor: &mut usize,
    count: usize,
    string_count: usize,
) -> Result<Vec<HermesStringKind>> {
    const ENTRY_SIZE: usize = 4;
    const COUNT_MASK: u32 = (1u32 << 31) - 1;
    let need: usize = count
        .checked_mul(ENTRY_SIZE)
        .ok_or(Error::HermesStringKindTruncated)?;
    let table_end: usize = cursor
        .checked_add(need)
        .ok_or(Error::HermesStringKindTruncated)?;
    if bytes.len() < table_end {
        return Err(Error::HermesStringKindTruncated);
    }
    let mut out: Vec<HermesStringKind> = Vec::with_capacity(string_count.min(bytes.len()));
    for i in 0..count {
        let base: usize = *cursor + i * ENTRY_SIZE;
        let word: u32 = u32::from_le_bytes(slice_4(bytes, base));
        let kind: HermesStringKind = if (word & (1u32 << 31)) != 0 {
            HermesStringKind::Identifier
        } else {
            HermesStringKind::String
        };
        let run_count: u32 = word & COUNT_MASK;
        let remaining: usize = string_count.saturating_sub(out.len());
        let take: usize = usize::try_from(run_count)
            .unwrap_or(usize::MAX)
            .min(remaining);
        for _ in 0..take {
            out.push(kind);
        }
    }
    *cursor = table_end;
    Ok(out)
}

fn skip_identifier_hash_table(bytes: &[u8], cursor: &mut usize, count: usize) {
    let Some(need): Option<usize> = count.checked_mul(IDENTIFIER_HASH_ENTRY_SIZE) else {
        *cursor = bytes.len();
        return;
    };
    let Some(end): Option<usize> = cursor
        .checked_add(need)
        .map(|end: usize| end.min(bytes.len()))
    else {
        *cursor = bytes.len();
        return;
    };
    *cursor = end;
}

fn parse_small_string_table(
    bytes: &[u8],
    cursor: &mut usize,
    count: usize,
) -> Result<Vec<SmallStringTableRaw>> {
    const SST_SIZE: usize = 4;
    let need: usize = count.checked_mul(SST_SIZE).ok_or(Error::HermesStringOob {
        offset: *cursor,
        length: usize::MAX,
        storage: bytes.len(),
    })?;
    let table_end: usize = cursor.checked_add(need).ok_or(Error::HermesStringOob {
        offset: *cursor,
        length: need,
        storage: bytes.len(),
    })?;
    if bytes.len() < table_end {
        return Err(Error::HermesStringOob {
            offset: *cursor,
            length: need,
            storage: bytes.len(),
        });
    }
    let mut out: Vec<SmallStringTableRaw> = Vec::with_capacity(count);
    for i in 0..count {
        let base: usize = *cursor + i * SST_SIZE;
        let word: u32 = u32::from_le_bytes(slice_4(bytes, base));
        let is_utf16: bool = (word & 0x0000_0001) != 0;
        let offset: u32 = (word >> 1) & 0x007f_ffff;
        let length: u32 = (word >> 24) & 0x0000_00ff;
        out.push(SmallStringTableRaw {
            is_utf16,
            offset,
            length,
        });
    }
    *cursor = table_end;
    Ok(out)
}

fn parse_overflow_string_table(
    bytes: &[u8],
    cursor: &mut usize,
    count: usize,
) -> Result<Vec<(u32, u32)>> {
    const ENTRY_SIZE: usize = 8;
    let need: usize = count
        .checked_mul(ENTRY_SIZE)
        .ok_or(Error::HermesStringOob {
            offset: *cursor,
            length: usize::MAX,
            storage: bytes.len(),
        })?;
    let table_end: usize = cursor.checked_add(need).ok_or(Error::HermesStringOob {
        offset: *cursor,
        length: need,
        storage: bytes.len(),
    })?;
    if bytes.len() < table_end {
        return Err(Error::HermesStringOob {
            offset: *cursor,
            length: need,
            storage: bytes.len(),
        });
    }
    let mut out: Vec<(u32, u32)> = Vec::with_capacity(count);
    for i in 0..count {
        let base: usize = *cursor + i * ENTRY_SIZE;
        let off: u32 = u32::from_le_bytes(slice_4(bytes, base));
        let len: u32 = u32::from_le_bytes(slice_4(bytes, base + 4));
        out.push((off, len));
    }
    *cursor = table_end;
    Ok(out)
}

fn decode_utf8_lossy_ascii(slice: &[u8]) -> String {
    let mut out: String = String::with_capacity(slice.len());
    for byte in slice {
        if (*byte as u32) < 0x80 {
            out.push(*byte as char);
        } else {
            out.push('?');
        }
    }
    out
}

fn decode_utf16_le_lossy(slice: &[u8]) -> String {
    let mut out: String = String::with_capacity(slice.len() / 2);
    let mut i: usize = 0;
    while i + 1 < slice.len() {
        let unit: u16 = u16::from_le_bytes([slice[i], slice[i + 1]]);
        i += 2;
        match char::from_u32(unit as u32) {
            Some(c) => out.push(c),
            None => out.push('?'),
        }
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyReport {
    pub function_count: usize,
    pub identifier_count: usize,
    pub string_count: usize,
    pub functions: Vec<FunctionDisasm>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDisasm {
    pub index: usize,
    pub function_name: String,
    pub param_count: u32,
    pub frame_size: u32,
    pub bytecode_size_bytes: u32,
    pub strict_mode: bool,
}

#[must_use]
pub fn disassemble(module: &HermesModule) -> DisassemblyReport {
    dbg_section("hermes.disassemble");
    dbg_kv("function_count", || module.functions.len().to_string());
    let mut functions: Vec<FunctionDisasm> = Vec::with_capacity(module.functions.len());
    for (i, f) in module.functions.iter().enumerate() {
        let name: String = module
            .string_by_global_id(f.function_name_id)
            .map(str::to_owned)
            .unwrap_or_else(|| format!("$func{i}"));
        dbg_line(|| {
            format!(
                "fn[{i}] {name} params={} frame={} bytecode={}B",
                f.param_count, f.frame_size, f.bytecode_size_bytes
            )
        });
        functions.push(FunctionDisasm {
            index: i,
            function_name: name,
            param_count: f.param_count,
            frame_size: f.frame_size,
            bytecode_size_bytes: f.bytecode_size_bytes,
            strict_mode: f.strict_mode,
        });
    }
    DisassemblyReport {
        function_count: module.functions.len(),
        identifier_count: module.identifiers.len(),
        string_count: module.strings.len(),
        functions,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsLiftReport {
    pub strings_by_index: BTreeMap<u32, String>,
    pub identifiers_by_index: BTreeMap<u32, String>,
    pub function_surface: Vec<String>,
}

#[must_use]
pub fn lift_to_js_surface(module: &HermesModule) -> JsLiftReport {
    let mut strings_by_index: BTreeMap<u32, String> = BTreeMap::new();
    for (i, s) in module.strings.iter().enumerate() {
        strings_by_index.insert(i as u32, s.clone());
    }
    let mut identifiers_by_index: BTreeMap<u32, String> = BTreeMap::new();
    for (i, s) in module.identifiers.iter().enumerate() {
        identifiers_by_index.insert(i as u32, s.clone());
    }
    let mut function_surface: Vec<String> = Vec::with_capacity(module.functions.len());
    for (i, f) in module.functions.iter().enumerate() {
        let name: String = module
            .string_by_global_id(f.function_name_id)
            .map(str::to_owned)
            .unwrap_or_else(|| format!("$func{i}"));
        let strict: &str = if f.strict_mode {
            "\"use strict\"; "
        } else {
            ""
        };
        let params: Vec<String> = (0..f.param_count).map(|p: u32| format!("$p{p}")).collect();
        function_surface.push(format!(
            "function {name}({}) {{ {}/* {} bytes */ }}",
            params.join(", "),
            strict,
            f.bytecode_size_bytes
        ));
    }
    JsLiftReport {
        strings_by_index,
        identifiers_by_index,
        function_surface,
    }
}

fn slice_4(bytes: &[u8], at: usize) -> [u8; 4] {
    [bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]
}

fn slice_8(bytes: &[u8], at: usize) -> [u8; 8] {
    [
        bytes[at],
        bytes[at + 1],
        bytes[at + 2],
        bytes[at + 3],
        bytes[at + 4],
        bytes[at + 5],
        bytes[at + 6],
        bytes[at + 7],
    ]
}

#[inline]
const fn align_up_const(n: usize, align: usize) -> usize {
    (n + align - 1) & !(align - 1)
}

#[inline]
fn align_up(n: usize, align: usize) -> usize {
    align_up_const(n, align)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    pub(crate) fn synth_minimal_hermes_v90() -> Vec<u8> {
        synth_minimal_hermes(90)
    }

    pub(crate) fn synth_minimal_hermes(version: u32) -> Vec<u8> {
        let identifiers: &[&str] = &["main", "log"];
        let strings: &[&str] = &["hello", "world"];
        let all_strings: Vec<&str> = identifiers.iter().chain(strings.iter()).copied().collect();
        let mut storage: Vec<u8> = Vec::new();
        let mut string_offsets: Vec<(u32, u32)> = Vec::new();
        for s in &all_strings {
            let off: u32 = storage.len() as u32;
            let len: u32 = s.len() as u32;
            storage.extend_from_slice(s.as_bytes());
            string_offsets.push((off, len));
        }
        let function_count: u32 = 1;
        let string_kind_count: u32 = 2;
        let identifier_count: u32 = identifiers.len() as u32;
        let string_count: u32 = all_strings.len() as u32;
        let overflow_string_count: u32 = 0;
        let string_storage_size: u32 = storage.len() as u32;
        let header_size: usize = header_size_for_version(version);
        let mut buf: Vec<u8> = Vec::with_capacity(header_size + 4096);
        buf.extend_from_slice(&HERMES_MAGIC.to_le_bytes());
        buf.extend_from_slice(&version.to_le_bytes());
        buf.extend_from_slice(&[0u8; 20]);
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&function_count.to_le_bytes());
        buf.extend_from_slice(&string_kind_count.to_le_bytes());
        buf.extend_from_slice(&identifier_count.to_le_bytes());
        buf.extend_from_slice(&string_count.to_le_bytes());
        buf.extend_from_slice(&overflow_string_count.to_le_bytes());
        buf.extend_from_slice(&string_storage_size.to_le_bytes());
        if version >= 87 {
            buf.extend_from_slice(&0u32.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes());
        }
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        if version >= 84 {
            buf.extend_from_slice(&0u32.to_le_bytes());
        }
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(0u8);
        while buf.len() < header_size {
            buf.push(0u8);
        }
        let fn_offset: u32 = 0;
        let fn_param_count: u32 = 2;
        let fn_bcsize: u32 = 0;
        let fn_name_id: u32 = 0;
        let fn_info_offset: u32 = 0;
        let fn_frame_size: u32 = 4;
        let fn_env_size: u32 = 0;
        let read_cache: u8 = 0;
        let write_cache: u8 = 0;
        let flag_byte: u8 = 0b0000_0100;
        let word0: u32 = fn_offset | (fn_param_count << 25);
        let word1: u32 = (fn_bcsize & 0x0000_7fff) | ((fn_name_id & 0x0001_ffff) << 15);
        let word2: u32 = fn_info_offset | (fn_frame_size << 25);
        let word3: u32 = (fn_env_size & 0xff)
            | ((read_cache as u32) << 8)
            | ((write_cache as u32) << 16)
            | ((flag_byte as u32) << 24);
        buf.extend_from_slice(&word0.to_le_bytes());
        buf.extend_from_slice(&word1.to_le_bytes());
        buf.extend_from_slice(&word2.to_le_bytes());
        buf.extend_from_slice(&word3.to_le_bytes());
        while buf.len() % 4 != 0 {
            buf.push(0u8);
        }
        let id_kind: u32 = (1u32 << 31) | (identifier_count & 0x7fff_ffff);
        let str_kind: u32 = (string_count - identifier_count) & 0x7fff_ffff;
        debug_assert_eq!(string_kind_count, 2);
        buf.extend_from_slice(&id_kind.to_le_bytes());
        buf.extend_from_slice(&str_kind.to_le_bytes());
        while buf.len() % 4 != 0 {
            buf.push(0u8);
        }
        for _ in 0..identifier_count {
            buf.extend_from_slice(&0u32.to_le_bytes());
        }
        while buf.len() % 4 != 0 {
            buf.push(0u8);
        }
        for (off, len) in &string_offsets {
            let length_bits: u32 = (*len) & 0xff;
            let offset_bits: u32 = (*off) & 0x007f_ffff;
            let word: u32 = (offset_bits << 1) | (length_bits << 24);
            buf.extend_from_slice(&word.to_le_bytes());
        }
        while buf.len() % 4 != 0 {
            buf.push(0u8);
        }
        buf.extend_from_slice(&storage);
        while buf.len() % 4 != 0 {
            buf.push(0u8);
        }
        let file_len: u32 = buf.len() as u32;
        buf[32..36].copy_from_slice(&file_len.to_le_bytes());
        buf
    }

    #[test]
    fn header_magic_round_trip() {
        let bytes: Vec<u8> = synth_minimal_hermes_v90();
        let h: HermesHeader = parse_header(&bytes).expect("parse header");
        assert_eq!(h.version, 90);
        assert_eq!(h.function_count, 1);
        assert_eq!(h.identifier_count, 2);
        assert_eq!(h.string_count, 4);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes: Vec<u8> = synth_minimal_hermes_v90();
        bytes[0] = 0xff;
        let err: Error = parse_header(&bytes).expect_err("must fail");
        assert!(matches!(err, Error::HermesBadMagic(_)));
    }

    #[test]
    fn rejects_unsupported_version() {
        let bytes: Vec<u8> = synth_minimal_hermes(40);
        let err: Error = parse(&bytes).expect_err("must fail");
        assert!(matches!(err, Error::HermesUnsupportedVersion(40)));
    }

    #[test]
    fn parse_full_module_v90() {
        let bytes: Vec<u8> = synth_minimal_hermes_v90();
        let module: HermesModule = parse(&bytes).expect("parse module");
        assert_eq!(module.functions.len(), 1);
        assert_eq!(module.identifiers.len(), 2);
        assert_eq!(module.strings.len(), 2);
        assert_eq!(module.identifiers[0], "main");
        assert_eq!(module.identifiers[1], "log");
        assert_eq!(module.strings[0], "hello");
        assert_eq!(module.strings[1], "world");
        assert!(module.functions[0].strict_mode);
        assert_eq!(module.functions[0].param_count, 2);
    }

    #[test]
    fn disassemble_emits_named_function() {
        let bytes: Vec<u8> = synth_minimal_hermes_v90();
        let module: HermesModule = parse(&bytes).expect("parse module");
        let report: DisassemblyReport = disassemble(&module);
        assert_eq!(report.function_count, 1);
        assert_eq!(report.functions[0].function_name, "main");
        assert!(report.functions[0].strict_mode);
    }

    #[test]
    fn lift_to_js_surface_round_trip() {
        let bytes: Vec<u8> = synth_minimal_hermes_v90();
        let module: HermesModule = parse(&bytes).expect("parse module");
        let lift: JsLiftReport = lift_to_js_surface(&module);
        assert_eq!(
            lift.strings_by_index.get(&0).map(String::as_str),
            Some("hello")
        );
        assert_eq!(
            lift.identifiers_by_index.get(&0).map(String::as_str),
            Some("main")
        );
        assert!(lift.function_surface[0].contains("function main"));
        assert!(lift.function_surface[0].contains("\"use strict\""));
    }

    #[test]
    fn detect_hermes_magic_in_bytes() {
        let bytes: Vec<u8> = synth_minimal_hermes_v90();
        assert_eq!(&bytes[..8], &HERMES_MAGIC_LE_BYTES);
    }

    #[test]
    fn parse_full_module_v60_minimum_supported() {
        let bytes: Vec<u8> = synth_minimal_hermes(60);
        let module: HermesModule = parse(&bytes).expect("parse v60");
        assert_eq!(module.header.version, 60);
    }

    #[test]
    fn parse_full_module_v96_maximum_supported() {
        let bytes: Vec<u8> = synth_minimal_hermes(96);
        let module: HermesModule = parse(&bytes).expect("parse v96");
        assert_eq!(module.header.version, 96);
    }

    fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn forged_function_count_rejected_without_oom() {
        let mut bytes: Vec<u8> = synth_minimal_hermes_v90();
        put_u32(&mut bytes, 40, u32::MAX);
        let err: Error = parse(&bytes).expect_err("forged function_count must fail");
        assert!(
            matches!(err, Error::HermesHeaderCountsExceedInput { .. }),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn forged_identifier_count_does_not_balloon_capacity() {
        let mut bytes: Vec<u8> = synth_minimal_hermes_v90();
        put_u32(&mut bytes, 48, u32::MAX);
        let err: Error = parse(&bytes).expect_err("forged identifier_count must fail");
        assert!(
            matches!(
                err,
                Error::HermesHeaderCountsExceedInput { .. } | Error::HermesStringKindTruncated
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn forged_string_count_rejected_without_oom() {
        let mut bytes: Vec<u8> = synth_minimal_hermes_v90();
        put_u32(&mut bytes, 52, u32::MAX);
        let err: Error = parse(&bytes).expect_err("forged string_count must fail");
        assert!(
            matches!(err, Error::HermesHeaderCountsExceedInput { .. }),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn forged_overflow_string_count_rejected_without_oom() {
        let mut bytes: Vec<u8> = synth_minimal_hermes_v90();
        put_u32(&mut bytes, 56, u32::MAX);
        let err: Error = parse(&bytes).expect_err("forged overflow_string_count must fail");
        assert!(
            matches!(err, Error::HermesHeaderCountsExceedInput { .. }),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn forged_string_storage_size_rejected_without_oom() {
        let mut bytes: Vec<u8> = synth_minimal_hermes_v90();
        put_u32(&mut bytes, 60, u32::MAX);
        let err: Error = parse(&bytes).expect_err("forged string_storage_size must fail");
        assert!(
            matches!(err, Error::HermesHeaderCountsExceedInput { .. }),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn forged_trailing_section_sizes_rejected_without_empty_buffers() {
        for (offset, field) in [
            (64usize, "big_int_count"),
            (68, "big_int_storage_size"),
            (72, "reg_exp_count"),
            (76, "reg_exp_storage_size"),
            (80, "array_buffer_size"),
            (84, "obj_key_buffer_size"),
            (88, "obj_value_buffer_size"),
        ] {
            let mut bytes: Vec<u8> = synth_minimal_hermes_v90();
            put_u32(&mut bytes, offset, 1);
            let err: Error = match parse(&bytes) {
                Ok(_) => panic!("{field} must not parse partially"),
                Err(err) => err,
            };
            assert!(
                matches!(err, Error::HermesHeaderCountsExceedInput { .. }),
                "unexpected {field} error: {err:?}"
            );
        }
    }

    #[test]
    fn all_counts_forged_max_returns_bounded_err() {
        let mut bytes: Vec<u8> = synth_minimal_hermes_v90();
        for at in [40usize, 44, 48, 52, 56, 60] {
            put_u32(&mut bytes, at, u32::MAX);
        }
        let err: Error = parse(&bytes).expect_err("fully forged header must fail");
        assert!(
            matches!(err, Error::HermesHeaderCountsExceedInput { .. }),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn header_count_guard_accepts_legitimate_minimal_bundle() {
        let bytes: Vec<u8> = synth_minimal_hermes_v90();
        let header: HermesHeader = parse_header(&bytes).expect("parse header");
        assert!(reject_oversized_header_counts(&header, bytes.len()).is_ok());
    }

    #[test]
    fn truncated_after_header_fails_cleanly() {
        let bytes: Vec<u8> = synth_minimal_hermes_v90();
        let truncated: &[u8] = &bytes[..HERMES_HEADER_TOTAL_SIZE + 2];
        let err: Error = parse(truncated).expect_err("truncated body must fail");
        assert!(
            matches!(
                err,
                Error::HermesHeaderCountsExceedInput { .. }
                    | Error::HermesFunctionOob { .. }
                    | Error::HermesStringOob { .. }
                    | Error::HermesStringKindTruncated
            ),
            "unexpected error: {err:?}"
        );
    }
}
