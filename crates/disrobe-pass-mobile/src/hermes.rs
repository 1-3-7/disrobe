use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const HERMES_MAGIC: u64 = 0x1f19_03c1_03bc_1fc6;
pub const HERMES_MAGIC_LE_BYTES: [u8; 8] = HERMES_MAGIC.to_le_bytes();

pub const HERMES_MIN_VERSION: u32 = 60;
pub const HERMES_MAX_VERSION: u32 = 96;

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
}

pub fn parse(bytes: &[u8]) -> Result<HermesModule> {
    let header: HermesHeader = parse_header(bytes)?;
    if header.version < HERMES_MIN_VERSION || header.version > HERMES_MAX_VERSION {
        return Err(Error::HermesUnsupportedVersion(header.version));
    }
    let header_size: usize = header_size_for_version(header.version);
    let mut cursor: usize = header_size;
    cursor = align_up(cursor, 4);
    let functions: Vec<SmallFunctionHeader> =
        parse_small_function_table(bytes, &mut cursor, header.function_count as usize)?;
    cursor = align_up(cursor, 4);
    let string_kinds: Vec<HermesStringKind> = parse_string_kind_table(
        bytes,
        &mut cursor,
        header.string_kind_count as usize,
        header.string_count as usize,
    )?;
    cursor = align_up(cursor, 4);
    skip_identifier_hash_table(bytes, &mut cursor, header.identifier_count as usize);
    cursor = align_up(cursor, 4);
    let small_entries: Vec<SmallStringTableRaw> =
        parse_small_string_table(bytes, &mut cursor, header.string_count as usize)?;
    cursor = align_up(cursor, 4);
    let overflow_entries: Vec<(u32, u32)> =
        parse_overflow_string_table(bytes, &mut cursor, header.overflow_string_count as usize)?;
    cursor = align_up(cursor, 4);
    let storage_offset: usize = cursor;
    let storage_end: usize = storage_offset
        .checked_add(header.string_storage_size as usize)
        .ok_or(Error::HermesStringOob {
            offset: storage_offset,
            length: header.string_storage_size as usize,
            storage: bytes.len(),
        })?;
    if storage_end > bytes.len() {
        return Err(Error::HermesStringOob {
            offset: storage_offset,
            length: header.string_storage_size as usize,
            storage: bytes.len(),
        });
    }
    let storage: &[u8] = &bytes[storage_offset..storage_end];
    let identifier_cutoff: usize = header.identifier_count as usize;
    let mut identifiers: Vec<String> = Vec::with_capacity(identifier_cutoff);
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
            (resolved.length_chars as usize).saturating_mul(2)
        } else {
            resolved.length_chars as usize
        };
        let off_usize: usize = resolved.offset as usize;
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
    Ok(HermesModule {
        header,
        functions,
        identifiers,
        strings,
        string_kinds,
        overflow_resolved,
        utf16_strings,
        raw_bytecode_size,
    })
}

struct ResolvedString {
    offset: u32,
    length_chars: u32,
    is_utf16: bool,
    from_overflow: bool,
}

fn resolve_entry(entry: &SmallStringTableRaw, overflow: &[(u32, u32)]) -> Result<ResolvedString> {
    if entry.length == SMALL_STRING_INVALID_LENGTH {
        let index: usize = entry.offset as usize;
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

fn parse_small_function_table(
    bytes: &[u8],
    cursor: &mut usize,
    count: usize,
) -> Result<Vec<SmallFunctionHeader>> {
    const SFH_SIZE: usize = 16;
    let need: usize = count.saturating_mul(SFH_SIZE);
    if bytes.len() < cursor.saturating_add(need) {
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
        let bytecode_size_bytes: u32 = word1 & 0x00ff_ffff;
        let function_name_id_lo: u32 = word1 >> 24;
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
        out.push(SmallFunctionHeader {
            offset,
            param_count,
            bytecode_size_bytes,
            function_name_id: function_name_id_lo,
            info_offset,
            frame_size,
            env_size,
            highest_read_cache_index,
            highest_write_cache_index,
            prohibit_invoke,
            strict_mode,
            has_exception_handler,
            has_debug_info,
            overflowed,
        });
    }
    *cursor += need;
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
    let need: usize = count.saturating_mul(ENTRY_SIZE);
    if bytes.len() < cursor.saturating_add(need) {
        return Err(Error::HermesStringKindTruncated);
    }
    let mut out: Vec<HermesStringKind> = Vec::with_capacity(string_count);
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
        let take: usize = (run_count as usize).min(remaining);
        for _ in 0..take {
            out.push(kind);
        }
    }
    *cursor += need;
    Ok(out)
}

fn skip_identifier_hash_table(bytes: &[u8], cursor: &mut usize, count: usize) {
    let need: usize = count.saturating_mul(4);
    let end: usize = cursor.saturating_add(need).min(bytes.len());
    *cursor = end;
}

fn parse_small_string_table(
    bytes: &[u8],
    cursor: &mut usize,
    count: usize,
) -> Result<Vec<SmallStringTableRaw>> {
    const SST_SIZE: usize = 4;
    let need: usize = count.saturating_mul(SST_SIZE);
    if bytes.len() < cursor.saturating_add(need) {
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
    *cursor += need;
    Ok(out)
}

fn parse_overflow_string_table(
    bytes: &[u8],
    cursor: &mut usize,
    count: usize,
) -> Result<Vec<(u32, u32)>> {
    const ENTRY_SIZE: usize = 8;
    let need: usize = count.saturating_mul(ENTRY_SIZE);
    if bytes.len() < cursor.saturating_add(need) {
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
    *cursor += need;
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
    let mut functions: Vec<FunctionDisasm> = Vec::with_capacity(module.functions.len());
    for (i, f) in module.functions.iter().enumerate() {
        let name: String = module
            .identifiers
            .get(f.function_name_id as usize)
            .cloned()
            .unwrap_or_else(|| format!("$func{i}"));
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
            .identifiers
            .get(f.function_name_id as usize)
            .cloned()
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
        let word1: u32 = fn_bcsize | (fn_name_id << 24);
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
}
