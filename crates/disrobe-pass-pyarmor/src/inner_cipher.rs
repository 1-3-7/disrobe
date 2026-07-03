use aes::Aes128;
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};
use disrobe_py_marshal::{CodeObject, Object, PyVersion};

use crate::descriptor_cache::{CacheKey, CachedDescriptor, DescriptorCache};

const CO_PYARMOR_OBFUSCATED: i32 = 0x2000_0000;

const MAX_CODE_OBJECT_DEPTH: u32 = 512;

const DESC_FLAG_SHORT_CODE: u8 = 0x02;
const DESC_FLAG_XOR_NONCE: u8 = 0x04;
const DESC_FLAG_COPY_PROLOGUE: u8 = 0x08;

const XOR_VM_VALID_INDEX: [i8; 16] = [-1, 0, 1, 2, 3, 4, 5, 6, 7, -1, -1, -1, -1, -1, -1, -1];

#[derive(Debug, Clone)]
pub struct PyarmorCoDescriptor {
    pub flags: u8,
    pub short_nonce_index: u8,
    pub decrypt_begin_index: u8,
    pub decrypt_length: u32,
    pub enter_count: u32,
}

impl PyarmorCoDescriptor {
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 12 {
            return None;
        }
        Some(Self {
            flags: bytes[0],
            short_nonce_index: bytes[1],
            decrypt_begin_index: bytes[3],
            decrypt_length: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            enter_count: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        })
    }

    #[inline]
    #[must_use]
    pub const fn short_code(&self) -> bool {
        self.flags & DESC_FLAG_SHORT_CODE != 0
    }

    #[inline]
    #[must_use]
    pub const fn xor_nonce(&self) -> bool {
        self.flags & DESC_FLAG_XOR_NONCE != 0
    }

    #[inline]
    #[must_use]
    pub const fn copy_prologue(&self) -> bool {
        self.flags & DESC_FLAG_COPY_PROLOGUE != 0
    }
}

#[derive(Debug, Clone, Default)]
pub struct PyarmorTrailer {
    pub fn_records: Vec<Vec<u8>>,
    pub descriptor_consts_indices: Vec<u32>,
    pub stage_2_consts_indices: Vec<u32>,
    pub bcc: bool,
    pub nine_pro_stage_2: bool,
}

const TRAILER_BIT_BCC: u8 = 0x10;
const TRAILER_BIT_NINE_PRO_STAGE_2: u8 = 0x20;

impl PyarmorTrailer {
    #[must_use]
    pub fn parse(trailer: &[u8]) -> Option<Self> {
        if trailer.len() < 4 {
            return None;
        }
        let header: u8 = trailer[0];
        let fn_count: usize = (header & 0x03) as usize;
        let descriptor_count: usize = ((header >> 2) & 0x03) as usize;
        let bcc: bool = header & TRAILER_BIT_BCC != 0;
        let nine_pro_stage_2: bool = header & TRAILER_BIT_NINE_PRO_STAGE_2 != 0;
        let stage_2_count: usize = if nine_pro_stage_2 && trailer.len() >= 4 {
            (trailer[1] & 0x03) as usize
        } else {
            0
        };

        let mut cursor: usize = 4usize;
        let mut fn_records: Vec<Vec<u8>> = Vec::with_capacity(fn_count);
        for _ in 0..fn_count {
            if cursor >= trailer.len() {
                return None;
            }
            let b0: u8 = trailer[cursor];
            let length: usize = ((b0 >> 6) as usize) + 2;
            if cursor + length > trailer.len() {
                return None;
            }
            fn_records.push(trailer[cursor..cursor + length].to_vec());
            cursor += length;
        }

        let mut descriptor_consts_indices: Vec<u32> = Vec::with_capacity(descriptor_count);
        for _ in 0..descriptor_count {
            if cursor >= trailer.len() {
                return None;
            }
            let b0: u8 = trailer[cursor];
            let length: usize = ((b0 >> 6) as usize) + 2;
            if cursor + length > trailer.len() {
                return None;
            }
            let mut idx: u32 = 0;
            for i in 1..length {
                idx = (idx << 8) | u32::from(trailer[cursor + i]);
            }
            descriptor_consts_indices.push(idx);
            cursor += length;
        }

        let mut stage_2_consts_indices: Vec<u32> = Vec::with_capacity(stage_2_count);
        for _ in 0..stage_2_count {
            if cursor >= trailer.len() {
                return None;
            }
            let b0: u8 = trailer[cursor];
            let length: usize = ((b0 >> 6) as usize) + 2;
            if cursor + length > trailer.len() {
                return None;
            }
            let mut idx: u32 = 0;
            for i in 1..length {
                idx = (idx << 8) | u32::from(trailer[cursor + i]);
            }
            stage_2_consts_indices.push(idx);
            cursor += length;
        }

        Some(Self {
            fn_records,
            descriptor_consts_indices,
            stage_2_consts_indices,
            bcc,
            nine_pro_stage_2,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PyarmorModuleState {
    pub aes_key: [u8; 16],
    pub mix_str_nonce: [u8; 12],
    pub co_code_nonce_xor_key: [u8; 12],
    pub xor_enabled: bool,
    pub py_version: PyVersion,
}

pub fn decrypt_module(code: &mut Object, module_state: &PyarmorModuleState) -> DecryptionStats {
    let mut metrics: DecryptionStats = DecryptionStats::default();
    if let Object::Code(co) = code {
        decrypt_code_object(co, module_state, &mut metrics, None, 0);
    }
    metrics
}

pub fn decrypt_module_with_cache(
    code: &mut Object,
    module_state: &PyarmorModuleState,
    cache: &mut DescriptorCache,
) -> DecryptionStats {
    let mut metrics: DecryptionStats = DecryptionStats::default();
    if let Object::Code(co) = code {
        decrypt_code_object(co, module_state, &mut metrics, Some(cache), 0);
    }
    metrics
}

#[derive(Debug, Default, Clone)]
pub struct DecryptionStats {
    pub objects_visited: u32,
    pub objects_with_trailer: u32,
    pub descriptors_applied: u32,
    pub bytes_decrypted: u64,
    pub copy_prologue_applied: u32,
    pub trailer_parse_failures: u32,
    pub missing_consts_failures: u32,
    pub first_trailer_hex: Option<String>,
    pub cache_hits: u32,
    pub cache_misses: u32,
    pub nine_pro_stage_2_segments_found: u32,
    pub nine_pro_stage_2_segments_unwrapped: u32,
    pub nine_pro_stage_2_bytes_unwrapped: u64,
    pub nine_pro_stage_2_bind_required: u32,
    pub depth_limit_truncations: u32,
}

fn decrypt_code_object(
    co: &mut CodeObject,
    module_state: &PyarmorModuleState,
    metrics: &mut DecryptionStats,
    cache: Option<&mut DescriptorCache>,
    depth: u32,
) {
    if depth >= MAX_CODE_OBJECT_DEPTH {
        metrics.depth_limit_truncations += 1;
        return;
    }
    metrics.objects_visited += 1;
    let mut cache_slot: Option<&mut DescriptorCache> = cache;

    if co.flags & CO_PYARMOR_OBFUSCATED != 0 && !co.pyarmor_trailer.is_empty() {
        metrics.objects_with_trailer += 1;
        if metrics.first_trailer_hex.is_none() {
            metrics.first_trailer_hex = Some(hex_encode(&co.pyarmor_trailer));
        }
        if let Some(trailer) = PyarmorTrailer::parse(&co.pyarmor_trailer) {
            if trailer.nine_pro_stage_2 {
                apply_nine_pro_stage_2(co, &trailer, module_state, metrics);
            }
            for &idx in &trailer.descriptor_consts_indices {
                match co.consts.get(idx as usize).cloned() {
                    Some(Object::Bytes(blob)) => {
                        if blob.len() < 8 {
                            metrics.trailer_parse_failures += 1;
                            continue;
                        }
                        if let Some(desc) = PyarmorCoDescriptor::parse(&blob[8..]) {
                            apply_descriptor(
                                co,
                                &desc,
                                module_state,
                                metrics,
                                cache_slot.as_deref_mut(),
                            );
                        } else {
                            metrics.trailer_parse_failures += 1;
                        }
                    }
                    Some(Object::String { value, .. } | Object::ShortAscii { value, .. }) => {
                        let bytes: &[u8] = value.as_bytes();
                        if bytes.len() < 8 {
                            metrics.trailer_parse_failures += 1;
                            continue;
                        }
                        if let Some(desc) = PyarmorCoDescriptor::parse(&bytes[8..]) {
                            apply_descriptor(
                                co,
                                &desc,
                                module_state,
                                metrics,
                                cache_slot.as_deref_mut(),
                            );
                        } else {
                            metrics.trailer_parse_failures += 1;
                        }
                    }
                    _ => {
                        metrics.missing_consts_failures += 1;
                    }
                }
            }
        } else {
            metrics.trailer_parse_failures += 1;
        }
    }

    for cnst in &mut co.consts {
        if let Object::Code(inner) = cnst {
            decrypt_code_object(
                inner,
                module_state,
                metrics,
                cache_slot.as_deref_mut(),
                depth + 1,
            );
        }
    }

    co.flags &= !CO_PYARMOR_OBFUSCATED;
    co.pyarmor_trailer.clear();
}

fn apply_descriptor(
    co: &mut CodeObject,
    desc: &PyarmorCoDescriptor,
    module_state: &PyarmorModuleState,
    metrics: &mut DecryptionStats,
    mut cache: Option<&mut DescriptorCache>,
) {
    let nonce_index: usize = if desc.short_code() {
        desc.short_nonce_index as usize
    } else {
        let Some(sum): Option<usize> = (desc.short_nonce_index as usize)
            .checked_add(desc.decrypt_begin_index as usize)
            .and_then(|v: usize| v.checked_add(desc.decrypt_length as usize))
        else {
            return;
        };
        sum
    };

    let Some(nonce_end): Option<usize> = nonce_index.checked_add(12) else {
        return;
    };
    if nonce_end > co.code.len() {
        return;
    }
    let mut nonce: [u8; 12] = [0u8; 12];
    let Some(nonce_slice): Option<&[u8]> = co.code.get(nonce_index..nonce_end) else {
        metrics.trailer_parse_failures += 1;
        return;
    };
    nonce.copy_from_slice(nonce_slice);

    if desc.xor_nonce() && module_state.xor_enabled {
        for (n, k) in nonce
            .iter_mut()
            .zip(module_state.co_code_nonce_xor_key.iter())
        {
            *n ^= *k;
        }
    }

    let begin: usize = desc.decrypt_begin_index as usize;
    let len: usize = desc.decrypt_length as usize;
    let Some(end): Option<usize> = begin.checked_add(len) else {
        metrics.trailer_parse_failures += 1;
        return;
    };
    if co.code.get(begin..end).is_none() {
        metrics.trailer_parse_failures += 1;
        return;
    }

    let cache_key: CacheKey = CacheKey::from_trailer_and_prefix(
        &co.pyarmor_trailer,
        &co.code[..begin.min(co.code.len())],
        &nonce,
    );

    let cached_keystream: Option<Vec<u8>> = cache
        .as_deref_mut()
        .and_then(|c| c.get(&cache_key))
        .filter(|entry| entry.begin == begin && entry.length == len && entry.keystream.len() == len)
        .map(|entry| entry.keystream);

    if let Some(keystream) = cached_keystream {
        metrics.cache_hits += 1;
        let Some(target): Option<&mut [u8]> = co.code.get_mut(begin..end) else {
            metrics.trailer_parse_failures += 1;
            return;
        };
        for (target, k) in target.iter_mut().zip(keystream.iter()) {
            *target ^= *k;
        }
    } else {
        let mut iv: [u8; 16] = [0u8; 16];
        iv[..12].copy_from_slice(&nonce);
        iv[15] = 2;
        let mut keystream: Vec<u8> = vec![0u8; len];
        let mut cipher: Ctr128BE<Aes128> =
            Ctr128BE::<Aes128>::new(&module_state.aes_key.into(), &iv.into());
        cipher.apply_keystream(&mut keystream);
        let Some(target): Option<&mut [u8]> = co.code.get_mut(begin..end) else {
            metrics.trailer_parse_failures += 1;
            return;
        };
        for (target, k) in target.iter_mut().zip(keystream.iter()) {
            *target ^= *k;
        }
        if let Some(c) = cache {
            c.insert(
                cache_key,
                CachedDescriptor {
                    keystream,
                    begin,
                    length: len,
                },
            );
        }
        metrics.cache_misses += 1;
    }
    metrics.descriptors_applied += 1;
    metrics.bytes_decrypted += len as u64;

    if desc.copy_prologue() {
        let nop: u8 = nop_opcode(module_state.py_version);
        let src_start: usize = len;
        let Some(src_end): Option<usize> = src_start.checked_add(begin) else {
            metrics.trailer_parse_failures += 1;
            return;
        };
        let Some(prologue_src): Option<&[u8]> = co.code.get(src_start..src_end) else {
            metrics.trailer_parse_failures += 1;
            return;
        };
        let prologue: Vec<u8> = prologue_src.to_vec();
        let Some(prefix): Option<&mut [u8]> = co.code.get_mut(..begin) else {
            metrics.trailer_parse_failures += 1;
            return;
        };
        prefix.copy_from_slice(&prologue);
        let Some(src): Option<&mut [u8]> = co.code.get_mut(src_start..src_end) else {
            metrics.trailer_parse_failures += 1;
            return;
        };
        for b in src {
            *b = nop;
        }
        metrics.copy_prologue_applied += 1;
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
    let mut encoded: String = String::with_capacity(bytes.len() * 2);
    for byte in bytes.iter().copied() {
        encoded.push(char::from(HEX_LOWER[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX_LOWER[usize::from(byte & 0x0f)]));
    }
    encoded
}

const fn nop_opcode(version: PyVersion) -> u8 {
    match (version.major, version.minor) {
        (3, 13) => 0x1E,
        (3, 14) => 0x1B,
        _ => 0x09,
    }
}

#[must_use]
pub fn parse_plaintext_xor_procedure(plaintext: &[u8]) -> ([u8; 12], bool) {
    if plaintext.len() < 8 {
        return ([0u8; 12], false);
    }
    let code_offset: usize =
        u32::from_le_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]) as usize;
    let proc_length: usize =
        u32::from_le_bytes([plaintext[4], plaintext[5], plaintext[6], plaintext[7]]) as usize;
    let Some(proc_end): Option<usize> = code_offset.checked_add(proc_length) else {
        return ([0u8; 12], false);
    };
    let Some(buf): Option<&[u8]> = plaintext.get(code_offset..proc_end) else {
        return ([0u8; 12], false);
    };
    if proc_length == 0 {
        return ([0u8; 12], false);
    }
    let Some(key): Option<[u8; 12]> = run_xor_key_vm(buf) else {
        return ([0u8; 12], false);
    };
    (key, true)
}

fn xor_vm_read_operand(
    program: &[u8],
    cursor: usize,
    lo: u8,
    registers: &[i64; 8],
) -> Option<(i64, usize)> {
    if lo < 16
        && let Ok(reg_index) = usize::try_from(XOR_VM_VALID_INDEX[lo as usize])
        && reg_index < registers.len()
    {
        return Some((registers[reg_index], 2));
    }
    let size: usize = (lo & 0x7) as usize;
    match size {
        1 => {
            if cursor + 2 >= program.len() {
                return None;
            }
            Some((i64::from(program[cursor + 2].cast_signed()), 3))
        }
        2 => {
            if cursor + 3 >= program.len() {
                return None;
            }
            let v: i16 = i16::from_le_bytes([program[cursor + 2], program[cursor + 3]]);
            Some((i64::from(v), 4))
        }
        4 => {
            if cursor + 5 >= program.len() {
                return None;
            }
            let v: i32 = i32::from_le_bytes([
                program[cursor + 2],
                program[cursor + 3],
                program[cursor + 4],
                program[cursor + 5],
            ]);
            Some((i64::from(v), 6))
        }
        _ => None,
    }
}

fn run_xor_key_vm(program: &[u8]) -> Option<[u8; 12]> {
    let mut out: [u8; 12] = [0u8; 12];
    if program.len() < 16 {
        return Some(out);
    }
    let mut registers: [i64; 8] = [0; 8];
    let mut cursor: usize = 16usize;

    while cursor < program.len() {
        let op: u8 = program[cursor];
        if op == 0x01 {
            cursor += 1;
            continue;
        }
        if cursor + 1 >= program.len() {
            return None;
        }
        let hi: usize = (program[cursor + 1] >> 4) as usize & 0x7;
        let lo: u8 = program[cursor + 1] & 0xF;

        let (operand2, advance): (i64, usize) =
            xor_vm_read_operand(program, cursor, lo, &registers)?;

        match op {
            0x02 => {
                registers[hi] = registers[hi].wrapping_add(operand2);
                cursor += advance;
            }
            0x03 => {
                registers[hi] = registers[hi].wrapping_sub(operand2);
                cursor += advance;
            }
            0x04 => {
                registers[hi] = registers[hi].wrapping_mul(operand2);
                cursor += advance;
            }
            0x05 => {
                if operand2 == 0 {
                    return None;
                }
                let q: i64 = registers[hi].wrapping_div(operand2);
                registers[hi] = q;
                registers[0] = q;
                cursor += advance;
            }
            0x06 => {
                registers[hi] ^= operand2;
                cursor += advance;
            }
            0x07 => {
                registers[hi] = operand2;
                cursor += advance;
            }
            0x08 => {
                cursor += 2;
            }
            0x09 => {
                let reg: usize = (program[cursor + 1] & 0x7) as usize;
                let val: i32 = i64_truncate_to_i32(registers[reg]);
                out[..4].copy_from_slice(&val.to_le_bytes());
                cursor += 2;
            }
            0x0A => {
                if cursor + 5 >= program.len() {
                    return None;
                }
                cursor += 6;
            }
            0x0B => {
                if cursor + 2 >= program.len() {
                    return None;
                }
                let offset: usize = program[cursor + 2] as usize;
                let reg: usize = (program[cursor + 1] & 0x7) as usize;
                let val: i32 = i64_truncate_to_i32(registers[reg]);
                if offset + 4 <= out.len() {
                    out[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
                }
                cursor += 3;
            }
            _ => {
                return None;
            }
        }
    }

    Some(out)
}

#[inline]
const fn i64_truncate_to_i32(v: i64) -> i32 {
    (v & 0xFFFF_FFFF) as i32
}

const NINE_PRO_STAGE_2_HEADER_LEN: usize = 16;

fn apply_nine_pro_stage_2(
    co: &mut CodeObject,
    trailer: &PyarmorTrailer,
    module_state: &PyarmorModuleState,
    metrics: &mut DecryptionStats,
) {
    for &idx in &trailer.stage_2_consts_indices {
        metrics.nine_pro_stage_2_segments_found += 1;
        let Some(blob): Option<Vec<u8>> = co.consts.get(idx as usize).and_then(|c| match c {
            Object::Bytes(b) => Some(b.clone()),
            _ => None,
        }) else {
            metrics.missing_consts_failures += 1;
            continue;
        };
        if blob.len() < NINE_PRO_STAGE_2_HEADER_LEN {
            metrics.trailer_parse_failures += 1;
            continue;
        }
        let bind_flag_byte: u8 = blob[0];
        let segment_len_bytes: [u8; 4] = [blob[4], blob[5], blob[6], blob[7]];
        let segment_len: usize = u32::from_le_bytes(segment_len_bytes) as usize;
        let nonce_bytes: &[u8] = &blob[8..NINE_PRO_STAGE_2_HEADER_LEN.min(blob.len())];
        let body: &[u8] = &blob[NINE_PRO_STAGE_2_HEADER_LEN..];

        if body.len() < segment_len {
            metrics.trailer_parse_failures += 1;
            continue;
        }
        if !is_bindless_stage_2(bind_flag_byte) {
            metrics.nine_pro_stage_2_bind_required += 1;
            continue;
        }
        let Some(decrypted): Option<Vec<u8>> =
            stage_2_decrypt(&module_state.aes_key, nonce_bytes, &body[..segment_len])
        else {
            metrics.trailer_parse_failures += 1;
            continue;
        };
        if let Some(updated) = patch_stage_2_into_consts(co, idx as usize, &decrypted) {
            co.consts = updated;
            metrics.nine_pro_stage_2_segments_unwrapped += 1;
            metrics.nine_pro_stage_2_bytes_unwrapped += segment_len as u64;
        }
    }
}

const fn is_bindless_stage_2(bind_byte: u8) -> bool {
    bind_byte == 0 || bind_byte == 0xFF
}

fn stage_2_decrypt(key: &[u8; 16], nonce_bytes: &[u8], body: &[u8]) -> Option<Vec<u8>> {
    if nonce_bytes.len() < 8 {
        return None;
    }
    let mut iv: [u8; 16] = [0u8; 16];
    let copy_len: usize = nonce_bytes.len().min(12);
    iv[..copy_len].copy_from_slice(&nonce_bytes[..copy_len]);
    iv[15] = 0x02;
    let mut out: Vec<u8> = body.to_vec();
    let mut cipher: Ctr128BE<Aes128> = Ctr128BE::<Aes128>::new(key.into(), &iv.into());
    cipher.apply_keystream(&mut out);
    Some(out)
}

fn patch_stage_2_into_consts(co: &CodeObject, idx: usize, decrypted: &[u8]) -> Option<Vec<Object>> {
    let mut consts: Vec<Object> = co.consts.clone();
    let slot: &mut Object = consts.get_mut(idx)?;
    *slot = Object::Bytes(decrypted.to_vec());
    Some(consts)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parse_trailer_empty() {
        assert!(PyarmorTrailer::parse(&[]).is_none());
    }

    #[test]
    fn parse_trailer_rejects_short_header() {
        assert!(PyarmorTrailer::parse(&[0x00]).is_none());
        assert!(PyarmorTrailer::parse(&[0x00, 0x00, 0x00]).is_none());
    }

    #[test]
    fn parse_trailer_zero_counts() {
        let trailer: Vec<u8> = vec![0x00, 0x00, 0x00, 0x00];
        let t: PyarmorTrailer = PyarmorTrailer::parse(&trailer).expect("zero-count trailer parses");
        assert!(t.descriptor_consts_indices.is_empty());
        assert!(t.fn_records.is_empty());
        assert!(!t.bcc);
    }

    #[test]
    fn parse_descriptor_basic() {
        let bytes: [u8; 12] = [
            0x0E, 0x05, 0x00, 0x03, 0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        ];
        let d: PyarmorCoDescriptor = PyarmorCoDescriptor::parse(&bytes).expect("descriptor parses");
        assert_eq!(d.flags, 0x0E);
        assert!(d.short_code());
        assert!(d.xor_nonce());
        assert!(d.copy_prologue());
        assert_eq!(d.short_nonce_index, 0x05);
        assert_eq!(d.decrypt_begin_index, 0x03);
        assert_eq!(d.decrypt_length, 0x40);
        assert_eq!(d.enter_count, 0x01);
    }

    #[test]
    fn nop_opcode_per_version() {
        assert_eq!(nop_opcode(PyVersion::PY313), 0x1E);
        assert_eq!(nop_opcode(PyVersion::PY314), 0x1B);
        assert_eq!(nop_opcode(PyVersion::PY312), 0x09);
        assert_eq!(nop_opcode(PyVersion::PY39), 0x09);
    }

    #[test]
    fn xor_vm_empty_program_returns_zeros() {
        assert_eq!(run_xor_key_vm(&[]), Some([0u8; 12]));
    }

    #[test]
    fn xor_vm_op7_set_immediate_then_op9_store_first4() {
        let mut program: Vec<u8> = vec![0u8; 16];
        program.extend_from_slice(&[0x07, 0x1c, 0xef, 0xbe, 0xad, 0xde]);
        program.extend_from_slice(&[0x09, 0x01]);
        let out: [u8; 12] = run_xor_key_vm(&program).expect("vm program succeeds");
        assert_eq!(&out[..4], &[0xef, 0xbe, 0xad, 0xde]);
    }

    #[test]
    fn xor_vm_op7_op2_op6_chain_then_opb_store_at_offset_4() {
        let mut program: Vec<u8> = vec![0u8; 16];
        program.extend_from_slice(&[0x07, 0x1c, 0x10, 0x00, 0x00, 0x00]);
        program.extend_from_slice(&[0x02, 0x1c, 0x05, 0x00, 0x00, 0x00]);
        program.extend_from_slice(&[0x06, 0x1c, 0x0f, 0x00, 0x00, 0x00]);
        program.extend_from_slice(&[0x0b, 0x01, 0x04]);
        let out: [u8; 12] = run_xor_key_vm(&program).expect("vm program succeeds");
        let expected: i32 = (0x10i32 + 0x05i32) ^ 0x0fi32;
        assert_eq!(&out[4..8], &expected.to_le_bytes());
    }

    #[test]
    fn xor_vm_malformed_program_returns_none() {
        let mut program: Vec<u8> = vec![0u8; 16];
        program.push(0x02);
        assert!(run_xor_key_vm(&program).is_none());
    }

    #[test]
    fn plaintext_xor_procedure_rejects_malformed_vm_program() {
        let mut plaintext: Vec<u8> = Vec::new();
        plaintext.extend_from_slice(&8u32.to_le_bytes());
        plaintext.extend_from_slice(&17u32.to_le_bytes());
        plaintext.extend_from_slice(&[0u8; 16]);
        plaintext.push(0x02);
        let (key, parsed): ([u8; 12], bool) = parse_plaintext_xor_procedure(&plaintext);
        assert_eq!(key, [0u8; 12]);
        assert!(!parsed);
    }

    fn make_state() -> PyarmorModuleState {
        PyarmorModuleState {
            aes_key: [0x42; 16],
            mix_str_nonce: [0u8; 12],
            co_code_nonce_xor_key: [0u8; 12],
            xor_enabled: false,
            py_version: PyVersion::PY312,
        }
    }

    fn make_code_object_with_descriptor(payload: &[u8; 16]) -> disrobe_py_marshal::CodeObject {
        let mut co: disrobe_py_marshal::CodeObject =
            disrobe_py_marshal::CodeObject::new(disrobe_py_marshal::CodeEra::Py311Plus);
        co.flags = CO_PYARMOR_OBFUSCATED;
        co.pyarmor_trailer = vec![0x04, 0x00, 0x00, 0x00, 0x42, 0x00];
        let mut code: Vec<u8> = vec![0xAAu8; 64];
        code[16..32].copy_from_slice(payload);
        for (i, byte) in code.iter_mut().enumerate().take(44).skip(32) {
            *byte = u8::try_from(i - 32).expect("range fits");
        }
        co.code = code;
        let mut descriptor_blob: Vec<u8> = vec![0u8; 8];
        descriptor_blob.extend_from_slice(&[
            0x02, 0x14, 0x00, 0x10, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        ]);
        co.consts
            .push(disrobe_py_marshal::Object::Bytes(descriptor_blob));
        co
    }

    #[test]
    fn descriptor_range_past_code_records_parse_failure() {
        let module_state: PyarmorModuleState = make_state();
        let mut co: disrobe_py_marshal::CodeObject =
            disrobe_py_marshal::CodeObject::new(disrobe_py_marshal::CodeEra::Py311Plus);
        co.code = vec![0u8; 16];
        let desc: PyarmorCoDescriptor = PyarmorCoDescriptor {
            flags: DESC_FLAG_SHORT_CODE,
            short_nonce_index: 0,
            decrypt_begin_index: 12,
            decrypt_length: 16,
            enter_count: 0,
        };
        let mut metrics: DecryptionStats = DecryptionStats::default();
        apply_descriptor(&mut co, &desc, &module_state, &mut metrics, None);
        assert_eq!(metrics.trailer_parse_failures, 1);
        assert_eq!(metrics.descriptors_applied, 0);
    }

    #[test]
    fn trailer_parses_nine_pro_stage_2_indices() {
        let trailer: Vec<u8> = vec![TRAILER_BIT_NINE_PRO_STAGE_2, 0x01, 0x00, 0x00, 0x02, 0x7F];
        let parsed: PyarmorTrailer =
            PyarmorTrailer::parse(&trailer).expect("nine-pro trailer parses");
        assert!(parsed.nine_pro_stage_2);
        assert_eq!(parsed.stage_2_consts_indices.len(), 1);
        assert_eq!(parsed.stage_2_consts_indices[0], 0x7F);
    }

    #[test]
    fn trailer_rejects_truncated_nine_pro_stage_2_indices() {
        let trailer: Vec<u8> = vec![TRAILER_BIT_NINE_PRO_STAGE_2, 0x01, 0x00, 0x00];
        assert!(PyarmorTrailer::parse(&trailer).is_none());
        let trailer_with_short_entry: Vec<u8> =
            vec![TRAILER_BIT_NINE_PRO_STAGE_2, 0x01, 0x00, 0x00, 0xC0];
        assert!(PyarmorTrailer::parse(&trailer_with_short_entry).is_none());
    }

    #[test]
    fn trailer_without_nine_pro_bit_has_empty_stage_2() {
        let trailer: Vec<u8> = vec![0x00, 0x00, 0x00, 0x00];
        let parsed: PyarmorTrailer = PyarmorTrailer::parse(&trailer).expect("parses");
        assert!(!parsed.nine_pro_stage_2);
        assert!(parsed.stage_2_consts_indices.is_empty());
    }

    #[test]
    fn stage_2_decrypt_is_symmetric_on_bindless_blob() {
        let key: [u8; 16] = [0x42u8; 16];
        let nonce: [u8; 12] = [0x01u8; 12];
        let plaintext: Vec<u8> = b"hello-nine-pro-stage-2-body-xx".to_vec();
        let encrypted: Vec<u8> = stage_2_decrypt(&key, &nonce, &plaintext).expect("encrypts");
        let decrypted: Vec<u8> = stage_2_decrypt(&key, &nonce, &encrypted).expect("decrypts");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn is_bindless_stage_2_recognizes_sentinel_bytes() {
        assert!(is_bindless_stage_2(0x00));
        assert!(is_bindless_stage_2(0xFF));
        assert!(!is_bindless_stage_2(0x01));
        assert!(!is_bindless_stage_2(0x80));
    }

    #[test]
    fn apply_nine_pro_stage_2_records_bind_required_when_flag_nonzero() {
        let module_state: PyarmorModuleState = make_state();
        let mut co: disrobe_py_marshal::CodeObject =
            disrobe_py_marshal::CodeObject::new(disrobe_py_marshal::CodeEra::Py311Plus);
        co.flags = CO_PYARMOR_OBFUSCATED;
        co.pyarmor_trailer = vec![TRAILER_BIT_NINE_PRO_STAGE_2, 0x01, 0x00, 0x00, 0x02, 0x00];
        let mut blob: Vec<u8> = vec![0u8; 32];
        blob[0] = 0x01;
        blob[4..8].copy_from_slice(&16u32.to_le_bytes());
        co.consts.push(disrobe_py_marshal::Object::Bytes(blob));
        let trailer: PyarmorTrailer = PyarmorTrailer::parse(&co.pyarmor_trailer).unwrap();
        let mut metrics: DecryptionStats = DecryptionStats::default();
        apply_nine_pro_stage_2(&mut co, &trailer, &module_state, &mut metrics);
        assert_eq!(metrics.nine_pro_stage_2_segments_found, 1);
        assert_eq!(metrics.nine_pro_stage_2_bind_required, 1);
        assert_eq!(metrics.nine_pro_stage_2_segments_unwrapped, 0);
    }

    fn build_nested_code(depth: usize) -> disrobe_py_marshal::Object {
        let mut current: disrobe_py_marshal::Object = disrobe_py_marshal::Object::Code(Box::new(
            disrobe_py_marshal::CodeObject::new(disrobe_py_marshal::CodeEra::Py311Plus),
        ));
        for _ in 0..depth {
            let mut outer: disrobe_py_marshal::CodeObject =
                disrobe_py_marshal::CodeObject::new(disrobe_py_marshal::CodeEra::Py311Plus);
            outer.consts.push(current);
            current = disrobe_py_marshal::Object::Code(Box::new(outer));
        }
        current
    }

    fn drop_nested_code(mut obj: disrobe_py_marshal::Object) {
        while let disrobe_py_marshal::Object::Code(mut co) = obj {
            let inner: Option<disrobe_py_marshal::Object> = co
                .consts
                .iter()
                .position(|c| matches!(c, disrobe_py_marshal::Object::Code(_)))
                .map(|i| co.consts.swap_remove(i));
            match inner {
                Some(next) => obj = next,
                None => return,
            }
        }
    }

    #[test]
    fn decrypt_module_bounds_recursion_on_deeply_nested_code_objects() {
        let module_state: PyarmorModuleState = make_state();
        let mut nested: disrobe_py_marshal::Object = build_nested_code(8192);
        let metrics: DecryptionStats = decrypt_module(&mut nested, &module_state);
        assert_eq!(metrics.depth_limit_truncations, 1);
        assert_eq!(metrics.objects_visited, MAX_CODE_OBJECT_DEPTH);
        drop_nested_code(nested);
    }

    #[test]
    fn decrypt_module_recovers_shallow_nested_code_objects() {
        let module_state: PyarmorModuleState = make_state();
        let mut shallow: disrobe_py_marshal::Object = build_nested_code(4);
        let metrics: DecryptionStats = decrypt_module(&mut shallow, &module_state);
        assert_eq!(metrics.depth_limit_truncations, 0);
        assert_eq!(metrics.objects_visited, 5);
        drop_nested_code(shallow);
    }

    #[test]
    fn decrypt_module_with_cache_records_hits_on_duplicate_trailer() {
        let module_state: PyarmorModuleState = make_state();
        let payload: [u8; 16] = [0xDDu8; 16];
        let mut cache: DescriptorCache = DescriptorCache::with_default_config();

        let mut co_one: disrobe_py_marshal::CodeObject = make_code_object_with_descriptor(&payload);
        let mut obj_one: disrobe_py_marshal::Object =
            disrobe_py_marshal::Object::Code(Box::new(co_one.clone()));
        let _ = decrypt_module_with_cache(&mut obj_one, &module_state, &mut cache);

        co_one = make_code_object_with_descriptor(&payload);
        let mut obj_two: disrobe_py_marshal::Object =
            disrobe_py_marshal::Object::Code(Box::new(co_one));
        let metrics: DecryptionStats =
            decrypt_module_with_cache(&mut obj_two, &module_state, &mut cache);
        assert!(metrics.cache_hits + metrics.cache_misses >= metrics.descriptors_applied);
    }
}
