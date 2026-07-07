use std::io::{Read as _, Write as _};

use crate::debug::{dbg_kv, dbg_kv_guarded, dbg_line, dbg_section};
use crate::error::{Error, Result};
use crate::obfuscator::{DeobfOptions, LuaObfuscatorKind, ObfuscatorDetection, PeelResult};
use crate::reader::common::{
    LUA_SIGNATURE, LUAC_DATA_TAIL, LuaChunk, LuaConstant, LuaDialect, LuaLocal, LuaProto,
    LuaUpvalueName,
};
use crate::serialize::serialize_chunk;

pub const SLUA_DECOY_HEADER_LEN: usize = 32;
pub const SLUA_DECOY_MAGIC: &[u8; 8] = b"UnityFS\x00";
pub const SLUA_ARCHIVE_MAGIC: &[u8; 4] = b"SLUA";
pub const LUA53_OPCODE_COUNT: usize = 47;
pub const LUA51_OPCODE_COUNT: usize = 38;
pub const LUA52_OPCODE_COUNT: usize = 40;

#[must_use]
pub const fn opcode_count_for(dialect: LuaDialect) -> usize {
    match dialect {
        LuaDialect::Lua51 => LUA51_OPCODE_COUNT,
        LuaDialect::Lua52 => LUA52_OPCODE_COUNT,
        _ => LUA53_OPCODE_COUNT,
    }
}

const LCG_MULTIPLIER: u64 = 1_664_525;
const LCG_INCREMENT: u64 = 1_013_904_223;

const COMPRESSION_NONE: u8 = 0;
const COMPRESSION_ZLIB: u8 = 1;
const COMPRESSION_BROTLI: u8 = 2;

const KEY_MODE_EMBEDDED: u8 = 1;
const KEY_MODE_EXTERNAL: u8 = 2;

const MAX_DECOMPRESSED: usize = 64 * 1024 * 1024;
const MAX_PROTO_DEPTH: usize = 200;
const MAX_SLUA_CODE_COUNT: usize = 1 << 20;
const MAX_SLUA_CONSTANT_COUNT: usize = 1 << 20;
const MAX_SLUA_UPVALUE_COUNT: usize = 1 << 16;
const MAX_SLUA_PROTO_COUNT: usize = 1 << 16;
const MAX_SLUA_LINE_COUNT: usize = 1 << 20;
const MAX_SLUA_LOCAL_COUNT: usize = 1 << 20;
const MAX_SLUA_UPVALUE_NAME_COUNT: usize = 1 << 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SluaCompression {
    None,
    Zlib,
    Brotli,
}

impl SluaCompression {
    const fn code(self) -> u8 {
        match self {
            Self::None => COMPRESSION_NONE,
            Self::Zlib => COMPRESSION_ZLIB,
            Self::Brotli => COMPRESSION_BROTLI,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            COMPRESSION_NONE => Some(Self::None),
            COMPRESSION_ZLIB => Some(Self::Zlib),
            COMPRESSION_BROTLI => Some(Self::Brotli),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SluaParams {
    pub seed: u64,
    pub perm: [u8; LUA53_OPCODE_COUNT],
    pub dialect: LuaDialect,
    perm_inv: [u8; LUA53_OPCODE_COUNT],
    active_count: usize,
}

impl SluaParams {
    pub fn new(seed: u64, perm: [u8; LUA53_OPCODE_COUNT]) -> Result<Self> {
        Self::new_for(LuaDialect::Lua53, seed, perm)
    }

    pub fn new_for(dialect: LuaDialect, seed: u64, perm: [u8; LUA53_OPCODE_COUNT]) -> Result<Self> {
        let active_count: usize = opcode_count_for(dialect);
        let mut perm_inv: [u8; LUA53_OPCODE_COUNT] = [0u8; LUA53_OPCODE_COUNT];
        let mut seen: [bool; LUA53_OPCODE_COUNT] = [false; LUA53_OPCODE_COUNT];
        for (index, &mapped) in perm.iter().enumerate().take(active_count) {
            let slot: usize = mapped as usize;
            if slot >= active_count || seen[slot] {
                return Err(Error::DecompileUnsupported(
                    "slua: opcode permutation table is not a bijection over the dialect opcode range",
                ));
            }
            seen[slot] = true;
            perm_inv[slot] = index as u8;
        }
        for (index, slot) in perm_inv.iter_mut().enumerate().skip(active_count) {
            *slot = index as u8;
        }
        Ok(Self {
            seed,
            perm,
            dialect,
            perm_inv,
            active_count,
        })
    }

    #[must_use]
    pub fn seed_derived(seed: u64) -> Self {
        Self::seed_derived_for(LuaDialect::Lua53, seed)
    }

    #[must_use]
    pub fn seed_derived_for(dialect: LuaDialect, seed: u64) -> Self {
        let active_count: usize = opcode_count_for(dialect);
        let mut perm: [u8; LUA53_OPCODE_COUNT] = identity_perm();
        let mut state: u64 = seed ^ 0x9E37_79B9_7F4A_7C15;
        let mut i: usize = active_count - 1;
        while i > 0 {
            state = state
                .wrapping_mul(LCG_MULTIPLIER)
                .wrapping_add(LCG_INCREMENT);
            let j: usize = (state >> 24) as usize % (i + 1);
            perm.swap(i, j);
            i -= 1;
        }
        Self::new_for(dialect, seed, perm).unwrap_or(Self {
            seed,
            perm: identity_perm(),
            dialect,
            perm_inv: identity_perm(),
            active_count,
        })
    }

    fn rotation(&self) -> u32 {
        (self.seed % self.active_count as u64) as u32
    }

    const fn tag_mask(&self) -> u8 {
        (self.seed & 0xFF) as u8
    }

    const fn len_mask(&self) -> u8 {
        ((self.seed >> 8) & 0xFF) as u8
    }

    fn obfuscate_opcode(&self, op: u8) -> u8 {
        if op as usize >= self.active_count {
            return op;
        }
        let permuted: u32 = u32::from(self.perm[op as usize]);
        ((permuted + self.rotation()) % self.active_count as u32) as u8
    }

    fn deobfuscate_opcode(&self, stored: u8) -> Option<u8> {
        if stored as usize >= self.active_count {
            return Some(stored);
        }
        let modulus: u32 = self.active_count as u32;
        let permuted: u32 = (u32::from(stored) + modulus - self.rotation() % modulus) % modulus;
        self.perm_inv.get(permuted as usize).copied()
    }
}

#[must_use]
const fn identity_perm() -> [u8; LUA53_OPCODE_COUNT] {
    let mut perm: [u8; LUA53_OPCODE_COUNT] = [0u8; LUA53_OPCODE_COUNT];
    let mut i: usize = 0;
    while i < LUA53_OPCODE_COUNT {
        perm[i] = i as u8;
        i += 1;
    }
    perm
}

#[must_use]
pub fn lcg_keystream(seed: u64, len: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(len);
    let mut state: u64 = seed;
    for _ in 0..len {
        state = state
            .wrapping_mul(LCG_MULTIPLIER)
            .wrapping_add(LCG_INCREMENT);
        out.push((state >> 24) as u8);
    }
    out
}

fn lcg_xor(seed: u64, data: &mut [u8]) {
    let mut state: u64 = seed;
    for byte in data {
        state = state
            .wrapping_mul(LCG_MULTIPLIER)
            .wrapping_add(LCG_INCREMENT);
        *byte ^= (state >> 24) as u8;
    }
}

fn zlib_compress(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder: flate2::write::ZlibEncoder<Vec<u8>> =
        flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(data)
        .map_err(|e| Error::Io(std::io::Error::other(format!("slua zlib write: {e}"))))?;
    encoder
        .finish()
        .map_err(|e| Error::Io(std::io::Error::other(format!("slua zlib finish: {e}"))))
}

fn zlib_decompress(data: &[u8]) -> Result<Vec<u8>> {
    zlib_decompress_capped(data, MAX_DECOMPRESSED)
}

fn zlib_decompress_capped(data: &[u8], limit: usize) -> Result<Vec<u8>> {
    let decoder: flate2::read::ZlibDecoder<&[u8]> = flate2::read::ZlibDecoder::new(data);
    let mut out: Vec<u8> = Vec::new();
    let take_limit: u64 = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    decoder
        .take(take_limit)
        .read_to_end(&mut out)
        .map_err(|e| Error::Io(std::io::Error::other(format!("slua zlib inflate: {e}"))))?;
    if out.len() > limit {
        return Err(Error::Io(std::io::Error::other(
            "slua zlib payload exceeds decompression cap",
        )));
    }
    Ok(out)
}

struct CappedSink {
    buf: Vec<u8>,
    limit: usize,
}

impl std::io::Write for CappedSink {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.buf.len().saturating_add(data.len()) > self.limit {
            return Err(std::io::Error::other(
                "slua: brotli payload exceeds decompression cap",
            ));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn brotli_decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut input: &[u8] = data;
    let mut sink: CappedSink = CappedSink {
        buf: Vec::new(),
        limit: MAX_DECOMPRESSED,
    };
    brotli_decompressor::BrotliDecompress(&mut input, &mut sink).map_err(|e| {
        Error::Io(std::io::Error::other(format!(
            "slua brotli decompress: {e}"
        )))
    })?;
    Ok(sink.buf)
}

fn compress(compression: SluaCompression, data: &[u8]) -> Result<Vec<u8>> {
    match compression {
        SluaCompression::None => Ok(data.to_vec()),
        SluaCompression::Zlib => zlib_compress(data),
        SluaCompression::Brotli => Err(Error::DecompileUnsupported(
            "slua: brotli compression is a recovery-only codec in disrobe (decode is supported); use none or zlib to author a fixture",
        )),
    }
}

fn decompress(compression: SluaCompression, data: &[u8]) -> Result<Vec<u8>> {
    dbg_kv("slua.decompress.codec", || format!("{compression:?}"));
    dbg_kv("slua.decompress.input_len", || data.len().to_string());
    match compression {
        SluaCompression::None => Ok(data.to_vec()),
        SluaCompression::Zlib => zlib_decompress(data),
        SluaCompression::Brotli => {
            dbg_kv("slua.decompress.cap_bytes", || MAX_DECOMPRESSED.to_string());
            brotli_decompress(data)
        }
    }
}

struct ObfWriter {
    out: Vec<u8>,
    little_endian: bool,
    const_xor_index: usize,
}

impl ObfWriter {
    fn new(little_endian: bool) -> Self {
        Self {
            out: Vec::new(),
            little_endian,
            const_xor_index: 0,
        }
    }

    fn key_byte(seed: u64, index: usize) -> u8 {
        seed.to_le_bytes()[index % 8]
    }

    fn push(&mut self, byte: u8) {
        self.out.push(byte);
    }

    fn write_size_plain(&mut self, value: u64, size_bytes: u8) {
        match size_bytes {
            8 => {
                if self.little_endian {
                    self.out.extend_from_slice(&value.to_le_bytes());
                } else {
                    self.out.extend_from_slice(&value.to_be_bytes());
                }
            }
            _ => {
                let narrowed: u32 = (value & 0xFFFF_FFFF) as u32;
                if self.little_endian {
                    self.out.extend_from_slice(&narrowed.to_le_bytes());
                } else {
                    self.out.extend_from_slice(&narrowed.to_be_bytes());
                }
            }
        }
    }

    fn write_value_bytes_xored(&mut self, seed: u64, bytes: &[u8]) {
        for &byte in bytes {
            let masked: u8 = byte ^ Self::key_byte(seed, self.const_xor_index);
            self.const_xor_index += 1;
            self.out.push(masked);
        }
    }
}

fn read_clean(dialect: LuaDialect, clean_luac: &[u8]) -> Result<LuaChunk> {
    match dialect {
        LuaDialect::Lua51 => crate::reader::lua51::read(clean_luac),
        LuaDialect::Lua52 => crate::reader::lua52::read(clean_luac),
        LuaDialect::Lua53 => crate::reader::lua53::read(clean_luac),
        _ => Err(Error::DecompileUnsupported(
            "slua: only Lua 5.1, 5.2 and 5.3 bytecode are supported by this scheme",
        )),
    }
}

pub fn obfuscate_bytecode(clean_luac: &[u8], params: &SluaParams) -> Result<Vec<u8>> {
    let chunk: LuaChunk = read_clean(params.dialect, clean_luac)?;
    if chunk.dialect != params.dialect {
        return Err(Error::DecompileUnsupported(
            "slua: clean bytecode dialect does not match the params dialect",
        ));
    }
    let mut w: ObfWriter = ObfWriter::new(chunk.little_endian);
    w.out.extend_from_slice(&LUA_SIGNATURE);
    w.push(chunk.version_byte);
    w.push(chunk.format);
    if matches!(chunk.dialect, LuaDialect::Lua53) {
        w.out.extend_from_slice(&LUAC_DATA_TAIL);
        w.push(chunk.size_of_int);
        w.push(chunk.size_of_size_t);
        w.push(chunk.size_of_instruction);
        w.push(chunk.size_of_lua_integer);
        w.push(chunk.size_of_lua_number);
        w.write_size_plain(0x5678, chunk.size_of_lua_integer);
        if chunk.size_of_lua_number == 8 {
            let bits: u64 = 370.5_f64.to_bits();
            w.write_size_plain(bits, 8);
        } else {
            let bits: u32 = (370.5_f32).to_bits();
            w.write_size_plain(u64::from(bits), 4);
        }
        w.push(1);
    } else {
        w.push(u8::from(chunk.little_endian));
        w.push(chunk.size_of_int);
        w.push(chunk.size_of_size_t);
        w.push(chunk.size_of_instruction);
        w.push(chunk.size_of_lua_number);
        w.push(u8::from(chunk.integral_number));
        if matches!(chunk.dialect, LuaDialect::Lua52) {
            w.out.extend_from_slice(&LUAC_DATA_TAIL);
        }
    }
    obf_write_proto(&mut w, &chunk.main, &chunk, params, 0)?;
    Ok(w.out)
}

fn obf_write_string(w: &mut ObfWriter, params: &SluaParams, value: Option<&str>, size_size_t: u8) {
    let Some(text) = value else {
        w.push(params.len_mask());
        return;
    };
    let stored_len: u64 = text.len() as u64 + 1;
    if stored_len < 0xFF {
        w.push((stored_len as u8) ^ params.len_mask());
    } else {
        w.push(0xFF ^ params.len_mask());
        let mut buf: Vec<u8> = Vec::new();
        match size_size_t {
            8 => buf.extend_from_slice(&stored_len.to_le_bytes()),
            _ => buf.extend_from_slice(&((stored_len & 0xFFFF_FFFF) as u32).to_le_bytes()),
        }
        for byte in &mut buf {
            *byte ^= params.len_mask();
        }
        w.out.extend_from_slice(&buf);
    }
    w.write_value_bytes_xored(params.seed, text.as_bytes());
}

fn obf_write_proto(
    w: &mut ObfWriter,
    proto: &LuaProto,
    chunk: &LuaChunk,
    params: &SluaParams,
    depth: usize,
) -> Result<()> {
    if depth > MAX_PROTO_DEPTH {
        return Err(Error::ProtoNestingTooDeep(depth));
    }
    w.const_xor_index = 0;
    obf_write_string(w, params, proto.source.as_deref(), chunk.size_of_size_t);
    w.write_size_plain(u64::from(proto.line_defined), chunk.size_of_int);
    w.write_size_plain(u64::from(proto.last_line_defined), chunk.size_of_int);
    w.push(proto.num_params);
    w.push(proto.is_vararg);
    w.push(proto.max_stack_size);

    w.write_size_plain(proto.code.len() as u64, chunk.size_of_int);
    for instruction in &proto.code {
        let op: u8 = (*instruction & 0x3F) as u8;
        if op as usize >= LUA53_OPCODE_COUNT {
            return Err(Error::DecompileUnsupported(
                "slua: instruction opcode out of Lua 5.3 range",
            ));
        }
        let obf_op: u8 = params.obfuscate_opcode(op);
        let rewritten: u32 = (*instruction & !0x3F) | u32::from(obf_op);
        w.write_size_plain(u64::from(rewritten), chunk.size_of_instruction);
    }

    w.write_size_plain(proto.constants.len() as u64, chunk.size_of_int);
    for constant in &proto.constants {
        obf_write_constant(w, constant, chunk, params);
    }

    w.write_size_plain(proto.upvalues.len() as u64, chunk.size_of_int);
    for _ in &proto.upvalues {
        w.push(0);
        w.push(0);
    }

    w.write_size_plain(proto.protos.len() as u64, chunk.size_of_int);
    for sub in &proto.protos {
        obf_write_proto(w, sub, chunk, params, depth + 1)?;
    }

    w.write_size_plain(proto.source_lines.len() as u64, chunk.size_of_int);
    for line in &proto.source_lines {
        w.write_size_plain(u64::from(*line), chunk.size_of_int);
    }

    w.write_size_plain(proto.locals.len() as u64, chunk.size_of_int);
    for local in &proto.locals {
        obf_write_string(w, params, Some(&local.name), chunk.size_of_size_t);
        w.write_size_plain(u64::from(local.start_pc), chunk.size_of_int);
        w.write_size_plain(u64::from(local.end_pc), chunk.size_of_int);
    }

    w.write_size_plain(proto.upvalues.len() as u64, chunk.size_of_int);
    for upvalue in &proto.upvalues {
        obf_write_string(w, params, Some(&upvalue.name), chunk.size_of_size_t);
    }
    Ok(())
}

fn obf_write_constant(
    w: &mut ObfWriter,
    constant: &LuaConstant,
    chunk: &LuaChunk,
    params: &SluaParams,
) {
    match constant {
        LuaConstant::Nil => w.push(params.tag_mask()),
        LuaConstant::Bool(value) => {
            w.push(0x01 ^ params.tag_mask());
            w.write_value_bytes_xored(params.seed, &[u8::from(*value)]);
        }
        LuaConstant::Number(value) => {
            w.push(0x03 ^ params.tag_mask());
            if chunk.size_of_lua_number == 8 {
                w.write_value_bytes_xored(params.seed, &value.to_bits().to_le_bytes());
            } else {
                w.write_value_bytes_xored(params.seed, &(*value as f32).to_bits().to_le_bytes());
            }
        }
        LuaConstant::Integer(value) => {
            w.push(0x13 ^ params.tag_mask());
            if chunk.size_of_lua_integer == 8 {
                w.write_value_bytes_xored(params.seed, &(*value as u64).to_le_bytes());
            } else {
                w.write_value_bytes_xored(
                    params.seed,
                    &((*value as u64 & 0xFFFF_FFFF) as u32).to_le_bytes(),
                );
            }
        }
        LuaConstant::Str(text) => {
            let tag: u8 = if text.len() + 1 < 0xFF { 0x04 } else { 0x14 };
            w.push(tag ^ params.tag_mask());
            obf_write_string(w, params, Some(text), chunk.size_of_size_t);
        }
        LuaConstant::ClosureRef(_) | LuaConstant::Import(_) | LuaConstant::Vector(_) => {
            w.push(params.tag_mask());
        }
    }
}

struct ObfReader<'a> {
    bytes: &'a [u8],
    pos: usize,
    little_endian: bool,
    const_xor_index: usize,
}

impl<'a> ObfReader<'a> {
    const fn new(bytes: &'a [u8], little_endian: bool) -> Self {
        Self {
            bytes,
            pos: 0,
            little_endian,
            const_xor_index: 0,
        }
    }

    fn key_byte(seed: u64, index: usize) -> u8 {
        seed.to_le_bytes()[index % 8]
    }

    fn read_u8(&mut self) -> Result<u8> {
        let byte: u8 = *self.bytes.get(self.pos).ok_or(Error::Truncated {
            offset: self.pos,
            needed: 1,
            had: 0,
        })?;
        self.pos += 1;
        Ok(byte)
    }

    fn read_raw(&mut self, n: usize) -> Result<&'a [u8]> {
        let end: usize = self.pos.checked_add(n).ok_or(Error::Truncated {
            offset: self.pos,
            needed: n,
            had: self.bytes.len().saturating_sub(self.pos),
        })?;
        let slice: &[u8] = self.bytes.get(self.pos..end).ok_or(Error::Truncated {
            offset: self.pos,
            needed: n,
            had: self.bytes.len().saturating_sub(self.pos),
        })?;
        self.pos = end;
        Ok(slice)
    }

    fn read_size_plain(&mut self, size_bytes: u8) -> Result<u64> {
        match size_bytes {
            8 => {
                let arr: [u8; 8] = self.read_array::<8>()?;
                Ok(if self.little_endian {
                    u64::from_le_bytes(arr)
                } else {
                    u64::from_be_bytes(arr)
                })
            }
            4 => {
                let arr: [u8; 4] = self.read_array::<4>()?;
                Ok(u64::from(if self.little_endian {
                    u32::from_le_bytes(arr)
                } else {
                    u32::from_be_bytes(arr)
                }))
            }
            other => Err(Error::BadIntSize(other)),
        }
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let slice: &[u8] = self.read_raw(N)?;
        slice.try_into().map_err(|_| Error::Truncated {
            offset: self.pos.saturating_sub(N),
            needed: N,
            had: slice.len(),
        })
    }

    fn read_masked_array<const N: usize>(&mut self, mask: u8) -> Result<[u8; N]> {
        let mut arr: [u8; N] = self.read_array::<N>()?;
        for byte in &mut arr {
            *byte ^= mask;
        }
        Ok(arr)
    }

    fn read_value_bytes_xored(&mut self, seed: u64, n: usize) -> Result<Vec<u8>> {
        let slice: &[u8] = self.read_raw(n)?;
        let mut out: Vec<u8> = Vec::with_capacity(n);
        for &byte in slice {
            out.push(byte ^ Self::key_byte(seed, self.const_xor_index));
            self.const_xor_index += 1;
        }
        Ok(out)
    }

    fn read_value_array_xored<const N: usize>(&mut self, seed: u64) -> Result<[u8; N]> {
        let slice: &[u8] = self.read_raw(N)?;
        let mut out: [u8; N] = [0u8; N];
        for (index, byte) in slice.iter().enumerate() {
            out[index] = *byte ^ Self::key_byte(seed, self.const_xor_index);
            self.const_xor_index += 1;
        }
        Ok(out)
    }
}

pub fn deobfuscate_bytecode(obf: &[u8], params: &SluaParams) -> Result<Vec<u8>> {
    let chunk: LuaChunk = parse_obfuscated(obf, params)?;
    serialize_chunk(&chunk)
}

fn parse_obfuscated(bytes: &[u8], params: &SluaParams) -> Result<LuaChunk> {
    let mut r: ObfReader<'_> = ObfReader::new(bytes, true);
    let signature: &[u8] = r.read_raw(4)?;
    if signature != LUA_SIGNATURE {
        return Err(Error::BadSignature);
    }
    let version: u8 = r.read_u8()?;
    let expected_version: u8 = params.dialect.version_byte().unwrap_or(0x53);
    if version != expected_version {
        return Err(Error::UnsupportedLuaVersion(version));
    }
    let format: u8 = r.read_u8()?;
    let mut size_lua_integer: u8 = 0;
    let mut integral_number: bool = false;
    let (size_int, size_size_t, size_instr, size_lua_number): (u8, u8, u8, u8) =
        if matches!(params.dialect, LuaDialect::Lua53) {
            let tail: &[u8] = r.read_raw(6)?;
            if tail != LUAC_DATA_TAIL {
                return Err(Error::BadLuacData(r.pos.saturating_sub(6)));
            }
            let size_int: u8 = r.read_u8()?;
            let size_size_t: u8 = r.read_u8()?;
            let size_instr: u8 = r.read_u8()?;
            size_lua_integer = r.read_u8()?;
            let size_lua_number: u8 = r.read_u8()?;
            let _int_check: u64 = r.read_size_plain(size_lua_integer)?;
            if size_lua_number == 8 {
                let _num_check: u64 = r.read_size_plain(8)?;
            } else {
                let _num_check: u64 = r.read_size_plain(4)?;
            }
            let _upval_size: u8 = r.read_u8()?;
            (size_int, size_size_t, size_instr, size_lua_number)
        } else {
            let _endian: u8 = r.read_u8()?;
            let size_int: u8 = r.read_u8()?;
            let size_size_t: u8 = r.read_u8()?;
            let size_instr: u8 = r.read_u8()?;
            let size_lua_number: u8 = r.read_u8()?;
            integral_number = r.read_u8()? != 0;
            if matches!(params.dialect, LuaDialect::Lua52) {
                let tail: &[u8] = r.read_raw(6)?;
                if tail != LUAC_DATA_TAIL {
                    return Err(Error::BadLuacData(r.pos.saturating_sub(6)));
                }
            }
            (size_int, size_size_t, size_instr, size_lua_number)
        };
    let main: LuaProto = obf_read_proto(
        &mut r,
        params,
        size_int,
        size_size_t,
        size_instr,
        size_lua_integer,
        size_lua_number,
        0,
    )?;
    Ok(LuaChunk {
        dialect: params.dialect,
        version_byte: expected_version,
        format,
        little_endian: true,
        size_of_int: size_int,
        size_of_size_t: size_size_t,
        size_of_instruction: size_instr,
        size_of_lua_integer: size_lua_integer,
        size_of_lua_number: size_lua_number,
        integral_number,
        main,
    })
}

fn obf_read_string(
    r: &mut ObfReader<'_>,
    params: &SluaParams,
    size_size_t: u8,
) -> Result<Option<String>> {
    let first: u8 = r.read_u8()? ^ params.len_mask();
    let len: u64 = if first == 0xFF {
        match size_size_t {
            8 => u64::from_le_bytes(r.read_masked_array::<8>(params.len_mask())?),
            4 => u64::from(u32::from_le_bytes(
                r.read_masked_array::<4>(params.len_mask())?,
            )),
            other => return Err(Error::BadIntSize(other)),
        }
    } else {
        u64::from(first)
    };
    if len == 0 {
        return Ok(None);
    }
    let raw_len: usize = checked_payload_len(len.saturating_sub(1), "slua string")?;
    let bytes: Vec<u8> = r.read_value_bytes_xored(params.seed, raw_len)?;
    let text: String = String::from_utf8_lossy(&bytes).into_owned();
    Ok(Some(text))
}

#[allow(clippy::too_many_arguments)]
fn obf_read_proto(
    r: &mut ObfReader<'_>,
    params: &SluaParams,
    size_int: u8,
    size_size_t: u8,
    size_instr: u8,
    size_lua_integer: u8,
    size_lua_number: u8,
    depth: usize,
) -> Result<LuaProto> {
    if depth > MAX_PROTO_DEPTH {
        return Err(Error::ProtoNestingTooDeep(depth));
    }
    r.const_xor_index = 0;
    let source: Option<String> = obf_read_string(r, params, size_size_t)?;
    let line_defined: u32 = checked_u32(r.read_size_plain(size_int)?, "slua line_defined")?;
    let last_line_defined: u32 =
        checked_u32(r.read_size_plain(size_int)?, "slua last_line_defined")?;
    let num_params: u8 = r.read_u8()?;
    let is_vararg: u8 = r.read_u8()?;
    let max_stack_size: u8 = r.read_u8()?;

    let code_len: u64 = r.read_size_plain(size_int)?;
    let code_count: usize = checked_count(
        code_len,
        MAX_SLUA_CODE_COUNT,
        "slua code",
        r,
        usize::from(size_instr),
    )?;
    let mut code: Vec<u32> = Vec::with_capacity(code_count);
    for _ in 0..code_count {
        let raw: u32 = checked_u32(r.read_size_plain(size_instr)?, "slua instruction")?;
        let stored_op: u8 = (raw & 0x3F) as u8;
        let clean_op: u8 =
            params
                .deobfuscate_opcode(stored_op)
                .ok_or(Error::DecompileUnsupported(
                    "slua: stored opcode falls outside the permutation table",
                ))?;
        code.push((raw & !0x3F) | u32::from(clean_op));
    }

    let const_count: u64 = r.read_size_plain(size_int)?;
    let constant_count: usize =
        checked_count(const_count, MAX_SLUA_CONSTANT_COUNT, "slua constants", r, 1)?;
    let mut constants: Vec<LuaConstant> = Vec::with_capacity(constant_count);
    for _ in 0..constant_count {
        constants.push(obf_read_constant(
            r,
            params,
            size_size_t,
            size_lua_integer,
            size_lua_number,
        )?);
    }

    let upval_count: u64 = r.read_size_plain(size_int)?;
    let upvalue_count: usize =
        checked_count(upval_count, MAX_SLUA_UPVALUE_COUNT, "slua upvalues", r, 2)?;
    let mut upvalues: Vec<LuaUpvalueName> = Vec::with_capacity(upvalue_count);
    for _ in 0..upvalue_count {
        let _in_stack: u8 = r.read_u8()?;
        let _idx: u8 = r.read_u8()?;
        upvalues.push(LuaUpvalueName {
            name: String::new(),
        });
    }

    let proto_count: u64 = r.read_size_plain(size_int)?;
    let child_proto_count: usize =
        checked_count(proto_count, MAX_SLUA_PROTO_COUNT, "slua child protos", r, 1)?;
    let mut protos: Vec<LuaProto> = Vec::with_capacity(child_proto_count);
    for _ in 0..child_proto_count {
        protos.push(obf_read_proto(
            r,
            params,
            size_int,
            size_size_t,
            size_instr,
            size_lua_integer,
            size_lua_number,
            depth + 1,
        )?);
    }

    let line_count: u64 = r.read_size_plain(size_int)?;
    let source_line_count: usize = checked_count(
        line_count,
        MAX_SLUA_LINE_COUNT,
        "slua source lines",
        r,
        usize::from(size_int),
    )?;
    let mut source_lines: Vec<u32> = Vec::with_capacity(source_line_count);
    for _ in 0..source_line_count {
        source_lines.push(checked_u32(
            r.read_size_plain(size_int)?,
            "slua source line",
        )?);
    }

    let local_count: u64 = r.read_size_plain(size_int)?;
    let local_min_width: usize = usize::from(size_int)
        .checked_mul(2)
        .and_then(|pc_bytes: usize| pc_bytes.checked_add(1))
        .ok_or(Error::LimitExceeded {
            section: "slua locals",
            count: local_count,
            limit: MAX_SLUA_LOCAL_COUNT,
        })?;
    let parsed_local_count: usize = checked_count(
        local_count,
        MAX_SLUA_LOCAL_COUNT,
        "slua locals",
        r,
        local_min_width,
    )?;
    let mut locals: Vec<LuaLocal> = Vec::with_capacity(parsed_local_count);
    for _ in 0..parsed_local_count {
        let name: String = obf_read_string(r, params, size_size_t)?.unwrap_or_default();
        let start_pc: u32 = checked_u32(r.read_size_plain(size_int)?, "slua local start_pc")?;
        let end_pc: u32 = checked_u32(r.read_size_plain(size_int)?, "slua local end_pc")?;
        locals.push(LuaLocal {
            name,
            start_pc,
            end_pc,
        });
    }

    let upval_names: u64 = r.read_size_plain(size_int)?;
    let upvalue_name_count: usize = checked_count(
        upval_names,
        MAX_SLUA_UPVALUE_NAME_COUNT,
        "slua upvalue names",
        r,
        1,
    )?;
    for idx in 0..upvalue_name_count {
        let name: String = obf_read_string(r, params, size_size_t)?.unwrap_or_default();
        if idx < upvalues.len() {
            upvalues[idx].name = name;
        }
    }

    Ok(LuaProto {
        source,
        line_defined,
        last_line_defined,
        num_params,
        is_vararg,
        max_stack_size,
        code,
        constants,
        protos,
        source_lines,
        locals,
        upvalues,
    })
}

fn obf_read_constant(
    r: &mut ObfReader<'_>,
    params: &SluaParams,
    size_size_t: u8,
    size_lua_integer: u8,
    size_lua_number: u8,
) -> Result<LuaConstant> {
    let tag: u8 = r.read_u8()? ^ params.tag_mask();
    match tag {
        0x00 => Ok(LuaConstant::Nil),
        0x01 => {
            let value: [u8; 1] = r.read_value_array_xored::<1>(params.seed)?;
            Ok(LuaConstant::Bool(value[0] != 0))
        }
        0x03 => match size_lua_number {
            8 => {
                let bytes: [u8; 8] = r.read_value_array_xored::<8>(params.seed)?;
                Ok(LuaConstant::Number(f64::from_le_bytes(bytes)))
            }
            4 => {
                let bytes: [u8; 4] = r.read_value_array_xored::<4>(params.seed)?;
                let raw: u32 = u32::from_le_bytes(bytes);
                Ok(LuaConstant::Number(f64::from(f32::from_bits(raw))))
            }
            other => Err(Error::BadNumberSize(other)),
        },
        0x13 => match size_lua_integer {
            8 => {
                let bytes: [u8; 8] = r.read_value_array_xored::<8>(params.seed)?;
                Ok(LuaConstant::Integer(i64::from_le_bytes(bytes)))
            }
            4 => {
                let bytes: [u8; 4] = r.read_value_array_xored::<4>(params.seed)?;
                let raw: u32 = u32::from_le_bytes(bytes);
                Ok(LuaConstant::Integer(i64::from(raw as i32)))
            }
            other => Err(Error::BadIntSize(other)),
        },
        0x04 | 0x14 => Ok(obf_read_string(r, params, size_size_t)?
            .map_or(LuaConstant::Str(String::new()), LuaConstant::Str)),
        other => Err(Error::BadConstantTag(other, r.pos)),
    }
}

const U32_FIELD_LIMIT: usize = u32::MAX as usize;

fn checked_u32(value: u64, section: &'static str) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::LimitExceeded {
        section,
        count: value,
        limit: U32_FIELD_LIMIT,
    })
}

fn checked_payload_len(value: u64, section: &'static str) -> Result<usize> {
    usize::try_from(value).map_err(|_| Error::LimitExceeded {
        section,
        count: value,
        limit: usize::MAX,
    })
}

fn checked_count(
    count: u64,
    limit: usize,
    section: &'static str,
    r: &ObfReader<'_>,
    min_entry_width: usize,
) -> Result<usize> {
    let native: usize = usize::try_from(count).map_err(|_| Error::LimitExceeded {
        section,
        count,
        limit,
    })?;
    if native > limit {
        return Err(Error::LimitExceeded {
            section,
            count,
            limit,
        });
    }
    let min_bytes: usize = native
        .checked_mul(min_entry_width)
        .ok_or(Error::LimitExceeded {
            section,
            count,
            limit,
        })?;
    let remaining: usize = r.bytes.len().saturating_sub(r.pos);
    if min_bytes > remaining {
        return Err(Error::Truncated {
            offset: r.pos,
            needed: min_bytes,
            had: remaining,
        });
    }
    Ok(native)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SluaArchiveEntry {
    pub name: String,
    pub obfuscated_bytecode: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SluaArchive {
    pub seed: Option<u64>,
    pub perm: Option<[u8; LUA53_OPCODE_COUNT]>,
    pub dialect: LuaDialect,
    pub compression: SluaCompression,
    pub entries: Vec<SluaArchiveEntry>,
}

const fn dialect_code(dialect: LuaDialect) -> u8 {
    match dialect {
        LuaDialect::Lua51 => 0x51,
        LuaDialect::Lua52 => 0x52,
        _ => 0x53,
    }
}

const fn dialect_from_code(code: u8) -> Option<LuaDialect> {
    match code {
        0x51 => Some(LuaDialect::Lua51),
        0x52 => Some(LuaDialect::Lua52),
        0x53 => Some(LuaDialect::Lua53),
        _ => None,
    }
}

pub fn build_archive(
    params: &SluaParams,
    embed_key: bool,
    compression: SluaCompression,
    entries: &[(String, Vec<u8>)],
) -> Result<Vec<u8>> {
    let mut archive: Vec<u8> = Vec::new();
    archive.extend_from_slice(SLUA_ARCHIVE_MAGIC);
    archive.push(dialect_code(params.dialect));
    if embed_key {
        archive.push(KEY_MODE_EMBEDDED);
        archive.extend_from_slice(&params.seed.to_le_bytes());
        archive.extend_from_slice(&params.perm);
    } else {
        archive.push(KEY_MODE_EXTERNAL);
    }
    archive.push(compression.code());
    let entry_count: u32 = u32::try_from(entries.len())
        .map_err(|_| Error::IntegrityViolated("slua: too many entries to encode"))?;
    archive.extend_from_slice(&entry_count.to_le_bytes());
    for (name, clean_bytecode) in entries {
        let obfuscated: Vec<u8> = obfuscate_bytecode(clean_bytecode, params)?;
        let mut payload: Vec<u8> = Vec::with_capacity(obfuscated.len() + 1);
        payload.push(compression.code());
        let compressed: Vec<u8> = compress(compression, &obfuscated)?;
        payload.extend_from_slice(&compressed);
        lcg_xor(params.seed, &mut payload);
        let name_len: u16 = u16::try_from(name.len())
            .map_err(|_| Error::IntegrityViolated("slua: entry name too long to encode"))?;
        archive.extend_from_slice(&name_len.to_le_bytes());
        archive.extend_from_slice(name.as_bytes());
        let payload_len: u32 = u32::try_from(payload.len())
            .map_err(|_| Error::IntegrityViolated("slua: entry payload too large to encode"))?;
        archive.extend_from_slice(&payload_len.to_le_bytes());
        archive.extend_from_slice(&payload);
    }

    let mut bundle: Vec<u8> = Vec::with_capacity(SLUA_DECOY_HEADER_LEN + archive.len());
    let mut decoy: [u8; SLUA_DECOY_HEADER_LEN] = [0u8; SLUA_DECOY_HEADER_LEN];
    decoy[..SLUA_DECOY_MAGIC.len()].copy_from_slice(SLUA_DECOY_MAGIC);
    decoy[8..12].copy_from_slice(&6u32.to_be_bytes());
    bundle.extend_from_slice(&decoy);
    bundle.extend_from_slice(&archive);
    Ok(bundle)
}

struct LeReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> LeReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn read_u8(&mut self) -> Result<u8> {
        let byte: u8 = *self.bytes.get(self.pos).ok_or(Error::Truncated {
            offset: self.pos,
            needed: 1,
            had: 0,
        })?;
        self.pos += 1;
        Ok(byte)
    }

    fn read_u16(&mut self) -> Result<u16> {
        let slice: &[u8] = self.read(2)?;
        Ok(u16::from_le_bytes([slice[0], slice[1]]))
    }

    fn read_u32(&mut self) -> Result<u32> {
        let slice: &[u8] = self.read(4)?;
        Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    }

    fn read_u64(&mut self) -> Result<u64> {
        let slice: &[u8] = self.read(8)?;
        Ok(u64::from_le_bytes([
            slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
        ]))
    }

    fn read(&mut self, n: usize) -> Result<&'a [u8]> {
        let end: usize = self.pos.checked_add(n).ok_or(Error::Truncated {
            offset: self.pos,
            needed: n,
            had: self.bytes.len().saturating_sub(self.pos),
        })?;
        let slice: &[u8] = self.bytes.get(self.pos..end).ok_or(Error::Truncated {
            offset: self.pos,
            needed: n,
            had: self.bytes.len().saturating_sub(self.pos),
        })?;
        self.pos = end;
        Ok(slice)
    }
}

pub fn parse_archive(payload: &[u8]) -> Result<SluaArchive> {
    if payload.len() < SLUA_DECOY_HEADER_LEN {
        return Err(Error::IntegrityViolated(
            "slua: payload smaller than decoy header",
        ));
    }
    let decoy: &[u8] = &payload[..SLUA_DECOY_HEADER_LEN];
    if &decoy[..SLUA_DECOY_MAGIC.len()] != SLUA_DECOY_MAGIC {
        return Err(Error::NoObfuscatorSignature(
            "slua: missing decoy `UnityFS` header",
        ));
    }
    let body: &[u8] = &payload[SLUA_DECOY_HEADER_LEN..];
    let mut r: LeReader<'_> = LeReader::new(body);
    let magic: &[u8] = r.read(4)?;
    if magic != SLUA_ARCHIVE_MAGIC {
        return Err(Error::NoObfuscatorSignature(
            "slua: missing `SLUA` archive magic after decoy header",
        ));
    }
    let dialect_byte: u8 = r.read_u8()?;
    let dialect: LuaDialect = dialect_from_code(dialect_byte)
        .ok_or(Error::DecompileUnsupported("slua: unknown dialect code"))?;
    let key_mode: u8 = r.read_u8()?;
    let (seed, perm): (Option<u64>, Option<[u8; LUA53_OPCODE_COUNT]>) = match key_mode {
        KEY_MODE_EMBEDDED => {
            let seed: u64 = r.read_u64()?;
            let perm_slice: &[u8] = r.read(LUA53_OPCODE_COUNT)?;
            let mut perm: [u8; LUA53_OPCODE_COUNT] = [0u8; LUA53_OPCODE_COUNT];
            perm.copy_from_slice(perm_slice);
            (Some(seed), Some(perm))
        }
        KEY_MODE_EXTERNAL => (None, None),
        other => {
            return Err(Error::BadConstantTag(other, r.pos));
        }
    };
    let compression_code: u8 = r.read_u8()?;
    let compression: SluaCompression = SluaCompression::from_code(compression_code).ok_or(
        Error::DecompileUnsupported("slua: unknown compression code"),
    )?;
    let entry_count: u32 = r.read_u32()?;
    if entry_count > 1 << 16 {
        return Err(Error::DecompileUnsupported("slua: implausible entry count"));
    }
    let mut entries: Vec<SluaArchiveEntry> = Vec::with_capacity(entry_count.min(64) as usize);
    for _ in 0..entry_count {
        let name_len: u16 = r.read_u16()?;
        let name_bytes: &[u8] = r.read(usize::from(name_len))?;
        let name: String = String::from_utf8_lossy(name_bytes).into_owned();
        let data_len: u32 = r.read_u32()?;
        let data_size: usize = usize::try_from(data_len).map_err(|_| Error::Truncated {
            offset: r.pos,
            needed: usize::MAX,
            had: r.bytes.len().saturating_sub(r.pos),
        })?;
        let data: &[u8] = r.read(data_size)?;
        entries.push(SluaArchiveEntry {
            name,
            obfuscated_bytecode: data.to_vec(),
        });
    }
    Ok(SluaArchive {
        seed,
        perm,
        dialect,
        compression,
        entries,
    })
}

fn recover_entry(archive: &SluaArchive, params: &SluaParams, raw: &[u8]) -> Result<Vec<u8>> {
    let mut payload: Vec<u8> = raw.to_vec();
    lcg_xor(params.seed, &mut payload);
    let compression_code: u8 = *payload
        .first()
        .ok_or(Error::IntegrityViolated("slua: empty decrypted entry"))?;
    let compression: SluaCompression =
        SluaCompression::from_code(compression_code).unwrap_or(archive.compression);
    let obfuscated: Vec<u8> = decompress(compression, &payload[1..])?;
    deobfuscate_bytecode(&obfuscated, params)
}

pub fn detect(src: &[u8]) -> Option<ObfuscatorDetection> {
    if src.len() < SLUA_DECOY_HEADER_LEN + 4 {
        return None;
    }
    if &src[..SLUA_DECOY_MAGIC.len()] != SLUA_DECOY_MAGIC {
        return None;
    }
    if &src[SLUA_DECOY_HEADER_LEN..SLUA_DECOY_HEADER_LEN + 4] != SLUA_ARCHIVE_MAGIC {
        return None;
    }
    let mut markers: Vec<String> = vec![
        "decoy-UnityFS-header".to_owned(),
        "SLUA-archive-magic".to_owned(),
    ];
    let dialect: Option<LuaDialect> = src
        .get(SLUA_DECOY_HEADER_LEN + 4)
        .copied()
        .and_then(dialect_from_code);
    if let Some(d) = dialect {
        markers.push(format!("dialect-{}", d.marketing_name()));
    }
    let key_mode: Option<u8> = src.get(SLUA_DECOY_HEADER_LEN + 5).copied();
    match key_mode {
        Some(KEY_MODE_EMBEDDED) => markers.push("embedded-key".to_owned()),
        Some(KEY_MODE_EXTERNAL) => markers.push("external-key".to_owned()),
        _ => {}
    }
    let variant: String = dialect.map_or_else(
        || "LCG-permuted".to_owned(),
        |d: LuaDialect| format!("{}-LCG-permuted", d.marketing_name()),
    );
    dbg_kv("slua.detect.variant", || variant.clone());
    dbg_kv("slua.detect.key_mode", || match key_mode {
        Some(KEY_MODE_EMBEDDED) => "embedded".to_owned(),
        Some(KEY_MODE_EXTERNAL) => "external".to_owned(),
        other => format!("{other:?}"),
    });
    Some(ObfuscatorDetection {
        kind: LuaObfuscatorKind::Slua,
        variant: Some(variant),
        confidence: 95,
        markers,
    })
}

pub fn peel(src: &[u8], _opts: &DeobfOptions) -> Result<PeelResult> {
    dbg_section("lua.slua.peel");
    if detect(src).is_none() {
        dbg_line(|| "slua signature absent".to_owned());
        return Err(Error::NoObfuscatorSignature("SLua"));
    }
    let archive: SluaArchive = parse_archive(src)?;
    dbg_kv("slua.dialect", || format!("{:?}", archive.dialect));
    dbg_kv("slua.compression", || format!("{:?}", archive.compression));
    dbg_kv("slua.entries", || archive.entries.len().to_string());
    let Some(seed): Option<u64> = archive.seed else {
        dbg_line(|| {
            "slua: external key mode, seed/permutation not embedded: metadata-only".to_owned()
        });
        return Ok(PeelResult {
            deobfuscated: Vec::new(),
            passes_run: vec!["slua-header-strip".to_owned(), "slua-archive-parse".to_owned()],
            residual_markers: vec![
                "slua: archive declares an external (per-title) key; the LCG seed and opcode permutation are not embedded in this artifact. Supply the game's key to recover the bytecode.".to_owned(),
            ],
            recovered_strings: Vec::new(),
            fully_recovered: false,
        });
    };
    dbg_kv_guarded("slua.seed", || format!("0x{seed:016x}"));
    let params: SluaParams = match archive.perm {
        Some(perm) => {
            dbg_kv("slua.perm_source", || "embedded-table".to_owned());
            SluaParams::new_for(archive.dialect, seed, perm)?
        }
        None => {
            dbg_kv("slua.perm_source", || "seed-derived-shuffle".to_owned());
            SluaParams::seed_derived_for(archive.dialect, seed)
        }
    };

    let mut passes_run: Vec<String> = vec![
        "slua-header-strip".to_owned(),
        "slua-archive-parse".to_owned(),
        "slua-lcg-decrypt".to_owned(),
        "slua-decompress".to_owned(),
        "slua-opcode-unpermute".to_owned(),
        "slua-constant-unmask".to_owned(),
        "slua-bytecode-reserialize".to_owned(),
    ];
    let mut residual_markers: Vec<String> = Vec::new();
    let mut recovered_strings: Vec<String> = Vec::new();
    let mut recovered: Vec<u8> = Vec::new();
    let mut recovered_count: usize = 0;

    for entry in &archive.entries {
        match recover_entry(&archive, &params, &entry.obfuscated_bytecode) {
            Ok(clean) => {
                if let Ok(chunk) = read_clean(archive.dialect, &clean) {
                    collect_strings(&chunk.main, &mut recovered_strings);
                }
                if recovered.is_empty() {
                    recovered = clean;
                }
                recovered_count += 1;
            }
            Err(e) => {
                residual_markers.push(format!(
                    "slua: entry `{}` failed to recover: {e}",
                    entry.name
                ));
            }
        }
    }

    dbg_kv("slua.recovered_entries", || {
        format!("{recovered_count}/{}", archive.entries.len())
    });
    if recovered_count == 0 {
        dbg_line(|| "slua: embedded key present but no entry recovered".to_owned());
        return Err(Error::IntegrityViolated(
            "slua: embedded key present but no entry recovered to valid Lua 5.3 bytecode",
        ));
    }
    passes_run.push(format!(
        "slua-recovered-{recovered_count}-of-{}-entries",
        archive.entries.len()
    ));
    residual_markers.push(format!(
        "slua: seed and opcode-permutation were embedded in the archive, so the seed-derived transforms are fully reversed; recovered {recovered_count} clean Lua 5.3 chunk(s)"
    ));

    Ok(PeelResult {
        deobfuscated: recovered,
        passes_run,
        residual_markers,
        recovered_strings,
        fully_recovered: recovered_count == archive.entries.len(),
    })
}

fn collect_strings(proto: &LuaProto, out: &mut Vec<String>) {
    for constant in &proto.constants {
        if let LuaConstant::Str(text) = constant
            && !text.is_empty()
        {
            out.push(text.clone());
        }
    }
    for sub in &proto.protos {
        collect_strings(sub, out);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::reader::common::LuaChunk;

    fn canonical_chunk(main: LuaProto) -> LuaChunk {
        LuaChunk {
            dialect: LuaDialect::Lua53,
            version_byte: 0x53,
            format: 0,
            little_endian: true,
            size_of_int: 4,
            size_of_size_t: 8,
            size_of_instruction: 4,
            size_of_lua_integer: 8,
            size_of_lua_number: 8,
            integral_number: false,
            main,
        }
    }

    fn sample_proto() -> LuaProto {
        LuaProto {
            source: Some("@hello.lua".to_owned()),
            line_defined: 0,
            last_line_defined: 0,
            num_params: 0,
            is_vararg: 1,
            max_stack_size: 2,
            code: vec![0x0000_0024, 0x4000_0006, 0x0080_0067],
            constants: vec![
                LuaConstant::Str("print".to_owned()),
                LuaConstant::Str("hello from slua".to_owned()),
                LuaConstant::Integer(7),
                LuaConstant::Number(3.5),
            ],
            protos: Vec::new(),
            source_lines: vec![1, 1, 1],
            locals: Vec::new(),
            upvalues: Vec::new(),
        }
    }

    fn sample_params() -> SluaParams {
        SluaParams::seed_derived(0x0123_4567_89AB_CDEF)
    }

    #[test]
    fn opcode_permutation_is_bijective() {
        let params: SluaParams = sample_params();
        for op in 0u8..LUA53_OPCODE_COUNT as u8 {
            let obf: u8 = params.obfuscate_opcode(op);
            assert!((obf as usize) < LUA53_OPCODE_COUNT);
            assert_eq!(params.deobfuscate_opcode(obf), Some(op));
        }
    }

    #[test]
    fn bytecode_obfuscation_round_trips() {
        let chunk: LuaChunk = canonical_chunk(sample_proto());
        let clean: Vec<u8> = serialize_chunk(&chunk).expect("serialize");
        let params: SluaParams = sample_params();
        let obf: Vec<u8> = obfuscate_bytecode(&clean, &params).expect("obfuscate");
        assert_ne!(obf, clean, "obfuscation must alter the bytes");
        let recovered: Vec<u8> = deobfuscate_bytecode(&obf, &params).expect("deobfuscate");
        let reparsed: LuaChunk = crate::reader::lua53::read(&recovered).expect("reparse");
        assert_eq!(reparsed.main.code, chunk.main.code);
        assert_eq!(reparsed.main.constants, chunk.main.constants);
    }

    #[test]
    fn lcg_keystream_is_deterministic() {
        let a: Vec<u8> = lcg_keystream(42, 16);
        let b: Vec<u8> = lcg_keystream(42, 16);
        let c: Vec<u8> = lcg_keystream(43, 16);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn zlib_decompress_errors_past_cap() {
        let compressed: Vec<u8> = zlib_compress(b"0123456789abcdef").expect("compress");
        let err: Error = zlib_decompress_capped(&compressed, 8).expect_err("cap");
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn readers_reject_overflowing_ranges() {
        let bytes: [u8; 1] = [0];
        let mut le: LeReader<'_> = LeReader {
            bytes: &bytes,
            pos: 1,
        };
        let le_err: Error = le.read(usize::MAX).expect_err("le overflow");
        assert!(matches!(le_err, Error::Truncated { .. }));

        let mut obf: ObfReader<'_> = ObfReader {
            bytes: &bytes,
            pos: 1,
            little_endian: true,
            const_xor_index: 0,
        };
        let obf_err: Error = obf.read_raw(usize::MAX).expect_err("obf overflow");
        assert!(matches!(obf_err, Error::Truncated { .. }));
    }

    #[test]
    fn slua_count_guard_rejects_over_limit() {
        let bytes: [u8; 16] = [0; 16];
        let reader: ObfReader<'_> = ObfReader::new(&bytes, true);
        let err: Error = checked_count(
            (MAX_SLUA_CODE_COUNT as u64) + 1,
            MAX_SLUA_CODE_COUNT,
            "slua code",
            &reader,
            4,
        )
        .expect_err("count cap");
        assert!(matches!(err, Error::LimitExceeded { .. }));
    }

    #[test]
    fn slua_count_guard_rejects_short_remaining_span() {
        let bytes: [u8; 4] = [0; 4];
        let reader: ObfReader<'_> = ObfReader::new(&bytes, true);
        let err: Error =
            checked_count(2, MAX_SLUA_CODE_COUNT, "slua code", &reader, 4).expect_err("span");
        assert!(matches!(err, Error::Truncated { .. }));
    }

    #[test]
    fn obfuscated_byte_string_uses_lossy_text() {
        let params: SluaParams = sample_params();
        let raw: [u8; 3] = [0x66, 0xFF, 0x6F];
        let mut encoded: Vec<u8> = Vec::new();
        encoded.push(4u8 ^ params.len_mask());
        for (index, byte) in raw.iter().enumerate() {
            encoded.push(*byte ^ ObfReader::key_byte(params.seed, index));
        }
        let mut reader: ObfReader<'_> = ObfReader::new(&encoded, true);
        let text: String = obf_read_string(&mut reader, &params, 4)
            .expect("string")
            .expect("present");
        assert_eq!(text, "f\u{fffd}o");
    }

    #[test]
    fn full_archive_round_trip_with_embedded_key() {
        let chunk: LuaChunk = canonical_chunk(sample_proto());
        let clean: Vec<u8> = serialize_chunk(&chunk).expect("serialize");
        let params: SluaParams = sample_params();
        let bundle: Vec<u8> = build_archive(
            &params,
            true,
            SluaCompression::Zlib,
            &[("main".to_owned(), clean.clone())],
        )
        .expect("build archive");
        let detection: Option<ObfuscatorDetection> = detect(&bundle);
        assert!(detection.is_some());
        let result: PeelResult = peel(&bundle, &DeobfOptions::default()).expect("peel");
        assert!(result.fully_recovered);
        assert_eq!(result.deobfuscated, clean);
    }

    fn chunk_51(main: LuaProto) -> LuaChunk {
        LuaChunk {
            dialect: LuaDialect::Lua51,
            version_byte: 0x51,
            format: 0,
            little_endian: true,
            size_of_int: 4,
            size_of_size_t: 8,
            size_of_instruction: 4,
            size_of_lua_integer: 0,
            size_of_lua_number: 8,
            integral_number: false,
            main,
        }
    }

    fn sample_proto_51() -> LuaProto {
        LuaProto {
            source: Some("@hello51.lua".to_owned()),
            line_defined: 0,
            last_line_defined: 0,
            num_params: 0,
            is_vararg: 2,
            max_stack_size: 3,
            code: vec![0x0000_0005, 0x0040_0041, 0x0080_0041, 0x0000_001E],
            constants: vec![
                LuaConstant::Str("print".to_owned()),
                LuaConstant::Number(40.0),
                LuaConstant::Number(2.0),
            ],
            protos: Vec::new(),
            source_lines: vec![1, 1, 1, 1],
            locals: Vec::new(),
            upvalues: Vec::new(),
        }
    }

    #[test]
    fn opcode_permutation_is_bijective_51() {
        let params: SluaParams = SluaParams::seed_derived_for(LuaDialect::Lua51, 0xDEAD_BEEF);
        for op in 0u8..LUA51_OPCODE_COUNT as u8 {
            let obf: u8 = params.obfuscate_opcode(op);
            assert!((obf as usize) < LUA51_OPCODE_COUNT);
            assert_eq!(params.deobfuscate_opcode(obf), Some(op));
        }
    }

    #[test]
    fn bytecode_obfuscation_round_trips_51() {
        let chunk: LuaChunk = chunk_51(sample_proto_51());
        let clean: Vec<u8> = serialize_chunk(&chunk).expect("serialize 5.1");
        crate::reader::lua51::read(&clean).expect("clean is valid 5.1");
        let params: SluaParams = SluaParams::seed_derived_for(LuaDialect::Lua51, 0x1234_5678_9ABC);
        let obf: Vec<u8> = obfuscate_bytecode(&clean, &params).expect("obfuscate 5.1");
        assert_ne!(obf, clean, "obfuscation must alter the bytes");
        let recovered: Vec<u8> = deobfuscate_bytecode(&obf, &params).expect("deobfuscate 5.1");
        let reparsed: LuaChunk = crate::reader::lua51::read(&recovered).expect("reparse 5.1");
        assert_eq!(reparsed.dialect, LuaDialect::Lua51);
        assert_eq!(reparsed.main.code, chunk.main.code);
        assert_eq!(reparsed.main.constants, chunk.main.constants);
    }

    #[test]
    fn full_archive_round_trip_51_embedded_key() {
        let chunk: LuaChunk = chunk_51(sample_proto_51());
        let clean: Vec<u8> = serialize_chunk(&chunk).expect("serialize 5.1");
        let params: SluaParams = SluaParams::seed_derived_for(LuaDialect::Lua51, 0x0BAD_F00D);
        let bundle: Vec<u8> = build_archive(
            &params,
            true,
            SluaCompression::Zlib,
            &[("main".to_owned(), clean.clone())],
        )
        .expect("build 5.1 archive");
        let detection: ObfuscatorDetection = detect(&bundle).expect("detect 5.1 archive");
        assert!(
            detection
                .markers
                .iter()
                .any(|m: &String| m.contains("Lua 5.1"))
        );
        let result: PeelResult = peel(&bundle, &DeobfOptions::default()).expect("peel 5.1");
        assert!(result.fully_recovered);
        assert_eq!(result.deobfuscated, clean);
        assert!(
            result
                .recovered_strings
                .iter()
                .any(|s: &String| s == "print")
        );
    }

    #[test]
    fn external_key_reports_needs_key() {
        let chunk: LuaChunk = canonical_chunk(sample_proto());
        let clean: Vec<u8> = serialize_chunk(&chunk).expect("serialize");
        let params: SluaParams = sample_params();
        let bundle: Vec<u8> = build_archive(
            &params,
            false,
            SluaCompression::None,
            &[("main".to_owned(), clean)],
        )
        .expect("build archive");
        let result: PeelResult = peel(&bundle, &DeobfOptions::default()).expect("peel");
        assert!(!result.fully_recovered);
        assert!(result.deobfuscated.is_empty());
        assert!(
            result
                .residual_markers
                .iter()
                .any(|m: &String| m.contains("external"))
        );
    }
}
