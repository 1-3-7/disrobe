use std::collections::BTreeMap;

use crate::debug::{dbg_enabled, dbg_kv, dbg_kv_guarded, dbg_line, dbg_section};
use crate::decompile::lift::{LiftedProto, lift_proto_dialect};
use crate::error::{Error, Result};
use crate::obfuscator::PeelResult;
use crate::obfuscator::string_decode::decode_base64_standard;
use crate::reader::common::{LuaConstant, LuaDialect, LuaProto};

pub const VM_MAGIC: &[u8; 4] = b"DVM1";

pub const VM_KIND_IRONBREW2: u8 = 1;
pub const VM_KIND_MOONSEC: u8 = 2;

pub const VOP_MOVE: u8 = 0;
pub const VOP_LOADK: u8 = 1;
pub const VOP_LOADBOOL: u8 = 2;
pub const VOP_LOADNIL: u8 = 3;
pub const VOP_GETGLOBAL: u8 = 5;
pub const VOP_GETTABLE: u8 = 6;
pub const VOP_SETGLOBAL: u8 = 7;
pub const VOP_SETTABLE: u8 = 9;
pub const VOP_NEWTABLE: u8 = 10;
pub const VOP_SELF: u8 = 11;
pub const VOP_ADD: u8 = 12;
pub const VOP_SUB: u8 = 13;
pub const VOP_MUL: u8 = 14;
pub const VOP_DIV: u8 = 15;
pub const VOP_MOD: u8 = 16;
pub const VOP_POW: u8 = 17;
pub const VOP_UNM: u8 = 18;
pub const VOP_NOT: u8 = 19;
pub const VOP_LEN: u8 = 20;
pub const VOP_CONCAT: u8 = 21;
pub const VOP_JMP: u8 = 22;
pub const VOP_EQ: u8 = 23;
pub const VOP_LT: u8 = 24;
pub const VOP_LE: u8 = 25;
pub const VOP_TEST: u8 = 26;
pub const VOP_CALL: u8 = 28;
pub const VOP_RETURN: u8 = 30;
pub const VOP_FORLOOP: u8 = 31;
pub const VOP_FORPREP: u8 = 32;
pub const VOP_SETLIST: u8 = 34;

const VK_NIL: u8 = 0;
const VK_BOOL: u8 = 1;
const VK_NUMBER: u8 = 3;
const VK_STRING: u8 = 4;

const LUA51_OPCODE_OF_VOP: [(u8, u8); 33] = [
    (VOP_MOVE, 0),
    (VOP_LOADK, 1),
    (VOP_LOADBOOL, 2),
    (VOP_LOADNIL, 3),
    (VOP_GETGLOBAL, 5),
    (VOP_GETTABLE, 6),
    (VOP_SETGLOBAL, 7),
    (VOP_SETTABLE, 9),
    (VOP_NEWTABLE, 10),
    (VOP_SELF, 11),
    (VOP_ADD, 12),
    (VOP_SUB, 13),
    (VOP_MUL, 14),
    (VOP_DIV, 15),
    (VOP_MOD, 16),
    (VOP_POW, 17),
    (VOP_UNM, 18),
    (VOP_NOT, 19),
    (VOP_LEN, 20),
    (VOP_CONCAT, 21),
    (VOP_JMP, 22),
    (VOP_EQ, 23),
    (VOP_LT, 24),
    (VOP_LE, 25),
    (VOP_TEST, 26),
    (VOP_CALL, 28),
    (VOP_RETURN, 30),
    (VOP_FORLOOP, 31),
    (VOP_FORPREP, 32),
    (VOP_SETLIST, 34),
    (VOP_SETLIST, 34),
    (VOP_SETLIST, 34),
    (VOP_SETLIST, 34),
];

pub const BUILDER_MAGIC: &[u8; 4] = b"DPB1";

pub const PB_PUSH_IMM: u8 = 0x01;
pub const PB_PUSH_SEED: u8 = 0x02;
pub const PB_PUSH_IDX: u8 = 0x03;
pub const PB_ADD: u8 = 0x10;
pub const PB_MUL: u8 = 0x11;
pub const PB_XOR: u8 = 0x12;
pub const PB_AND: u8 = 0x13;
pub const PB_MOD: u8 = 0x14;
pub const PB_ROTL: u8 = 0x15;
pub const PB_LOOP_BEGIN: u8 = 0x20;
pub const PB_LOOP_END: u8 = 0x21;
pub const PB_EMIT_MAP: u8 = 0x30;
pub const PB_SET_XORKEY: u8 = 0x31;
pub const PB_HALT: u8 = 0x3F;

const PB_STACK_LIMIT: usize = 256;
const PB_STEP_LIMIT: usize = 1 << 20;
const EMBEDDED_PAYLOAD_SCAN_LIMIT: usize = 8 << 20;
const LUA_STRING_PAYLOAD_CAP: usize = 16 << 20;
const LUA_TABLE_PAYLOAD_CAP: usize = 16 << 20;
const BASE64_PAYLOAD_CHAR_CAP: usize = (LUA_STRING_PAYLOAD_CAP / 3) * 4 + 8;
const BOOTSTRAP_SCAN_LIMIT: usize = 8 << 20;
const SEED_NAMES: &[&str] = &[
    "MS_VM_SEED",
    "MS_SEED",
    "MOONSEC_VM_SEED",
    "MOONSEC_SEED",
    "moonsec_seed",
    "__moonsec_seed",
    "_seed",
    "seed",
];
const BUILDER_NAMES: &[&str] = &[
    "MS_VM_BUILDER",
    "MS_VM_PERM",
    "MS_PERMBUILD",
    "MOONSEC_VM_BUILDER",
    "MOONSEC_PERM",
    "moonsec_builder",
    "moonsec_perm",
    "__moonsec_builder",
    "_perm",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapKeys {
    pub opmap: BTreeMap<u8, u8>,
    pub xor_key: Option<u8>,
}

#[derive(Debug, Clone)]
struct BuilderCursor<'a> {
    code: &'a [u8],
    pos: usize,
}

impl<'a> BuilderCursor<'a> {
    #[inline]
    fn new(code: &'a [u8]) -> Self {
        Self { code, pos: 0 }
    }

    #[inline]
    fn read_u8(&mut self) -> Result<u8> {
        let byte: u8 = *self
            .code
            .get(self.pos)
            .ok_or(Error::BootstrapEmulationFailed("builder stream truncated"))?;
        self.pos += 1;
        Ok(byte)
    }

    #[inline]
    fn read_u32(&mut self) -> Result<u32> {
        let b0: u32 = u32::from(self.read_u8()?);
        let b1: u32 = u32::from(self.read_u8()?);
        let b2: u32 = u32::from(self.read_u8()?);
        let b3: u32 = u32::from(self.read_u8()?);
        Ok(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24))
    }
}

#[derive(Debug, Clone, Copy)]
struct LoopFrame {
    body_start: usize,
    remaining: u32,
    index: u32,
}

pub fn emulate_perm_builder(builder: &[u8], seed: u32) -> Result<BootstrapKeys> {
    if !builder.starts_with(BUILDER_MAGIC) {
        return Err(Error::BootstrapEmulationFailed("builder magic mismatch"));
    }
    let mut cur: BuilderCursor<'_> = BuilderCursor::new(&builder[4..]);
    let mut stack: Vec<u32> = Vec::with_capacity(PB_STACK_LIMIT);
    let mut loops: Vec<LoopFrame> = Vec::new();
    let mut opmap: BTreeMap<u8, u8> = BTreeMap::new();
    let mut xor_key: Option<u8> = None;
    let mut steps: usize = 0;

    let push = |stack: &mut Vec<u32>, value: u32| -> Result<()> {
        if stack.len() >= PB_STACK_LIMIT {
            return Err(Error::BootstrapEmulationFailed("builder stack overflow"));
        }
        stack.push(value);
        Ok(())
    };
    let pop = |stack: &mut Vec<u32>| -> Result<u32> {
        stack
            .pop()
            .ok_or(Error::BootstrapEmulationFailed("builder stack underflow"))
    };

    loop {
        steps += 1;
        if steps > PB_STEP_LIMIT {
            return Err(Error::BootstrapEmulationFailed(
                "builder step budget exhausted",
            ));
        }
        let op: u8 = cur.read_u8()?;
        match op {
            PB_PUSH_IMM => {
                let imm: u32 = cur.read_u32()?;
                push(&mut stack, imm)?;
            }
            PB_PUSH_SEED => push(&mut stack, seed)?,
            PB_PUSH_IDX => {
                let frame: &LoopFrame = loops
                    .last()
                    .ok_or(Error::BootstrapEmulationFailed("PUSH_IDX outside loop"))?;
                push(&mut stack, frame.index)?;
            }
            PB_ADD => {
                let rhs: u32 = pop(&mut stack)?;
                let lhs: u32 = pop(&mut stack)?;
                push(&mut stack, lhs.wrapping_add(rhs))?;
            }
            PB_MUL => {
                let rhs: u32 = pop(&mut stack)?;
                let lhs: u32 = pop(&mut stack)?;
                push(&mut stack, lhs.wrapping_mul(rhs))?;
            }
            PB_XOR => {
                let rhs: u32 = pop(&mut stack)?;
                let lhs: u32 = pop(&mut stack)?;
                push(&mut stack, lhs ^ rhs)?;
            }
            PB_AND => {
                let rhs: u32 = pop(&mut stack)?;
                let lhs: u32 = pop(&mut stack)?;
                push(&mut stack, lhs & rhs)?;
            }
            PB_MOD => {
                let rhs: u32 = pop(&mut stack)?;
                let lhs: u32 = pop(&mut stack)?;
                if rhs == 0 {
                    return Err(Error::BootstrapEmulationFailed("builder modulo by zero"));
                }
                push(&mut stack, lhs % rhs)?;
            }
            PB_ROTL => {
                let amount: u32 = pop(&mut stack)? & 31;
                let value: u32 = pop(&mut stack)?;
                push(&mut stack, value.rotate_left(amount))?;
            }
            PB_LOOP_BEGIN => {
                let count: u32 = cur.read_u32()?;
                let frame: LoopFrame = LoopFrame {
                    body_start: cur.pos,
                    remaining: count,
                    index: 0,
                };
                if frame.remaining == 0 {
                    skip_loop_body(&mut cur)?;
                } else {
                    loops.push(frame);
                }
            }
            PB_LOOP_END => {
                let frame: &mut LoopFrame = loops.last_mut().ok_or(
                    Error::BootstrapEmulationFailed("LOOP_END without LOOP_BEGIN"),
                )?;
                frame.remaining -= 1;
                if frame.remaining == 0 {
                    loops.pop();
                } else {
                    frame.index += 1;
                    cur.pos = frame.body_start;
                }
            }
            PB_EMIT_MAP => {
                let canonical: u32 = pop(&mut stack)?;
                let encoded: u32 = pop(&mut stack)?;
                let encoded8: u8 = u8::try_from(encoded & 0xFF)
                    .map_err(|_| Error::BootstrapEmulationFailed("encoded op out of range"))?;
                let canonical8: u8 = u8::try_from(canonical & 0xFF)
                    .map_err(|_| Error::BootstrapEmulationFailed("canonical op out of range"))?;
                opmap.insert(encoded8, canonical8);
            }
            PB_SET_XORKEY => {
                let value: u32 = pop(&mut stack)?;
                xor_key = Some((value & 0xFF) as u8);
            }
            PB_HALT => break,
            other => {
                let _ = other;
                return Err(Error::BootstrapEmulationFailed("unknown builder opcode"));
            }
        }
    }

    if opmap.is_empty() {
        return Err(Error::BootstrapEmulationFailed(
            "builder produced no opcode map",
        ));
    }
    Ok(BootstrapKeys { opmap, xor_key })
}

fn skip_loop_body(cur: &mut BuilderCursor<'_>) -> Result<()> {
    let mut depth: usize = 1;
    while depth > 0 {
        let op: u8 = cur.read_u8()?;
        match op {
            PB_PUSH_IMM => {
                let _ = cur.read_u32()?;
            }
            PB_LOOP_BEGIN => {
                let _ = cur.read_u32()?;
                depth += 1;
            }
            PB_LOOP_END => depth -= 1,
            PB_HALT => {
                return Err(Error::BootstrapEmulationFailed(
                    "HALT inside skipped loop body",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevirtReport {
    pub kind: u8,
    pub xor_key: u8,
    pub handlers_recovered: usize,
    pub handlers_total: usize,
    pub opcodes_lifted: usize,
    pub opcodes_total: usize,
    pub constants_decoded: usize,
}

impl DevirtReport {
    #[inline]
    #[must_use]
    pub fn handler_coverage_pct(&self) -> u8 {
        ratio_pct(self.handlers_recovered, self.handlers_total)
    }

    #[inline]
    #[must_use]
    pub fn opcode_coverage_pct(&self) -> u8 {
        ratio_pct(self.opcodes_lifted, self.opcodes_total)
    }
}

#[inline]
#[must_use]
fn ratio_pct(num: usize, den: usize) -> u8 {
    if den == 0 {
        return 100;
    }
    let pct: usize = num.saturating_mul(100) / den;
    u8::try_from(pct.min(100)).unwrap_or(100)
}

#[derive(Debug, Clone)]
pub struct Devirtualized {
    pub proto: LuaProto,
    pub report: DevirtReport,
}

#[must_use]
pub fn recover_seed(bootstrap: &str) -> Option<u32> {
    let marker: &str = "SEED=";
    if let Some(marker_start) = bootstrap.find(marker) {
        let start: usize = marker_start + marker.len();
        let digits: String = bootstrap[start..]
            .trim_start()
            .chars()
            .take_while(|c: &char| c.is_ascii_digit())
            .collect();
        if let Ok(seed) = digits.parse::<u32>() {
            return Some(seed);
        }
    }
    for name in SEED_NAMES {
        if let Some(value_start) = find_lua_assignment_value(bootstrap, name)
            && let Some(seed) = parse_lua_u32_at(bootstrap.as_bytes(), value_start)
        {
            return Some(seed);
        }
    }
    None
}

#[must_use]
pub fn extract_builder_program(text: &str) -> Option<Vec<u8>> {
    let marker: &str = "PERMBUILD=";
    if let Some(marker_start) = text.find(marker) {
        let start: usize = marker_start + marker.len();
        let hex: String = text[start..]
            .chars()
            .take_while(|c: &char| c.is_ascii_hexdigit())
            .collect();
        if let Some(builder) = decode_hex(&hex) {
            return Some(builder);
        }
    }
    extract_named_lua_byte_buffer(text, BUILDER_NAMES, BUILDER_MAGIC)
}

#[must_use]
fn find_lua_assignment_value(text: &str, name: &str) -> Option<usize> {
    let bytes: &[u8] = text.as_bytes();
    let limit: usize = bytes.len().min(BOOTSTRAP_SCAN_LIMIT);
    let mut search_start: usize = 0;
    while search_start < limit {
        let haystack: &str = text.get(search_start..limit)?;
        let found: usize = haystack.find(name)? + search_start;
        let before: bool = found
            .checked_sub(1)
            .and_then(|idx: usize| bytes.get(idx).copied())
            .is_some_and(is_lua_ident_byte);
        let after: bool = bytes
            .get(found + name.len())
            .copied()
            .is_some_and(is_lua_ident_byte);
        if !before && !after {
            let mut pos: usize = found + name.len();
            while pos < limit && bytes[pos].is_ascii_whitespace() {
                pos += 1;
            }
            if bytes.get(pos).copied() == Some(b'=') {
                pos += 1;
                while pos < limit && bytes[pos].is_ascii_whitespace() {
                    pos += 1;
                }
                return Some(pos);
            }
        }
        search_start = found + name.len();
    }
    None
}

#[inline]
#[must_use]
fn is_lua_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

#[must_use]
fn parse_lua_u32_at(bytes: &[u8], start: usize) -> Option<u32> {
    parse_lua_u32_with_end_at(bytes, start).map(|(value, _): (u32, usize)| value)
}

#[must_use]
fn parse_lua_u32_with_end_at(bytes: &[u8], start: usize) -> Option<(u32, usize)> {
    let mut pos: usize = start;
    while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
        pos += 1;
    }
    if bytes.get(pos).copied() == Some(b'0')
        && matches!(bytes.get(pos + 1).copied(), Some(b'x' | b'X'))
    {
        pos += 2;
        let hex_start: usize = pos;
        while pos < bytes.len() && bytes[pos].is_ascii_hexdigit() {
            pos += 1;
        }
        if pos == hex_start {
            return None;
        }
        return u32::from_str_radix(std::str::from_utf8(&bytes[hex_start..pos]).ok()?, 16)
            .ok()
            .map(|value: u32| (value, pos));
    }
    let dec_start: usize = pos;
    while pos < bytes.len() && bytes[pos].is_ascii_digit() {
        pos += 1;
    }
    if pos == dec_start {
        return None;
    }
    std::str::from_utf8(&bytes[dec_start..pos])
        .ok()?
        .parse::<u32>()
        .ok()
        .map(|value: u32| (value, pos))
}

#[must_use]
fn table_number_terminates(bytes: &[u8], pos: usize) -> bool {
    matches!(bytes.get(pos).copied(), Some(b',' | b';' | b'}'))
        || bytes.get(pos).is_some_and(u8::is_ascii_whitespace)
        || bytes.get(pos).is_none()
}

#[must_use]
fn extract_named_lua_byte_buffer(text: &str, names: &[&str], magic: &[u8]) -> Option<Vec<u8>> {
    let bytes: &[u8] = text.as_bytes();
    for name in names {
        let mut search_start: usize = 0;
        while search_start < bytes.len().min(BOOTSTRAP_SCAN_LIMIT) {
            let value_start: usize = match find_lua_assignment_value(&text[search_start..], name) {
                Some(pos) => search_start + pos,
                None => break,
            };
            let decoded: Option<(Vec<u8>, usize)> = match bytes.get(value_start).copied() {
                Some(b'"' | b'\'') => decode_lua_quoted_string(bytes, value_start),
                Some(b'[') => decode_lua_long_string(bytes, value_start),
                Some(b'{') => decode_lua_byte_table(bytes, value_start),
                _ => None,
            };
            if let Some((buffer, next)) = decoded {
                if buffer.starts_with(magic) {
                    return Some(buffer);
                }
                search_start = next;
            } else {
                search_start = value_start.saturating_add(1);
            }
        }
    }
    None
}

fn decode_lua_byte_table(bytes: &[u8], start: usize) -> Option<(Vec<u8>, usize)> {
    if *bytes.get(start)? != b'{' {
        return None;
    }
    let mut out: Vec<u8> = Vec::new();
    let mut pos: usize = start + 1;
    loop {
        while pos < bytes.len()
            && (bytes[pos].is_ascii_whitespace() || bytes[pos] == b',' || bytes[pos] == b';')
        {
            pos += 1;
        }
        if *bytes.get(pos)? == b'}' {
            return Some((out, pos + 1));
        }
        let (value, next): (u32, usize) = parse_lua_u32_with_end_at(bytes, pos)?;
        if value > u32::from(u8::MAX) {
            return None;
        }
        out.push(value as u8);
        if out.len() > LUA_TABLE_PAYLOAD_CAP {
            return None;
        }
        pos = next;
        if !table_number_terminates(bytes, pos) {
            return None;
        }
    }
}

pub fn recover_bootstrap_keys(bootstrap: &str) -> Result<BootstrapKeys> {
    let builder: Vec<u8> = extract_builder_program(bootstrap).ok_or(
        Error::BootstrapEmulationFailed("no PERMBUILD init program present"),
    )?;
    let seed: u32 = recover_seed(bootstrap).ok_or(Error::BootstrapEmulationFailed(
        "no SEED present for init program",
    ))?;
    emulate_perm_builder(&builder, seed)
}

#[must_use]
fn canonical_vop_to_lua51(vop: u8) -> Option<u8> {
    LUA51_OPCODE_OF_VOP
        .iter()
        .find(|(v, _): &&(u8, u8)| *v == vop)
        .map(|(_, o): &(u8, u8)| *o)
}

struct VmCursor<'a> {
    data: &'a [u8],
    pos: usize,
    xor_key: u8,
}

impl<'a> VmCursor<'a> {
    fn new(data: &'a [u8], xor_key: u8) -> Self {
        Self {
            data,
            pos: 0,
            xor_key,
        }
    }

    fn read_u8(&mut self) -> Result<u8> {
        let byte: u8 = *self
            .data
            .get(self.pos)
            .ok_or(Error::LuauTruncated { offset: self.pos })?;
        self.pos += 1;
        Ok(byte ^ self.xor_key)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let b0: u32 = u32::from(self.read_u8()?);
        let b1: u32 = u32::from(self.read_u8()?);
        let b2: u32 = u32::from(self.read_u8()?);
        let b3: u32 = u32::from(self.read_u8()?);
        Ok(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24))
    }

    fn read_f64(&mut self) -> Result<f64> {
        let mut raw: [u8; 8] = [0u8; 8];
        for slot in &mut raw {
            *slot = self.read_u8()?;
        }
        Ok(f64::from_le_bytes(raw))
    }

    fn read_string(&mut self) -> Result<String> {
        let len: u32 = self.read_u32()?;
        let n: usize = usize::try_from(len).unwrap_or(0);
        let available: usize = self.data.len().saturating_sub(self.pos);
        if n > available {
            return Err(Error::LuauTruncated { offset: self.pos });
        }
        let mut bytes: Vec<u8> = Vec::with_capacity(n);
        for _ in 0..n {
            bytes.push(self.read_u8()?);
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}

pub fn devirtualize(payload: &[u8], bootstrap: &str) -> Result<Devirtualized> {
    dbg_section("lua.devirtualize");
    if !payload.starts_with(VM_MAGIC) {
        dbg_line(|| "VM payload magic absent: not a disrobe-emitted vm container".to_owned());
        return Err(Error::NoObfuscatorSignature("VM payload magic"));
    }
    let kind: u8 = *payload.get(4).ok_or(Error::LuauTruncated { offset: 4 })?;
    let header_key: u8 = *payload.get(5).ok_or(Error::LuauTruncated { offset: 5 })?;
    dbg_kv("vm_family", || match kind {
        VM_KIND_IRONBREW2 => "ironbrew2".to_owned(),
        VM_KIND_MOONSEC => "moonsec".to_owned(),
        other => format!("unknown(0x{other:02x})"),
    });
    let keys: BootstrapKeys = recover_bootstrap_keys(bootstrap)?;
    let xor_key: u8 = keys.xor_key.unwrap_or(header_key);
    dbg_kv("xor_key_source", || {
        if keys.xor_key.is_some() {
            "bootstrap-emulated".to_owned()
        } else {
            "payload-header".to_owned()
        }
    });
    dbg_kv_guarded("xor_key", || format!("0x{xor_key:02x}"));
    let opmap: BTreeMap<u8, u8> = keys.opmap;
    dbg_kv("opmap_entries", || opmap.len().to_string());
    if dbg_enabled() {
        let table: String = opmap
            .iter()
            .map(|(enc, canon): (&u8, &u8)| format!("0x{enc:02x}->{canon}"))
            .collect::<Vec<String>>()
            .join(" ");
        dbg_line(|| format!("opmap encoded->canonical: {table}"));
    }

    let body: &[u8] = &payload[6..];
    let mut c: VmCursor<'_> = VmCursor::new(body, xor_key);

    let max_stack_size: u8 = c.read_u8()?;
    let num_params: u8 = c.read_u8()?;
    let is_vararg: u8 = c.read_u8()?;

    let const_count: u32 = c.read_u32()?;
    let mut constants: Vec<LuaConstant> = Vec::with_capacity(const_count.min(1024) as usize);
    let mut constants_decoded: usize = 0;
    for _ in 0..const_count {
        let tag: u8 = c.read_u8()?;
        let value: LuaConstant = match tag {
            VK_NIL => LuaConstant::Nil,
            VK_BOOL => LuaConstant::Bool(c.read_u8()? != 0),
            VK_NUMBER => LuaConstant::Number(c.read_f64()?),
            VK_STRING => LuaConstant::Str(c.read_string()?),
            other => return Err(Error::BadConstantTag(other, c.pos)),
        };
        constants_decoded += 1;
        constants.push(value);
    }

    let code_count: u32 = c.read_u32()?;
    let mut code: Vec<u32> = Vec::with_capacity(code_count.min(1 << 20) as usize);
    let mut opcodes_lifted: usize = 0;
    let opcodes_total: usize = code_count as usize;
    for _ in 0..code_count {
        let encoded_op: u8 = c.read_u8()?;
        let a: u32 = c.read_u32()?;
        let b: u32 = c.read_u32()?;
        let cc: u32 = c.read_u32()?;
        let canonical_vop: u8 = opmap.get(&encoded_op).copied().unwrap_or(encoded_op);
        let Some(lua_op): Option<u8> = canonical_vop_to_lua51(canonical_vop) else {
            code.push(0);
            continue;
        };
        opcodes_lifted += 1;
        code.push(encode_lua51(lua_op, canonical_vop, a, b, cc));
    }

    let stream_ops: usize = distinct_encoded_ops(payload, xor_key);
    let handlers_total: usize = opmap.len().max(stream_ops);
    let handlers_recovered: usize = opmap
        .keys()
        .filter(|enc: &&u8| canonical_vop_to_lua51(opmap[enc]).is_some())
        .count();

    let report: DevirtReport = DevirtReport {
        kind,
        xor_key,
        handlers_recovered,
        handlers_total,
        opcodes_lifted,
        opcodes_total,
        constants_decoded,
    };
    dbg_kv("handlers", || {
        format!(
            "{handlers_recovered}/{handlers_total} ({}%)",
            report.handler_coverage_pct()
        )
    });
    dbg_kv("opcodes", || {
        format!(
            "{opcodes_lifted}/{opcodes_total} ({}%)",
            report.opcode_coverage_pct()
        )
    });
    dbg_kv("constants_decoded", || constants_decoded.to_string());

    let proto: LuaProto = LuaProto {
        source: Some("devirtualized".to_owned()),
        line_defined: 0,
        last_line_defined: 0,
        num_params,
        is_vararg,
        max_stack_size: max_stack_size.max(2),
        code,
        constants,
        protos: Vec::new(),
        source_lines: Vec::new(),
        locals: Vec::new(),
        upvalues: Vec::new(),
    };
    Ok(Devirtualized { proto, report })
}

#[must_use]
fn distinct_encoded_ops(payload: &[u8], xor_key: u8) -> usize {
    let body: &[u8] = payload.get(6..).unwrap_or(&[]);
    let mut c: VmCursor<'_> = VmCursor::new(body, xor_key);
    let mut seen: std::collections::BTreeSet<u8> = std::collections::BTreeSet::new();
    if scan_encoded_ops(&mut c, &mut seen).is_err() {
        return seen.len();
    }
    seen.len()
}

fn scan_encoded_ops(c: &mut VmCursor<'_>, seen: &mut std::collections::BTreeSet<u8>) -> Result<()> {
    let _max: u8 = c.read_u8()?;
    let _params: u8 = c.read_u8()?;
    let _vararg: u8 = c.read_u8()?;
    let const_count: u32 = c.read_u32()?;
    for _ in 0..const_count {
        let tag: u8 = c.read_u8()?;
        match tag {
            VK_NIL => {}
            VK_BOOL => {
                let _ = c.read_u8()?;
            }
            VK_NUMBER => {
                let _ = c.read_f64()?;
            }
            VK_STRING => {
                let _ = c.read_string()?;
            }
            other => return Err(Error::BadConstantTag(other, c.pos)),
        }
    }
    let code_count: u32 = c.read_u32()?;
    for _ in 0..code_count {
        let op: u8 = c.read_u8()?;
        seen.insert(op);
        let _ = c.read_u32()?;
        let _ = c.read_u32()?;
        let _ = c.read_u32()?;
    }
    Ok(())
}

#[must_use]
fn encode_lua51(lua_op: u8, vop: u8, a: u32, b: u32, c: u32) -> u32 {
    let op: u32 = u32::from(lua_op) & 0x3F;
    let a6: u32 = (a & 0xFF) << 6;
    if vop == VOP_LOADK || vop == VOP_GETGLOBAL || vop == VOP_SETGLOBAL {
        let bx: u32 = (b & 0x3FFFF) << 14;
        return op | a6 | bx;
    }
    if vop == VOP_JMP || vop == VOP_FORLOOP || vop == VOP_FORPREP {
        let sbx: i32 = b as i32 + 0x1FFFF;
        let bx: u32 = ((sbx as u32) & 0x3FFFF) << 14;
        return op | a6 | bx;
    }
    let c9: u32 = (c & 0x1FF) << 14;
    let b9: u32 = (b & 0x1FF) << 23;
    op | a6 | c9 | b9
}

#[must_use]
pub fn extract_embedded_payload(text: &str) -> Option<Vec<u8>> {
    if let Some(payload) = extract_marker_payload(text) {
        return Some(payload);
    }
    extract_lua_string_payload(text)
}

#[must_use]
fn extract_marker_payload(text: &str) -> Option<Vec<u8>> {
    let marker: &str = "VMPAYLOAD=";
    if let Some(start) = text.find(marker).map(|idx: usize| idx + marker.len()) {
        let tail: &str = &text[start..];
        if let Some(encoded) = tail.strip_prefix("base64:") {
            return decode_base64_payload_run(encoded);
        }
        let hex: String = tail
            .chars()
            .take_while(|c: &char| c.is_ascii_hexdigit())
            .collect();
        if !hex.is_empty() {
            return decode_hex(&hex);
        }
        return decode_base64_payload_run(tail);
    }
    for marker in ["VMPAYLOAD_B64=", "VMPAYLOAD64="] {
        if let Some(start) = text.find(marker).map(|idx: usize| idx + marker.len()) {
            return decode_base64_payload_run(&text[start..]);
        }
    }
    None
}

#[must_use]
fn extract_lua_string_payload(text: &str) -> Option<Vec<u8>> {
    let bytes: &[u8] = text.as_bytes();
    let limit: usize = bytes.len().min(EMBEDDED_PAYLOAD_SCAN_LIMIT);
    let mut pos: usize = 0;
    while pos < limit {
        match bytes[pos] {
            b'\'' | b'"' => match decode_lua_quoted_string(bytes, pos) {
                Some((decoded, next)) => {
                    if decoded.starts_with(VM_MAGIC) {
                        return Some(decoded);
                    }
                    if let Some(payload) = decode_base64_payload_bytes(&decoded) {
                        return Some(payload);
                    }
                    pos = next;
                }
                None => pos += 1,
            },
            b'[' => match decode_lua_long_string(bytes, pos) {
                Some((decoded, next)) => {
                    if decoded.starts_with(VM_MAGIC) {
                        return Some(decoded);
                    }
                    if let Some(payload) = decode_base64_payload_bytes(&decoded) {
                        return Some(payload);
                    }
                    pos = next;
                }
                None => pos += 1,
            },
            _ => pos += 1,
        }
    }
    None
}

#[must_use]
fn decode_base64_payload_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    let encoded: &str = std::str::from_utf8(bytes).ok()?;
    decode_base64_payload_run(encoded)
}

#[must_use]
fn decode_base64_payload_run(text: &str) -> Option<Vec<u8>> {
    let encoded: String = text
        .chars()
        .take_while(|c: &char| is_base64_payload_char(*c))
        .collect();
    if encoded.len() < 8 || encoded.len() > BASE64_PAYLOAD_CHAR_CAP {
        return None;
    }
    let decoded: Vec<u8> = decode_base64_standard(&encoded)?;
    if decoded.len() > LUA_STRING_PAYLOAD_CAP || !decoded.starts_with(VM_MAGIC) {
        return None;
    }
    Some(decoded)
}

#[inline]
#[must_use]
const fn is_base64_payload_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=')
}

fn decode_lua_quoted_string(bytes: &[u8], start: usize) -> Option<(Vec<u8>, usize)> {
    let quote: u8 = *bytes.get(start)?;
    if quote != b'\'' && quote != b'"' {
        return None;
    }
    let mut out: Vec<u8> = Vec::new();
    let mut pos: usize = start + 1;
    while pos < bytes.len() {
        let byte: u8 = bytes[pos];
        if byte == quote {
            return Some((out, pos + 1));
        }
        if byte == b'\\' {
            pos += 1;
            let escaped: u8 = *bytes.get(pos)?;
            if escaped.is_ascii_digit() {
                let mut value: u16 = 0;
                let mut digits: usize = 0;
                while digits < 3 && pos < bytes.len() && bytes[pos].is_ascii_digit() {
                    value = value
                        .checked_mul(10)?
                        .checked_add(u16::from(bytes[pos] - b'0'))?;
                    pos += 1;
                    digits += 1;
                }
                if value > u16::from(u8::MAX) {
                    return None;
                }
                out.push(value as u8);
                if out.len() > LUA_STRING_PAYLOAD_CAP {
                    return None;
                }
                continue;
            }
            if escaped == b'x' {
                let hi: u8 = hex_nibble(*bytes.get(pos + 1)?)?;
                let lo: u8 = hex_nibble(*bytes.get(pos + 2)?)?;
                out.push((hi << 4) | lo);
                pos += 3;
                if out.len() > LUA_STRING_PAYLOAD_CAP {
                    return None;
                }
                continue;
            }
            if escaped == b'z' {
                pos += 1;
                while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
                    pos += 1;
                }
                continue;
            }
            out.push(match escaped {
                b'a' => 7,
                b'b' => 8,
                b'f' => 12,
                b'n' => b'\n',
                b'r' => b'\r',
                b't' => b'\t',
                b'v' => 11,
                b'\\' => b'\\',
                b'\'' => b'\'',
                b'"' => b'"',
                b'\n' => b'\n',
                b'\r' => b'\n',
                other => other,
            });
        } else {
            out.push(byte);
        }
        pos += 1;
        if out.len() > LUA_STRING_PAYLOAD_CAP {
            return None;
        }
    }
    None
}

fn decode_lua_long_string(bytes: &[u8], start: usize) -> Option<(Vec<u8>, usize)> {
    if *bytes.get(start)? != b'[' {
        return None;
    }
    let mut eq_count: usize = 0;
    let mut open_end: usize = start + 1;
    while *bytes.get(open_end)? == b'=' {
        eq_count += 1;
        open_end += 1;
    }
    if *bytes.get(open_end)? != b'[' {
        return None;
    }
    let body_start: usize = open_end + 1;
    let mut pos: usize = body_start;
    while pos < bytes.len() {
        if bytes[pos] == b']' {
            let mut end_pos: usize = pos + 1;
            let mut matched: usize = 0;
            while matched < eq_count && *bytes.get(end_pos)? == b'=' {
                matched += 1;
                end_pos += 1;
            }
            if matched == eq_count && *bytes.get(end_pos)? == b']' {
                let body: &[u8] = &bytes[body_start..pos];
                if body.len() > LUA_STRING_PAYLOAD_CAP {
                    return None;
                }
                return Some((body.to_vec(), end_pos + 1));
            }
        }
        pos += 1;
    }
    None
}

#[must_use]
fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if hex.len() < 2 || !hex.len().is_multiple_of(2) {
        return None;
    }
    let raw: &[u8] = hex.as_bytes();
    let mut bytes: Vec<u8> = Vec::with_capacity(hex.len() / 2);
    let mut i: usize = 0;
    while i + 1 < raw.len() {
        let hi: u8 = hex_nibble(raw[i])?;
        let lo: u8 = hex_nibble(raw[i + 1])?;
        bytes.push((hi << 4) | lo);
        i += 2;
    }
    Some(bytes)
}

#[inline]
#[must_use]
fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Lift a `VMPAYLOAD=` blob encoded in disrobe's own `DVM1` reference container back to Lua.
pub fn devirt_to_peel(src: &[u8], text: &str, payload: &[u8], tag: &str) -> Result<PeelResult> {
    dbg_kv("devirt_to_peel.tag", || tag.to_owned());
    let Ok(dv): Result<Devirtualized> = devirtualize(payload, text) else {
        dbg_line(|| format!("{tag}: devirtualization failed, passing payload through"));
        return Ok(PeelResult::passthrough(
            src,
            vec![format!(
                "{tag} vm payload present but devirtualization failed (the opcode permutation and xor key could not be reconstructed by emulating the bootstrap init program)"
            )],
        ));
    };
    let lifted: LiftedProto = lift_proto_dialect(&dv.proto, LuaDialect::Lua51, 0);
    let recovered_strings: Vec<String> = dv
        .proto
        .constants
        .iter()
        .filter_map(|k: &LuaConstant| match k {
            LuaConstant::Str(s) => Some(s.clone()),
            _ => None,
        })
        .collect();
    let fully: bool = dv.report.handlers_recovered == dv.report.handlers_total
        && dv.report.opcodes_lifted == dv.report.opcodes_total
        && lifted.fully_structured;
    dbg_kv("devirt_to_peel.fully_recovered", || fully.to_string());
    dbg_kv("recovered_strings", || recovered_strings.len().to_string());
    let summary: String = format!(
        "{tag} devirt: handlers {}/{} ({}%), opcodes {}/{} ({}%), constants {} decoded, xor key 0x{:02X}",
        dv.report.handlers_recovered,
        dv.report.handlers_total,
        dv.report.handler_coverage_pct(),
        dv.report.opcodes_lifted,
        dv.report.opcodes_total,
        dv.report.opcode_coverage_pct(),
        dv.report.constants_decoded,
        dv.report.xor_key,
    );
    Ok(PeelResult {
        deobfuscated: lifted.source.into_bytes(),
        passes_run: vec![
            format!("{tag}-vm-bootstrap-emulate"),
            format!("{tag}-vm-handler-recovery"),
            format!("{tag}-vm-constant-decode"),
            format!("{tag}-vm-lift-lua51"),
        ],
        residual_markers: if fully {
            Vec::new()
        } else {
            vec![format!("{summary}; some handlers/opcodes unresolved")]
        },
        recovered_strings,
        fully_recovered: fully,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn push_u32_le(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn looped_slot_builder(slot_count: u32, step: u32, base: u32, mask: u32) -> Vec<u8> {
        let mut program: Vec<u8> = Vec::new();
        program.extend_from_slice(BUILDER_MAGIC);
        program.push(PB_PUSH_SEED);
        program.push(PB_PUSH_IMM);
        push_u32_le(&mut program, mask);
        program.push(PB_AND);
        program.push(PB_SET_XORKEY);
        program.push(PB_LOOP_BEGIN);
        push_u32_le(&mut program, slot_count);
        program.push(PB_PUSH_IDX);
        program.push(PB_PUSH_IMM);
        push_u32_le(&mut program, step);
        program.push(PB_MUL);
        program.push(PB_PUSH_IMM);
        push_u32_le(&mut program, base);
        program.push(PB_ADD);
        program.push(PB_PUSH_SEED);
        program.push(PB_ADD);
        program.push(PB_PUSH_IMM);
        push_u32_le(&mut program, 0xFF);
        program.push(PB_AND);
        program.push(PB_PUSH_IDX);
        program.push(PB_EMIT_MAP);
        program.push(PB_LOOP_END);
        program.push(PB_HALT);
        program
    }

    fn reference_encoded(idx: u32, seed: u32, step: u32, base: u32) -> u8 {
        let computed: u32 = idx.wrapping_mul(step).wrapping_add(base).wrapping_add(seed);
        (computed & 0xFF) as u8
    }

    #[test]
    fn emulator_runs_loop_and_derives_slot_table() {
        let slot_count: u32 = 6;
        let seed: u32 = 0x1234_5678;
        let step: u32 = 11;
        let base: u32 = 0x40;
        let mask: u32 = 0xFF;
        let builder: Vec<u8> = looped_slot_builder(slot_count, step, base, mask);

        let keys: BootstrapKeys = emulate_perm_builder(&builder, seed).expect("emulate");
        assert_eq!(keys.xor_key, Some((seed & mask) as u8));
        assert_eq!(keys.opmap.len(), slot_count as usize);
        for slot in 0..slot_count {
            let encoded: u8 = reference_encoded(slot, seed, step, base);
            assert_eq!(
                keys.opmap.get(&encoded).copied(),
                Some(slot as u8),
                "loop iteration {slot} must emit its computed encoded byte mapped to slot {slot}"
            );
        }
    }

    #[test]
    fn emulator_is_seed_sensitive() {
        let step: u32 = 9;
        let base: u32 = 0x30;
        let builder: Vec<u8> = looped_slot_builder(4, step, base, 0xFF);

        let a: BootstrapKeys = emulate_perm_builder(&builder, 0xAAAA).expect("emulate a");
        let b: BootstrapKeys = emulate_perm_builder(&builder, 0xBBBB).expect("emulate b");
        assert_ne!(
            a.opmap, b.opmap,
            "changing the seed must change the derived permutation"
        );
    }

    #[test]
    fn emulator_rejects_bad_magic() {
        let bogus: Vec<u8> = vec![0u8; 16];
        assert!(emulate_perm_builder(&bogus, 0).is_err());
    }

    #[test]
    fn emulator_bounds_runaway_loops() {
        let mut program: Vec<u8> = Vec::new();
        program.extend_from_slice(BUILDER_MAGIC);
        program.push(PB_LOOP_BEGIN);
        push_u32_le(&mut program, u32::MAX);
        program.push(PB_PUSH_IMM);
        push_u32_le(&mut program, 1);
        program.push(PB_PUSH_IMM);
        push_u32_le(&mut program, 1);
        program.push(PB_EMIT_MAP);
        program.push(PB_LOOP_END);
        program.push(PB_HALT);
        assert!(emulate_perm_builder(&program, 0).is_err());
    }

    #[test]
    fn vop_maps_to_lua51_opcode() {
        assert_eq!(canonical_vop_to_lua51(VOP_MOVE), Some(0));
        assert_eq!(canonical_vop_to_lua51(VOP_CALL), Some(28));
        assert_eq!(canonical_vop_to_lua51(VOP_RETURN), Some(30));
    }

    #[test]
    fn read_string_rejects_huge_length_before_allocating() {
        let mut data: Vec<u8> = Vec::new();
        push_u32_le(&mut data, u32::MAX);
        data.extend_from_slice(b"only four real payload bytes follow the length header");
        let mut c: VmCursor<'_> = VmCursor::new(&data, 0);
        let err: Error = c
            .read_string()
            .expect_err("u32::MAX length over a tiny buffer must be a bounded error, not an OOM");
        assert!(
            matches!(err, Error::LuauTruncated { .. }),
            "expected LuauTruncated structured error, got {err:?}"
        );
    }

    #[test]
    fn read_string_recovers_valid_length() {
        let payload: &[u8] = b"recovered";
        let mut data: Vec<u8> = Vec::new();
        push_u32_le(&mut data, payload.len() as u32);
        data.extend_from_slice(payload);
        let mut c: VmCursor<'_> = VmCursor::new(&data, 0);
        let recovered: String = c
            .read_string()
            .expect("valid length must recover the string");
        assert_eq!(recovered, "recovered");
    }

    #[test]
    fn embedded_payload_reads_decimal_lua_string() {
        let payload: &[u8] = b"DVM1\x01\x02\x03";
        let mut escaped: String = String::new();
        for byte in payload {
            escaped.push('\\');
            escaped.push_str(&byte.to_string());
        }
        let text: String = format!("-- Luraph\nlocal bc=\"{escaped}\"\nreturn bc");
        assert_eq!(extract_embedded_payload(&text).as_deref(), Some(payload));
    }

    #[test]
    fn embedded_payload_reads_hex_lua_string() {
        let text: &str = "-- Luraph\nlocal bc='\\x44\\x56\\x4d\\x31\\x09'";
        assert_eq!(
            extract_embedded_payload(text).as_deref(),
            Some(b"DVM1\x09".as_slice())
        );
    }

    #[test]
    fn embedded_payload_reads_base64_marker() {
        let text: &str = "-- Luraph\nVMPAYLOAD_B64=RFZNMQECAw==\nreturn true";
        assert_eq!(
            extract_embedded_payload(text).as_deref(),
            Some(b"DVM1\x01\x02\x03".as_slice())
        );
    }

    #[test]
    fn embedded_payload_reads_base64_lua_string() {
        let text: &str = "-- MoonSec v3\nlocal bc='RFZNMQk='\nreturn bc";
        assert_eq!(
            extract_embedded_payload(text).as_deref(),
            Some(b"DVM1\x09".as_slice())
        );
    }

    #[test]
    fn embedded_payload_reads_long_lua_string() {
        let text: &str = "local bc = [=[DVM1payload]=]";
        assert_eq!(
            extract_embedded_payload(text).as_deref(),
            Some(b"DVM1payload".as_slice())
        );
    }

    #[test]
    fn embedded_payload_ignores_non_vm_lua_string() {
        let text: &str = "local bc = '\\27\\76\\80\\72'";
        assert!(extract_embedded_payload(text).is_none());
    }
}
