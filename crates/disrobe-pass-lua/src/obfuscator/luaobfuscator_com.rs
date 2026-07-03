use crate::error::{Error, Result};
use crate::obfuscator::{DeobfOptions, LuaObfuscatorKind, ObfuscatorDetection, PeelResult};
use crate::reader::common::{LuaConstant, LuaDialect, LuaProto};

const MARKERS: &[&[u8]] = &[
    b"-- luaobfuscator.com",
    b"luaobfuscator_com",
    b"LOC_FREE_TIER",
    b"LuaObfuscator.com",
    b"luaobfuscator.com",
    b"Welcome to LuaObfuscator",
];

const DISPATCH_FINGERPRINTS: &[&[u8]] = &[
    b"local v0=tonumber;local v1=string.byte;local v2=string.char;local v3=string.sub",
    b"local v4=string.gsub;local v5=string.rep;local v6=table.concat;local v7=table.insert",
    b"local v8=math.ldexp",
    b"local v9=getfenv or function()",
];

const RLE_DISPATCH_HINT: &[u8] = b"if (v1(v30,2)==81) then";

const PACK_PREFIX_LEN: usize = 4;
const RLE_MARKER: u8 = b'Q';

const CONST_TAG_BOOL: u8 = 1;
const CONST_TAG_NUMBER: u8 = 2;
const CONST_TAG_STRING: u8 = 3;

const MAX_PROTO_DEPTH: usize = 200;
const MAX_LOC_CONSTANTS: usize = 1usize << 16;
const MAX_LOC_INSTRUCTIONS: usize = 1usize << 20;
const MAX_LOC_PROTOS: usize = 1usize << 16;
const MAX_LOC_STRING_BYTES: usize = 16usize << 20;

#[must_use]
pub fn detect(src: &[u8]) -> Option<ObfuscatorDetection> {
    let mut found: Vec<String> = Vec::new();
    for m in MARKERS {
        if disrobe_core::byte_search::contains(src, m) {
            found.push(String::from_utf8_lossy(m).into_owned());
        }
    }
    if !found.is_empty() {
        return Some(ObfuscatorDetection {
            kind: LuaObfuscatorKind::LuaObfuscatorCom,
            variant: Some("free-tier".to_owned()),
            confidence: 80,
            markers: found,
        });
    }
    fingerprint_detect(src)
}

fn fingerprint_detect(src: &[u8]) -> Option<ObfuscatorDetection> {
    let head: &[u8] = &src[..src.len().min(4096)];
    let mut hits: u32 = 0;
    let mut evidence: Vec<String> = Vec::new();
    for fp in DISPATCH_FINGERPRINTS {
        if disrobe_core::byte_search::contains(head, fp) {
            hits += 1;
        }
    }
    if hits < 3 {
        return None;
    }
    let rle_present: bool = disrobe_core::byte_search::contains(src, RLE_DISPATCH_HINT);
    if !rle_present {
        return None;
    }
    evidence.push("LuaObfuscator dispatch table fingerprint".to_owned());
    evidence.push("RLE marker v1(v30,2)==81 (Q-prefix)".to_owned());
    Some(ObfuscatorDetection {
        kind: LuaObfuscatorKind::LuaObfuscatorCom,
        variant: Some("free-tier-vm".to_owned()),
        confidence: 72,
        markers: evidence,
    })
}

pub fn peel(src: &[u8], _opts: &DeobfOptions) -> Result<PeelResult> {
    if detect(src).is_none() {
        return Err(Error::NoObfuscatorSignature("luaobfuscator.com"));
    }
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(src);

    if let Some(packed) = extract_packed_token(&text) {
        let raw: Vec<u8> = unpack_hex_rle(&packed);
        if let Ok(chunk) = deserialize_chunk(&raw) {
            return Ok(chunk_peel_result(&chunk, packed.len(), raw.len()));
        }
        return Ok(PeelResult::passthrough(
            src,
            vec![format!(
                "luaobfuscator.com free-tier: hex+RLE-unpacked the embedded bytecode ({} packed -> {} raw bytes) but the deserialized chunk layout did not validate",
                packed.len(),
                raw.len()
            )],
        ));
    }

    Ok(PeelResult::passthrough(
        src,
        vec![
            "luaobfuscator.com free-tier vm detected, but no LOL!-prefixed hex+RLE bytecode literal could be located in this artifact".to_owned(),
        ],
    ))
}

#[derive(Debug, Clone, PartialEq)]
struct LocChunk {
    constants: Vec<LuaConstant>,
    param_count: u8,
    instrs: Vec<LocInstr>,
    protos: Vec<LocChunk>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LocInstr {
    op: u16,
    a: u16,
    b: i64,
    c: u16,
    itype: u8,
}

struct ChunkCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ChunkCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn u8(&mut self) -> Result<u8> {
        let byte: u8 = *self
            .data
            .get(self.pos)
            .ok_or(Error::LuauTruncated { offset: self.pos })?;
        self.pos += 1;
        Ok(byte)
    }

    fn u16(&mut self) -> Result<u16> {
        let lo: u16 = u16::from(self.u8()?);
        let hi: u16 = u16::from(self.u8()?);
        Ok((hi << 8) | lo)
    }

    fn u32(&mut self) -> Result<u32> {
        let b0: u32 = u32::from(self.u8()?);
        let b1: u32 = u32::from(self.u8()?);
        let b2: u32 = u32::from(self.u8()?);
        let b3: u32 = u32::from(self.u8()?);
        Ok(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24))
    }

    fn f64(&mut self) -> Result<f64> {
        let mut raw: [u8; 8] = [0u8; 8];
        for slot in &mut raw {
            *slot = self.u8()?;
        }
        Ok(f64::from_le_bytes(raw))
    }

    fn lstring(&mut self) -> Result<String> {
        let len: u32 = self.u32()?;
        if len == 0 {
            return Ok(String::new());
        }
        let n: usize = checked_loc_count("loc string byte", len, MAX_LOC_STRING_BYTES)?;
        let end: usize = self
            .pos
            .checked_add(n)
            .filter(|e: &usize| *e <= self.data.len())
            .ok_or(Error::LuauTruncated { offset: self.pos })?;
        let bytes: &[u8] = &self.data[self.pos..end];
        self.pos = end;
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }
}

fn checked_loc_count(section: &'static str, raw: u32, limit: usize) -> Result<usize> {
    let count: usize = usize::try_from(raw).map_err(|_| Error::LimitExceeded {
        section,
        count: u64::from(raw),
        limit,
    })?;
    if count > limit {
        return Err(Error::LimitExceeded {
            section,
            count: u64::from(raw),
            limit,
        });
    }
    Ok(count)
}

fn read_chunk(c: &mut ChunkCursor<'_>, depth: usize) -> Result<LocChunk> {
    if depth > MAX_PROTO_DEPTH {
        return Err(Error::ProtoNestingTooDeep(depth));
    }
    let const_count: usize = checked_loc_count("loc constant", c.u32()?, MAX_LOC_CONSTANTS)?;
    let mut constants: Vec<LuaConstant> = Vec::with_capacity(const_count);
    for _ in 0..const_count {
        let tag: u8 = c.u8()?;
        let value: LuaConstant = match tag {
            CONST_TAG_BOOL => LuaConstant::Bool(c.u8()? != 0),
            CONST_TAG_NUMBER => LuaConstant::Number(c.f64()?),
            CONST_TAG_STRING => LuaConstant::Str(c.lstring()?),
            other => return Err(Error::BadConstantTag(other, c.pos)),
        };
        constants.push(value);
    }

    let param_count: u8 = c.u8()?;

    let instr_count: usize = checked_loc_count("loc instruction", c.u32()?, MAX_LOC_INSTRUCTIONS)?;
    let mut instrs: Vec<LocInstr> = Vec::with_capacity(instr_count);
    for _ in 0..instr_count {
        let desc: u8 = c.u8()?;
        if desc & 1 != 0 {
            continue;
        }
        let itype: u8 = (desc >> 1) & 3;
        let op: u16 = c.u16()?;
        let a: u16 = c.u16()?;
        let (b, cc): (i64, u16) = match itype {
            0 => (i64::from(c.u16()?), c.u16()?),
            1 => (i64::from(c.u32()?), 0),
            2 => (i64::from(c.u32()?) - (1 << 16), 0),
            _ => (i64::from(c.u32()?) - (1 << 16), c.u16()?),
        };
        instrs.push(LocInstr {
            op,
            a,
            b,
            c: cc,
            itype,
        });
    }

    let proto_count: usize = checked_loc_count("loc proto", c.u32()?, MAX_LOC_PROTOS)?;
    let mut protos: Vec<LocChunk> = Vec::with_capacity(proto_count);
    for _ in 0..proto_count {
        protos.push(read_chunk(c, depth + 1)?);
    }

    Ok(LocChunk {
        constants,
        param_count,
        instrs,
        protos,
    })
}

fn deserialize_chunk(raw: &[u8]) -> Result<LocChunk> {
    let mut c: ChunkCursor<'_> = ChunkCursor::new(raw);
    let chunk: LocChunk = read_chunk(&mut c, 0)?;
    if c.pos != raw.len() {
        return Err(Error::BootstrapEmulationFailed(
            "loc chunk did not consume the unpacked stream exactly",
        ));
    }
    Ok(chunk)
}

fn chunk_to_proto(chunk: &LocChunk) -> LuaProto {
    let mut max_reg: u8 = 2;
    let mut code: Vec<u32> = Vec::with_capacity(chunk.instrs.len());
    for ins in &chunk.instrs {
        max_reg = max_reg.max(saturating_u16_to_u8(ins.a));
        code.push(encode_word(ins));
    }
    let protos: Vec<LuaProto> = chunk.protos.iter().map(chunk_to_proto).collect();
    LuaProto {
        source: Some("luaobfuscator-com-devirtualized".to_owned()),
        line_defined: 0,
        last_line_defined: 0,
        num_params: chunk.param_count,
        is_vararg: 2,
        max_stack_size: max_reg.saturating_add(2).max(2),
        code,
        constants: chunk.constants.clone(),
        protos,
        source_lines: Vec::new(),
        locals: Vec::new(),
        upvalues: Vec::new(),
    }
}

fn saturating_u16_to_u8(value: u16) -> u8 {
    u8::try_from(value).unwrap_or(u8::MAX)
}

fn encode_word(ins: &LocInstr) -> u32 {
    let op: u32 = u32::from(ins.op) & 0x3F;
    let a: u32 = (u32::from(ins.a)) & 0xFF;
    match ins.itype {
        1 => {
            let bx: u32 = (ins.b.clamp(0, 0x3FFFF) as u32) & 0x3FFFF;
            op | (a << 6) | (bx << 14)
        }
        2 => {
            let sbx: i64 = ins.b + 0x1FFFF;
            let bx: u32 = (sbx.clamp(0, 0x3FFFF) as u32) & 0x3FFFF;
            op | (a << 6) | (bx << 14)
        }
        _ => {
            let b: u32 = (ins.b.clamp(0, 0x1FF) as u32) & 0x1FF;
            let cc: u32 = u32::from(ins.c) & 0x1FF;
            op | (a << 6) | (cc << 14) | (b << 23)
        }
    }
}

fn collect_strings(chunk: &LocChunk, out: &mut Vec<String>) {
    for k in &chunk.constants {
        if let LuaConstant::Str(s) = k {
            out.push(s.clone());
        }
    }
    for p in &chunk.protos {
        collect_strings(p, out);
    }
}

fn count_constants(chunk: &LocChunk) -> usize {
    chunk.constants.len() + chunk.protos.iter().map(count_constants).sum::<usize>()
}

fn count_protos(chunk: &LocChunk) -> usize {
    chunk.protos.len() + chunk.protos.iter().map(count_protos).sum::<usize>()
}

fn is_readable_constant(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let printable: usize = s
        .chars()
        .filter(|c: &char| c.is_ascii_graphic() || *c == ' ' || *c == '_' || *c == '.')
        .count();
    printable * 100 >= s.chars().count() * 80
}

fn chunk_peel_result(chunk: &LocChunk, packed_len: usize, raw_len: usize) -> PeelResult {
    let lifted: crate::decompile::lift::LiftedProto =
        crate::decompile::lift::lift_proto_dialect(&chunk_to_proto(chunk), LuaDialect::Lua51, 0);

    let mut all_strings: Vec<String> = Vec::new();
    collect_strings(chunk, &mut all_strings);
    let readable: Vec<String> = all_strings
        .iter()
        .filter(|s: &&String| is_readable_constant(s))
        .cloned()
        .collect();
    let residual_encrypted: usize = all_strings.len() - readable.len();
    let total_consts: usize = count_constants(chunk);
    let proto_count: usize = count_protos(chunk);

    let mut residual_markers: Vec<String> = Vec::new();
    let summary: String = format!(
        "luaobfuscator.com free-tier: hex+RLE-unpacked {packed_len}->{raw_len} bytes, deserialized the IronBrew2-lineage vm chunk ({total_consts} constants across {} functions); recovered {} readable string constant(s) from the static pool",
        proto_count + 1,
        readable.len(),
    );
    residual_markers.push(summary);
    if residual_encrypted > 0 {
        residual_markers.push(format!(
            "{residual_encrypted} string constant(s) carry a second per-string cipher layer (ciphertext paired with its own static key constant) that the vm applies through its in-band bit32.bxor decrypt routine; both halves are present statically and are surfaced in the lifted vm body, not pre-decoded by the unpacker"
        ));
    }

    PeelResult {
        deobfuscated: lifted.source.into_bytes(),
        passes_run: vec![
            "luaobfuscator-com-hex-rle-unpack".to_owned(),
            "luaobfuscator-com-chunk-deserialize".to_owned(),
            "luaobfuscator-com-constant-pool-recover".to_owned(),
            "luaobfuscator-com-vm-lift-lua51".to_owned(),
        ],
        residual_markers,
        recovered_strings: readable,
        fully_recovered: false,
    }
}

#[must_use]
fn extract_packed_token(text: &str) -> Option<String> {
    let bytes: &[u8] = text.as_bytes();
    let mut best: Option<(usize, usize)> = None;
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' || bytes[i] == b'\'' {
            let quote: u8 = bytes[i];
            let start: usize = i + 1;
            let mut j: usize = start;
            while j < bytes.len() && bytes[j] != quote {
                j += 1;
            }
            if j < bytes.len() {
                let inner: &str = &text[start..j];
                if is_loc_packed_literal(inner)
                    && best.is_none_or(|(_, len): (usize, usize)| inner.len() > len)
                {
                    best = Some((start, inner.len()));
                }
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    best.map(|(start, len): (usize, usize)| text[start..start + len].to_owned())
}

#[must_use]
fn is_loc_packed_literal(s: &str) -> bool {
    if s.len() < PACK_PREFIX_LEN + 2 {
        return false;
    }
    let body: &[u8] = &s.as_bytes()[PACK_PREFIX_LEN..];
    if !body.len().is_multiple_of(2) {
        return false;
    }
    body.iter().all(|b: &u8| {
        b.is_ascii_digit() || (*b >= b'A' && *b <= b'F') || (*b >= b'a' && *b <= b'f') || *b == b'Q'
    })
}

#[must_use]
pub fn unpack_hex_rle(packed: &str) -> Vec<u8> {
    let body: &[u8] = &packed.as_bytes()[packed.len().min(PACK_PREFIX_LEN)..];
    let mut out: Vec<u8> = Vec::with_capacity(body.len() / 2);
    let mut run: Option<usize> = None;
    let mut i: usize = 0;
    while i + 1 < body.len() {
        let g0: u8 = body[i];
        let g1: u8 = body[i + 1];
        i += 2;
        if g1 == RLE_MARKER {
            run = decimal_digit(g0).map(usize::from);
            continue;
        }
        let (Some(hi), Some(lo)): (Option<u8>, Option<u8>) = (hex_nibble(g0), hex_nibble(g1))
        else {
            run = None;
            continue;
        };
        let byte: u8 = (hi << 4) | lo;
        match run.take() {
            Some(count) => {
                for _ in 0..count {
                    out.push(byte);
                }
            }
            None => out.push(byte),
        }
    }
    out
}

#[inline]
#[must_use]
fn decimal_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        _ => None,
    }
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn unpack_inverts_hex_groups_and_runs() {
        let packed: &str = "LOL!00013Q0742";
        let raw: Vec<u8> = unpack_hex_rle(packed);
        assert_eq!(raw, vec![0x00, 0x01, 0x07, 0x07, 0x07, 0x42]);
    }

    #[test]
    fn loc_literal_recognized_only_with_prefix_and_hex_body() {
        assert!(is_loc_packed_literal("LOL!0001"));
        assert!(is_loc_packed_literal("LOL!2Q00"));
        assert!(!is_loc_packed_literal("0001"));
        assert!(!is_loc_packed_literal("LOL!00G1"));
    }

    #[test]
    fn deserialize_round_trips_a_minimal_chunk() {
        let mut raw: Vec<u8> = Vec::new();
        raw.extend_from_slice(&1u32.to_le_bytes());
        raw.push(CONST_TAG_STRING);
        raw.extend_from_slice(&5u32.to_le_bytes());
        raw.extend_from_slice(b"hello");
        raw.push(0);
        raw.extend_from_slice(&0u32.to_le_bytes());
        raw.extend_from_slice(&0u32.to_le_bytes());
        let chunk: LocChunk = deserialize_chunk(&raw).expect("deserialize");
        let mut strings: Vec<String> = Vec::new();
        collect_strings(&chunk, &mut strings);
        assert_eq!(strings, vec!["hello".to_owned()]);
    }

    #[test]
    fn deserialize_rejects_huge_constant_count_before_reserve() {
        let mut raw: Vec<u8> = Vec::new();
        raw.extend_from_slice(&u32::MAX.to_le_bytes());
        let err: Error = deserialize_chunk(&raw).expect_err("constant count cap");
        assert!(matches!(
            err,
            Error::LimitExceeded {
                section: "loc constant",
                count: 4_294_967_295,
                ..
            }
        ));
    }

    #[test]
    fn deserialize_rejects_huge_instruction_count_before_reserve() {
        let mut raw: Vec<u8> = Vec::new();
        raw.extend_from_slice(&0u32.to_le_bytes());
        raw.push(0);
        raw.extend_from_slice(&u32::MAX.to_le_bytes());
        let err: Error = deserialize_chunk(&raw).expect_err("instruction count cap");
        assert!(matches!(
            err,
            Error::LimitExceeded {
                section: "loc instruction",
                count: 4_294_967_295,
                ..
            }
        ));
    }

    #[test]
    fn deserialize_rejects_huge_proto_count_before_reserve() {
        let mut raw: Vec<u8> = Vec::new();
        raw.extend_from_slice(&0u32.to_le_bytes());
        raw.push(0);
        raw.extend_from_slice(&0u32.to_le_bytes());
        raw.extend_from_slice(&u32::MAX.to_le_bytes());
        let err: Error = deserialize_chunk(&raw).expect_err("proto count cap");
        assert!(matches!(
            err,
            Error::LimitExceeded {
                section: "loc proto",
                count: 4_294_967_295,
                ..
            }
        ));
    }

    #[test]
    fn deserialize_rejects_huge_string_len_before_reserve() {
        let mut raw: Vec<u8> = Vec::new();
        raw.extend_from_slice(&1u32.to_le_bytes());
        raw.push(CONST_TAG_STRING);
        raw.extend_from_slice(&u32::MAX.to_le_bytes());
        let err: Error = deserialize_chunk(&raw).expect_err("string len cap");
        assert!(matches!(
            err,
            Error::LimitExceeded {
                section: "loc string byte",
                count: 4_294_967_295,
                ..
            }
        ));
    }
}
