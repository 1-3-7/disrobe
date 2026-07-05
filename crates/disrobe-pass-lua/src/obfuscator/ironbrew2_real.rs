use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::reader::common::LuaConstant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    Plain,
    Lzw,
}

#[derive(Debug, Clone)]
pub struct VmKeys {
    pub xor_key: u8,
    pub const_bool: u8,
    pub const_float: u8,
    pub const_string: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IbType {
    Abc,
    ABx,
    AsBx,
    AsBxC,
}

#[derive(Debug, Clone)]
pub struct IbInstr {
    pub itype: IbType,
    pub mask: u8,
    pub op: u16,
    pub a: i64,
    pub b: i64,
    pub c: i64,
}

#[derive(Debug, Clone)]
pub struct IbChunk {
    pub constants: Vec<LuaConstant>,
    pub param_count: u8,
    pub instrs: Vec<IbInstr>,
    pub functions: Vec<IbChunk>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkStep {
    ParameterCount,
    Instructions,
    Functions,
    LineInfo,
}

#[must_use]
pub fn strip_watermark(src: &str) -> &str {
    src.find("]]")
        .map_or(src, |idx: usize| src[idx + 2..].trim_start())
}

#[must_use]
pub fn detect_real(src: &str) -> bool {
    let has_brand: bool = src.contains("IronBrew") || src.contains("Ironbrew");
    let body: &str = strip_watermark(src);
    let has_payload: bool = body.contains("ByteString") || body.contains("16777216");
    let has_deser: bool = body.contains("Deserialize") || body.contains("__index");
    has_brand && has_payload && has_deser
}

pub fn decode_bytestring(body: &str) -> Result<(Vec<u8>, Compression)> {
    if let Some(plain) = extract_plain_bytestring(body) {
        return Ok((plain, Compression::Plain));
    }
    if let Some(literal) = extract_compressed_literal(body) {
        let raw: Vec<u8> = lzw_decompress_base36(&literal)?;
        return Ok((raw, Compression::Lzw));
    }
    if let Some(literal) = longest_base36_literal(body) {
        let raw: Vec<u8> = lzw_decompress_base36(&literal)?;
        return Ok((raw, Compression::Lzw));
    }
    Err(Error::BootstrapEmulationFailed(
        "no ByteString payload in ironbrew2 vm",
    ))
}

#[must_use]
fn longest_base36_literal(body: &str) -> Option<String> {
    let bytes: &[u8] = body.as_bytes();
    let mut best: Option<String> = None;
    let mut best_len: usize = 0;
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] == b'\'' || bytes[i] == b'"' {
            let quote: u8 = bytes[i];
            let start: usize = i + 1;
            let mut j: usize = start;
            while j < bytes.len() && bytes[j] != quote {
                j += 1;
            }
            if j < bytes.len() {
                let literal: &str = &body[start..j];
                let is_b36: bool = literal.len() > 16
                    && literal
                        .chars()
                        .all(|c: char| c.is_ascii_digit() || c.is_ascii_uppercase());
                if is_b36 && literal.len() > best_len {
                    best_len = literal.len();
                    best = Some(literal.to_owned());
                }
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    best
}

#[must_use]
fn extract_plain_bytestring(body: &str) -> Option<Vec<u8>> {
    let marker: usize = body.find("ByteString")?;
    let after: &str = &body[marker..];
    let eq: usize = after.find('=')?;
    let rest: &str = after[eq + 1..].trim_start();
    let quote: char = rest.chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let inner: &str = &rest[1..];
    let end: usize = inner.find(quote)?;
    parse_decimal_escapes(&inner[..end])
}

#[must_use]
fn parse_decimal_escapes(literal: &str) -> Option<Vec<u8>> {
    let bytes: &[u8] = literal.as_bytes();
    let mut out: Vec<u8> = Vec::new();
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' {
            return None;
        }
        i += 1;
        let mut value: u32 = 0;
        let mut digits: usize = 0;
        while i < bytes.len() && digits < 3 && bytes[i].is_ascii_digit() {
            value = value * 10 + u32::from(bytes[i] - b'0');
            i += 1;
            digits += 1;
        }
        if digits == 0 {
            return None;
        }
        out.push((value & 0xFF) as u8);
    }
    if out.is_empty() { None } else { Some(out) }
}

#[must_use]
fn extract_compressed_literal(body: &str) -> Option<String> {
    let dpos: usize = body.find("decompress")?;
    find_first_base36_string(&body[dpos..])
}

#[must_use]
fn find_first_base36_string(s: &str) -> Option<String> {
    let bytes: &[u8] = s.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] == b'\'' || bytes[i] == b'"' {
            let quote: u8 = bytes[i];
            let start: usize = i + 1;
            let mut j: usize = start;
            while j < bytes.len() && bytes[j] != quote {
                j += 1;
            }
            if j >= bytes.len() {
                return None;
            }
            let literal: &str = &s[start..j];
            if !literal.is_empty()
                && literal
                    .chars()
                    .all(|c: char| c.is_ascii_digit() || c.is_ascii_uppercase())
            {
                return Some(literal.to_owned());
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    None
}

const LZW_MAX_OUTPUT: usize = 64 << 20;
const LZW_MAX_DICT: usize = 1 << 20;
const IB_CONST_COUNT_CAP: usize = 1 << 16;
const IB_INSTRUCTION_COUNT_CAP: usize = 1 << 20;
const IB_FUNCTION_COUNT_CAP: usize = 1 << 16;
const IB_LINEINFO_COUNT_CAP: usize = 1 << 20;

pub fn lzw_decompress_base36(s: &str) -> Result<Vec<u8>> {
    let chars: Vec<char> = s.chars().collect();
    let mut i: usize = 0;
    let read_token = |i: &mut usize| -> Option<u64> {
        let len: usize = base36_digit(*chars.get(*i)?)? as usize;
        *i += 1;
        if len == 0 || *i + len > chars.len() {
            return None;
        }
        let mut value: u64 = 0;
        for k in 0..len {
            value = value * 36 + u64::from(base36_digit(chars[*i + k])?);
        }
        *i += len;
        Some(value)
    };
    let mut dictionary: Vec<Vec<u8>> = (0..256u32).map(|n: u32| vec![n as u8]).collect();
    let first: u64 =
        read_token(&mut i).ok_or(Error::BootstrapEmulationFailed("lzw stream malformed"))?;
    let first_idx: usize = usize::try_from(first)
        .map_err(|_| Error::BootstrapEmulationFailed("lzw first token range"))?;
    let mut prev: Vec<u8> = dictionary
        .get(first_idx)
        .cloned()
        .ok_or(Error::BootstrapEmulationFailed("lzw first token undefined"))?;
    let mut out: Vec<u8> = prev.clone();
    while i < chars.len() {
        let Some(tok): Option<u64> = read_token(&mut i) else {
            break;
        };
        let k_idx: usize =
            usize::try_from(tok).map_err(|_| Error::BootstrapEmulationFailed("lzw token range"))?;
        let entry: Vec<u8> = match k_idx.cmp(&dictionary.len()) {
            std::cmp::Ordering::Less => dictionary[k_idx].clone(),
            std::cmp::Ordering::Equal => {
                let mut ext: Vec<u8> = prev.clone();
                ext.push(prev[0]);
                ext
            }
            std::cmp::Ordering::Greater => {
                return Err(Error::BootstrapEmulationFailed("lzw token gap"));
            }
        };
        if out.len().saturating_add(entry.len()) > LZW_MAX_OUTPUT {
            return Err(Error::BootstrapEmulationFailed(
                "lzw output exceeds ceiling",
            ));
        }
        out.extend_from_slice(&entry);
        if dictionary.len() < LZW_MAX_DICT {
            let mut new_entry: Vec<u8> = prev.clone();
            new_entry.push(entry[0]);
            dictionary.push(new_entry);
        }
        prev = entry;
    }
    Ok(out)
}

#[must_use]
fn base36_digit(c: char) -> Option<u32> {
    match c {
        '0'..='9' => Some(c as u32 - '0' as u32),
        'A'..='Z' => Some(c as u32 - 'A' as u32 + 10),
        _ => None,
    }
}

pub fn recover_keys(body: &str) -> Result<VmKeys> {
    let xor_key: u8 =
        find_xor_key(body).ok_or(Error::BootstrapEmulationFailed("vm xor key not found"))?;
    let (const_bool, const_float, const_string): (u8, u8, u8) = find_const_mapping(body).ok_or(
        Error::BootstrapEmulationFailed("constant mapping not found"),
    )?;
    Ok(VmKeys {
        xor_key,
        const_bool,
        const_float,
        const_string,
    })
}

#[must_use]
fn find_xor_key(body: &str) -> Option<u8> {
    let bytes: &[u8] = body.as_bytes();
    let mut counts: BTreeMap<u8, usize> = BTreeMap::new();
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i] == b',' && i > 0 && bytes[i - 1].is_ascii_alphanumeric() {
            let mut j: usize = i + 1;
            let mut value: u32 = 0;
            let mut digits: usize = 0;
            while j < bytes.len() && bytes[j].is_ascii_digit() && digits < 3 {
                value = value * 10 + u32::from(bytes[j] - b'0');
                j += 1;
                digits += 1;
            }
            if digits > 0 && j < bytes.len() && bytes[j] == b')' && value <= 255 {
                *counts.entry(value as u8).or_insert(0) += 1;
            }
            i = j;
        } else {
            i += 1;
        }
    }
    counts
        .into_iter()
        .max_by_key(|(_, n): &(u8, usize)| *n)
        .map(|(k, _): (u8, usize)| k)
}

#[must_use]
fn find_const_mapping(body: &str) -> Option<(u8, u8, u8)> {
    let compact: String = body.chars().filter(|c: &char| !c.is_whitespace()).collect();
    let bytes: &[u8] = compact.as_bytes();
    let bool_pos: usize = compact.find("~=0)")?;
    let bool_tag: u8 = tag_before(&compact, bool_pos)?;
    let mut after: Vec<(usize, u8)> = Vec::new();
    let mut from: usize = 0;
    while let Some(rel) = compact[from..].find("==") {
        let abs: usize = from + rel;
        let mut j: usize = abs + 2;
        let mut value: u32 = 0;
        let mut digits: usize = 0;
        while j < bytes.len() && bytes[j].is_ascii_digit() && digits < 3 {
            value = value * 10 + u32::from(bytes[j] - b'0');
            j += 1;
            digits += 1;
        }
        if digits > 0 && j < bytes.len() && bytes[j] == b')' && abs > bool_pos {
            after.push((abs, value as u8));
        }
        from = abs + 2;
    }
    after.sort_by_key(|(p, _): &(usize, u8)| *p);
    if after.len() < 2 {
        return None;
    }
    Some((bool_tag, after[0].1, after[1].1))
}

#[must_use]
fn tag_before(compact: &str, pos: usize) -> Option<u8> {
    let prefix: &str = &compact[..pos];
    let eqs: usize = prefix.rfind("==")?;
    let bytes: &[u8] = compact.as_bytes();
    let mut j: usize = eqs + 2;
    let mut value: u32 = 0;
    let mut digits: usize = 0;
    while j < bytes.len() && bytes[j].is_ascii_digit() && digits < 3 {
        value = value * 10 + u32::from(bytes[j] - b'0');
        j += 1;
        digits += 1;
    }
    if digits == 0 {
        return None;
    }
    Some(value as u8)
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
    key: u8,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8], key: u8) -> Self {
        Self { data, pos: 0, key }
    }
    fn u8(&mut self) -> Result<u8> {
        let b: u8 = *self
            .data
            .get(self.pos)
            .ok_or(Error::LuauTruncated { offset: self.pos })?;
        self.pos += 1;
        Ok(b ^ self.key)
    }
    fn u16(&mut self) -> Result<u16> {
        let w: u16 = u16::from(self.u8()?);
        let x: u16 = u16::from(self.u8()?);
        Ok((x << 8) | w)
    }
    fn u32(&mut self) -> Result<u32> {
        let a: u32 = u32::from(self.u8()?);
        let b: u32 = u32::from(self.u8()?);
        let c: u32 = u32::from(self.u8()?);
        let d: u32 = u32::from(self.u8()?);
        Ok((d << 24) | (c << 16) | (b << 8) | a)
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
        let n: usize = len as usize;
        let mut bytes: Vec<u8> = Vec::with_capacity(n.min(1 << 20));
        for _ in 0..n {
            bytes.push(self.u8()?);
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }
}

fn checked_count(
    raw: u32,
    limit: usize,
    section: &'static str,
    cursor: &Cursor<'_>,
    min_entry_width: usize,
) -> Result<usize> {
    let count: usize = raw as usize;
    if count > limit {
        return Err(Error::LimitExceeded {
            section,
            count: u64::from(raw),
            limit,
        });
    }
    let needed: usize = count
        .checked_mul(min_entry_width)
        .ok_or(Error::LimitExceeded {
            section,
            count: u64::from(raw),
            limit,
        })?;
    let remaining: usize = cursor.remaining();
    if needed > remaining {
        return Err(Error::Truncated {
            offset: cursor.pos,
            needed,
            had: remaining,
        });
    }
    Ok(count)
}

fn read_chunk(
    c: &mut Cursor<'_>,
    keys: &VmKeys,
    steps: &[ChunkStep],
    depth: usize,
) -> Result<IbChunk> {
    if depth > 200 {
        return Err(Error::ProtoNestingTooDeep(depth));
    }
    let const_count: usize =
        checked_count(c.u32()?, IB_CONST_COUNT_CAP, "ironbrew constants", c, 1)?;
    let mut constants: Vec<LuaConstant> = Vec::with_capacity(const_count);
    for _ in 0..const_count {
        let tag: u8 = c.u8()?;
        let value: LuaConstant = if tag == keys.const_bool {
            LuaConstant::Bool(c.u8()? != 0)
        } else if tag == keys.const_float {
            LuaConstant::Number(c.f64()?)
        } else if tag == keys.const_string {
            LuaConstant::Str(c.lstring()?)
        } else {
            return Err(Error::BadConstantTag(tag, c.pos));
        };
        constants.push(value);
    }
    let mut param_count: u8 = 0;
    let mut instrs: Vec<IbInstr> = Vec::new();
    let mut functions: Vec<IbChunk> = Vec::new();
    for step in steps {
        match step {
            ChunkStep::ParameterCount => param_count = c.u8()?,
            ChunkStep::Instructions => {
                let count: usize = checked_count(
                    c.u32()?,
                    IB_INSTRUCTION_COUNT_CAP,
                    "ironbrew instructions",
                    c,
                    1,
                )?;
                instrs.reserve(count);
                for _ in 0..count {
                    let desc: u8 = c.u8()?;
                    if desc & 1 != 0 {
                        continue;
                    }
                    let type_bits: u8 = (desc >> 1) & 3;
                    let mask: u8 = (desc >> 3) & 7;
                    let op: u16 = c.u16()?;
                    let a: i64 = i64::from(c.u16()?);
                    let (itype, b, cc): (IbType, i64, i64) = match type_bits {
                        0 => (IbType::Abc, i64::from(c.u16()?), i64::from(c.u16()?)),
                        1 => (IbType::ABx, i64::from(c.u32()?), 0),
                        2 => (IbType::AsBx, i64::from(c.u32()?) - (1 << 16), 0),
                        _ => (
                            IbType::AsBxC,
                            i64::from(c.u32()?) - (1 << 16),
                            i64::from(c.u16()?),
                        ),
                    };
                    instrs.push(IbInstr {
                        itype,
                        mask,
                        op,
                        a,
                        b,
                        c: cc,
                    });
                }
            }
            ChunkStep::Functions => {
                let count: usize =
                    checked_count(c.u32()?, IB_FUNCTION_COUNT_CAP, "ironbrew functions", c, 1)?;
                for _ in 0..count {
                    functions.push(read_chunk(c, keys, steps, depth + 1)?);
                }
            }
            ChunkStep::LineInfo => {
                let count: usize =
                    checked_count(c.u32()?, IB_LINEINFO_COUNT_CAP, "ironbrew lineinfo", c, 4)?;
                for _ in 0..count {
                    let _ = c.u32()?;
                }
            }
        }
    }
    Ok(IbChunk {
        constants,
        param_count,
        instrs,
        functions,
    })
}

pub fn deserialize_chunk(payload: &[u8], keys: &VmKeys) -> Result<IbChunk> {
    let candidates: [[ChunkStep; 4]; 6] = [
        [
            ChunkStep::ParameterCount,
            ChunkStep::Instructions,
            ChunkStep::Functions,
            ChunkStep::LineInfo,
        ],
        [
            ChunkStep::ParameterCount,
            ChunkStep::Functions,
            ChunkStep::Instructions,
            ChunkStep::LineInfo,
        ],
        [
            ChunkStep::Instructions,
            ChunkStep::ParameterCount,
            ChunkStep::Functions,
            ChunkStep::LineInfo,
        ],
        [
            ChunkStep::Instructions,
            ChunkStep::Functions,
            ChunkStep::ParameterCount,
            ChunkStep::LineInfo,
        ],
        [
            ChunkStep::Functions,
            ChunkStep::ParameterCount,
            ChunkStep::Instructions,
            ChunkStep::LineInfo,
        ],
        [
            ChunkStep::Functions,
            ChunkStep::Instructions,
            ChunkStep::ParameterCount,
            ChunkStep::LineInfo,
        ],
    ];
    let no_line: [[ChunkStep; 3]; 6] = [
        [
            ChunkStep::ParameterCount,
            ChunkStep::Instructions,
            ChunkStep::Functions,
        ],
        [
            ChunkStep::ParameterCount,
            ChunkStep::Functions,
            ChunkStep::Instructions,
        ],
        [
            ChunkStep::Instructions,
            ChunkStep::ParameterCount,
            ChunkStep::Functions,
        ],
        [
            ChunkStep::Instructions,
            ChunkStep::Functions,
            ChunkStep::ParameterCount,
        ],
        [
            ChunkStep::Functions,
            ChunkStep::ParameterCount,
            ChunkStep::Instructions,
        ],
        [
            ChunkStep::Functions,
            ChunkStep::Instructions,
            ChunkStep::ParameterCount,
        ],
    ];
    for order in &no_line {
        let mut c: Cursor<'_> = Cursor::new(payload, keys.key());
        if let Ok(chunk) = read_chunk(&mut c, keys, order, 0)
            && c.pos == payload.len()
        {
            return Ok(chunk);
        }
    }
    for order in &candidates {
        let mut c: Cursor<'_> = Cursor::new(payload, keys.key());
        if let Ok(chunk) = read_chunk(&mut c, keys, order, 0)
            && c.pos == payload.len()
        {
            return Ok(chunk);
        }
    }
    Err(Error::BootstrapEmulationFailed(
        "no chunk-step order consumed the payload exactly",
    ))
}

impl VmKeys {
    #[inline]
    #[must_use]
    fn key(&self) -> u8 {
        self.xor_key
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn checked_count_rejects_over_cap() {
        let cursor: Cursor<'_> = Cursor::new(&[0u8; 16], 0);
        let err: Error = checked_count(
            (IB_CONST_COUNT_CAP as u32) + 1,
            IB_CONST_COUNT_CAP,
            "ironbrew constants",
            &cursor,
            1,
        )
        .expect_err("cap");

        assert!(matches!(err, Error::LimitExceeded { .. }));
    }

    #[test]
    fn checked_count_rejects_short_remaining_bytes() {
        let cursor: Cursor<'_> = Cursor::new(&[0u8; 4], 0);
        let err: Error = checked_count(2, IB_LINEINFO_COUNT_CAP, "ironbrew lineinfo", &cursor, 4)
            .expect_err("span");

        assert!(matches!(err, Error::Truncated { .. }));
    }
}
