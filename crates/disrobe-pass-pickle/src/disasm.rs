use disrobe_bytes::{ByteReadError, ByteReader};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::opcode::{ArgKind, Effect, OpInfo, lookup};

const OPCODE_BUDGET: usize = 5_000_000;
const MAX_LONG_BODY: usize = 4_096;
const LONG_BODY_BUDGET: usize = 1 << 18;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum DecodedArg {
    None,
    Bool(bool),
    Int(i64),
    BigInt(String),
    Float(f64),
    Str(String),
    Bytes(Vec<u8>),
    GlobalPair { module: String, name: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Insn {
    pub offset: usize,
    pub opcode: u8,
    pub name: String,
    pub effect: Effect,
    pub proto: u8,
    pub arg: DecodedArg,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Disassembly {
    pub protocol: u8,
    pub instructions: Vec<Insn>,
    pub frame_count: usize,
    pub stop_offset: Option<usize>,
}

#[derive(Debug)]
struct Cursor<'a> {
    reader: ByteReader<'a>,
    long_budget: usize,
}

impl<'a> Cursor<'a> {
    #[inline]
    const fn new(bytes: &'a [u8]) -> Self {
        Self {
            reader: ByteReader::new(bytes),
            long_budget: LONG_BODY_BUDGET,
        }
    }

    #[inline]
    const fn position(&self) -> usize {
        self.reader.position()
    }

    fn charge_long(&mut self, n: usize) -> Result<()> {
        if n > MAX_LONG_BODY {
            return Err(Error::LongTooLong {
                declared: n,
                limit: MAX_LONG_BODY,
                offset: self.position(),
            });
        }
        self.long_budget = self.long_budget.checked_sub(n).ok_or(Error::LongBudget {
            limit: LONG_BODY_BUDGET,
        })?;
        Ok(())
    }

    #[inline]
    const fn remaining(&self) -> usize {
        self.reader.remaining()
    }

    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8]> {
        self.reader
            .read_bytes(n)
            .map_err(|error: ByteReadError| Self::truncated(error, what))
    }

    fn read_u8(&mut self, what: &'static str) -> Result<u8> {
        self.reader
            .read_u8()
            .map_err(|error: ByteReadError| Self::truncated(error, what))
    }

    fn read_u16_le(&mut self, what: &'static str) -> Result<u16> {
        self.reader
            .read_u16_le()
            .map_err(|error: ByteReadError| Self::truncated(error, what))
    }

    fn read_u32_le(&mut self, what: &'static str) -> Result<u32> {
        self.reader
            .read_u32_le()
            .map_err(|error: ByteReadError| Self::truncated(error, what))
    }

    fn read_i32_le(&mut self, what: &'static str) -> Result<i32> {
        self.reader
            .read_i32_le()
            .map_err(|error: ByteReadError| Self::truncated(error, what))
    }

    fn read_u64_le(&mut self, what: &'static str) -> Result<u64> {
        self.reader
            .read_u64_le()
            .map_err(|error: ByteReadError| Self::truncated(error, what))
    }

    fn read_u64_be(&mut self, what: &'static str) -> Result<u64> {
        self.reader
            .read_u64_be()
            .map_err(|error: ByteReadError| Self::truncated(error, what))
    }

    const fn truncated(error: ByteReadError, what: &'static str) -> Error {
        Error::Truncated {
            what,
            offset: error.offset,
            needed: error.needed,
            had: error.available,
        }
    }

    fn read_line(&mut self, what: &'static str) -> Result<&'a [u8]> {
        let start: usize = self.position();
        let remaining: &[u8] = self
            .reader
            .peek_bytes(self.remaining())
            .map_err(|error: ByteReadError| Self::truncated(error, what))?;
        let rel: usize =
            remaining
                .iter()
                .position(|&b: &u8| b == b'\n')
                .ok_or(Error::MissingNewline {
                    what,
                    offset: start,
                })?;
        let line_and_newline: &[u8] = self.take(rel + 1, what)?;
        Ok(&line_and_newline[..rel])
    }
}

fn decode_signed(slice: &[u8]) -> i64 {
    if slice.is_empty() {
        return 0;
    }
    let mut value: i64 = 0;
    for (i, &b) in slice.iter().enumerate() {
        value |= i64::from(b) << (8 * i);
    }
    let bits: u32 = (slice.len() * 8) as u32;
    if bits < 64 && (slice[slice.len() - 1] & 0x80) != 0 {
        value -= 1i64 << bits;
    }
    value
}

fn big_int_decimal(slice: &[u8]) -> String {
    if slice.is_empty() {
        return "0".to_string();
    }
    let negative: bool = (slice[slice.len() - 1] & 0x80) != 0;
    let mut magnitude: Vec<u8> = slice.to_vec();
    if negative {
        let mut carry: u16 = 1;
        for b in &mut magnitude {
            let v: u16 = (u16::from(!*b)) + carry;
            *b = (v & 0xff) as u8;
            carry = v >> 8;
        }
    }
    let mut digits: Vec<u8> = vec![0];
    for &byte in magnitude.iter().rev() {
        let mut carry: u32 = u32::from(byte);
        for d in &mut digits {
            let cur: u32 = u32::from(*d) * 256 + carry;
            *d = (cur % 10) as u8;
            carry = cur / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    while digits.len() > 1 && *digits.last().unwrap_or(&0) == 0 {
        digits.pop();
    }
    let mut out: String = String::with_capacity(digits.len() + 1);
    if negative {
        out.push('-');
    }
    for &d in digits.iter().rev() {
        out.push((b'0' + d) as char);
    }
    out
}

fn decode_arg(cur: &mut Cursor<'_>, info: &OpInfo) -> Result<DecodedArg> {
    match info.arg {
        ArgKind::None => Ok(DecodedArg::None),
        ArgKind::Uint1 => Ok(DecodedArg::Int(i64::from(cur.read_u8("uint1")?))),
        ArgKind::Uint2 => Ok(DecodedArg::Int(i64::from(cur.read_u16_le("uint2")?))),
        ArgKind::Uint4 => Ok(DecodedArg::Int(i64::from(cur.read_u32_le("uint4")?))),
        ArgKind::Int4 => Ok(DecodedArg::Int(i64::from(cur.read_i32_le("int4")?))),
        ArgKind::Uint8 => {
            let v: u64 = cur.read_u64_le("uint8")?;
            match i64::try_from(v) {
                Ok(n) => Ok(DecodedArg::Int(n)),
                Err(_) => Ok(DecodedArg::BigInt(v.to_string())),
            }
        }
        ArgKind::Long1 => {
            let n: usize = usize::from(cur.read_u8("long1-len")?);
            cur.charge_long(n)?;
            let body: &[u8] = cur.take(n, "long1-body")?;
            Ok(long_arg(body))
        }
        ArgKind::Long4 => {
            let n: usize = cur.read_u32_le("long4-len")? as usize;
            cur.charge_long(n)?;
            let body: &[u8] = cur.take(n, "long4-body")?;
            Ok(long_arg(body))
        }
        ArgKind::Float8 => {
            let bits: u64 = cur.read_u64_be("float8")?;
            Ok(DecodedArg::Float(f64::from_bits(bits)))
        }
        ArgKind::FloatNl => {
            let line: &[u8] = cur.read_line("floatnl")?;
            let s: &str = std::str::from_utf8(line).map_err(|_| Error::BadUtf8 {
                what: "floatnl",
                offset: cur.position(),
            })?;
            s.trim()
                .parse::<f64>()
                .map(DecodedArg::Float)
                .map_err(|e| Error::BadLiteral {
                    what: "float",
                    offset: cur.position(),
                    detail: e.to_string(),
                })
        }
        ArgKind::DecimalNlShort => {
            let line: &[u8] = cur.read_line("decimalnl_short")?;
            decode_int_line(line, cur.position())
        }
        ArgKind::DecimalNlLong => {
            let line: &[u8] = cur.read_line("decimalnl_long")?;
            let trimmed: &[u8] = line.strip_suffix(b"L").unwrap_or(line);
            decode_int_line(trimmed, cur.position())
        }
        ArgKind::String1 => {
            let n: usize = usize::from(cur.read_u8("len1")?);
            Ok(DecodedArg::Str(decode_latin1(cur.take(n, "body1")?)))
        }
        ArgKind::Bytes1 => {
            let n: usize = usize::from(cur.read_u8("len1")?);
            Ok(DecodedArg::Bytes(cur.take(n, "body1")?.to_vec()))
        }
        ArgKind::String4 => {
            let n: u32 = cur.read_u32_le("len4")?;
            guard_len(cur, u64::from(n), "body4")?;
            Ok(DecodedArg::Str(decode_latin1(
                cur.take(n as usize, "body4")?,
            )))
        }
        ArgKind::Bytes4 => {
            let n: u32 = cur.read_u32_le("len4")?;
            guard_len(cur, u64::from(n), "body4")?;
            Ok(DecodedArg::Bytes(cur.take(n as usize, "body4")?.to_vec()))
        }
        ArgKind::Bytes8 | ArgKind::ByteArray8 => {
            let n: u64 = cur.read_u64_le("len8")?;
            guard_len(cur, n, "body8")?;
            Ok(DecodedArg::Bytes(cur.take(n as usize, "body8")?.to_vec()))
        }
        ArgKind::UnicodeString1 => {
            let n: usize = usize::from(cur.read_u8("ulen1")?);
            Ok(unicode_arg(cur.take(n, "ubody1")?))
        }
        ArgKind::UnicodeString4 => {
            let n: u32 = cur.read_u32_le("ulen4")?;
            guard_len(cur, u64::from(n), "ubody4")?;
            Ok(unicode_arg(cur.take(n as usize, "ubody4")?))
        }
        ArgKind::UnicodeString8 => {
            let n: u64 = cur.read_u64_le("ulen8")?;
            guard_len(cur, n, "ubody8")?;
            Ok(unicode_arg(cur.take(n as usize, "ubody8")?))
        }
        ArgKind::UnicodeStringNl => {
            let line: &[u8] = cur.read_line("unicodestringnl")?;
            let s: String = decode_raw_unicode_escape(line);
            Ok(DecodedArg::Str(s))
        }
        ArgKind::StringNl => {
            let line: &[u8] = cur.read_line("stringnl")?;
            Ok(DecodedArg::Str(decode_quoted_string(line)))
        }
        ArgKind::StringNlNoEscape => {
            let line: &[u8] = cur.read_line("stringnl_noescape")?;
            Ok(DecodedArg::Str(String::from_utf8_lossy(line).into_owned()))
        }
        ArgKind::StringNlNoEscapePair => {
            let module: &[u8] = cur.read_line("global-module")?;
            let name: &[u8] = cur.read_line("global-name")?;
            Ok(DecodedArg::GlobalPair {
                module: String::from_utf8_lossy(module).into_owned(),
                name: String::from_utf8_lossy(name).into_owned(),
            })
        }
    }
}

fn long_arg(body: &[u8]) -> DecodedArg {
    if body.len() <= 8 {
        DecodedArg::Int(decode_signed(body))
    } else {
        DecodedArg::BigInt(big_int_decimal(body))
    }
}

fn decode_int_line(line: &[u8], offset: usize) -> Result<DecodedArg> {
    let s: &str = std::str::from_utf8(line).map_err(|_| Error::BadUtf8 {
        what: "int",
        offset,
    })?;
    let t: &str = s.trim();
    if t == "00" {
        return Ok(DecodedArg::Bool(false));
    }
    if t == "01" {
        return Ok(DecodedArg::Bool(true));
    }
    if let Ok(v) = t.parse::<i64>() {
        return Ok(DecodedArg::Int(v));
    }
    if t.chars().all(|c: char| c.is_ascii_digit() || c == '-') && !t.is_empty() {
        return Ok(DecodedArg::BigInt(t.to_string()));
    }
    Err(Error::BadLiteral {
        what: "int",
        offset,
        detail: t.to_string(),
    })
}

fn unicode_arg(body: &[u8]) -> DecodedArg {
    DecodedArg::Str(String::from_utf8_lossy(body).into_owned())
}

fn decode_latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b: &u8| char::from(b)).collect()
}

fn decode_quoted_string(line: &[u8]) -> String {
    let trimmed: &[u8] = line.strip_suffix(b"\r").unwrap_or(line);
    let inner: &[u8] = match (trimmed.first(), trimmed.last()) {
        (Some(b'\''), Some(b'\'')) | (Some(b'"'), Some(b'"')) if trimmed.len() >= 2 => {
            &trimmed[1..trimmed.len() - 1]
        }
        _ => trimmed,
    };
    decode_latin1(&escape_decode(inner))
}

fn escape_decode(inner: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(inner.len());
    let mut i: usize = 0;
    while i < inner.len() {
        if inner[i] != b'\\' {
            out.push(inner[i]);
            i += 1;
            continue;
        }
        let Some(&next): Option<&u8> = inner.get(i + 1) else {
            out.push(b'\\');
            i += 1;
            continue;
        };
        match next {
            b'n' => push_advance(&mut out, b'\n', &mut i),
            b't' => push_advance(&mut out, b'\t', &mut i),
            b'r' => push_advance(&mut out, b'\r', &mut i),
            b'a' => push_advance(&mut out, 0x07, &mut i),
            b'b' => push_advance(&mut out, 0x08, &mut i),
            b'f' => push_advance(&mut out, 0x0c, &mut i),
            b'v' => push_advance(&mut out, 0x0b, &mut i),
            b'\\' => push_advance(&mut out, b'\\', &mut i),
            b'\'' => push_advance(&mut out, b'\'', &mut i),
            b'"' => push_advance(&mut out, b'"', &mut i),
            b'\n' => i += 2,
            b'x' => match (inner.get(i + 2), inner.get(i + 3)) {
                (Some(&hi), Some(&lo)) if hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit() => {
                    out.push((hex_nibble(hi) << 4) | hex_nibble(lo));
                    i += 4;
                }
                _ => {
                    out.push(b'\\');
                    out.push(b'x');
                    i += 2;
                }
            },
            b'0'..=b'7' => {
                let mut value: u16 = 0;
                let mut consumed: usize = 0;
                while consumed < 3 {
                    match inner.get(i + 1 + consumed) {
                        Some(&d) if (b'0'..=b'7').contains(&d) => {
                            value = value * 8 + u16::from(d - b'0');
                            consumed += 1;
                        }
                        _ => break,
                    }
                }
                out.push((value & 0xff) as u8);
                i += 1 + consumed;
            }
            other => {
                out.push(b'\\');
                out.push(other);
                i += 2;
            }
        }
    }
    out
}

fn push_advance(out: &mut Vec<u8>, byte: u8, i: &mut usize) {
    out.push(byte);
    *i += 2;
}

fn decode_raw_unicode_escape(line: &[u8]) -> String {
    let mut out: String = String::with_capacity(line.len());
    let mut i: usize = 0;
    while i < line.len() {
        if line[i] == b'\\' && i + 1 < line.len() {
            let (digits, span): (usize, usize) = match line[i + 1] {
                b'u' => (4, 6),
                b'U' => (8, 10),
                _ => (0, 0),
            };
            if digits != 0
                && i + span <= line.len()
                && let Ok(hex) = std::str::from_utf8(&line[i + 2..i + span])
                && let Ok(cp) = u32::from_str_radix(hex, 16)
                && hex.bytes().all(|b: u8| b.is_ascii_hexdigit())
                && let Some(c) = char::from_u32(cp)
            {
                out.push(c);
                i += span;
                continue;
            }
        }
        out.push(char::from(line[i]));
        i += 1;
    }
    out
}

#[inline]
const fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

fn guard_len(cur: &Cursor<'_>, declared: u64, what: &'static str) -> Result<()> {
    if declared > cur.remaining() as u64 {
        return Err(Error::LengthOverflow {
            what,
            declared,
            remaining: cur.remaining(),
        });
    }
    Ok(())
}

fn frame_len(arg: &DecodedArg, offset: usize) -> Result<u64> {
    match arg {
        DecodedArg::Int(v) => u64::try_from(*v).map_err(|_| Error::BadLiteral {
            what: "frame",
            offset,
            detail: v.to_string(),
        }),
        DecodedArg::BigInt(v) => v.parse::<u64>().map_err(|e| Error::BadLiteral {
            what: "frame",
            offset,
            detail: e.to_string(),
        }),
        _ => Err(Error::BadLiteral {
            what: "frame",
            offset,
            detail: "expected unsigned frame length".to_owned(),
        }),
    }
}

pub fn disassemble(bytes: &[u8]) -> Result<Disassembly> {
    crate::debug::dbg_section("pickle disassemble");
    crate::debug::dbg_kv("input-len", || bytes.len().to_string());
    crate::debug::dbg_hex("input-magic", bytes, 8);
    if bytes.is_empty() {
        crate::debug::dbg_kv("classify", || "empty stream".to_owned());
        return Err(Error::Empty);
    }
    let header_proto: Option<u8> = (bytes[0] == 0x80 && bytes.len() >= 2).then(|| bytes[1]);
    crate::debug::dbg_kv("protocol-header", || match header_proto {
        Some(p) => format!("\\x80 frame opener declares protocol {p}"),
        None => format!(
            "protocol-0/1 text stream (no \\x80 opener, first byte 0x{:02x})",
            bytes[0]
        ),
    });
    let mut cur: Cursor<'_> = Cursor::new(bytes);
    let mut instructions: Vec<Insn> = Vec::new();
    let mut protocol: u8 = 0;
    let mut frame_count: usize = 0;
    let mut stop_offset: Option<usize> = None;
    let mut budget: usize = OPCODE_BUDGET;

    loop {
        if cur.remaining() == 0 {
            crate::debug::dbg_kv("decode-fault", || {
                format!("ran out of bytes at offset {} before STOP", cur.position())
            });
            return Err(Error::NoStop);
        }
        budget = budget.checked_sub(1).ok_or(Error::OpcodeBudget {
            limit: OPCODE_BUDGET,
        })?;
        let offset: usize = cur.position();
        let opcode: u8 = cur.read_u8("opcode")?;
        let Some(info): Option<&OpInfo> = lookup(opcode) else {
            crate::debug::dbg_kv("decode-fault", || {
                format!("unknown opcode 0x{opcode:02x} at offset {offset}")
            });
            return Err(Error::UnknownOpcode { opcode, offset });
        };
        let arg: DecodedArg = decode_arg(&mut cur, info)?;
        match info.effect {
            Effect::Proto => {
                if let DecodedArg::Int(p) = arg {
                    let bumped: u8 = protocol.max(p as u8);
                    if bumped != protocol {
                        crate::debug::dbg_kv("protocol", || {
                            format!(
                                "PROTO opcode at offset {offset} raises detected protocol to {bumped}"
                            )
                        });
                    }
                    protocol = bumped;
                }
            }
            Effect::Frame => {
                let declared: u64 = frame_len(&arg, offset)?;
                guard_len(&cur, declared, "frame-body")?;
                frame_count += 1;
                crate::debug::dbg_kv("frame", || {
                    format!("FRAME #{frame_count} at offset {offset}")
                });
            }
            Effect::Stop => {
                stop_offset = Some(offset);
                crate::debug::dbg_kv("stop", || format!("STOP at offset {offset}"));
            }
            _ => {}
        }
        let is_stop: bool = info.effect == Effect::Stop;
        instructions.push(Insn {
            offset,
            opcode,
            name: info.name.to_string(),
            effect: info.effect,
            proto: info.proto,
            arg,
        });
        if is_stop {
            break;
        }
    }

    let result: Disassembly = Disassembly {
        protocol,
        instructions,
        frame_count,
        stop_offset,
    };
    crate::debug::dbg_kv("disassembled", || {
        format!(
            "protocol={} opcodes={} frames={} stop_offset={:?}",
            result.protocol,
            result.instructions.len(),
            result.frame_count,
            result.stop_offset
        )
    });
    Ok(result)
}

fn skip_arg(cur: &mut Cursor<'_>, info: &OpInfo) -> Result<()> {
    match info.arg {
        ArgKind::None => Ok(()),
        ArgKind::Uint1 => cur.read_u8("uint1").map(drop),
        ArgKind::Uint2 => cur.read_u16_le("uint2").map(drop),
        ArgKind::Uint4 => cur.read_u32_le("uint4").map(drop),
        ArgKind::Int4 => cur.read_i32_le("int4").map(drop),
        ArgKind::Uint8 => cur.read_u64_le("uint8").map(drop),
        ArgKind::Float8 => cur.read_u64_be("float8").map(drop),
        ArgKind::Long1 => {
            let n: usize = usize::from(cur.read_u8("long1-len")?);
            cur.charge_long(n)?;
            cur.take(n, "long1-body").map(drop)
        }
        ArgKind::Long4 => {
            let n: usize = cur.read_u32_le("long4-len")? as usize;
            cur.charge_long(n)?;
            cur.take(n, "long4-body").map(drop)
        }
        ArgKind::String1 => {
            let n: usize = usize::from(cur.read_u8("len1")?);
            cur.take(n, "body1").map(drop)
        }
        ArgKind::Bytes1 => {
            let n: usize = usize::from(cur.read_u8("len1")?);
            cur.take(n, "body1").map(drop)
        }
        ArgKind::UnicodeString1 => {
            let n: usize = usize::from(cur.read_u8("ulen1")?);
            cur.take(n, "ubody1").map(drop)
        }
        ArgKind::String4 => {
            let n: u32 = cur.read_u32_le("len4")?;
            guard_len(cur, u64::from(n), "body4")?;
            cur.take(n as usize, "body4").map(drop)
        }
        ArgKind::Bytes4 => {
            let n: u32 = cur.read_u32_le("len4")?;
            guard_len(cur, u64::from(n), "body4")?;
            cur.take(n as usize, "body4").map(drop)
        }
        ArgKind::UnicodeString4 => {
            let n: u32 = cur.read_u32_le("ulen4")?;
            guard_len(cur, u64::from(n), "ubody4")?;
            cur.take(n as usize, "ubody4").map(drop)
        }
        ArgKind::Bytes8 | ArgKind::ByteArray8 => {
            let n: u64 = cur.read_u64_le("len8")?;
            guard_len(cur, n, "body8")?;
            cur.take(n as usize, "body8").map(drop)
        }
        ArgKind::UnicodeString8 => {
            let n: u64 = cur.read_u64_le("ulen8")?;
            guard_len(cur, n, "ubody8")?;
            cur.take(n as usize, "ubody8").map(drop)
        }
        ArgKind::DecimalNlLong
        | ArgKind::DecimalNlShort
        | ArgKind::FloatNl
        | ArgKind::StringNl
        | ArgKind::StringNlNoEscape
        | ArgKind::StringNlNoEscapePair
        | ArgKind::UnicodeStringNl => decode_arg(cur, info).map(drop),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StreamEnd {
    pub(crate) len: usize,
    pub(crate) protocol: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StreamProbe {
    pub(crate) opcodes: usize,
    pub(crate) end: Option<StreamEnd>,
}

pub(crate) fn probe_stream(bytes: &[u8], opcode_budget: usize) -> StreamProbe {
    let mut cur: Cursor<'_> = Cursor::new(bytes);
    let mut protocol: u8 = 0;
    let mut opcodes: usize = 0;
    loop {
        if opcodes >= opcode_budget || cur.remaining() == 0 {
            return StreamProbe { opcodes, end: None };
        }
        opcodes += 1;
        let offset: usize = cur.position();
        let Ok(opcode): Result<u8> = cur.read_u8("opcode") else {
            return StreamProbe { opcodes, end: None };
        };
        let Some(info): Option<&OpInfo> = lookup(opcode) else {
            return StreamProbe { opcodes, end: None };
        };
        match info.effect {
            Effect::Proto => {
                let Ok(arg): Result<DecodedArg> = decode_arg(&mut cur, info) else {
                    return StreamProbe { opcodes, end: None };
                };
                if let DecodedArg::Int(p) = arg {
                    protocol = protocol.max(p as u8);
                }
            }
            Effect::Frame => {
                let Ok(arg): Result<DecodedArg> = decode_arg(&mut cur, info) else {
                    return StreamProbe { opcodes, end: None };
                };
                let Ok(declared): Result<u64> = frame_len(&arg, offset) else {
                    return StreamProbe { opcodes, end: None };
                };
                if guard_len(&cur, declared, "frame-body").is_err() {
                    return StreamProbe { opcodes, end: None };
                }
            }
            Effect::Stop => {
                return StreamProbe {
                    opcodes,
                    end: Some(StreamEnd {
                        len: cur.position(),
                        protocol,
                    }),
                };
            }
            _ => {
                if skip_arg(&mut cur, info).is_err() {
                    return StreamProbe { opcodes, end: None };
                }
            }
        }
    }
}

fn py_float_repr(v: f64) -> String {
    if v.is_nan() {
        return "nan".to_string();
    }
    if v.is_infinite() {
        return if v < 0.0 {
            "-inf".to_string()
        } else {
            "inf".to_string()
        };
    }
    let sign: &str = if v.is_sign_negative() { "-" } else { "" };
    let sci: String = format!("{:e}", v.abs());
    let Some((mantissa, exp_str)): Option<(&str, &str)> = sci.split_once('e') else {
        return format!("{sign}{sci}");
    };
    let exp: i32 = exp_str.parse::<i32>().unwrap_or(0);
    let digits: String = mantissa.chars().filter(|c: &char| *c != '.').collect();
    let ndigits: i32 = digits.len() as i32;
    let decpt: i32 = exp + 1;
    let body: String = if decpt <= -4 || decpt > 16 {
        let exp2: i32 = decpt - 1;
        let esign: &str = if exp2 < 0 { "-" } else { "+" };
        let mut m: String = String::with_capacity(digits.len() + 1);
        m.push_str(&digits[..1]);
        if ndigits > 1 {
            m.push('.');
            m.push_str(&digits[1..]);
        }
        format!("{m}e{esign}{:02}", exp2.abs())
    } else if decpt <= 0 {
        format!("0.{}{digits}", "0".repeat((-decpt) as usize))
    } else if decpt >= ndigits {
        format!("{digits}{}.0", "0".repeat((decpt - ndigits) as usize))
    } else {
        format!(
            "{}.{}",
            &digits[..decpt as usize],
            &digits[decpt as usize..]
        )
    };
    format!("{sign}{body}")
}

#[must_use]
pub fn render(dis: &Disassembly) -> String {
    let mut out: String = String::new();
    let mut indent: usize = 0;
    for insn in &dis.instructions {
        if matches!(insn.effect, Effect::Build | Effect::Reduce) && indent > 0 {
            indent -= 1;
        }
        let pad: String = "    ".repeat(indent);
        let arg_str: String = match &insn.arg {
            DecodedArg::None => String::new(),
            DecodedArg::Bool(b) => if *b { "True" } else { "False" }.to_owned(),
            DecodedArg::Int(v) => v.to_string(),
            DecodedArg::BigInt(s) => s.clone(),
            DecodedArg::Float(v) => py_float_repr(*v),
            DecodedArg::Str(s) => format!("{s:?}"),
            DecodedArg::Bytes(b) => format!("<{} bytes>", b.len()),
            DecodedArg::GlobalPair { module, name } => format!("{module} {name}"),
        };
        out.push_str(&format!(
            "{:>6}: {} {}{} {}\n",
            insn.offset, insn.opcode as char, pad, insn.name, arg_str
        ));
        if insn.effect == Effect::PushMark {
            indent += 1;
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_error() {
        assert!(matches!(disassemble(&[]), Err(Error::Empty)));
    }

    const ARG_SAMPLES: [(ArgKind, &[u8]); 25] = [
        (ArgKind::None, b""),
        (ArgKind::FloatNl, b"3.5\n"),
        (ArgKind::Uint1, &[0x02]),
        (ArgKind::Uint2, &[0x01, 0x00]),
        (ArgKind::Uint4, &[0x01, 0x00, 0x00, 0x00]),
        (ArgKind::Int4, &[0xff, 0xff, 0xff, 0xff]),
        (ArgKind::Uint8, &[0x01, 0, 0, 0, 0, 0, 0, 0]),
        (ArgKind::Float8, &[0x3f, 0xf0, 0, 0, 0, 0, 0, 0]),
        (ArgKind::Long1, &[0x02, 0x01, 0x00]),
        (ArgKind::Long4, &[0x02, 0, 0, 0, 0x01, 0x00]),
        (ArgKind::String1, b"\x03abc"),
        (ArgKind::String4, b"\x03\x00\x00\x00abc"),
        (ArgKind::Bytes1, &[0x02, 0xff, 0x00]),
        (ArgKind::Bytes4, &[0x02, 0, 0, 0, 0xff, 0x00]),
        (ArgKind::Bytes8, &[0x02, 0, 0, 0, 0, 0, 0, 0, 0xff, 0x00]),
        (
            ArgKind::ByteArray8,
            &[0x02, 0, 0, 0, 0, 0, 0, 0, 0xff, 0x00],
        ),
        (ArgKind::UnicodeString1, b"\x02hi"),
        (ArgKind::UnicodeString4, b"\x02\x00\x00\x00hi"),
        (
            ArgKind::UnicodeString8,
            b"\x02\x00\x00\x00\x00\x00\x00\x00hi",
        ),
        (ArgKind::UnicodeStringNl, b"hi\n"),
        (ArgKind::StringNl, b"'hi'\n"),
        (ArgKind::StringNlNoEscape, b"persistent-id\n"),
        (ArgKind::StringNlNoEscapePair, b"os\nsystem\n"),
        (ArgKind::DecimalNlShort, b"42\n"),
        (ArgKind::DecimalNlLong, b"42L\n"),
    ];

    fn probe_info(arg: ArgKind) -> OpInfo {
        OpInfo {
            code: 0x4e,
            name: "SAMPLE",
            arg,
            proto: 0,
            effect: Effect::PushConst,
        }
    }

    fn committed_fixtures(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries): std::io::Result<std::fs::ReadDir> = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path: std::path::PathBuf = entry.path();
            if path.is_dir() {
                committed_fixtures(&path, out);
            } else if path.extension().is_some_and(|e| e == "pkl") {
                out.push(path);
            }
        }
    }

    #[test]
    fn skipping_an_argument_advances_exactly_as_far_as_decoding_it() {
        for (kind, body) in ARG_SAMPLES {
            let info: OpInfo = probe_info(kind);
            let mut decoding: Cursor<'_> = Cursor::new(body);
            let decoded: Result<DecodedArg> = decode_arg(&mut decoding, &info);
            assert!(
                decoded.is_ok(),
                "{kind:?} sample must decode: {:?}",
                decoded.err()
            );
            let mut skipping: Cursor<'_> = Cursor::new(body);
            let skipped: Result<()> = skip_arg(&mut skipping, &info);
            assert!(
                skipped.is_ok(),
                "{kind:?} sample must skip: {:?}",
                skipped.err()
            );
            assert_eq!(
                decoding.position(),
                body.len(),
                "{kind:?} sample must be exactly one argument, or the comparison proves nothing"
            );
            assert_eq!(
                skipping.position(),
                decoding.position(),
                "skipping a {kind:?} argument left the cursor somewhere else than decoding it, so \
                 a probed stream end would disagree with the disassembler"
            );
        }
    }

    #[test]
    fn every_opcode_argument_kind_has_a_skip_sample() {
        for info in crate::opcode::OPCODES {
            assert!(
                ARG_SAMPLES
                    .iter()
                    .any(|(kind, _): &(ArgKind, &[u8])| *kind == info.arg),
                "{} carries argument kind {:?}, which no skip/decode sample covers",
                info.name,
                info.arg
            );
        }
    }

    #[test]
    fn a_probed_stream_end_matches_the_disassembler_on_the_committed_corpus() {
        let root: std::path::PathBuf = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("pickle");
        assert!(
            root.is_dir(),
            "corpus/pickle must be committed: the probe is graded against the fixtures the \
             disassembler is graded against, and a missing corpus is a failure, not a skip"
        );
        let mut files: Vec<std::path::PathBuf> = Vec::new();
        committed_fixtures(&root, &mut files);
        assert!(!files.is_empty(), "no .pkl fixtures under {root:?}");
        let mut checked: usize = 0;
        let mut defects: Vec<String> = Vec::new();
        for file in &files {
            let bytes: Vec<u8> = std::fs::read(file).expect("read fixture");
            let Ok(dis): Result<Disassembly> = disassemble(&bytes) else {
                defects.push(format!("{file:?}: the committed fixture no longer disassembles"));
                continue;
            };
            let Some(stop): Option<usize> = dis.stop_offset else {
                defects.push(format!("{file:?}: the committed fixture carries no STOP"));
                continue;
            };
            let probe: StreamProbe = probe_stream(&bytes, OPCODE_BUDGET);
            let expected: Option<StreamEnd> = Some(StreamEnd {
                len: stop + 1,
                protocol: dis.protocol,
            });
            if probe.end == expected {
                checked += 1;
            } else {
                defects.push(format!(
                    "{file:?}: probed {:?}, the disassembler says {expected:?}",
                    probe.end
                ));
            }
        }
        assert!(
            defects.is_empty(),
            "the probe must stay identical to the disassembler it measures for:\n{}",
            defects.join("\n")
        );
        assert!(checked >= 100, "only {checked} fixtures were compared");
    }

    #[test]
    fn a_probe_reports_no_end_for_a_stream_without_a_stop() {
        let probe: StreamProbe = probe_stream(b"\x80\x02K\x07", OPCODE_BUDGET);
        assert_eq!(probe.end, None);
        assert!(probe.opcodes >= 2);
    }

    #[test]
    fn a_probe_stops_when_its_opcode_budget_runs_out() {
        let mut bytes: Vec<u8> = vec![0x80, 0x02];
        bytes.extend(std::iter::repeat_n(b'N', 64));
        bytes.push(b'.');
        assert_eq!(probe_stream(&bytes, 4).end, None);
        assert_eq!(probe_stream(&bytes, 4).opcodes, 4);
        assert_eq!(
            probe_stream(&bytes, OPCODE_BUDGET).end,
            Some(StreamEnd {
                len: bytes.len(),
                protocol: 2,
            })
        );
    }

    #[test]
    fn cursor_preserves_reader_endianness_and_truncation_context() {
        let integer_bytes: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
        let mut cur: Cursor<'_> = Cursor::new(&integer_bytes);

        assert_eq!(cur.reader.position(), 0);
        assert_eq!(cur.read_u16_le("uint2").expect("read uint2"), 0x0201);
        assert_eq!(cur.position(), 2);
        assert_eq!(cur.read_u16_le("uint2").expect("read second uint2"), 0x0403);
        let error: Error = cur.read_u8("opcode").expect_err("read past input");
        let float_bytes: [u8; 8] = 1.0f64.to_be_bytes();
        let mut float_cur: Cursor<'_> = Cursor::new(&float_bytes);
        let float_bits: u64 = float_cur.read_u64_be("float8").expect("read float8");
        assert_eq!(float_bits, 1.0f64.to_bits());
        assert!(matches!(
            error,
            Error::Truncated {
                what: "opcode",
                offset: 4,
                needed: 1,
                had: 0,
            }
        ));
    }

    #[test]
    fn proto2_none() {
        let bytes: &[u8] = b"\x80\x02N.";
        let dis: Disassembly = disassemble(bytes).expect("disasm");
        assert_eq!(dis.protocol, 2);
        assert_eq!(dis.instructions.first().unwrap().name, "PROTO");
        assert!(dis.stop_offset.is_some());
    }

    #[test]
    fn non_utf8_short_binunicode_does_not_drop_the_whole_stream() {
        let bytes: &[u8] = b"\x80\x04\x8c\x03a\xffb.";
        let dis: Disassembly =
            disassemble(bytes).expect("a bad unicode byte must not abort disasm");
        assert!(dis.stop_offset.is_some());
        let unicode: &Insn = dis
            .instructions
            .iter()
            .find(|i: &&Insn| i.name == "SHORT_BINUNICODE")
            .expect("the unicode opcode must still decode");
        assert!(
            matches!(&unicode.arg, DecodedArg::Str(value) if value.contains('\u{fffd}') && value.starts_with('a') && value.ends_with('b'))
        );
    }

    #[test]
    fn unknown_opcode_errors() {
        assert!(matches!(
            disassemble(&[0xff, b'.']),
            Err(Error::UnknownOpcode { .. })
        ));
    }

    #[test]
    fn no_stop_errors() {
        assert!(matches!(disassemble(b"\x80\x02N"), Err(Error::NoStop)));
    }

    #[test]
    fn bigint_decode() {
        assert_eq!(big_int_decimal(&[0xff, 0xff, 0xff, 0xff, 0xff]), "-1");
        assert_eq!(big_int_decimal(&[0x00, 0x01]), "256");
    }

    #[test]
    fn proto0_unicode_decodes_raw_unicode_escape() {
        let bytes: &[u8] = b"Vcaf\xe9 \\u2603 \\U0001f600\np0\n.";
        let dis: Disassembly = disassemble(bytes).expect("proto-0 unicode disasm");
        let insn: &Insn = dis
            .instructions
            .iter()
            .find(|i: &&Insn| i.name == "UNICODE")
            .expect("UNICODE opcode");
        assert_eq!(
            insn.arg,
            DecodedArg::Str("caf\u{e9} \u{2603} \u{1f600}".to_string()),
            "UNICODE body must decode via raw-unicode-escape: latin1 high bytes literal, lowercase \\uXXXX and uppercase \\UXXXXXXXX escapes resolved"
        );
    }

    #[test]
    fn raw_unicode_escape_edges_match_cpython() {
        assert_eq!(decode_raw_unicode_escape(b"a\\b"), "a\\b");
        assert_eq!(decode_raw_unicode_escape(b"\\u2603"), "\u{2603}");
        assert_eq!(decode_raw_unicode_escape(b"\\U0001f600"), "\u{1f600}");
        assert_eq!(decode_raw_unicode_escape(b"\\u26"), "\\u26");
        assert_eq!(decode_raw_unicode_escape(b"\\uZZZZ"), "\\uZZZZ");
        assert_eq!(decode_raw_unicode_escape(b"end\\"), "end\\");
        assert_eq!(decode_raw_unicode_escape(b"\xe9"), "\u{e9}");
    }

    #[test]
    fn proto0_string_hex_escape_decodes_latin1_not_utf8_lossy() {
        let bytes: &[u8] = b"S'\\x00\\xff\\x41'\np0\n.";
        let dis: Disassembly = disassemble(bytes).expect("proto-0 STRING disasm");
        let insn: &Insn = dis
            .instructions
            .iter()
            .find(|i: &&Insn| i.name == "STRING")
            .expect("STRING opcode");
        assert_eq!(
            insn.arg,
            DecodedArg::Str("\u{0}\u{ff}A".to_string()),
            "\\xff must map to latin-1 U+00FF (CPython escape_decode+latin-1), not the U+FFFD replacement char"
        );
    }

    #[test]
    fn proto0_string_octal_and_control_escapes_match_cpython() {
        let bytes: &[u8] = b"S'\\101\\102\\777\\0\\a\\b\\f\\v'\np0\n.";
        let dis: Disassembly = disassemble(bytes).expect("proto-0 STRING disasm");
        let insn: &Insn = dis
            .instructions
            .iter()
            .find(|i: &&Insn| i.name == "STRING")
            .expect("STRING opcode");
        assert_eq!(
            insn.arg,
            DecodedArg::Str("AB\u{ff}\u{0}\u{7}\u{8}\u{c}\u{b}".to_string()),
            "octal (masked to a byte) and \\a\\b\\f\\v must decode exactly like CPython escape_decode"
        );
    }

    #[test]
    fn binstring_family_decodes_latin1_string() {
        let short: &[u8] = b"\x80\x01U\x03a\xffc.";
        let dis: Disassembly = disassemble(short).expect("SHORT_BINSTRING disasm");
        let insn: &Insn = dis
            .instructions
            .iter()
            .find(|i: &&Insn| i.name == "SHORT_BINSTRING")
            .expect("SHORT_BINSTRING opcode");
        assert_eq!(
            insn.arg,
            DecodedArg::Str("a\u{ff}c".to_string()),
            "SHORT_BINSTRING is a latin-1 str in CPython pickletools, not raw bytes"
        );

        let long: &[u8] = b"\x80\x01T\x03\x00\x00\x00\x00\x7f\xff.";
        let dis4: Disassembly = disassemble(long).expect("BINSTRING disasm");
        let insn4: &Insn = dis4
            .instructions
            .iter()
            .find(|i: &&Insn| i.name == "BINSTRING")
            .expect("BINSTRING opcode");
        assert_eq!(insn4.arg, DecodedArg::Str("\u{0}\u{7f}\u{ff}".to_string()));
    }

    #[test]
    fn malformed_hex_escape_stays_tolerant_and_keeps_the_stream() {
        let bytes: &[u8] = b"S'a\\xg z'\np0\n.";
        let dis: Disassembly = disassemble(bytes).expect("a malformed \\x must not abort disasm");
        let insn: &Insn = dis
            .instructions
            .iter()
            .find(|i: &&Insn| i.name == "STRING")
            .expect("STRING opcode");
        assert_eq!(
            insn.arg,
            DecodedArg::Str("a\\xg z".to_string()),
            "CPython raises on a bad \\x; a deobfuscator keeps the literal sequence and the rest of the stream"
        );
    }

    #[test]
    fn float_repr_matches_cpython_float_repr() {
        let cases: &[(f64, &str)] = &[
            (1.0, "1.0"),
            (2.5, "2.5"),
            (0.1, "0.1"),
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (-2.5, "-2.5"),
            (100.0, "100.0"),
            (100_000_000.0, "100000000.0"),
            (12345.678, "12345.678"),
            (0.375, "0.375"),
            (0.01, "0.01"),
            (0.0001, "0.0001"),
            (1_234_567_890_123_456.0, "1234567890123456.0"),
            (9_999_999_999_999_998.0, "9999999999999998.0"),
            (1e16, "1e+16"),
            (1e20, "1e+20"),
            (1e100, "1e+100"),
            (1e-5, "1e-05"),
            (1e-100, "1e-100"),
            (f64::INFINITY, "inf"),
            (f64::NEG_INFINITY, "-inf"),
            (f64::NAN, "nan"),
        ];
        for &(value, expected) in cases {
            assert_eq!(
                py_float_repr(value),
                expected,
                "py_float_repr({value}) must match CPython repr(float)"
            );
        }
    }

    #[test]
    fn binfloat_one_renders_as_float_not_int() {
        let mut bytes: Vec<u8> = vec![0x80, 0x02, b'G'];
        bytes.extend_from_slice(&1.0f64.to_be_bytes());
        bytes.push(b'.');
        let dis: Disassembly = disassemble(&bytes).expect("BINFLOAT disasm");
        let text: String = render(&dis);
        assert!(
            text.contains("BINFLOAT 1.0"),
            "BINFLOAT 1.0 must render as 1.0 like pickletools, not 1; got:\n{text}"
        );
        assert!(!text.contains("BINFLOAT 1\n"));
    }

    #[test]
    fn length_overflow_guarded() {
        let bytes: &[u8] = b"\x80\x02B\xff\xff\xff\x7fAB.";
        assert!(matches!(
            disassemble(bytes),
            Err(Error::LengthOverflow { .. })
        ));
    }

    #[test]
    fn oversized_frame_length_is_rejected() {
        let mut bytes: Vec<u8> = b"\x80\x04\x95".to_vec();
        bytes.extend_from_slice(&u64::MAX.to_le_bytes());
        bytes.push(b'.');
        assert!(matches!(
            disassemble(&bytes),
            Err(Error::LengthOverflow {
                what: "frame-body",
                declared: u64::MAX,
                remaining: 1usize
            })
        ));
    }
}
