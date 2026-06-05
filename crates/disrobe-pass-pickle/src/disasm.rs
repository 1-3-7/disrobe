use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::opcode::{ArgKind, Effect, OpInfo, lookup};

const OPCODE_BUDGET: usize = 5_000_000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum DecodedArg {
    None,
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
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    #[inline]
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    #[inline]
    const fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::Truncated {
                what,
                offset: self.pos,
                needed: n,
                had: self.remaining(),
            });
        }
        let slice: &[u8] = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn read_line(&mut self, what: &'static str) -> Result<&'a [u8]> {
        let start: usize = self.pos;
        let rel: usize = self.bytes[start..]
            .iter()
            .position(|&b: &u8| b == b'\n')
            .ok_or(Error::MissingNewline {
                what,
                offset: start,
            })?;
        let line: &[u8] = &self.bytes[start..start + rel];
        self.pos = start + rel + 1;
        Ok(line)
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
        ArgKind::Uint1 => Ok(DecodedArg::Int(i64::from(cur.take(1, "uint1")?[0]))),
        ArgKind::Uint2 => {
            let b: &[u8] = cur.take(2, "uint2")?;
            Ok(DecodedArg::Int(i64::from(u16::from_le_bytes([b[0], b[1]]))))
        }
        ArgKind::Uint4 => {
            let b: &[u8] = cur.take(4, "uint4")?;
            Ok(DecodedArg::Int(i64::from(u32::from_le_bytes([
                b[0], b[1], b[2], b[3],
            ]))))
        }
        ArgKind::Int4 => {
            let b: &[u8] = cur.take(4, "int4")?;
            Ok(DecodedArg::Int(i64::from(i32::from_le_bytes([
                b[0], b[1], b[2], b[3],
            ]))))
        }
        ArgKind::Uint8 => {
            let b: &[u8] = cur.take(8, "uint8")?;
            let v: u64 = u64::from_le_bytes(b.try_into().unwrap_or([0; 8]));
            Ok(DecodedArg::Int(v as i64))
        }
        ArgKind::Long1 => {
            let n: usize = cur.take(1, "long1-len")?[0] as usize;
            let body: &[u8] = cur.take(n, "long1-body")?;
            Ok(long_arg(body))
        }
        ArgKind::Long4 => {
            let lb: &[u8] = cur.take(4, "long4-len")?;
            let n: u32 = u32::from_le_bytes([lb[0], lb[1], lb[2], lb[3]]);
            let body: &[u8] = cur.take(n as usize, "long4-body")?;
            Ok(long_arg(body))
        }
        ArgKind::Float8 => {
            let b: &[u8] = cur.take(8, "float8")?;
            Ok(DecodedArg::Float(f64::from_be_bytes(
                b.try_into().unwrap_or([0; 8]),
            )))
        }
        ArgKind::FloatNl => {
            let line: &[u8] = cur.read_line("floatnl")?;
            let s: &str = std::str::from_utf8(line).map_err(|_| Error::BadUtf8 {
                what: "floatnl",
                offset: cur.pos,
            })?;
            s.trim()
                .parse::<f64>()
                .map(DecodedArg::Float)
                .map_err(|e| Error::BadLiteral {
                    what: "float",
                    offset: cur.pos,
                    detail: e.to_string(),
                })
        }
        ArgKind::DecimalNlShort => {
            let line: &[u8] = cur.read_line("decimalnl_short")?;
            decode_int_line(line, cur.pos)
        }
        ArgKind::DecimalNlLong => {
            let line: &[u8] = cur.read_line("decimalnl_long")?;
            let trimmed: &[u8] = line.strip_suffix(b"L").unwrap_or(line);
            decode_int_line(trimmed, cur.pos)
        }
        ArgKind::String1 | ArgKind::Bytes1 => {
            let n: usize = cur.take(1, "len1")?[0] as usize;
            Ok(DecodedArg::Bytes(cur.take(n, "body1")?.to_vec()))
        }
        ArgKind::String4 | ArgKind::Bytes4 => {
            let lb: &[u8] = cur.take(4, "len4")?;
            let n: u32 = u32::from_le_bytes([lb[0], lb[1], lb[2], lb[3]]);
            guard_len(cur, u64::from(n), "body4")?;
            Ok(DecodedArg::Bytes(cur.take(n as usize, "body4")?.to_vec()))
        }
        ArgKind::Bytes8 | ArgKind::ByteArray8 => {
            let lb: &[u8] = cur.take(8, "len8")?;
            let n: u64 = u64::from_le_bytes(lb.try_into().unwrap_or([0; 8]));
            guard_len(cur, n, "body8")?;
            Ok(DecodedArg::Bytes(cur.take(n as usize, "body8")?.to_vec()))
        }
        ArgKind::UnicodeString1 => {
            let n: usize = cur.take(1, "ulen1")?[0] as usize;
            unicode_arg(cur.take(n, "ubody1")?, cur.pos)
        }
        ArgKind::UnicodeString4 => {
            let lb: &[u8] = cur.take(4, "ulen4")?;
            let n: u32 = u32::from_le_bytes([lb[0], lb[1], lb[2], lb[3]]);
            guard_len(cur, u64::from(n), "ubody4")?;
            unicode_arg(cur.take(n as usize, "ubody4")?, cur.pos)
        }
        ArgKind::UnicodeString8 => {
            let lb: &[u8] = cur.take(8, "ulen8")?;
            let n: u64 = u64::from_le_bytes(lb.try_into().unwrap_or([0; 8]));
            guard_len(cur, n, "ubody8")?;
            unicode_arg(cur.take(n as usize, "ubody8")?, cur.pos)
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
        return Ok(DecodedArg::Int(0));
    }
    if t == "01" {
        return Ok(DecodedArg::Int(1));
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

fn unicode_arg(body: &[u8], offset: usize) -> Result<DecodedArg> {
    std::str::from_utf8(body)
        .map(|s: &str| DecodedArg::Str(s.to_string()))
        .map_err(|_| Error::BadUtf8 {
            what: "unicode",
            offset,
        })
}

fn decode_quoted_string(line: &[u8]) -> String {
    let trimmed: &[u8] = line.strip_suffix(b"\r").unwrap_or(line);
    let inner: &[u8] = match (trimmed.first(), trimmed.last()) {
        (Some(b'\''), Some(b'\'')) | (Some(b'"'), Some(b'"')) if trimmed.len() >= 2 => {
            &trimmed[1..trimmed.len() - 1]
        }
        _ => trimmed,
    };
    decode_string_escapes(inner)
}

fn decode_string_escapes(inner: &[u8]) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(inner.len());
    let mut i: usize = 0;
    while i < inner.len() {
        if inner[i] == b'\\' && i + 1 < inner.len() {
            match inner[i + 1] {
                b'n' => out.push(b'\n'),
                b't' => out.push(b'\t'),
                b'r' => out.push(b'\r'),
                b'\\' => out.push(b'\\'),
                b'\'' => out.push(b'\''),
                b'"' => out.push(b'"'),
                b'x' if i + 3 < inner.len() => {
                    let hi: u8 = hex_nibble(inner[i + 2]);
                    let lo: u8 = hex_nibble(inner[i + 3]);
                    out.push((hi << 4) | lo);
                    i += 2;
                }
                other => {
                    out.push(b'\\');
                    out.push(other);
                }
            }
            i += 2;
        } else {
            out.push(inner[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn decode_raw_unicode_escape(line: &[u8]) -> String {
    let s: std::borrow::Cow<'_, str> = String::from_utf8_lossy(line);
    let mut out: String = String::with_capacity(s.len());
    let chars: Vec<char> = s.chars().collect();
    let mut i: usize = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() && chars[i + 1] == 'u' && i + 5 < chars.len() {
            let hex: String = chars[i + 2..i + 6].iter().collect();
            if let Ok(cp) = u32::from_str_radix(&hex, 16)
                && let Some(c) = char::from_u32(cp)
            {
                out.push(c);
                i += 6;
                continue;
            }
        }
        out.push(chars[i]);
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

pub fn disassemble(bytes: &[u8]) -> Result<Disassembly> {
    if bytes.is_empty() {
        return Err(Error::Empty);
    }
    let mut cur: Cursor<'_> = Cursor::new(bytes);
    let mut instructions: Vec<Insn> = Vec::new();
    let mut protocol: u8 = 0;
    let mut frame_count: usize = 0;
    let mut stop_offset: Option<usize> = None;
    let mut budget: usize = OPCODE_BUDGET;

    loop {
        if cur.remaining() == 0 {
            return Err(Error::NoStop);
        }
        budget = budget.checked_sub(1).ok_or(Error::OpcodeBudget {
            limit: OPCODE_BUDGET,
        })?;
        let offset: usize = cur.pos;
        let opcode: u8 = cur.take(1, "opcode")?[0];
        let info: &OpInfo = lookup(opcode).ok_or(Error::UnknownOpcode { opcode, offset })?;
        let arg: DecodedArg = decode_arg(&mut cur, info)?;
        match info.effect {
            Effect::Proto => {
                if let DecodedArg::Int(p) = arg {
                    protocol = protocol.max(p as u8);
                }
            }
            Effect::Frame => frame_count += 1,
            Effect::Stop => stop_offset = Some(offset),
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

    Ok(Disassembly {
        protocol,
        instructions,
        frame_count,
        stop_offset,
    })
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
            DecodedArg::Int(v) => v.to_string(),
            DecodedArg::BigInt(s) => s.clone(),
            DecodedArg::Float(v) => v.to_string(),
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

    #[test]
    fn proto2_none() {
        let bytes: &[u8] = b"\x80\x02N.";
        let dis: Disassembly = disassemble(bytes).expect("disasm");
        assert_eq!(dis.protocol, 2);
        assert_eq!(dis.instructions.first().unwrap().name, "PROTO");
        assert!(dis.stop_offset.is_some());
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
    fn length_overflow_guarded() {
        let bytes: &[u8] = b"\x80\x02B\xff\xff\xff\x7fAB.";
        assert!(matches!(
            disassemble(bytes),
            Err(Error::LengthOverflow { .. })
        ));
    }
}
