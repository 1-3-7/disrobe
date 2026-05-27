use serde::Serialize;

use crate::chunks::CodeChunk;
use crate::error::{Error, Result};
use crate::opcodes::{self, OpcodeSpec};
use crate::reader::Reader;

pub const TAG_LITERAL: u8 = 0;
pub const TAG_INTEGER: u8 = 1;
pub const TAG_ATOM: u8 = 2;
pub const TAG_XREG: u8 = 3;
pub const TAG_YREG: u8 = 4;
pub const TAG_LABEL: u8 = 5;
pub const TAG_CHARACTER: u8 = 6;
pub const TAG_EXTENDED: u8 = 7;

pub const EXT_LIST: u8 = 0x17;
pub const EXT_FPREG: u8 = 0x27;
pub const EXT_ALLOC_LIST: u8 = 0x37;
pub const EXT_LITERAL: u8 = 0x47;
pub const EXT_TYPED_REG: u8 = 0x57;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Operand {
    Literal(u64),
    SignedInteger(i64),
    Atom(u32),
    XReg(u32),
    YReg(u32),
    Label(u32),
    Character(u32),
    LiteralIndex(u32),
    FpReg(u32),
    List(Vec<Operand>),
    AllocList(Vec<Operand>),
    TypedReg { reg: Box<Operand>, type_index: u32 },
    BigInteger { sign: u8, magnitude_be: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Instruction {
    pub offset: usize,
    pub opcode: u32,
    pub name: &'static str,
    pub operands: Vec<Operand>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Disassembly {
    pub instructions: Vec<Instruction>,
}

pub fn disassemble(code: &CodeChunk) -> Result<Disassembly> {
    let mut reader: Reader<'_> = Reader::new(&code.code);
    let mut instructions: Vec<Instruction> = Vec::new();
    while !reader.is_empty() {
        let offset: usize = reader.position();
        let opcode: u32 = u32::from(reader.u8()?);
        let spec: OpcodeSpec = opcodes::opcode_spec(opcode).ok_or(Error::UnknownOpcode {
            opcode,
            offset,
            max_known: opcodes::MAX_OPCODE,
        })?;
        let mut operands: Vec<Operand> = Vec::with_capacity(spec.arity as usize);
        for _ in 0..spec.arity {
            operands.push(decode_operand(&mut reader)?);
        }
        instructions.push(Instruction {
            offset,
            opcode,
            name: spec.name,
            operands,
        });
        if spec.name == "int_code_end" {
            break;
        }
    }
    Ok(Disassembly { instructions })
}

pub fn decode_compact_simple(reader: &mut Reader<'_>) -> Result<(u8, u32)> {
    let op: Operand = decode_operand(reader)?;
    let tag: u8 = operand_tag(&op);
    let value: u32 = operand_u32(&op).ok_or(Error::BadCompactTerm(reader.position()))?;
    Ok((tag, value))
}

const fn operand_tag(op: &Operand) -> u8 {
    match op {
        Operand::Literal(_) => TAG_LITERAL,
        Operand::SignedInteger(_) | Operand::BigInteger { .. } => TAG_INTEGER,
        Operand::Atom(_) => TAG_ATOM,
        Operand::XReg(_) => TAG_XREG,
        Operand::YReg(_) => TAG_YREG,
        Operand::Label(_) => TAG_LABEL,
        Operand::Character(_) => TAG_CHARACTER,
        Operand::LiteralIndex(_)
        | Operand::FpReg(_)
        | Operand::List(_)
        | Operand::AllocList(_)
        | Operand::TypedReg { .. } => TAG_EXTENDED,
    }
}

#[allow(clippy::cast_possible_truncation)]
fn operand_u32(op: &Operand) -> Option<u32> {
    match op {
        Operand::Literal(v) => Some(*v as u32),
        Operand::SignedInteger(v) => Some(*v as u32),
        Operand::Atom(v)
        | Operand::XReg(v)
        | Operand::YReg(v)
        | Operand::Label(v)
        | Operand::Character(v)
        | Operand::LiteralIndex(v)
        | Operand::FpReg(v) => Some(*v),
        _ => None,
    }
}

fn decode_operand(reader: &mut Reader<'_>) -> Result<Operand> {
    let byte: u8 = reader.u8()?;
    let tag: u8 = byte & 0b0000_0111;
    if tag == TAG_EXTENDED {
        return decode_extended(reader, byte);
    }
    let value: CompactValue = decode_compact_value(reader, byte)?;
    Ok(match tag {
        TAG_LITERAL => Operand::Literal(value.into_u64()),
        TAG_INTEGER => match value {
            CompactValue::Small(v) => Operand::SignedInteger(v),
            CompactValue::Big { sign, magnitude_be } => Operand::BigInteger { sign, magnitude_be },
        },
        TAG_ATOM => Operand::Atom(value.into_u32_saturating()),
        TAG_XREG => Operand::XReg(value.into_u32_saturating()),
        TAG_YREG => Operand::YReg(value.into_u32_saturating()),
        TAG_LABEL => Operand::Label(value.into_u32_saturating()),
        TAG_CHARACTER => Operand::Character(value.into_u32_saturating()),
        _ => return Err(Error::BadCompactTerm(reader.position())),
    })
}

#[derive(Debug)]
enum CompactValue {
    Small(i64),
    Big { sign: u8, magnitude_be: Vec<u8> },
}

impl CompactValue {
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    fn into_u64(self) -> u64 {
        match self {
            Self::Small(v) => v as u64,
            Self::Big { magnitude_be, .. } => {
                let mut acc: u64 = 0;
                for b in magnitude_be.iter().take(8) {
                    acc = (acc << 8) | u64::from(*b);
                }
                acc
            }
        }
    }

    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    fn into_u32_saturating(self) -> u32 {
        match self {
            Self::Small(v) => {
                if v < 0 {
                    0
                } else if v > i64::from(u32::MAX) {
                    u32::MAX
                } else {
                    v as u32
                }
            }
            Self::Big { magnitude_be, .. } => {
                let mut acc: u64 = 0;
                for b in magnitude_be.iter().take(4) {
                    acc = (acc << 8) | u64::from(*b);
                }
                if acc > u64::from(u32::MAX) {
                    u32::MAX
                } else {
                    acc as u32
                }
            }
        }
    }
}

fn decode_compact_value(reader: &mut Reader<'_>, byte: u8) -> Result<CompactValue> {
    if byte & 0b1000 == 0 {
        let v: i64 = i64::from(byte >> 4);
        return Ok(CompactValue::Small(v));
    }
    if byte & 0b1_0000 == 0 {
        let next: u8 = reader.u8()?;
        let high: u64 = u64::from((byte & 0b1110_0000) >> 5);
        let combined: u64 = (high << 8) | u64::from(next);
        #[allow(clippy::cast_possible_wrap)]
        return Ok(CompactValue::Small(combined as i64));
    }
    let high_nibble: u8 = byte >> 5;
    let nbytes: usize = if high_nibble == 0b111 {
        let extra: CompactValue = decode_compact_value(reader, reader.peek(1)?[0])?;
        reader.u8()?;
        match extra {
            CompactValue::Small(v) if v >= 0 => (v as usize) + 9,
            _ => return Err(Error::BadCompactTerm(reader.position())),
        }
    } else {
        usize::from(high_nibble) + 2
    };
    let bytes: Vec<u8> = reader.take(nbytes)?.to_vec();
    if nbytes <= 8 {
        let mut acc: u64 = 0;
        for b in &bytes {
            acc = (acc << 8) | u64::from(*b);
        }
        let signed: i64 = sign_extend(acc, nbytes * 8);
        Ok(CompactValue::Small(signed))
    } else {
        let sign: u8 = u8::from(bytes[0] & 0x80 != 0);
        Ok(CompactValue::Big {
            sign,
            magnitude_be: bytes,
        })
    }
}

#[allow(clippy::cast_possible_wrap)]
const fn sign_extend(value: u64, bits: usize) -> i64 {
    if bits >= 64 {
        return value as i64;
    }
    let shift: u32 = (64 - bits) as u32;
    ((value << shift) as i64) >> shift
}

fn decode_extended(reader: &mut Reader<'_>, byte: u8) -> Result<Operand> {
    match byte {
        EXT_LIST => {
            let size_op: Operand = decode_operand(reader)?;
            let size: u32 =
                operand_u32(&size_op).ok_or(Error::BadCompactTerm(reader.position()))?;
            let mut items: Vec<Operand> = Vec::with_capacity(size as usize);
            for _ in 0..size {
                items.push(decode_operand(reader)?);
            }
            Ok(Operand::List(items))
        }
        EXT_FPREG => {
            let inner: Operand = decode_operand(reader)?;
            let v: u32 = operand_u32(&inner).ok_or(Error::BadCompactTerm(reader.position()))?;
            Ok(Operand::FpReg(v))
        }
        EXT_ALLOC_LIST => {
            let size_op: Operand = decode_operand(reader)?;
            let size: u32 =
                operand_u32(&size_op).ok_or(Error::BadCompactTerm(reader.position()))?;
            let mut items: Vec<Operand> = Vec::with_capacity((size as usize) * 2);
            for _ in 0..(size * 2) {
                items.push(decode_operand(reader)?);
            }
            Ok(Operand::AllocList(items))
        }
        EXT_LITERAL => {
            let inner: Operand = decode_operand(reader)?;
            let v: u32 = operand_u32(&inner).ok_or(Error::BadCompactTerm(reader.position()))?;
            Ok(Operand::LiteralIndex(v))
        }
        EXT_TYPED_REG => {
            let reg: Operand = decode_operand(reader)?;
            let type_op: Operand = decode_operand(reader)?;
            let type_index: u32 =
                operand_u32(&type_op).ok_or(Error::BadCompactTerm(reader.position()))?;
            Ok(Operand::TypedReg {
                reg: Box::new(reg),
                type_index,
            })
        }
        _ => Err(Error::BadCompactTerm(reader.position())),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::chunks::CodeChunk;

    fn synthetic_bs_match_code() -> CodeChunk {
        let bytes: Vec<u8> = vec![182, 0x15, 0x03, 0x17, 0x30, 0x52, 0x10, 0x10];
        CodeChunk {
            sub_size: 16,
            instruction_set: 0,
            opcode_max: 182,
            num_labels: 0,
            num_functions: 0,
            code: bytes,
        }
    }

    #[test]
    fn opcode_182_bs_match_decodes_with_command_list() {
        let code: CodeChunk = synthetic_bs_match_code();
        let d: Disassembly = disassemble(&code).expect("disasm");
        assert_eq!(d.instructions.len(), 1);
        let i: &Instruction = &d.instructions[0];
        assert_eq!(i.opcode, 182);
        assert_eq!(i.name, "bs_match");
        assert_eq!(i.operands.len(), 3);
        assert_eq!(i.operands[0], Operand::Label(1));
        assert_eq!(i.operands[1], Operand::XReg(0));
        let Operand::List(items) = &i.operands[2] else {
            panic!("expected list operand, got {:?}", i.operands[2]);
        };
        assert_eq!(items.len(), 3);
        assert_eq!(items[0], Operand::Atom(5));
        assert_eq!(items[1], Operand::Literal(1));
        assert_eq!(items[2], Operand::Literal(1));
    }

    #[test]
    fn opcode_182_renders_via_core_erlang_renderer() {
        let code: CodeChunk = synthetic_bs_match_code();
        let d: Disassembly = disassemble(&code).expect("disasm");
        let i: &Instruction = &d.instructions[0];
        assert_eq!(i.name, "bs_match");
        let serialized: String = serde_json::to_string(i).expect("ser");
        assert!(
            serialized.contains("\"bs_match\""),
            "serialized: {serialized}"
        );
        assert!(serialized.contains("\"List\""), "serialized: {serialized}");
    }
}
