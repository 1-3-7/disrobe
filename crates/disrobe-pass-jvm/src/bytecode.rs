use serde::{Deserialize, Serialize};

use crate::classfile::{ClassFile, ConstantPoolEntry};
use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperandShape {
    NoOperand,
    Byte,
    Short,
    LocalIndex,
    BranchShort,
    BranchWide,
    ConstPool1,
    ConstPool2,
    Iinc,
    NewArray,
    InvokeInterface,
    InvokeDynamic,
    MultiANewArray,
    Wide,
    TableSwitch,
    LookupSwitch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OpcodeInfo {
    pub mnemonic: &'static str,
    pub shape: OperandShape,
}

#[inline]
#[must_use]
pub const fn opcode_info(op: u8) -> Option<OpcodeInfo> {
    macro_rules! op {
        ($m:literal, $s:expr) => {
            Some(OpcodeInfo {
                mnemonic: $m,
                shape: $s,
            })
        };
    }
    match op {
        0x00 => op!("nop", OperandShape::NoOperand),
        0x01 => op!("aconst_null", OperandShape::NoOperand),
        0x02 => op!("iconst_m1", OperandShape::NoOperand),
        0x03 => op!("iconst_0", OperandShape::NoOperand),
        0x04 => op!("iconst_1", OperandShape::NoOperand),
        0x05 => op!("iconst_2", OperandShape::NoOperand),
        0x06 => op!("iconst_3", OperandShape::NoOperand),
        0x07 => op!("iconst_4", OperandShape::NoOperand),
        0x08 => op!("iconst_5", OperandShape::NoOperand),
        0x09 => op!("lconst_0", OperandShape::NoOperand),
        0x0A => op!("lconst_1", OperandShape::NoOperand),
        0x0B => op!("fconst_0", OperandShape::NoOperand),
        0x0C => op!("fconst_1", OperandShape::NoOperand),
        0x0D => op!("fconst_2", OperandShape::NoOperand),
        0x0E => op!("dconst_0", OperandShape::NoOperand),
        0x0F => op!("dconst_1", OperandShape::NoOperand),
        0x10 => op!("bipush", OperandShape::Byte),
        0x11 => op!("sipush", OperandShape::Short),
        0x12 => op!("ldc", OperandShape::ConstPool1),
        0x13 => op!("ldc_w", OperandShape::ConstPool2),
        0x14 => op!("ldc2_w", OperandShape::ConstPool2),
        0x15 => op!("iload", OperandShape::LocalIndex),
        0x16 => op!("lload", OperandShape::LocalIndex),
        0x17 => op!("fload", OperandShape::LocalIndex),
        0x18 => op!("dload", OperandShape::LocalIndex),
        0x19 => op!("aload", OperandShape::LocalIndex),
        0x1A => op!("iload_0", OperandShape::NoOperand),
        0x1B => op!("iload_1", OperandShape::NoOperand),
        0x1C => op!("iload_2", OperandShape::NoOperand),
        0x1D => op!("iload_3", OperandShape::NoOperand),
        0x1E => op!("lload_0", OperandShape::NoOperand),
        0x1F => op!("lload_1", OperandShape::NoOperand),
        0x20 => op!("lload_2", OperandShape::NoOperand),
        0x21 => op!("lload_3", OperandShape::NoOperand),
        0x22 => op!("fload_0", OperandShape::NoOperand),
        0x23 => op!("fload_1", OperandShape::NoOperand),
        0x24 => op!("fload_2", OperandShape::NoOperand),
        0x25 => op!("fload_3", OperandShape::NoOperand),
        0x26 => op!("dload_0", OperandShape::NoOperand),
        0x27 => op!("dload_1", OperandShape::NoOperand),
        0x28 => op!("dload_2", OperandShape::NoOperand),
        0x29 => op!("dload_3", OperandShape::NoOperand),
        0x2A => op!("aload_0", OperandShape::NoOperand),
        0x2B => op!("aload_1", OperandShape::NoOperand),
        0x2C => op!("aload_2", OperandShape::NoOperand),
        0x2D => op!("aload_3", OperandShape::NoOperand),
        0x2E => op!("iaload", OperandShape::NoOperand),
        0x2F => op!("laload", OperandShape::NoOperand),
        0x30 => op!("faload", OperandShape::NoOperand),
        0x31 => op!("daload", OperandShape::NoOperand),
        0x32 => op!("aaload", OperandShape::NoOperand),
        0x33 => op!("baload", OperandShape::NoOperand),
        0x34 => op!("caload", OperandShape::NoOperand),
        0x35 => op!("saload", OperandShape::NoOperand),
        0x36 => op!("istore", OperandShape::LocalIndex),
        0x37 => op!("lstore", OperandShape::LocalIndex),
        0x38 => op!("fstore", OperandShape::LocalIndex),
        0x39 => op!("dstore", OperandShape::LocalIndex),
        0x3A => op!("astore", OperandShape::LocalIndex),
        0x3B => op!("istore_0", OperandShape::NoOperand),
        0x3C => op!("istore_1", OperandShape::NoOperand),
        0x3D => op!("istore_2", OperandShape::NoOperand),
        0x3E => op!("istore_3", OperandShape::NoOperand),
        0x3F => op!("lstore_0", OperandShape::NoOperand),
        0x40 => op!("lstore_1", OperandShape::NoOperand),
        0x41 => op!("lstore_2", OperandShape::NoOperand),
        0x42 => op!("lstore_3", OperandShape::NoOperand),
        0x43 => op!("fstore_0", OperandShape::NoOperand),
        0x44 => op!("fstore_1", OperandShape::NoOperand),
        0x45 => op!("fstore_2", OperandShape::NoOperand),
        0x46 => op!("fstore_3", OperandShape::NoOperand),
        0x47 => op!("dstore_0", OperandShape::NoOperand),
        0x48 => op!("dstore_1", OperandShape::NoOperand),
        0x49 => op!("dstore_2", OperandShape::NoOperand),
        0x4A => op!("dstore_3", OperandShape::NoOperand),
        0x4B => op!("astore_0", OperandShape::NoOperand),
        0x4C => op!("astore_1", OperandShape::NoOperand),
        0x4D => op!("astore_2", OperandShape::NoOperand),
        0x4E => op!("astore_3", OperandShape::NoOperand),
        0x4F => op!("iastore", OperandShape::NoOperand),
        0x50 => op!("lastore", OperandShape::NoOperand),
        0x51 => op!("fastore", OperandShape::NoOperand),
        0x52 => op!("dastore", OperandShape::NoOperand),
        0x53 => op!("aastore", OperandShape::NoOperand),
        0x54 => op!("bastore", OperandShape::NoOperand),
        0x55 => op!("castore", OperandShape::NoOperand),
        0x56 => op!("sastore", OperandShape::NoOperand),
        0x57 => op!("pop", OperandShape::NoOperand),
        0x58 => op!("pop2", OperandShape::NoOperand),
        0x59 => op!("dup", OperandShape::NoOperand),
        0x5A => op!("dup_x1", OperandShape::NoOperand),
        0x5B => op!("dup_x2", OperandShape::NoOperand),
        0x5C => op!("dup2", OperandShape::NoOperand),
        0x5D => op!("dup2_x1", OperandShape::NoOperand),
        0x5E => op!("dup2_x2", OperandShape::NoOperand),
        0x5F => op!("swap", OperandShape::NoOperand),
        0x60 => op!("iadd", OperandShape::NoOperand),
        0x61 => op!("ladd", OperandShape::NoOperand),
        0x62 => op!("fadd", OperandShape::NoOperand),
        0x63 => op!("dadd", OperandShape::NoOperand),
        0x64 => op!("isub", OperandShape::NoOperand),
        0x65 => op!("lsub", OperandShape::NoOperand),
        0x66 => op!("fsub", OperandShape::NoOperand),
        0x67 => op!("dsub", OperandShape::NoOperand),
        0x68 => op!("imul", OperandShape::NoOperand),
        0x69 => op!("lmul", OperandShape::NoOperand),
        0x6A => op!("fmul", OperandShape::NoOperand),
        0x6B => op!("dmul", OperandShape::NoOperand),
        0x6C => op!("idiv", OperandShape::NoOperand),
        0x6D => op!("ldiv", OperandShape::NoOperand),
        0x6E => op!("fdiv", OperandShape::NoOperand),
        0x6F => op!("ddiv", OperandShape::NoOperand),
        0x70 => op!("irem", OperandShape::NoOperand),
        0x71 => op!("lrem", OperandShape::NoOperand),
        0x72 => op!("frem", OperandShape::NoOperand),
        0x73 => op!("drem", OperandShape::NoOperand),
        0x74 => op!("ineg", OperandShape::NoOperand),
        0x75 => op!("lneg", OperandShape::NoOperand),
        0x76 => op!("fneg", OperandShape::NoOperand),
        0x77 => op!("dneg", OperandShape::NoOperand),
        0x78 => op!("ishl", OperandShape::NoOperand),
        0x79 => op!("lshl", OperandShape::NoOperand),
        0x7A => op!("ishr", OperandShape::NoOperand),
        0x7B => op!("lshr", OperandShape::NoOperand),
        0x7C => op!("iushr", OperandShape::NoOperand),
        0x7D => op!("lushr", OperandShape::NoOperand),
        0x7E => op!("iand", OperandShape::NoOperand),
        0x7F => op!("land", OperandShape::NoOperand),
        0x80 => op!("ior", OperandShape::NoOperand),
        0x81 => op!("lor", OperandShape::NoOperand),
        0x82 => op!("ixor", OperandShape::NoOperand),
        0x83 => op!("lxor", OperandShape::NoOperand),
        0x84 => op!("iinc", OperandShape::Iinc),
        0x85 => op!("i2l", OperandShape::NoOperand),
        0x86 => op!("i2f", OperandShape::NoOperand),
        0x87 => op!("i2d", OperandShape::NoOperand),
        0x88 => op!("l2i", OperandShape::NoOperand),
        0x89 => op!("l2f", OperandShape::NoOperand),
        0x8A => op!("l2d", OperandShape::NoOperand),
        0x8B => op!("f2i", OperandShape::NoOperand),
        0x8C => op!("f2l", OperandShape::NoOperand),
        0x8D => op!("f2d", OperandShape::NoOperand),
        0x8E => op!("d2i", OperandShape::NoOperand),
        0x8F => op!("d2l", OperandShape::NoOperand),
        0x90 => op!("d2f", OperandShape::NoOperand),
        0x91 => op!("i2b", OperandShape::NoOperand),
        0x92 => op!("i2c", OperandShape::NoOperand),
        0x93 => op!("i2s", OperandShape::NoOperand),
        0x94 => op!("lcmp", OperandShape::NoOperand),
        0x95 => op!("fcmpl", OperandShape::NoOperand),
        0x96 => op!("fcmpg", OperandShape::NoOperand),
        0x97 => op!("dcmpl", OperandShape::NoOperand),
        0x98 => op!("dcmpg", OperandShape::NoOperand),
        0x99 => op!("ifeq", OperandShape::BranchShort),
        0x9A => op!("ifne", OperandShape::BranchShort),
        0x9B => op!("iflt", OperandShape::BranchShort),
        0x9C => op!("ifge", OperandShape::BranchShort),
        0x9D => op!("ifgt", OperandShape::BranchShort),
        0x9E => op!("ifle", OperandShape::BranchShort),
        0x9F => op!("if_icmpeq", OperandShape::BranchShort),
        0xA0 => op!("if_icmpne", OperandShape::BranchShort),
        0xA1 => op!("if_icmplt", OperandShape::BranchShort),
        0xA2 => op!("if_icmpge", OperandShape::BranchShort),
        0xA3 => op!("if_icmpgt", OperandShape::BranchShort),
        0xA4 => op!("if_icmple", OperandShape::BranchShort),
        0xA5 => op!("if_acmpeq", OperandShape::BranchShort),
        0xA6 => op!("if_acmpne", OperandShape::BranchShort),
        0xA7 => op!("goto", OperandShape::BranchShort),
        0xA8 => op!("jsr", OperandShape::BranchShort),
        0xA9 => op!("ret", OperandShape::LocalIndex),
        0xAA => op!("tableswitch", OperandShape::TableSwitch),
        0xAB => op!("lookupswitch", OperandShape::LookupSwitch),
        0xAC => op!("ireturn", OperandShape::NoOperand),
        0xAD => op!("lreturn", OperandShape::NoOperand),
        0xAE => op!("freturn", OperandShape::NoOperand),
        0xAF => op!("dreturn", OperandShape::NoOperand),
        0xB0 => op!("areturn", OperandShape::NoOperand),
        0xB1 => op!("return", OperandShape::NoOperand),
        0xB2 => op!("getstatic", OperandShape::ConstPool2),
        0xB3 => op!("putstatic", OperandShape::ConstPool2),
        0xB4 => op!("getfield", OperandShape::ConstPool2),
        0xB5 => op!("putfield", OperandShape::ConstPool2),
        0xB6 => op!("invokevirtual", OperandShape::ConstPool2),
        0xB7 => op!("invokespecial", OperandShape::ConstPool2),
        0xB8 => op!("invokestatic", OperandShape::ConstPool2),
        0xB9 => op!("invokeinterface", OperandShape::InvokeInterface),
        0xBA => op!("invokedynamic", OperandShape::InvokeDynamic),
        0xBB => op!("new", OperandShape::ConstPool2),
        0xBC => op!("newarray", OperandShape::NewArray),
        0xBD => op!("anewarray", OperandShape::ConstPool2),
        0xBE => op!("arraylength", OperandShape::NoOperand),
        0xBF => op!("athrow", OperandShape::NoOperand),
        0xC0 => op!("checkcast", OperandShape::ConstPool2),
        0xC1 => op!("instanceof", OperandShape::ConstPool2),
        0xC2 => op!("monitorenter", OperandShape::NoOperand),
        0xC3 => op!("monitorexit", OperandShape::NoOperand),
        0xC4 => op!("wide", OperandShape::Wide),
        0xC5 => op!("multianewarray", OperandShape::MultiANewArray),
        0xC6 => op!("ifnull", OperandShape::BranchShort),
        0xC7 => op!("ifnonnull", OperandShape::BranchShort),
        0xC8 => op!("goto_w", OperandShape::BranchWide),
        0xC9 => op!("jsr_w", OperandShape::BranchWide),
        0xCA => op!("breakpoint", OperandShape::NoOperand),
        0xFE => op!("impdep1", OperandShape::NoOperand),
        0xFF => op!("impdep2", OperandShape::NoOperand),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operands {
    None,
    Byte(i32),
    Short(i32),
    Local(u16),
    Branch(i32),
    ConstPool(u16),
    Iinc {
        index: u16,
        delta: i32,
    },
    NewArray(u8),
    InvokeInterface {
        index: u16,
        count: u8,
    },
    InvokeDynamic(u16),
    MultiANewArray {
        index: u16,
        dimensions: u8,
    },
    TableSwitch {
        default: i32,
        low: i32,
        high: i32,
        offsets: Vec<i32>,
    },
    LookupSwitch {
        default: i32,
        pairs: Vec<(i32, i32)>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instruction {
    pub pc: u32,
    pub opcode: u8,
    pub mnemonic: &'static str,
    pub wide: bool,
    pub operands: Operands,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExceptionEntry {
    pub start_pc: u16,
    pub end_pc: u16,
    pub handler_pc: u16,
    pub catch_type: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeAttribute {
    pub max_stack: u16,
    pub max_locals: u16,
    pub code: Vec<u8>,
    pub exception_table: Vec<ExceptionEntry>,
    pub dropped_exception_entries: usize,
}

#[inline]
fn exception_entry_is_sane(entry: &ExceptionEntry, code_length: usize) -> bool {
    let start: usize = usize::from(entry.start_pc);
    let end: usize = usize::from(entry.end_pc);
    let handler: usize = usize::from(entry.handler_pc);
    start < end && end <= code_length && handler < code_length
}

#[inline]
const fn be_u16(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}

#[inline]
const fn be_i16(b: &[u8], o: usize) -> i16 {
    i16::from_be_bytes([b[o], b[o + 1]])
}

#[inline]
const fn be_i32(b: &[u8], o: usize) -> i32 {
    i32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

pub fn parse_code_attribute(info: &[u8]) -> Result<CodeAttribute> {
    if info.len() < 8 {
        return Err(Error::Truncated {
            offset: 0,
            needed: 8,
            had: info.len(),
        });
    }
    let max_stack: u16 = be_u16(info, 0);
    let max_locals: u16 = be_u16(info, 2);
    let code_length_raw: u32 = u32::from_be_bytes([info[4], info[5], info[6], info[7]]);
    let code_length: usize = usize::try_from(code_length_raw).map_err(|_| Error::BadBytecode {
        offset: 4,
        reason: "code_length overflow",
    })?;
    let code_start: usize = 8;
    let code_end: usize = code_start
        .checked_add(code_length)
        .ok_or(Error::BadBytecode {
            offset: code_start,
            reason: "code_length overflow",
        })?;
    if code_end > info.len() {
        return Err(Error::Truncated {
            offset: code_start,
            needed: code_length,
            had: info.len().saturating_sub(code_start),
        });
    }
    let code: Vec<u8> = info[code_start..code_end].to_vec();
    let mut pos: usize = code_end;
    let exc_count_end: usize = end_for(info, pos, 2)?;
    let exc_count: usize = usize::from(be_u16(info, pos));
    pos = exc_count_end;
    let mut exception_table: Vec<ExceptionEntry> = Vec::with_capacity(exc_count);
    let mut dropped_exception_entries: usize = 0;
    for _ in 0..exc_count {
        let entry_end: usize = end_for(info, pos, 8)?;
        let entry: ExceptionEntry = ExceptionEntry {
            start_pc: be_u16(info, pos),
            end_pc: be_u16(info, pos + 2),
            handler_pc: be_u16(info, pos + 4),
            catch_type: be_u16(info, pos + 6),
        };
        pos = entry_end;
        if exception_entry_is_sane(&entry, code.len()) {
            exception_table.push(entry);
        } else {
            dropped_exception_entries += 1;
        }
    }
    Ok(CodeAttribute {
        max_stack,
        max_locals,
        code,
        exception_table,
        dropped_exception_entries,
    })
}

pub fn disassemble(code: &[u8]) -> Result<Vec<Instruction>> {
    let mut out: Vec<Instruction> = Vec::new();
    let mut i: usize = 0;
    while i < code.len() {
        let pc: u32 = u32::try_from(i).map_err(|_| Error::BadBytecode {
            offset: i,
            reason: "bytecode offset overflow",
        })?;
        let opcode: u8 = code[i];
        let Some(info): Option<OpcodeInfo> = opcode_info(opcode) else {
            return Err(Error::UnknownOpcode(opcode, i));
        };
        let (operands, len, wide): (Operands, usize, bool) = decode_operands(code, i, info.shape)?;
        out.push(Instruction {
            pc,
            opcode,
            mnemonic: info.mnemonic,
            wide,
            operands,
        });
        i += len;
    }
    Ok(out)
}

const fn end_for(code: &[u8], from: usize, n: usize) -> Result<usize> {
    let Some(end): Option<usize> = from.checked_add(n) else {
        return Err(Error::Truncated {
            offset: from,
            needed: n,
            had: code.len().saturating_sub(from),
        });
    };
    if end > code.len() {
        return Err(Error::Truncated {
            offset: from,
            needed: n,
            had: code.len().saturating_sub(from),
        });
    }
    Ok(end)
}

fn need(code: &[u8], from: usize, n: usize) -> Result<()> {
    let _end: usize = end_for(code, from, n)?;
    Ok(())
}

fn decode_operands(code: &[u8], i: usize, shape: OperandShape) -> Result<(Operands, usize, bool)> {
    let after: usize = i.checked_add(1).ok_or(Error::BadBytecode {
        offset: i,
        reason: "operand offset overflow",
    })?;
    match shape {
        OperandShape::NoOperand => Ok((Operands::None, 1, false)),
        OperandShape::Byte => {
            need(code, after, 1)?;
            Ok((Operands::Byte(i32::from(code[after] as i8)), 2, false))
        }
        OperandShape::Short => {
            need(code, after, 2)?;
            Ok((Operands::Short(i32::from(be_i16(code, after))), 3, false))
        }
        OperandShape::LocalIndex => {
            need(code, after, 1)?;
            Ok((Operands::Local(u16::from(code[after])), 2, false))
        }
        OperandShape::BranchShort => {
            need(code, after, 2)?;
            Ok((Operands::Branch(i32::from(be_i16(code, after))), 3, false))
        }
        OperandShape::BranchWide => {
            need(code, after, 4)?;
            Ok((Operands::Branch(be_i32(code, after)), 5, false))
        }
        OperandShape::ConstPool1 => {
            need(code, after, 1)?;
            Ok((Operands::ConstPool(u16::from(code[after])), 2, false))
        }
        OperandShape::ConstPool2 => {
            need(code, after, 2)?;
            Ok((Operands::ConstPool(be_u16(code, after)), 3, false))
        }
        OperandShape::Iinc => {
            need(code, after, 2)?;
            Ok((
                Operands::Iinc {
                    index: u16::from(code[after]),
                    delta: i32::from(code[after + 1] as i8),
                },
                3,
                false,
            ))
        }
        OperandShape::NewArray => {
            need(code, after, 1)?;
            Ok((Operands::NewArray(code[after]), 2, false))
        }
        OperandShape::InvokeInterface => {
            need(code, after, 4)?;
            Ok((
                Operands::InvokeInterface {
                    index: be_u16(code, after),
                    count: code[after + 2],
                },
                5,
                false,
            ))
        }
        OperandShape::InvokeDynamic => {
            need(code, after, 4)?;
            Ok((Operands::InvokeDynamic(be_u16(code, after)), 5, false))
        }
        OperandShape::MultiANewArray => {
            need(code, after, 3)?;
            Ok((
                Operands::MultiANewArray {
                    index: be_u16(code, after),
                    dimensions: code[after + 2],
                },
                4,
                false,
            ))
        }
        OperandShape::Wide => decode_wide(code, i),
        OperandShape::TableSwitch => decode_tableswitch(code, i),
        OperandShape::LookupSwitch => decode_lookupswitch(code, i),
    }
}

fn decode_wide(code: &[u8], i: usize) -> Result<(Operands, usize, bool)> {
    need(code, i + 1, 1)?;
    let sub: u8 = code[i + 1];
    if sub == 0x84 {
        need(code, i + 2, 4)?;
        Ok((
            Operands::Iinc {
                index: be_u16(code, i + 2),
                delta: i32::from(be_i16(code, i + 4)),
            },
            6,
            true,
        ))
    } else {
        need(code, i + 2, 2)?;
        Ok((Operands::Local(be_u16(code, i + 2)), 4, true))
    }
}

const fn switch_pad(i: usize) -> usize {
    (4 - ((i + 1) % 4)) % 4
}

fn decode_tableswitch(code: &[u8], i: usize) -> Result<(Operands, usize, bool)> {
    let pad: usize = switch_pad(i);
    let base: usize = i
        .checked_add(1)
        .and_then(|after: usize| after.checked_add(pad))
        .ok_or(Error::BadBytecode {
            offset: i,
            reason: "tableswitch base overflow",
        })?;
    need(code, base, 12)?;
    let default: i32 = be_i32(code, base);
    let low: i32 = be_i32(code, base + 4);
    let high: i32 = be_i32(code, base + 8);
    let count: i64 = i64::from(high) - i64::from(low) + 1;
    if count < 0 || count > i64::from(u32::MAX) {
        return Err(Error::BadBytecode {
            offset: i,
            reason: "tableswitch high < low or count overflow",
        });
    }
    let count_usize: usize = usize::try_from(count).map_err(|_| Error::BadBytecode {
        offset: i,
        reason: "tableswitch count overflow",
    })?;
    let table: usize = base.checked_add(12).ok_or(Error::BadBytecode {
        offset: base,
        reason: "tableswitch table overflow",
    })?;
    let table_len: usize = count_usize.checked_mul(4).ok_or(Error::BadBytecode {
        offset: i,
        reason: "tableswitch byte count overflow",
    })?;
    let table_end: usize = end_for(code, table, table_len)?;
    let mut offsets: Vec<i32> = Vec::with_capacity(count_usize);
    for k in 0..count_usize {
        offsets.push(be_i32(code, table + k * 4));
    }
    let len: usize = table_end.checked_sub(i).ok_or(Error::BadBytecode {
        offset: i,
        reason: "tableswitch length overflow",
    })?;
    Ok((
        Operands::TableSwitch {
            default,
            low,
            high,
            offsets,
        },
        len,
        false,
    ))
}

fn decode_lookupswitch(code: &[u8], i: usize) -> Result<(Operands, usize, bool)> {
    let pad: usize = switch_pad(i);
    let base: usize = i
        .checked_add(1)
        .and_then(|after: usize| after.checked_add(pad))
        .ok_or(Error::BadBytecode {
            offset: i,
            reason: "lookupswitch base overflow",
        })?;
    need(code, base, 8)?;
    let default: i32 = be_i32(code, base);
    let npairs: i32 = be_i32(code, base + 4);
    if npairs < 0 {
        return Err(Error::BadBytecode {
            offset: i,
            reason: "lookupswitch negative npairs",
        });
    }
    let npairs_usize: usize = usize::try_from(npairs).map_err(|_| Error::BadBytecode {
        offset: i,
        reason: "lookupswitch pair count overflow",
    })?;
    let table: usize = base.checked_add(8).ok_or(Error::BadBytecode {
        offset: base,
        reason: "lookupswitch table overflow",
    })?;
    let table_len: usize = npairs_usize.checked_mul(8).ok_or(Error::BadBytecode {
        offset: i,
        reason: "lookupswitch byte count overflow",
    })?;
    let table_end: usize = end_for(code, table, table_len)?;
    let mut pairs: Vec<(i32, i32)> = Vec::with_capacity(npairs_usize);
    for k in 0..npairs_usize {
        let m: usize = table + k * 8;
        pairs.push((be_i32(code, m), be_i32(code, m + 4)));
    }
    let len: usize = table_end.checked_sub(i).ok_or(Error::BadBytecode {
        offset: i,
        reason: "lookupswitch length overflow",
    })?;
    Ok((Operands::LookupSwitch { default, pairs }, len, false))
}

#[must_use]
pub fn branch_target(insn: &Instruction) -> Option<u32> {
    match &insn.operands {
        Operands::Branch(off) => Some((i64::from(insn.pc) + i64::from(*off)) as u32),
        _ => None,
    }
}

#[must_use]
pub fn escape_java_string(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || c == '\u{7F}' => {
                let _ = std::fmt::Write::write_fmt(&mut out, format_args!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn resolve_ref(cf: &ClassFile, index: u16) -> Option<String> {
    let idx: usize = usize::from(index);
    if idx == 0 || idx >= cf.constant_pool.len() {
        return None;
    }
    match &cf.constant_pool[idx] {
        ConstantPoolEntry::Methodref {
            class_index,
            name_and_type_index,
        }
        | ConstantPoolEntry::InterfaceMethodref {
            class_index,
            name_and_type_index,
        }
        | ConstantPoolEntry::Fieldref {
            class_index,
            name_and_type_index,
        } => {
            let owner: String = cf.class_name(*class_index).unwrap_or("?").to_string();
            let (name, desc): (String, String) = name_and_type(cf, *name_and_type_index)?;
            Some(format!("{owner}.{name}:{desc}"))
        }
        ConstantPoolEntry::Class { .. } => cf.class_name(index).ok().map(str::to_string),
        ConstantPoolEntry::String { utf8_index } => {
            cf.utf8_at(*utf8_index).ok().map(escape_java_string)
        }
        ConstantPoolEntry::Integer(v) => Some(v.to_string()),
        ConstantPoolEntry::Float(bits) => Some(java_float_literal(*bits)),
        ConstantPoolEntry::Long(v) => Some(format!("{v}L")),
        ConstantPoolEntry::Double(bits) => Some(java_double_literal(*bits)),
        _ => None,
    }
}

#[must_use]
pub fn field_descriptor_at(cf: &ClassFile, index: u16) -> Option<String> {
    let idx: usize = usize::from(index);
    if idx == 0 || idx >= cf.constant_pool.len() {
        return None;
    }
    if let ConstantPoolEntry::Fieldref {
        name_and_type_index,
        ..
    } = cf.constant_pool[idx]
    {
        return name_and_type(cf, name_and_type_index).map(|(_, desc): (String, String)| desc);
    }
    None
}

#[must_use]
pub fn method_name_descriptor_at(cf: &ClassFile, index: u16) -> Option<(String, String)> {
    let idx: usize = usize::from(index);
    if idx == 0 || idx >= cf.constant_pool.len() {
        return None;
    }
    match cf.constant_pool[idx] {
        ConstantPoolEntry::Methodref {
            name_and_type_index,
            ..
        }
        | ConstantPoolEntry::InterfaceMethodref {
            name_and_type_index,
            ..
        } => name_and_type(cf, name_and_type_index),
        ConstantPoolEntry::InvokeDynamic {
            name_and_type_index,
            ..
        } => name_and_type(cf, name_and_type_index),
        _ => None,
    }
}

#[must_use]
pub fn class_internal_name_at(cf: &ClassFile, index: u16) -> Option<String> {
    cf.class_name(index).ok().map(str::to_string)
}

fn java_float_literal(bits: u32) -> String {
    let v: f32 = f32::from_bits(bits);
    if v.is_nan() {
        if bits == f32::NAN.to_bits() {
            return "Float.NaN".to_string();
        }
        return format!("Float.intBitsToFloat(0x{bits:08x})");
    }
    if v.is_infinite() {
        return if v < 0.0 {
            "Float.NEGATIVE_INFINITY".to_string()
        } else {
            "Float.POSITIVE_INFINITY".to_string()
        };
    }
    let body: String = format!("{v:e}");
    format!("{body}f")
}

fn java_double_literal(bits: u64) -> String {
    let v: f64 = f64::from_bits(bits);
    if v.is_nan() {
        if bits == f64::NAN.to_bits() {
            return "Double.NaN".to_string();
        }
        return format!("Double.longBitsToDouble(0x{bits:016x}L)");
    }
    if v.is_infinite() {
        return if v < 0.0 {
            "Double.NEGATIVE_INFINITY".to_string()
        } else {
            "Double.POSITIVE_INFINITY".to_string()
        };
    }
    format!("{v:e}")
}

fn name_and_type(cf: &ClassFile, index: u16) -> Option<(String, String)> {
    let idx: usize = usize::from(index);
    if idx == 0 || idx >= cf.constant_pool.len() {
        return None;
    }
    if let ConstantPoolEntry::NameAndType {
        name_index,
        descriptor_index,
    } = cf.constant_pool[idx]
    {
        let name: String = cf.utf8_at(name_index).ok()?.to_string();
        let desc: String = cf.utf8_at(descriptor_index).ok()?.to_string();
        Some((name, desc))
    } else {
        None
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn opcode_table_covers_canonical_range() {
        for op in 0x00u8..=0xC9u8 {
            assert!(opcode_info(op).is_some(), "missing opcode 0x{op:02X}");
        }
    }

    #[test]
    fn disassembles_iconst_ireturn() {
        let code: &[u8] = &[0x04, 0xAC];
        let insns: Vec<Instruction> = disassemble(code).expect("disasm");
        assert_eq!(insns.len(), 2);
        assert_eq!(insns[0].mnemonic, "iconst_1");
        assert_eq!(insns[1].mnemonic, "ireturn");
    }

    #[test]
    fn float_literal_preserves_noncanonical_nan_bits() {
        assert_eq!(java_float_literal(0x7fc0_0000), "Float.NaN");
        assert_eq!(java_float_literal(f32::NAN.to_bits()), "Float.NaN");
        assert_eq!(
            java_float_literal(0x7f80_0001),
            "Float.intBitsToFloat(0x7f800001)"
        );
        assert_eq!(
            java_float_literal(0xff80_0001),
            "Float.intBitsToFloat(0xff800001)"
        );
        assert_eq!(java_float_literal(0x7f80_0000), "Float.POSITIVE_INFINITY");
        assert_eq!(java_float_literal(0xff80_0000), "Float.NEGATIVE_INFINITY");
        assert_eq!(java_float_literal(1.0f32.to_bits()), "1e0f");
    }

    #[test]
    fn double_literal_preserves_noncanonical_nan_bits() {
        assert_eq!(java_double_literal(0x7ff8_0000_0000_0000), "Double.NaN");
        assert_eq!(java_double_literal(f64::NAN.to_bits()), "Double.NaN");
        assert_eq!(
            java_double_literal(0xfff8_0000_0000_0001),
            "Double.longBitsToDouble(0xfff8000000000001L)"
        );
        assert_eq!(
            java_double_literal(0x7ff0_0000_0000_0001),
            "Double.longBitsToDouble(0x7ff0000000000001L)"
        );
        assert_eq!(
            java_double_literal(0x7ff0_0000_0000_0000),
            "Double.POSITIVE_INFINITY"
        );
        assert_eq!(
            java_double_literal(0xfff0_0000_0000_0000),
            "Double.NEGATIVE_INFINITY"
        );
        assert_eq!(java_double_literal(1.0f64.to_bits()), "1e0");
    }

    #[test]
    fn exception_sanity_gate_drops_obfuscator_planted_entries() {
        let code: [u8; 2] = [0x04, 0xAC];
        let mut info: Vec<u8> = Vec::new();
        info.extend_from_slice(&0u16.to_be_bytes());
        info.extend_from_slice(&1u16.to_be_bytes());
        info.extend_from_slice(&(code.len() as u32).to_be_bytes());
        info.extend_from_slice(&code);
        info.extend_from_slice(&2u16.to_be_bytes());
        info.extend_from_slice(&0u16.to_be_bytes());
        info.extend_from_slice(&2u16.to_be_bytes());
        info.extend_from_slice(&0u16.to_be_bytes());
        info.extend_from_slice(&0u16.to_be_bytes());
        info.extend_from_slice(&9999u16.to_be_bytes());
        info.extend_from_slice(&9999u16.to_be_bytes());
        info.extend_from_slice(&9999u16.to_be_bytes());
        info.extend_from_slice(&0u16.to_be_bytes());
        info.extend_from_slice(&0u16.to_be_bytes());

        let parsed: CodeAttribute = parse_code_attribute(&info).expect("parse code attribute");
        assert_eq!(parsed.exception_table.len(), 1);
        assert_eq!(parsed.dropped_exception_entries, 1);
        assert_eq!(parsed.exception_table[0].handler_pc, 0);
    }

    #[test]
    fn decodes_bipush_signed() {
        let code: &[u8] = &[0x10, 0xFF];
        let insns: Vec<Instruction> = disassemble(code).expect("disasm");
        assert_eq!(insns[0].operands, Operands::Byte(-1));
    }

    #[test]
    fn decodes_branch_target() {
        let code: &[u8] = &[0xA7, 0x00, 0x05];
        let insns: Vec<Instruction> = disassemble(code).expect("disasm");
        assert_eq!(branch_target(&insns[0]), Some(5));
    }

    #[test]
    fn decodes_wide_iload() {
        let code: &[u8] = &[0xC4, 0x15, 0x01, 0x00];
        let insns: Vec<Instruction> = disassemble(code).expect("disasm");
        assert!(insns[0].wide);
        assert_eq!(insns[0].operands, Operands::Local(256));
    }

    #[test]
    fn decodes_tableswitch_alignment() {
        let mut code: Vec<u8> = vec![0xAA];
        let pad: usize = switch_pad(0);
        code.extend(std::iter::repeat_n(0u8, pad));
        code.extend_from_slice(&20i32.to_be_bytes());
        code.extend_from_slice(&0i32.to_be_bytes());
        code.extend_from_slice(&1i32.to_be_bytes());
        code.extend_from_slice(&7i32.to_be_bytes());
        code.extend_from_slice(&11i32.to_be_bytes());
        let insns: Vec<Instruction> = disassemble(&code).expect("disasm");
        match &insns[0].operands {
            Operands::TableSwitch {
                default,
                low,
                high,
                offsets,
            } => {
                assert_eq!(*default, 20);
                assert_eq!(*low, 0);
                assert_eq!(*high, 1);
                assert_eq!(offsets.len(), 2);
            }
            other => panic!("expected tableswitch, got {other:?}"),
        }
    }

    #[test]
    fn truncated_operand_errors() {
        let code: &[u8] = &[0x10];
        let err: Error = disassemble(code).expect_err("truncated");
        assert!(matches!(err, Error::Truncated { .. }));
    }

    #[test]
    fn need_rejects_offset_overflow() {
        let err: Error = need(&[], usize::MAX - 1, 2).expect_err("overflowing end must fail");
        assert!(matches!(
            err,
            Error::Truncated {
                offset,
                needed: 2,
                ..
            } if offset == usize::MAX - 1
        ));
    }
}
