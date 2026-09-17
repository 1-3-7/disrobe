use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::classfile::{ClassFile, ConstantPoolEntry};
use crate::error::{Error, Result};
#[cfg(feature = "semantic-reach")]
use crate::reach::{self, SemanticEntryPoint, SemanticSurface};

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
    #[serde(default)]
    pub nested_attribute_name_indices: Vec<u16>,
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
    #[cfg(feature = "semantic-reach")]
    let observation: reach::ObservationToken = reach::enter(
        SemanticSurface::CodeAttribute,
        SemanticEntryPoint::ParseCodeAttribute,
    );
    let result: Result<CodeAttribute> = parse_code_attribute_inner(info);
    #[cfg(feature = "semantic-reach")]
    match &result {
        Ok(attribute) => {
            let items: usize = attribute
                .code
                .len()
                .saturating_add(attribute.exception_table.len())
                .saturating_add(attribute.nested_attribute_name_indices.len());
            observation.accepted(info.len(), items);
        }
        Err(_) => observation.rejected(),
    }
    result
}

fn parse_code_attribute_inner(info: &[u8]) -> Result<CodeAttribute> {
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
    if code_length == 0 || code_length > u16::MAX as usize {
        return Err(Error::BadBytecode {
            offset: 4,
            reason: "Code attribute length must be between 1 and 65535 bytes",
        });
    }
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
    let exception_bytes: usize = exc_count.checked_mul(8).ok_or(Error::BadBytecode {
        offset: pos,
        reason: "exception table size overflow",
    })?;
    let _: usize = end_for(info, pos, exception_bytes)?;
    let mut exception_table: Vec<ExceptionEntry> = Vec::with_capacity(exc_count);
    for _ in 0..exc_count {
        let entry_offset: usize = pos;
        let entry_end: usize = end_for(info, pos, 8)?;
        let entry: ExceptionEntry = ExceptionEntry {
            start_pc: be_u16(info, pos),
            end_pc: be_u16(info, pos + 2),
            handler_pc: be_u16(info, pos + 4),
            catch_type: be_u16(info, pos + 6),
        };
        pos = entry_end;
        if !exception_entry_is_sane(&entry, code.len()) {
            return Err(Error::BadBytecode {
                offset: entry_offset,
                reason: "invalid exception table entry",
            });
        }
        exception_table.push(entry);
    }
    let attributes_count_end: usize = end_for(info, pos, 2)?;
    let attributes_count: usize = usize::from(be_u16(info, pos));
    pos = attributes_count_end;
    let mut nested_attribute_name_indices: Vec<u16> = Vec::with_capacity(attributes_count);
    for _ in 0..attributes_count {
        let attribute_header_end: usize = end_for(info, pos, 6)?;
        let attribute_name_index: u16 = be_u16(info, pos);
        let attribute_length_raw: u32 =
            u32::from_be_bytes([info[pos + 2], info[pos + 3], info[pos + 4], info[pos + 5]]);
        let attribute_length: usize =
            usize::try_from(attribute_length_raw).map_err(|_| Error::BadBytecode {
                offset: pos + 2,
                reason: "Code attribute length overflow",
            })?;
        nested_attribute_name_indices.push(attribute_name_index);
        pos = end_for(info, attribute_header_end, attribute_length)?;
    }
    if pos != info.len() {
        return Err(Error::BadBytecode {
            offset: pos,
            reason: "trailing bytes in Code attribute",
        });
    }
    Ok(CodeAttribute {
        max_stack,
        max_locals,
        code,
        exception_table,
        dropped_exception_entries: 0,
        nested_attribute_name_indices,
    })
}

pub fn validate_code_attribute(cf: &ClassFile, code: &CodeAttribute) -> Result<Vec<Instruction>> {
    if code.code.is_empty() || code.code.len() > u16::MAX as usize {
        return Err(Error::BadBytecode {
            offset: code.code.len(),
            reason: "Code attribute length must be between 1 and 65535 bytes",
        });
    }
    let instructions: Vec<Instruction> = disassemble(&code.code)?;
    let boundaries: BTreeSet<u32> = instructions
        .iter()
        .map(|instruction: &Instruction| instruction.pc)
        .collect();
    let code_length: u32 = u32::try_from(code.code.len()).map_err(|_| Error::BadBytecode {
        offset: code.code.len(),
        reason: "Code length is out of range",
    })?;
    for entry in &code.exception_table {
        let start: u32 = u32::from(entry.start_pc);
        let end: u32 = u32::from(entry.end_pc);
        let handler: u32 = u32::from(entry.handler_pc);
        if start >= end
            || end > code_length
            || handler >= code_length
            || !boundaries.contains(&start)
            || (end != code_length && !boundaries.contains(&end))
            || !boundaries.contains(&handler)
        {
            return Err(Error::BadBytecode {
                offset: usize::from(entry.start_pc),
                reason: "exception table target is not an instruction boundary",
            });
        }
        if entry.catch_type != 0 {
            let _: &str = cf.class_name(entry.catch_type)?;
        }
    }
    for name_index in &code.nested_attribute_name_indices {
        let _: &str = cf.utf8_at(*name_index)?;
    }
    for instruction in &instructions {
        validate_instruction_operands(cf, code, instruction)?;
        match &instruction.operands {
            Operands::Branch(offset) => {
                validate_control_target(instruction.pc, *offset, &boundaries)?;
            }
            Operands::TableSwitch {
                default, offsets, ..
            } => {
                validate_control_target(instruction.pc, *default, &boundaries)?;
                for offset in offsets {
                    validate_control_target(instruction.pc, *offset, &boundaries)?;
                }
            }
            Operands::LookupSwitch { default, pairs } => {
                if pairs
                    .windows(2)
                    .any(|pair: &[(i32, i32)]| pair[0].0 >= pair[1].0)
                {
                    return Err(Error::BadBytecode {
                        offset: instruction.pc as usize,
                        reason: "lookupswitch keys are not strictly increasing",
                    });
                }
                validate_control_target(instruction.pc, *default, &boundaries)?;
                for (_, offset) in pairs {
                    validate_control_target(instruction.pc, *offset, &boundaries)?;
                }
            }
            _ => {}
        }
    }
    Ok(instructions)
}

fn constant_pool_entry(cf: &ClassFile, index: u16, pc: u32) -> Result<&ConstantPoolEntry> {
    let pool_index: usize = usize::from(index);
    if pool_index == 0 {
        return Err(Error::BadBytecode {
            offset: pc as usize,
            reason: "bytecode constant pool index is zero",
        });
    }
    cf.constant_pool
        .get(pool_index)
        .ok_or(Error::BadConstantIndex {
            idx: pool_index,
            size: cf.constant_pool.len(),
        })
}

fn name_and_type_descriptor(cf: &ClassFile, index: u16, method: bool, pc: u32) -> Result<&str> {
    let entry: &ConstantPoolEntry = constant_pool_entry(cf, index, pc)?;
    let ConstantPoolEntry::NameAndType {
        name_index,
        descriptor_index,
    } = entry
    else {
        return Err(Error::BadBytecode {
            offset: pc as usize,
            reason: "member reference has an invalid name-and-type entry",
        });
    };
    let _: &str = cf.utf8_at(*name_index)?;
    let descriptor: &str = cf.utf8_at(*descriptor_index)?;
    let descriptor_valid: bool = if method {
        crate::descriptor::parse_method(descriptor).is_some()
    } else {
        crate::descriptor::parse_field(descriptor).is_some()
    };
    if !descriptor_valid {
        return Err(Error::BadBytecode {
            offset: pc as usize,
            reason: "member reference has an invalid descriptor",
        });
    }
    Ok(descriptor)
}

fn validate_field_reference(cf: &ClassFile, index: u16, pc: u32) -> Result<()> {
    let entry: &ConstantPoolEntry = constant_pool_entry(cf, index, pc)?;
    let ConstantPoolEntry::Fieldref {
        class_index,
        name_and_type_index,
    } = entry
    else {
        return Err(Error::BadBytecode {
            offset: pc as usize,
            reason: "field opcode does not reference a field",
        });
    };
    let _: &str = cf.class_name(*class_index)?;
    let _: &str = name_and_type_descriptor(cf, *name_and_type_index, false, pc)?;
    Ok(())
}

fn validate_method_reference(
    cf: &ClassFile,
    index: u16,
    pc: u32,
    allow_interface: bool,
    require_interface: bool,
) -> Result<crate::descriptor::MethodDescriptor> {
    let entry: &ConstantPoolEntry = constant_pool_entry(cf, index, pc)?;
    let (class_index, name_and_type_index, is_interface): (u16, u16, bool) = match entry {
        ConstantPoolEntry::Methodref {
            class_index,
            name_and_type_index,
        } => (*class_index, *name_and_type_index, false),
        ConstantPoolEntry::InterfaceMethodref {
            class_index,
            name_and_type_index,
        } => (*class_index, *name_and_type_index, true),
        _ => {
            return Err(Error::BadBytecode {
                offset: pc as usize,
                reason: "invoke opcode does not reference a method",
            });
        }
    };
    if is_interface && !allow_interface || require_interface && !is_interface {
        return Err(Error::BadBytecode {
            offset: pc as usize,
            reason: "invoke opcode references the wrong method kind",
        });
    }
    let _: &str = cf.class_name(class_index)?;
    let descriptor: &str = name_and_type_descriptor(cf, name_and_type_index, true, pc)?;
    crate::descriptor::parse_method(descriptor).ok_or(Error::BadBytecode {
        offset: pc as usize,
        reason: "invoke opcode has an invalid method descriptor",
    })
}

fn validate_method_handle(cf: &ClassFile, reference_kind: u8, index: u16, pc: u32) -> Result<()> {
    match reference_kind {
        1..=4 => validate_field_reference(cf, index, pc),
        5 | 8 => validate_method_reference(cf, index, pc, false, false).map(|_| ()),
        6 | 7 => validate_method_reference(cf, index, pc, true, false).map(|_| ()),
        9 => validate_method_reference(cf, index, pc, true, true).map(|_| ()),
        _ => Err(Error::BadBytecode {
            offset: pc as usize,
            reason: "method handle has an invalid reference kind",
        }),
    }
}

fn bootstrap_method_count(cf: &ClassFile, pc: u32) -> Result<usize> {
    let mut bootstrap_info: Option<&[u8]> = None;
    for attribute in &cf.attributes {
        let name: &str = cf.utf8_at(attribute.name_index)?;
        if name != "BootstrapMethods" {
            continue;
        }
        if bootstrap_info.is_some() {
            return Err(Error::BadBytecode {
                offset: pc as usize,
                reason: "class has duplicate BootstrapMethods attributes",
            });
        }
        bootstrap_info = Some(&attribute.info);
    }
    let Some(info): Option<&[u8]> = bootstrap_info else {
        return Ok(0);
    };
    let count_bytes: &[u8] = info.get(0..2).ok_or(Error::BadBytecode {
        offset: pc as usize,
        reason: "BootstrapMethods attribute is truncated",
    })?;
    let count: usize = usize::from(u16::from_be_bytes([count_bytes[0], count_bytes[1]]));
    let mut cursor: usize = 2;
    for _ in 0..count {
        let header: &[u8] = info.get(cursor..cursor + 4).ok_or(Error::BadBytecode {
            offset: pc as usize,
            reason: "BootstrapMethods entry is truncated",
        })?;
        let method_ref: u16 = u16::from_be_bytes([header[0], header[1]]);
        let argument_count: usize = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let method_entry: &ConstantPoolEntry = constant_pool_entry(cf, method_ref, pc)?;
        let ConstantPoolEntry::MethodHandle {
            reference_kind,
            reference_index,
        } = method_entry
        else {
            return Err(Error::BadBytecode {
                offset: pc as usize,
                reason: "BootstrapMethods entry does not reference a method handle",
            });
        };
        validate_method_handle(cf, *reference_kind, *reference_index, pc)?;
        cursor = cursor.checked_add(4).ok_or(Error::BadBytecode {
            offset: pc as usize,
            reason: "BootstrapMethods offset overflow",
        })?;
        let arguments_size: usize = argument_count.checked_mul(2).ok_or(Error::BadBytecode {
            offset: pc as usize,
            reason: "BootstrapMethods argument count overflow",
        })?;
        let arguments_end: usize =
            cursor
                .checked_add(arguments_size)
                .ok_or(Error::BadBytecode {
                    offset: pc as usize,
                    reason: "BootstrapMethods offset overflow",
                })?;
        let arguments: &[u8] = info.get(cursor..arguments_end).ok_or(Error::BadBytecode {
            offset: pc as usize,
            reason: "BootstrapMethods arguments are truncated",
        })?;
        for argument in arguments.chunks_exact(2) {
            let argument_index: u16 = u16::from_be_bytes([argument[0], argument[1]]);
            let entry: &ConstantPoolEntry = constant_pool_entry(cf, argument_index, pc)?;
            if !matches!(
                entry,
                ConstantPoolEntry::Integer(_)
                    | ConstantPoolEntry::Float(_)
                    | ConstantPoolEntry::Long(_)
                    | ConstantPoolEntry::Double(_)
                    | ConstantPoolEntry::String { .. }
                    | ConstantPoolEntry::Class { .. }
                    | ConstantPoolEntry::MethodHandle { .. }
                    | ConstantPoolEntry::MethodType { .. }
                    | ConstantPoolEntry::Dynamic { .. }
            ) {
                return Err(Error::BadBytecode {
                    offset: pc as usize,
                    reason: "BootstrapMethods argument has an invalid constant kind",
                });
            }
        }
        cursor = arguments_end;
    }
    if cursor != info.len() {
        return Err(Error::BadBytecode {
            offset: pc as usize,
            reason: "BootstrapMethods attribute has trailing bytes",
        });
    }
    Ok(count)
}

fn validate_bootstrap_method_index(cf: &ClassFile, index: u16, pc: u32) -> Result<()> {
    let count: usize = bootstrap_method_count(cf, pc)?;
    if usize::from(index) >= count {
        return Err(Error::BadBytecode {
            offset: pc as usize,
            reason: "dynamic constant bootstrap method index is out of range",
        });
    }
    Ok(())
}

fn validate_dynamic_constant(
    cf: &ClassFile,
    bootstrap_method_attr_index: u16,
    name_and_type_index: u16,
    pc: u32,
    category_two: bool,
) -> Result<()> {
    validate_bootstrap_method_index(cf, bootstrap_method_attr_index, pc)?;
    let descriptor: &str = name_and_type_descriptor(cf, name_and_type_index, false, pc)?;
    let value_type: crate::descriptor::JavaType = crate::descriptor::parse_field(descriptor)
        .ok_or(Error::BadBytecode {
            offset: pc as usize,
            reason: "dynamic constant has an invalid descriptor",
        })?;
    if value_type.category_two() != category_two {
        return Err(Error::BadBytecode {
            offset: pc as usize,
            reason: "dynamic constant has the wrong value category",
        });
    }
    Ok(())
}

fn validate_ldc(cf: &ClassFile, index: u16, pc: u32, category_two: bool) -> Result<()> {
    let entry: &ConstantPoolEntry = constant_pool_entry(cf, index, pc)?;
    match (entry, category_two) {
        (ConstantPoolEntry::Long(_) | ConstantPoolEntry::Double(_), true)
        | (ConstantPoolEntry::Integer(_) | ConstantPoolEntry::Float(_), false) => Ok(()),
        (ConstantPoolEntry::String { utf8_index }, false) => {
            let _: &str = cf.utf8_at(*utf8_index)?;
            Ok(())
        }
        (ConstantPoolEntry::Class { .. }, false) => {
            let _: &str = cf.class_name(index)?;
            Ok(())
        }
        (ConstantPoolEntry::MethodType { descriptor_index }, false) => {
            let descriptor: &str = cf.utf8_at(*descriptor_index)?;
            if crate::descriptor::parse_method(descriptor).is_none() {
                return Err(Error::BadBytecode {
                    offset: pc as usize,
                    reason: "method type constant has an invalid descriptor",
                });
            }
            Ok(())
        }
        (
            ConstantPoolEntry::MethodHandle {
                reference_kind,
                reference_index,
            },
            false,
        ) => validate_method_handle(cf, *reference_kind, *reference_index, pc),
        (
            ConstantPoolEntry::Dynamic {
                bootstrap_method_attr_index,
                name_and_type_index,
            },
            expected_category_two,
        ) => validate_dynamic_constant(
            cf,
            *bootstrap_method_attr_index,
            *name_and_type_index,
            pc,
            expected_category_two,
        ),
        _ => Err(Error::BadBytecode {
            offset: pc as usize,
            reason: "ldc opcode references an incompatible constant",
        }),
    }
}

fn validate_class_reference(
    cf: &ClassFile,
    index: u16,
    pc: u32,
    require_array: bool,
    forbid_array: bool,
) -> Result<&str> {
    let class_name: &str = cf.class_name(index)?;
    if require_array && !class_name.starts_with('[') || forbid_array && class_name.starts_with('[')
    {
        return Err(Error::BadBytecode {
            offset: pc as usize,
            reason: "class opcode references an incompatible class descriptor",
        });
    }
    Ok(class_name)
}

fn validate_instruction_operands(
    cf: &ClassFile,
    code: &CodeAttribute,
    instruction: &Instruction,
) -> Result<()> {
    match (&instruction.operands, instruction.opcode) {
        (Operands::ConstPool(index), 0x12 | 0x13) => {
            validate_ldc(cf, *index, instruction.pc, false)
        }
        (Operands::ConstPool(index), 0x14) => validate_ldc(cf, *index, instruction.pc, true),
        (Operands::ConstPool(index), 0xB2..=0xB5) => {
            validate_field_reference(cf, *index, instruction.pc)
        }
        (Operands::ConstPool(index), 0xB6) => {
            validate_method_reference(cf, *index, instruction.pc, false, false).map(|_| ())
        }
        (Operands::ConstPool(index), 0xB7 | 0xB8) => {
            validate_method_reference(cf, *index, instruction.pc, true, false).map(|_| ())
        }
        (Operands::ConstPool(index), 0xBB) => {
            validate_class_reference(cf, *index, instruction.pc, false, true).map(|_| ())
        }
        (Operands::ConstPool(index), 0xBD | 0xC0 | 0xC1) => {
            validate_class_reference(cf, *index, instruction.pc, false, false).map(|_| ())
        }
        (Operands::InvokeInterface { index, count }, 0xB9) => {
            let descriptor: crate::descriptor::MethodDescriptor =
                validate_method_reference(cf, *index, instruction.pc, true, true)?;
            let expected_count: usize = descriptor
                .params
                .iter()
                .map(
                    |parameter: &crate::descriptor::JavaType| {
                        if parameter.category_two() { 2 } else { 1 }
                    },
                )
                .sum::<usize>()
                .saturating_add(1);
            let reserved_offset: usize = instruction.pc as usize + 4;
            if usize::from(*count) != expected_count
                || code.code.get(reserved_offset).copied() != Some(0)
            {
                return Err(Error::BadBytecode {
                    offset: instruction.pc as usize,
                    reason: "invokeinterface operands are invalid",
                });
            }
            Ok(())
        }
        (Operands::InvokeDynamic(index), 0xBA) => {
            let entry: &ConstantPoolEntry = constant_pool_entry(cf, *index, instruction.pc)?;
            let ConstantPoolEntry::InvokeDynamic {
                bootstrap_method_attr_index,
                name_and_type_index,
            } = entry
            else {
                return Err(Error::BadBytecode {
                    offset: instruction.pc as usize,
                    reason: "invokedynamic does not reference an invoke-dynamic constant",
                });
            };
            validate_bootstrap_method_index(cf, *bootstrap_method_attr_index, instruction.pc)?;
            let _: &str = name_and_type_descriptor(cf, *name_and_type_index, true, instruction.pc)?;
            let first_reserved: usize = instruction.pc as usize + 3;
            let second_reserved: usize = instruction.pc as usize + 4;
            if code.code.get(first_reserved).copied() != Some(0)
                || code.code.get(second_reserved).copied() != Some(0)
            {
                return Err(Error::BadBytecode {
                    offset: instruction.pc as usize,
                    reason: "invokedynamic reserved operands are nonzero",
                });
            }
            Ok(())
        }
        (Operands::MultiANewArray { index, dimensions }, 0xC5) => {
            let class_name: &str =
                validate_class_reference(cf, *index, instruction.pc, true, false)?;
            let available_dimensions: usize = class_name
                .bytes()
                .take_while(|byte: &u8| *byte == b'[')
                .count();
            if *dimensions == 0 || usize::from(*dimensions) > available_dimensions {
                return Err(Error::BadBytecode {
                    offset: instruction.pc as usize,
                    reason: "multianewarray dimensions are invalid",
                });
            }
            Ok(())
        }
        (Operands::NewArray(array_type), 0xBC) if !(4..=11).contains(array_type) => {
            Err(Error::BadBytecode {
                offset: instruction.pc as usize,
                reason: "newarray has an invalid primitive type",
            })
        }
        (
            Operands::ConstPool(_)
            | Operands::InvokeInterface { .. }
            | Operands::InvokeDynamic(_)
            | Operands::MultiANewArray { .. },
            _,
        ) => Err(Error::BadBytecode {
            offset: instruction.pc as usize,
            reason: "opcode has an incompatible operand form",
        }),
        _ => Ok(()),
    }
}

fn validate_control_target(pc: u32, relative: i32, boundaries: &BTreeSet<u32>) -> Result<()> {
    let target: i64 = i64::from(pc)
        .checked_add(i64::from(relative))
        .ok_or(Error::BadBytecode {
            offset: pc as usize,
            reason: "control-flow target overflow",
        })?;
    let target_pc: u32 = u32::try_from(target).map_err(|_| Error::BadBytecode {
        offset: pc as usize,
        reason: "control-flow target is out of range",
    })?;
    if !boundaries.contains(&target_pc) {
        return Err(Error::BadBytecode {
            offset: pc as usize,
            reason: "control-flow target is not an instruction boundary",
        });
    }
    Ok(())
}

pub fn disassemble(code: &[u8]) -> Result<Vec<Instruction>> {
    #[cfg(feature = "semantic-reach")]
    let observation: reach::ObservationToken =
        reach::enter(SemanticSurface::Bytecode, SemanticEntryPoint::Disassemble);
    let result: Result<Vec<Instruction>> = disassemble_inner(code);
    #[cfg(feature = "semantic-reach")]
    match &result {
        Ok(instructions) => observation.accepted(code.len(), instructions.len()),
        Err(_) => observation.rejected(),
    }
    result
}

fn disassemble_inner(code: &[u8]) -> Result<Vec<Instruction>> {
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
    } else if matches!(sub, 0x15..=0x19 | 0x36..=0x3A | 0xA9) {
        need(code, i + 2, 2)?;
        Ok((Operands::Local(be_u16(code, i + 2)), 4, true))
    } else {
        Err(Error::BadBytecode {
            offset: i + 1,
            reason: "illegal wide opcode",
        })
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
    fn exception_sanity_gate_rejects_invalid_entries() {
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

        let parsed: Result<CodeAttribute> = parse_code_attribute(&info);
        assert!(matches!(parsed, Err(Error::BadBytecode { .. })));
    }

    #[test]
    fn code_attribute_requires_nested_attribute_count() {
        let info: [u8; 11] = [0, 0, 0, 0, 0, 0, 0, 1, 0xB1, 0, 0];
        let parsed: Result<CodeAttribute> = parse_code_attribute(&info);
        assert!(matches!(parsed, Err(Error::Truncated { .. })));
    }

    #[test]
    fn reserved_classfile_opcodes_are_refused() {
        for opcode in [0xCA, 0xFE, 0xFF] {
            let parsed: Result<Vec<Instruction>> = disassemble(&[opcode]);
            assert!(matches!(parsed, Err(Error::UnknownOpcode(_, 0))));
        }
    }

    #[test]
    fn illegal_wide_opcode_is_refused() {
        let parsed: Result<Vec<Instruction>> = disassemble(&[0xC4, 0xB1, 0x00, 0x00]);
        assert!(matches!(parsed, Err(Error::BadBytecode { .. })));
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
