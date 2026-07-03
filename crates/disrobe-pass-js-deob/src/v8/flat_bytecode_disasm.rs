//! Disassembler for a flat V8 Ignition `BytecodeArray` (a contiguous opcode stream).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::error::{Error, Result};

use super::bytecode_opcodes::{OpcodeTable, OperandKind, V8OpcodeSpec};
use super::bytenode::NodeVersion;

fn push_format(out: &mut String, args: std::fmt::Arguments<'_>) {
    let result: std::result::Result<(), std::fmt::Error> = std::fmt::write(out, args);
    if let Err(error) = result {
        unreachable!("string formatting failed: {error}");
    }
}

#[must_use]
pub(crate) const fn intrinsic_name(id: u64) -> Option<&'static str> {
    match id {
        0 => Some("AsyncFunctionAwait"),
        1 => Some("AsyncFunctionEnter"),
        2 => Some("AsyncFunctionReject"),
        3 => Some("AsyncFunctionResolve"),
        4 => Some("AsyncGeneratorAwait"),
        5 => Some("AsyncGeneratorReject"),
        6 => Some("AsyncGeneratorResolve"),
        7 => Some("AsyncGeneratorYieldWithAwait"),
        8 => Some("CreateJSGeneratorObject"),
        9 => Some("GeneratorGetResumeMode"),
        10 => Some("GeneratorClose"),
        11 => Some("GetImportMetaObject"),
        12 => Some("CopyDataProperties"),
        13 => Some("CopyDataPropertiesWithExcludedPropertiesOnStack"),
        14 => Some("CreateIterResultObject"),
        15 => Some("CreateAsyncFromSyncIterator"),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperandScale {
    Single,
    Double,
    Quadruple,
}

impl OperandScale {
    #[must_use]
    pub const fn multiplier(self) -> usize {
        match self {
            Self::Single => 1usize,
            Self::Double => 2usize,
            Self::Quadruple => 4usize,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedOperand {
    pub kind: OperandKind,
    pub raw_bytes: Vec<u8>,
    pub signed_value: i64,
    pub unsigned_value: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedInstruction {
    pub offset: usize,
    pub scale: OperandScale,
    pub opcode_byte: u8,
    pub mnemonic: &'static str,
    pub operands: Vec<DecodedOperand>,
    pub byte_size: usize,
}

impl DecodedInstruction {
    #[must_use]
    pub fn render(&self) -> String {
        let mut out: String = String::with_capacity(64usize);
        out.push_str(self.mnemonic);
        for (i, operand) in self.operands.iter().enumerate() {
            if i == 0 {
                out.push(' ');
            } else {
                out.push_str(", ");
            }
            match operand.kind {
                OperandKind::Imm => {
                    out.push('#');
                    out.push_str(&operand.signed_value.to_string());
                }
                OperandKind::UImm
                | OperandKind::Flag8
                | OperandKind::Flag16
                | OperandKind::RegCount => {
                    out.push('#');
                    out.push_str(&operand.unsigned_value.to_string());
                }
                OperandKind::Reg
                | OperandKind::RegOut
                | OperandKind::RegOutPair
                | OperandKind::RegOutTriple
                | OperandKind::RegOutList
                | OperandKind::RegPair
                | OperandKind::RegList
                | OperandKind::RegInOut => {
                    out.push('r');
                    out.push_str(&operand.signed_value.to_string());
                }
                OperandKind::Idx => {
                    out.push('[');
                    out.push_str(&operand.unsigned_value.to_string());
                    out.push(']');
                }
                OperandKind::RuntimeId | OperandKind::IntrinsicId => {
                    if self.mnemonic == "InvokeIntrinsic" {
                        if let Some(name) = intrinsic_name(operand.unsigned_value) {
                            out.push_str("[_");
                            out.push_str(name);
                            out.push(']');
                        } else {
                            out.push_str("rt#");
                            out.push_str(&operand.unsigned_value.to_string());
                        }
                    } else {
                        out.push_str("rt#");
                        out.push_str(&operand.unsigned_value.to_string());
                    }
                }
                OperandKind::NativeContextIndex => {
                    out.push_str("nc[");
                    out.push_str(&operand.unsigned_value.to_string());
                    out.push(']');
                }
                OperandKind::None => {}
            }
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Disassembly {
    pub node_version: NodeVersion,
    pub v8_version_label: &'static str,
    pub instructions: Vec<DecodedInstruction>,
    pub bytes_consumed: usize,
    pub trailing_garbage: usize,
    pub unknown_opcode_counts: BTreeMap<u8, usize>,
}

impl Disassembly {
    #[must_use]
    pub fn render_text(&self) -> String {
        let mut out: String = String::with_capacity(self.instructions.len() * 32usize);
        for ins in &self.instructions {
            push_format(
                &mut out,
                format_args!("{:>5}: {}\n", ins.offset, ins.render()),
            );
        }
        out
    }

    #[must_use]
    pub fn mnemonic_histogram(&self) -> BTreeMap<&'static str, usize> {
        let mut hist: BTreeMap<&'static str, usize> = BTreeMap::new();
        for ins in &self.instructions {
            *hist.entry(ins.mnemonic).or_insert(0usize) += 1usize;
        }
        hist
    }
}

#[must_use]
pub fn disassemble(bytes: &[u8], node: NodeVersion) -> Disassembly {
    let table: OpcodeTable = OpcodeTable::for_node(node);
    disassemble_with_table(bytes, &table)
}

#[allow(clippy::too_many_lines)]
#[must_use]
pub fn disassemble_with_table(bytes: &[u8], table: &OpcodeTable) -> Disassembly {
    let mut instructions: Vec<DecodedInstruction> = Vec::with_capacity(bytes.len() / 4usize);
    let mut unknown: BTreeMap<u8, usize> = BTreeMap::new();
    let mut cursor: usize = 0usize;
    let len: usize = bytes.len();
    while cursor < len {
        let start: usize = cursor;
        let scale: OperandScale = match bytes[cursor] {
            b if mnemonic_matches(table, b, "Wide") => {
                cursor = cursor.saturating_add(1);
                OperandScale::Double
            }
            b if mnemonic_matches(table, b, "ExtraWide") => {
                cursor = cursor.saturating_add(1);
                OperandScale::Quadruple
            }
            _ => OperandScale::Single,
        };
        if cursor >= len {
            break;
        }
        let opcode_byte: u8 = bytes[cursor];
        cursor = cursor.saturating_add(1);
        let Some(spec): Option<&V8OpcodeSpec> = table.lookup_byte(opcode_byte) else {
            *unknown.entry(opcode_byte).or_insert(0usize) += 1usize;
            continue;
        };
        let mut operands: Vec<DecodedOperand> = Vec::with_capacity(spec.operand_count as usize);
        let mut ok: bool = true;
        for i in 0..spec.operand_count as usize {
            let kind: OperandKind = spec.operands[i];
            let unscaled: usize = kind.unscaled_byte_size();
            let scaled: usize = unscaled.saturating_mul(scale.multiplier());
            if scaled == 0 {
                operands.push(DecodedOperand {
                    kind,
                    raw_bytes: Vec::new(),
                    signed_value: 0i64,
                    unsigned_value: 0u64,
                });
                continue;
            }
            if cursor.saturating_add(scaled) > len {
                ok = false;
                break;
            }
            let raw: Vec<u8> = bytes[cursor..cursor.saturating_add(scaled)].to_vec();
            cursor = cursor.saturating_add(scaled);
            let (signed_value, unsigned_value): (i64, u64) = decode_operand_value(&raw, kind);
            operands.push(DecodedOperand {
                kind,
                raw_bytes: raw,
                signed_value,
                unsigned_value,
            });
        }
        if !ok {
            cursor = start;
            break;
        }
        instructions.push(DecodedInstruction {
            offset: start,
            scale,
            opcode_byte,
            mnemonic: spec.mnemonic,
            operands,
            byte_size: cursor.saturating_sub(start),
        });
    }
    let trailing_garbage: usize = len.saturating_sub(cursor);
    Disassembly {
        node_version: table.node_version,
        v8_version_label: table.v8_version_label,
        instructions,
        bytes_consumed: cursor,
        trailing_garbage,
        unknown_opcode_counts: unknown,
    }
}

fn mnemonic_matches(table: &OpcodeTable, byte: u8, mnemonic: &str) -> bool {
    table
        .lookup_byte(byte)
        .is_some_and(|s: &V8OpcodeSpec| s.mnemonic == mnemonic)
}

fn decode_operand_value(bytes: &[u8], kind: OperandKind) -> (i64, u64) {
    match (kind, bytes.len()) {
        (OperandKind::Imm, 1) => {
            let signed: i8 = bytes[0].cast_signed();
            (i64::from(signed), u64::from(bytes[0]))
        }
        (OperandKind::Imm, 2) => {
            let v: i16 = i16::from_le_bytes([bytes[0], bytes[1]]);
            (i64::from(v), u64::from(v.cast_unsigned()))
        }
        (OperandKind::Imm, 4) => {
            let v: i32 = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            (i64::from(v), u64::from(v.cast_unsigned()))
        }
        (_, 1) => (i64::from(bytes[0]), u64::from(bytes[0])),
        (_, 2) => {
            let v: u16 = u16::from_le_bytes([bytes[0], bytes[1]]);
            (i64::from(v), u64::from(v))
        }
        (_, 4) => {
            let v: u32 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            (i64::from(v), u64::from(v))
        }
        _ => (0i64, 0u64),
    }
}

pub fn encode_instruction(
    table: &OpcodeTable,
    mnemonic: &str,
    operands: &[i64],
) -> Result<Vec<u8>> {
    let byte: u8 = table.lookup_mnemonic(mnemonic).ok_or_else(|| {
        Error::OxcParse(format!(
            "unknown mnemonic `{mnemonic}` for {label}",
            label = table.v8_version_label
        ))
    })?;
    let spec: &V8OpcodeSpec = table
        .lookup_byte(byte)
        .ok_or_else(|| Error::OxcParse(format!("table inconsistency for `{mnemonic}`")))?;
    let mut out: Vec<u8> = Vec::with_capacity(spec.unscaled_size());
    out.push(byte);
    if operands.len() != spec.operand_count as usize {
        return Err(Error::OxcParse(format!(
            "{mnemonic} expects {expected} operands, got {got}",
            expected = spec.operand_count,
            got = operands.len()
        )));
    }
    for (i, value) in operands.iter().enumerate() {
        let kind: OperandKind = spec.operands[i];
        match kind.unscaled_byte_size() {
            0 => {}
            1 => {
                let byte: u8 = u8::try_from(value.unsigned_abs() & 0xFF).unwrap_or(u8::MAX);
                let signed_byte: u8 = if *value < 0 {
                    let masked: i64 = value & 0xFF;
                    u8::try_from(masked).unwrap_or(0u8)
                } else {
                    byte
                };
                out.push(signed_byte);
            }
            2 => {
                let v16: i16 =
                    i16::try_from(*value).unwrap_or(if *value < 0 { i16::MIN } else { i16::MAX });
                out.extend_from_slice(&v16.to_le_bytes());
            }
            4 => {
                let v32: i32 =
                    i32::try_from(*value).unwrap_or(if *value < 0 { i32::MIN } else { i32::MAX });
                out.extend_from_slice(&v32.to_le_bytes());
            }
            _ => unreachable!("operand widths are 0/1/2/4"),
        }
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn enc(table: &OpcodeTable, mnemonic: &str, operands: &[i64]) -> Vec<u8> {
        encode_instruction(table, mnemonic, operands).expect("encode")
    }

    #[test]
    fn round_trip_ldar_star0_return() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node22);
        let mut stream: Vec<u8> = Vec::new();
        stream.extend(enc(&table, "Ldar", &[3i64]));
        stream.extend(enc(&table, "Star0", &[]));
        stream.extend(enc(&table, "Return", &[]));
        let disasm: Disassembly = disassemble(&stream, NodeVersion::Node22);
        assert_eq!(disasm.instructions.len(), 3usize);
        assert_eq!(disasm.instructions[0].mnemonic, "Ldar");
        assert_eq!(disasm.instructions[1].mnemonic, "Star0");
        assert_eq!(disasm.instructions[2].mnemonic, "Return");
        assert_eq!(disasm.trailing_garbage, 0usize);
    }

    #[test]
    fn round_trip_lda_smi_with_imm() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node22);
        let stream: Vec<u8> = enc(&table, "LdaSmi", &[42i64]);
        let disasm: Disassembly = disassemble(&stream, NodeVersion::Node22);
        assert_eq!(disasm.instructions.len(), 1);
        assert_eq!(disasm.instructions[0].mnemonic, "LdaSmi");
        assert_eq!(disasm.instructions[0].operands[0].signed_value, 42i64);
    }

    #[test]
    fn wide_prefix_doubles_operand_width() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node22);
        let wide_byte: u8 = table.lookup_mnemonic("Wide").expect("wide present");
        let lda_byte: u8 = table.lookup_mnemonic("LdaSmi").expect("lda present");
        let mut stream: Vec<u8> = vec![wide_byte, lda_byte];
        stream.extend_from_slice(&(1234i16).to_le_bytes());
        let disasm: Disassembly = disassemble(&stream, NodeVersion::Node22);
        assert_eq!(disasm.instructions.len(), 1);
        assert!(matches!(disasm.instructions[0].scale, OperandScale::Double));
        assert_eq!(disasm.instructions[0].operands[0].signed_value, 1234i64);
    }

    #[test]
    fn renders_pretty_text() {
        let table: OpcodeTable = OpcodeTable::for_node(NodeVersion::Node22);
        let mut stream: Vec<u8> = Vec::new();
        stream.extend(enc(&table, "LdaConstant", &[7i64]));
        stream.extend(enc(&table, "Return", &[]));
        let disasm: Disassembly = disassemble(&stream, NodeVersion::Node22);
        let txt: String = disasm.render_text();
        assert!(txt.contains("LdaConstant [7]"));
        assert!(txt.contains("Return"));
    }
}
