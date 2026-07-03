use serde::{Deserialize, Serialize};

use crate::error::{Result, RubyError};
use crate::mruby::ops::{MrubyOp, MrubyOpcode, OperandFormat, lookup};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MrubyInstruction {
    pub pc: u32,
    pub opcode: u8,
    pub mnemonic: String,
    pub op: MrubyOp,
    pub operands: Vec<u32>,
}

pub fn disassemble_iseq(iseq: &[u8]) -> Result<Vec<MrubyInstruction>> {
    let mut out: Vec<MrubyInstruction> = Vec::with_capacity(iseq.len() / 2);
    let mut pc: usize = 0usize;
    while pc < iseq.len() {
        let start: usize = pc;
        let opcode: u8 = iseq[pc];
        pc += 1;
        let spec: &MrubyOpcode = lookup(opcode).ok_or(RubyError::MrubyUnknownOpcode {
            op: opcode,
            at: start,
        })?;

        let (widen_a, widen_b): (bool, bool) = match spec.op {
            MrubyOp::Ext1 | MrubyOp::Ext2 | MrubyOp::Ext3 => {
                let inner_byte: u8 = *iseq
                    .get(pc)
                    .ok_or(RubyError::MrubyIrepTruncated { at: pc })?;
                pc += 1;
                let inner: &MrubyOpcode =
                    lookup(inner_byte).ok_or(RubyError::MrubyUnknownOpcode {
                        op: inner_byte,
                        at: pc - 1,
                    })?;
                let (wa, wb): (bool, bool) = match spec.op {
                    MrubyOp::Ext1 => (true, false),
                    MrubyOp::Ext2 => (false, true),
                    _ => (true, true),
                };
                let operands: Vec<u32> = read_operands(iseq, &mut pc, inner.format, wa, wb)?;
                out.push(MrubyInstruction {
                    pc: u32::try_from(start).unwrap_or(u32::MAX),
                    opcode: inner_byte,
                    mnemonic: inner.mnemonic.to_owned(),
                    op: inner.op,
                    operands,
                });
                continue;
            }
            _ => (false, false),
        };

        let operands: Vec<u32> = read_operands(iseq, &mut pc, spec.format, widen_a, widen_b)?;
        out.push(MrubyInstruction {
            pc: u32::try_from(start).unwrap_or(u32::MAX),
            opcode,
            mnemonic: spec.mnemonic.to_owned(),
            op: spec.op,
            operands,
        });
    }
    Ok(out)
}

fn read_operands(
    iseq: &[u8],
    pc: &mut usize,
    format: OperandFormat,
    widen_a: bool,
    widen_b: bool,
) -> Result<Vec<u32>> {
    let mut ops: Vec<u32> = Vec::with_capacity(3);
    match format {
        OperandFormat::Z => {}
        OperandFormat::B => ops.push(read_b_or_s(iseq, pc, widen_a)?),
        OperandFormat::Bb => {
            ops.push(read_b_or_s(iseq, pc, widen_a)?);
            ops.push(read_b_or_s(iseq, pc, widen_b)?);
        }
        OperandFormat::Bbb => {
            ops.push(read_b_or_s(iseq, pc, widen_a)?);
            ops.push(read_b_or_s(iseq, pc, widen_b)?);
            ops.push(u32::from(read_b(iseq, pc)?));
        }
        OperandFormat::Bs => {
            ops.push(read_b_or_s(iseq, pc, widen_a)?);
            ops.push(u32::from(read_s(iseq, pc)?));
        }
        OperandFormat::Bss => {
            ops.push(read_b_or_s(iseq, pc, widen_a)?);
            ops.push(u32::from(read_s(iseq, pc)?));
            ops.push(u32::from(read_s(iseq, pc)?));
        }
        OperandFormat::S => ops.push(u32::from(read_s(iseq, pc)?)),
        OperandFormat::W => ops.push(read_w(iseq, pc)?),
    }
    Ok(ops)
}

#[inline]
fn read_b_or_s(iseq: &[u8], pc: &mut usize, widen: bool) -> Result<u32> {
    if widen {
        Ok(u32::from(read_s(iseq, pc)?))
    } else {
        Ok(u32::from(read_b(iseq, pc)?))
    }
}

#[inline]
fn read_b(iseq: &[u8], pc: &mut usize) -> Result<u8> {
    let b: u8 = *iseq
        .get(*pc)
        .ok_or(RubyError::MrubyIrepTruncated { at: *pc })?;
    *pc += 1;
    Ok(b)
}

#[inline]
fn read_s(iseq: &[u8], pc: &mut usize) -> Result<u16> {
    let slice: &[u8] = iseq
        .get(*pc..pc.saturating_add(2))
        .ok_or(RubyError::MrubyIrepTruncated { at: *pc })?;
    let arr: [u8; 2] = slice
        .try_into()
        .map_err(|_| RubyError::MrubyIrepTruncated { at: *pc })?;
    *pc += 2;
    Ok(u16::from_be_bytes(arr))
}

#[inline]
fn read_w(iseq: &[u8], pc: &mut usize) -> Result<u32> {
    let slice: &[u8] = iseq
        .get(*pc..pc.saturating_add(3))
        .ok_or(RubyError::MrubyIrepTruncated { at: *pc })?;
    let value: u32 = (u32::from(slice[0]) << 16) | (u32::from(slice[1]) << 8) | u32::from(slice[2]);
    *pc += 3;
    Ok(value)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn decodes_loadself_loadsym_send_return() {
        let iseq: Vec<u8> = vec![
            0x12, 0x01, 0x10, 0x02, 0x00, 0x2f, 0x01, 0x00, 0x01, 0x38, 0x01,
        ];
        let ins: Vec<MrubyInstruction> = disassemble_iseq(&iseq).expect("disasm");
        assert_eq!(ins[0].mnemonic, "LOADSELF");
        assert_eq!(ins[0].operands, vec![1u32]);
        assert_eq!(ins[1].mnemonic, "LOADSYM");
        assert_eq!(ins[1].operands, vec![2u32, 0u32]);
        assert_eq!(ins[2].mnemonic, "SEND");
        assert_eq!(ins[2].operands, vec![1u32, 0u32, 1u32]);
        assert_eq!(ins[3].mnemonic, "RETURN");
        assert_eq!(ins[3].operands, vec![1u32]);
    }

    #[test]
    fn jmp_reads_16bit_be_offset() {
        let iseq: Vec<u8> = vec![0x25, 0x12, 0x34];
        let ins: Vec<MrubyInstruction> = disassemble_iseq(&iseq).expect("disasm");
        assert_eq!(ins[0].mnemonic, "JMP");
        assert_eq!(ins[0].operands, vec![0x1234u32]);
    }

    #[test]
    fn ext1_widens_first_operand_to_16bit() {
        let move_idx: u8 = 1;
        let ext1_idx: u8 = super::super::ops::OPS
            .iter()
            .position(|o| o.mnemonic == "EXT1")
            .map(|p| u8::try_from(p).expect("fits"))
            .expect("EXT1 present");
        let iseq: Vec<u8> = vec![ext1_idx, move_idx, 0x01, 0x00, 0x05];
        let ins: Vec<MrubyInstruction> = disassemble_iseq(&iseq).expect("disasm");
        assert_eq!(ins[0].mnemonic, "MOVE");
        assert_eq!(ins[0].operands, vec![0x0100u32, 0x05u32]);
    }

    #[test]
    fn unknown_opcode_errs() {
        let iseq: Vec<u8> = vec![0xFFu8];
        let err: RubyError = disassemble_iseq(&iseq).expect_err("unknown");
        assert!(matches!(
            err,
            RubyError::MrubyUnknownOpcode { op: 0xFF, .. }
        ));
    }

    #[test]
    fn truncated_operand_errs() {
        let iseq: Vec<u8> = vec![0x25, 0x12];
        let err: RubyError = disassemble_iseq(&iseq).expect_err("truncated");
        assert!(matches!(err, RubyError::MrubyIrepTruncated { .. }));
    }
}
