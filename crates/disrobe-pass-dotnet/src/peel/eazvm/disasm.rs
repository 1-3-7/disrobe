use super::dispatch::OpcodeMap;
use super::opcodes::{CilOp, CilOperand, read_int32_special};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualInstr {
    pub virtual_offset: u32,
    pub op: CilOp,
    pub operand: DecodedOperand,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedOperand {
    None,
    I32(i32),
    Var(u16),
    Branch(u32),
    MemberId(i32),
    StringId(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    UnknownVirtualCode(i32, u32),
    Truncated(u32),
}

const MAX_INSTRS: usize = 65_536;

pub fn decode_stream(code: &[u8], map: &OpcodeMap) -> Result<Vec<VirtualInstr>, DecodeError> {
    let mut instrs: Vec<VirtualInstr> = Vec::new();
    let mut pos: usize = 0;

    while pos < code.len() {
        if instrs.len() >= MAX_INSTRS {
            return Err(DecodeError::Truncated(pos as u32));
        }
        let virtual_offset: u32 = u32::try_from(pos).unwrap_or(u32::MAX);
        let virtual_code: i32 =
            read_int32_special(code, pos).ok_or(DecodeError::Truncated(virtual_offset))?;
        pos += 4;
        let op: CilOp = map
            .get(virtual_code)
            .ok_or(DecodeError::UnknownVirtualCode(
                virtual_code,
                virtual_offset,
            ))?;

        let operand: DecodedOperand = match op.operand() {
            CilOperand::None => DecodedOperand::None,
            CilOperand::InlineI8 => {
                let b: i8 = read_i8(code, pos).ok_or(DecodeError::Truncated(virtual_offset))?;
                pos += 1;
                DecodedOperand::I32(i32::from(b))
            }
            CilOperand::InlineI32 => {
                let v: i32 =
                    read_i32_le(code, pos).ok_or(DecodeError::Truncated(virtual_offset))?;
                pos += 4;
                DecodedOperand::I32(v)
            }
            CilOperand::VarByte => {
                let b: u8 = *code
                    .get(pos)
                    .ok_or(DecodeError::Truncated(virtual_offset))?;
                pos += 1;
                DecodedOperand::Var(u16::from(b))
            }
            CilOperand::VarWord => {
                let v: u16 =
                    read_u16_le(code, pos).ok_or(DecodeError::Truncated(virtual_offset))?;
                pos += 2;
                DecodedOperand::Var(v)
            }
            CilOperand::ShortBranch => {
                let v: i32 =
                    read_i32_le(code, pos).ok_or(DecodeError::Truncated(virtual_offset))?;
                pos += 4;
                DecodedOperand::Branch(v.cast_unsigned())
            }
            CilOperand::InlineMember => {
                let v: i32 =
                    read_int32_special(code, pos).ok_or(DecodeError::Truncated(virtual_offset))?;
                pos += 4;
                DecodedOperand::MemberId(v)
            }
            CilOperand::InlineString => {
                let v: i32 =
                    read_int32_special(code, pos).ok_or(DecodeError::Truncated(virtual_offset))?;
                pos += 4;
                DecodedOperand::StringId(v)
            }
        };

        instrs.push(VirtualInstr {
            virtual_offset,
            op,
            operand,
        });
    }

    Ok(instrs)
}

fn read_i8(code: &[u8], pos: usize) -> Option<i8> {
    code.get(pos).map(|b: &u8| b.cast_signed())
}

fn read_u16_le(code: &[u8], pos: usize) -> Option<u16> {
    let slice: &[u8] = code.get(pos..pos.checked_add(2)?)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_i32_le(code: &[u8], pos: usize) -> Option<i32> {
    let slice: &[u8] = code.get(pos..pos.checked_add(4)?)?;
    Some(i32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}
