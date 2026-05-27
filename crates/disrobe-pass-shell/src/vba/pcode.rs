use serde::Serialize;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PCodeOpcode {
    LitConstStr,
    LitConstI2,
    LitConstI4,
    LdVar,
    StVar,
    Call,
    CallByName,
    Ret,
    Jmp,
    JmpIfFalse,
    Add,
    Sub,
    Mul,
    Div,
    Concat,
    NewObject,
    Unknown(u16),
}

#[derive(Debug, Clone, Serialize)]
pub struct PCodeInstruction {
    pub offset: usize,
    pub opcode: PCodeOpcode,
    pub immediate: Option<i64>,
    pub immediate_str: Option<String>,
    pub mnemonic: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PCodeDisasm {
    pub instructions: Vec<PCodeInstruction>,
    pub strings: Vec<String>,
}

pub fn disassemble_pcode(stream: &[u8]) -> Result<PCodeDisasm> {
    if stream.len() < 2 {
        return Err(Error::VbaPcode {
            reason: "pcode stream too short".to_owned(),
        });
    }
    let mut instructions: Vec<PCodeInstruction> = Vec::new();
    let mut strings: Vec<String> = Vec::new();
    let mut i: usize = 0;
    while i + 1 < stream.len() {
        let offset: usize = i;
        let op_raw: u16 = u16::from_le_bytes([stream[i], stream[i + 1]]);
        i += 2;
        let opcode: PCodeOpcode = classify(op_raw);
        let (immediate, immediate_str, mnem): (Option<i64>, Option<String>, String) = match opcode {
            PCodeOpcode::LitConstI2 => {
                if i + 1 >= stream.len() {
                    break;
                }
                let v: i16 = i16::from_le_bytes([stream[i], stream[i + 1]]);
                i += 2;
                (Some(v as i64), None, format!("LitConstI2 {v}"))
            }
            PCodeOpcode::LitConstI4 => {
                if i + 3 >= stream.len() {
                    break;
                }
                let v: i32 =
                    i32::from_le_bytes([stream[i], stream[i + 1], stream[i + 2], stream[i + 3]]);
                i += 4;
                (Some(v as i64), None, format!("LitConstI4 {v}"))
            }
            PCodeOpcode::LitConstStr => {
                if i + 1 >= stream.len() {
                    break;
                }
                let len: usize = u16::from_le_bytes([stream[i], stream[i + 1]]) as usize;
                i += 2;
                if i + len > stream.len() {
                    break;
                }
                let raw: &[u8] = &stream[i..i + len];
                i += len;
                let s: String = String::from_utf8_lossy(raw).into_owned();
                strings.push(s.clone());
                (None, Some(s.clone()), format!("LitConstStr \"{s}\""))
            }
            PCodeOpcode::Unknown(raw) => (None, None, format!("?op_{raw:#04x}")),
            other => (None, None, format!("{other:?}")),
        };
        instructions.push(PCodeInstruction {
            offset,
            opcode,
            immediate,
            immediate_str,
            mnemonic: mnem,
        });
    }
    Ok(PCodeDisasm {
        instructions,
        strings,
    })
}

const fn classify(raw: u16) -> PCodeOpcode {
    match raw {
        0x0001 => PCodeOpcode::LitConstI2,
        0x0002 => PCodeOpcode::LitConstI4,
        0x0003 => PCodeOpcode::LitConstStr,
        0x0010 => PCodeOpcode::LdVar,
        0x0011 => PCodeOpcode::StVar,
        0x0020 => PCodeOpcode::Call,
        0x0021 => PCodeOpcode::CallByName,
        0x0030 => PCodeOpcode::Ret,
        0x0040 => PCodeOpcode::Jmp,
        0x0041 => PCodeOpcode::JmpIfFalse,
        0x0050 => PCodeOpcode::Add,
        0x0051 => PCodeOpcode::Sub,
        0x0052 => PCodeOpcode::Mul,
        0x0053 => PCodeOpcode::Div,
        0x0054 => PCodeOpcode::Concat,
        0x0060 => PCodeOpcode::NewObject,
        other => PCodeOpcode::Unknown(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disassembles_minimal_stream() -> Result<()> {
        let stream: &[u8] = &[
            0x01, 0x00, 0x2A, 0x00, 0x03, 0x00, 0x02, 0x00, b'h', b'i', 0x30, 0x00,
        ];
        let d: PCodeDisasm = disassemble_pcode(stream)?;
        assert!(
            d.instructions
                .iter()
                .any(|x: &PCodeInstruction| x.opcode == PCodeOpcode::LitConstI2
                    && x.immediate == Some(42))
        );
        assert!(d.strings.contains(&"hi".to_owned()));
        Ok(())
    }

    #[test]
    fn rejects_short_stream() {
        let r: Result<PCodeDisasm> = disassemble_pcode(&[0u8]);
        assert!(r.is_err());
    }
}
