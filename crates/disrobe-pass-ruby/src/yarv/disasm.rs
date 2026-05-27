use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Result, RubyError};
use crate::yarv::opcodes::{OpcodeSpec, YarvVersion, opcode_table};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct YarvInstruction {
    pub offset: u32,
    pub opcode: u8,
    pub mnemonic: String,
    pub operands: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct YarvDisasm {
    pub version: YarvVersion,
    pub instructions: Vec<YarvInstruction>,
    pub iseq_label: String,
}

pub(crate) fn disassemble(
    code: &[u8],
    version: YarvVersion,
    iseq_label: &str,
) -> Result<YarvDisasm> {
    let table: BTreeMap<u8, OpcodeSpec> = opcode_table(version);
    let mut instructions: Vec<YarvInstruction> = Vec::with_capacity(code.len() / 4);
    let mut offset: usize = 0usize;
    while offset < code.len() {
        let op: u8 = code[offset];
        let Some(spec) = table.get(&op) else {
            return Err(RubyError::YarvUnknownOpcode {
                op,
                major: version.major,
                minor: version.minor,
            });
        };
        let operand_count: usize = spec.operands as usize;
        let need: usize = 1 + operand_count * 4;
        if offset + need > code.len() {
            return Err(RubyError::Truncated {
                got: code.len() - offset,
                need,
            });
        }
        let mut operands: Vec<u32> = Vec::with_capacity(operand_count);
        for i in 0..operand_count {
            let start: usize = offset + 1 + i * 4;
            let arr: [u8; 4] = code[start..start + 4]
                .try_into()
                .map_err(|_| RubyError::Truncated { got: 0, need: 4 })?;
            operands.push(u32::from_le_bytes(arr));
        }
        instructions.push(YarvInstruction {
            offset: u32::try_from(offset).unwrap_or(u32::MAX),
            opcode: op,
            mnemonic: spec.mnemonic.to_owned(),
            operands,
        });
        offset += need;
    }
    Ok(YarvDisasm {
        version,
        instructions,
        iseq_label: iseq_label.to_owned(),
    })
}

#[must_use]
pub fn render_iseq_disasm(d: &YarvDisasm) -> String {
    let mut out: String = String::with_capacity(d.instructions.len() * 32);
    let _: core::result::Result<(), core::fmt::Error> = core::fmt::Write::write_fmt(
        &mut out,
        format_args!(
            "== disasm: {} (ruby {}.{}) ==\n",
            d.iseq_label, d.version.major, d.version.minor
        ),
    );
    for ins in &d.instructions {
        let mut line: String = format!("{:04} {:<28}", ins.offset, ins.mnemonic);
        for (idx, op) in ins.operands.iter().enumerate() {
            if idx == 0 {
                line.push(' ');
            } else {
                line.push_str(", ");
            }
            let _: core::result::Result<(), core::fmt::Error> =
                core::fmt::Write::write_fmt(&mut line, format_args!("{op}"));
        }
        line.push('\n');
        out.push_str(&line);
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn disassemble_nop_leave() {
        let code: Vec<u8> = vec![0x00, 0x2E];
        let d: YarvDisasm = disassemble(&code, YarvVersion::new(3, 2), "<top>").expect("disasm");
        assert_eq!(d.instructions.len(), 2);
        assert_eq!(d.instructions[0].mnemonic, "nop");
        assert_eq!(d.instructions[1].mnemonic, "leave");
    }

    #[test]
    fn disassemble_with_operands() {
        let mut code: Vec<u8> = vec![0x01];
        code.extend_from_slice(&3u32.to_le_bytes());
        code.extend_from_slice(&0u32.to_le_bytes());
        code.push(0x2E);
        let d: YarvDisasm = disassemble(&code, YarvVersion::new(3, 2), "<x>").expect("disasm");
        assert_eq!(d.instructions[0].mnemonic, "getlocal");
        assert_eq!(d.instructions[0].operands, vec![3u32, 0u32]);
    }

    #[test]
    fn rejects_unknown_opcode() {
        let code: Vec<u8> = vec![0xFFu8];
        let err: RubyError =
            disassemble(&code, YarvVersion::new(1, 9), "<x>").expect_err("unknown");
        assert!(matches!(err, RubyError::YarvUnknownOpcode { .. }));
    }

    #[test]
    fn render_contains_header_and_lines() {
        let code: Vec<u8> = vec![0x00, 0x2E];
        let d: YarvDisasm = disassemble(&code, YarvVersion::new(3, 2), "<top>").expect("disasm");
        let s: String = render_iseq_disasm(&d);
        assert!(s.contains("== disasm: <top> (ruby 3.2) =="));
        assert!(s.contains("nop"));
        assert!(s.contains("leave"));
    }
}
