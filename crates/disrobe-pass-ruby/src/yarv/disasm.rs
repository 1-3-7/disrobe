//! Human-readable rendering of decoded YARV iseq bodies.
//!
//! Operates on the [`YarvIseqBody`] streams produced by IBF body lifting in
//! [`crate::yarv::ibf`]; each instruction is printed as `pc mnemonic op, op, ...` with operands
//! shown in their resolved form (literals quoted, ids as `:name`, iseq refs as `iseq[N]`, branch
//! targets as `->NNNN`).

use core::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::yarv::ibf::{IbfImage, YarvIbfInstruction, YarvIseqBody, YarvOperand};
use crate::yarv::opcodes::YarvVersion;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct YarvInstruction {
    pub offset: u32,
    pub opcode: u32,
    pub mnemonic: String,
    pub operands: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct YarvDisasm {
    pub version: YarvVersion,
    pub iseq_label: String,
    pub instructions: Vec<YarvInstruction>,
}

/// Render a decoded image to a full disassembly listing, one block per iseq body.
#[must_use]
pub fn render_image_disasm(image: &IbfImage, version: YarvVersion) -> String {
    let mut out: String =
        String::with_capacity(image.recovered_instruction_count as usize * 24 + 64);
    for body in &image.iseqs {
        let label: String = if body.index == 0 {
            "<top>".to_owned()
        } else {
            format!("<iseq:{}>", body.index)
        };
        let _: core::result::Result<(), core::fmt::Error> = writeln!(
            out,
            "== disasm: {label} (ruby {}.{}) ==",
            version.major, version.minor
        );
        for instr in &body.instructions {
            push_instruction(&mut out, instr);
        }
    }
    out
}

/// Render a single decoded iseq body into the typed [`YarvDisasm`] structure.
#[must_use]
pub fn disassemble_body(body: &YarvIseqBody, version: YarvVersion, label: &str) -> YarvDisasm {
    let instructions: Vec<YarvInstruction> = body
        .instructions
        .iter()
        .map(|i| YarvInstruction {
            offset: i.pc,
            opcode: i.opcode,
            mnemonic: i.mnemonic.clone(),
            operands: i.operands.iter().map(render_operand).collect(),
        })
        .collect();
    YarvDisasm {
        version,
        iseq_label: label.to_owned(),
        instructions,
    }
}

fn push_instruction(out: &mut String, instr: &YarvIbfInstruction) {
    let mut line: String = format!("{:04} {:<28}", instr.pc, instr.mnemonic);
    for (idx, op) in instr.operands.iter().enumerate() {
        if idx == 0 {
            line.push(' ');
        } else {
            line.push_str(", ");
        }
        line.push_str(&render_operand(op));
    }
    line.push('\n');
    out.push_str(&line);
}

fn render_operand(op: &YarvOperand) -> String {
    match op {
        YarvOperand::Literal(s) => format!("{s:?}"),
        YarvOperand::NumLiteral(s) => s.clone(),
        YarvOperand::Id(s) => format!(":{s}"),
        YarvOperand::ObjectRef(i) => format!("obj[{i}]"),
        YarvOperand::IseqRef(i) => format!("iseq[{i}]"),
        YarvOperand::Offset(o) => format!("->{o:04}"),
        YarvOperand::Num(n) => n.to_string(),
        YarvOperand::Builtin(name) => format!("<builtin {name}>"),
        YarvOperand::Call { method, argc } => format!("<calldata :{method} argc:{argc}>"),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::yarv::ibf::{YarvIbfInstruction, YarvIseqBody, YarvOperand};

    fn body() -> YarvIseqBody {
        YarvIseqBody {
            index: 0,
            offset: 0,
            iseq_size: 3,
            local_table: Vec::new(),
            param_lead_num: 0,
            catch_entries: Vec::new(),
            instructions: vec![
                YarvIbfInstruction {
                    pc: 0,
                    opcode: 18,
                    mnemonic: "putself".to_owned(),
                    operands: vec![],
                },
                YarvIbfInstruction {
                    pc: 1,
                    opcode: 22,
                    mnemonic: "putstring".to_owned(),
                    operands: vec![YarvOperand::Literal("hello world".to_owned())],
                },
                YarvIbfInstruction {
                    pc: 3,
                    opcode: 58,
                    mnemonic: "opt_send_without_block".to_owned(),
                    operands: vec![YarvOperand::Num(0)],
                },
            ],
        }
    }

    #[test]
    fn renders_disasm_block_header_and_lines() {
        let image: IbfImage = IbfImage {
            iseq_offsets: vec![0],
            objects: vec![],
            iseqs: vec![body()],
            recovered_literal_count: 1,
            recovered_instruction_count: 3,
        };
        let s: String = render_image_disasm(&image, YarvVersion::new(3, 4));
        assert!(s.contains("== disasm: <top> (ruby 3.4) =="));
        assert!(s.contains("putself"));
        assert!(s.contains("putstring"));
        assert!(s.contains("\"hello world\""));
    }

    #[test]
    fn disassemble_body_resolves_operands() {
        let d: YarvDisasm = disassemble_body(&body(), YarvVersion::new(3, 4), "<top>");
        assert_eq!(d.instructions.len(), 3);
        assert_eq!(d.instructions[1].mnemonic, "putstring");
        assert_eq!(d.instructions[1].operands, vec!["\"hello world\""]);
    }
}
