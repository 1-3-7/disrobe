use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::cil::{FlowControl, Instruction, MethodBody, OperandValue};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CSharpPseudo {
    pub method_name: String,
    pub body: String,
    pub instruction_count: u32,
    pub flow_summary: FlowSummary,
}

#[derive(Debug, Clone, Default, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowSummary {
    pub branches: u32,
    pub calls: u32,
    pub returns: u32,
    pub throws: u32,
}

#[must_use]
pub fn emit_csharp(method_name: &str, body: &MethodBody) -> CSharpPseudo {
    let mut text: String = String::with_capacity(body.instructions.len() * 24);
    let _ = writeln!(text, "// pseudo-c# reconstructed from cil");
    let _ = writeln!(text, "void {method_name}()");
    let _ = writeln!(text, "{{");
    let _ = writeln!(
        text,
        "    // max_stack={} init_locals={}",
        body.max_stack, body.init_locals
    );
    let mut flow: FlowSummary = FlowSummary::default();
    for ins in &body.instructions {
        accumulate(&mut flow, ins.flow);
        emit_instruction(&mut text, ins);
    }
    let _ = writeln!(text, "}}");
    CSharpPseudo {
        method_name: method_name.to_owned(),
        body: text,
        instruction_count: u32::try_from(body.instructions.len()).unwrap_or(u32::MAX),
        flow_summary: flow,
    }
}

const fn accumulate(flow: &mut FlowSummary, fc: FlowControl) {
    match fc {
        FlowControl::Branch | FlowControl::CondBranch => {
            flow.branches = flow.branches.saturating_add(1);
        }
        FlowControl::Call => flow.calls = flow.calls.saturating_add(1),
        FlowControl::Return => flow.returns = flow.returns.saturating_add(1),
        FlowControl::Throw => flow.throws = flow.throws.saturating_add(1),
        FlowControl::Next | FlowControl::Meta | FlowControl::Break => {}
    }
}

fn emit_instruction(text: &mut String, ins: &Instruction) {
    let line: String = match &ins.operand {
        OperandValue::None => format!("    IL_{:04X}: {};", ins.offset, ins.name),
        OperandValue::I32(v) => format!("    IL_{:04X}: {} {};", ins.offset, ins.name, v),
        OperandValue::I64(v) => format!("    IL_{:04X}: {} {}L;", ins.offset, ins.name, v),
        OperandValue::U8(v) => format!("    IL_{:04X}: {} {};", ins.offset, ins.name, v),
        OperandValue::U16(v) => format!("    IL_{:04X}: {} {};", ins.offset, ins.name, v),
        OperandValue::F32Bits(b) => {
            format!(
                "    IL_{:04X}: {} {};",
                ins.offset,
                ins.name,
                f32::from_bits(*b)
            )
        }
        OperandValue::F64Bits(b) => {
            format!(
                "    IL_{:04X}: {} {};",
                ins.offset,
                ins.name,
                f64::from_bits(*b)
            )
        }
        OperandValue::BrTarget(t) => {
            let target: i64 = i64::from(ins.offset) + i64::from(*t);
            format!("    IL_{:04X}: {} IL_{target:04X};", ins.offset, ins.name)
        }
        OperandValue::Token(tok) => {
            format!("    IL_{:04X}: {} 0x{tok:08X};", ins.offset, ins.name)
        }
        OperandValue::Switch(targets) => {
            let joined: String = targets
                .iter()
                .map(|t: &i32| format!("0x{:08X}", i64::from(ins.offset) + i64::from(*t)))
                .collect::<Vec<String>>()
                .join(", ");
            format!("    IL_{:04X}: {} [{joined}];", ins.offset, ins.name)
        }
    };
    let _ = writeln!(text, "{line}");
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::cil::disassemble;

    #[test]
    fn emit_csharp_round_trips_simple_method() {
        let code: [u8; 4] = [0x16, 0x17, 0x58, 0x2A];
        let instructions: Vec<Instruction> = disassemble(&code).expect("disasm");
        let body: MethodBody = MethodBody {
            max_stack: 2,
            code_size: 4,
            local_var_sig_tok: 0,
            init_locals: false,
            instructions,
        };
        let out: CSharpPseudo = emit_csharp("Main", &body);
        assert_eq!(out.instruction_count, 4);
        assert!(out.body.contains("ldc.i4.0"));
        assert!(out.body.contains("add"));
        assert!(out.body.contains("ret"));
        assert_eq!(out.flow_summary.returns, 1);
    }
}
