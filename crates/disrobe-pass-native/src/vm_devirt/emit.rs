use std::fmt::Write as _;

use super::cfg::VmBlock;
use super::lift::{LiftedProgram, VmInsn};
use super::microop::MicroOp;
use super::structure::StructuredNode;

#[must_use]
pub fn emit_recovered_listing(program: &LiftedProgram) -> String {
    let mut out: String = String::new();
    let _ = writeln!(
        out,
        "; recovered virtual instructions (entry @ 0x{:04x}, {} insns)",
        program.entry_offset,
        program.insns.len()
    );
    let mut ordered: Vec<&VmInsn> = program.insns.iter().collect();
    ordered.sort_by_key(|i: &&VmInsn| i.offset);
    for insn in ordered {
        let _ = writeln!(out, "{}", format_insn(insn));
    }
    if !program.unresolved_opcodes.is_empty() {
        let _ = writeln!(
            out,
            "; {} unresolved opcode(s): {:?}",
            program.unresolved_opcodes.len(),
            program.unresolved_opcodes
        );
    }
    out
}

fn format_insn(insn: &VmInsn) -> String {
    let mnem: &str = insn.micro_op.mnemonic();
    let operand: String = if let Some(imm) = insn.imm {
        format!(" {imm}")
    } else if let Some(reg) = insn.reg {
        format!(" r{reg}")
    } else if let Some(target) = insn.branch_target {
        format!(" -> 0x{target:04x}")
    } else {
        String::new()
    };
    format!("  0x{:04x}: {mnem}{operand}", insn.offset)
}

#[must_use]
pub fn emit_pseudocode(program: &LiftedProgram, nodes: &[StructuredNode]) -> String {
    let mut out: String = String::new();
    let _ = writeln!(out, "fn recovered_vm_function() {{");
    let mut ctx: EmitCtx<'_> = EmitCtx { program };
    for node in nodes {
        ctx.emit_node(node, 1, &mut out);
    }
    let _ = writeln!(out, "}}");
    out
}

struct EmitCtx<'a> {
    program: &'a LiftedProgram,
}

impl EmitCtx<'_> {
    fn emit_node(&mut self, node: &StructuredNode, depth: usize, out: &mut String) {
        let pad: String = "    ".repeat(depth);
        match node {
            StructuredNode::Linear { block_offset } => {
                self.emit_block_body(*block_offset, depth, out, true);
            }
            StructuredNode::Loop {
                header_offset,
                body,
            } => {
                let _ = writeln!(out, "{pad}while (true) {{");
                self.emit_block_body(*header_offset, depth + 1, out, true);
                for child in body {
                    self.emit_node(child, depth + 1, out);
                }
                let _ = writeln!(out, "{pad}}}");
            }
            StructuredNode::IfElse {
                head_offset,
                then_branch,
                else_branch,
            } => {
                self.emit_block_body(*head_offset, depth, out, false);
                let _ = writeln!(out, "{pad}if (cond) {{");
                for child in then_branch {
                    self.emit_node(child, depth + 1, out);
                }
                if else_branch.is_empty() {
                    let _ = writeln!(out, "{pad}}}");
                } else {
                    let _ = writeln!(out, "{pad}}} else {{");
                    for child in else_branch {
                        self.emit_node(child, depth + 1, out);
                    }
                    let _ = writeln!(out, "{pad}}}");
                }
            }
        }
    }

    fn emit_block_body(
        &self,
        block_offset: u32,
        depth: usize,
        out: &mut String,
        include_terminator: bool,
    ) {
        let pad: String = "    ".repeat(depth);
        let Some(block): Option<Vec<&VmInsn>> = self.block_insns(block_offset) else {
            let _ = writeln!(out, "{pad}invalid missing-block 0x{block_offset:04x};");
            return;
        };
        for insn in block {
            if !include_terminator && insn.micro_op.is_conditional_branch() {
                continue;
            }
            let line: String = self.statement_for(insn);
            if !line.is_empty() {
                let _ = writeln!(out, "{pad}{line}");
            }
        }
    }

    fn block_insns(&self, block_offset: u32) -> Option<Vec<&VmInsn>> {
        let mut ordered: Vec<&VmInsn> = self.program.insns.iter().collect();
        ordered.sort_by_key(|i: &&VmInsn| i.offset);
        let start: usize = ordered
            .iter()
            .position(|i: &&VmInsn| i.offset == block_offset)?;
        let mut out: Vec<&VmInsn> = Vec::new();
        for insn in &ordered[start..] {
            out.push(insn);
            if insn.micro_op.is_terminator() {
                break;
            }
        }
        Some(out)
    }

    fn statement_for(&self, insn: &VmInsn) -> String {
        match insn.micro_op {
            MicroOp::PushImm => format!("push {};", required_imm(insn)),
            MicroOp::PushReg => format!("push {};", required_reg(insn)),
            MicroOp::PopReg => format!("{} = pop();", required_reg(insn)),
            MicroOp::LoadMem => "push load(pop());".to_owned(),
            MicroOp::StoreMem => "store(pop(), pop());".to_owned(),
            MicroOp::Binary { op } => {
                format!("push (pop() {} pop());", bin_symbol(op))
            }
            MicroOp::Unary { op } => match op {
                super::microop::UnKind::Neg => "push -pop();".to_owned(),
                super::microop::UnKind::Not => "push ~pop();".to_owned(),
            },
            MicroOp::Compare { op } => {
                format!("push (pop() {} pop());", cmp_symbol(op))
            }
            MicroOp::BranchTrue => {
                format!("if (pop()) goto {};", required_target(insn))
            }
            MicroOp::BranchFalse => format!("if (!pop()) goto {};", required_target(insn)),
            MicroOp::Jump => format!("goto {};", required_target(insn)),
            MicroOp::Call => "call();".to_owned(),
            MicroOp::Return => "return pop();".to_owned(),
            MicroOp::Nop => String::new(),
            MicroOp::Unknown => format!("/* unknown opcode 0x{:02x} */", insn.opcode),
        }
    }
}

fn required_imm(insn: &VmInsn) -> String {
    match insn.imm {
        Some(imm) => imm.to_string(),
        None => format!("<missing-imm@0x{:04x}>", insn.offset),
    }
}

fn required_reg(insn: &VmInsn) -> String {
    match insn.reg {
        Some(reg) => format!("r{reg}"),
        None => format!("<missing-reg@0x{:04x}>", insn.offset),
    }
}

fn required_target(insn: &VmInsn) -> String {
    match insn.branch_target {
        Some(target) => format!("0x{target:04x}"),
        None => format!("<missing-target@0x{:04x}>", insn.offset),
    }
}

const fn bin_symbol(op: super::microop::BinKind) -> &'static str {
    use super::microop::BinKind as B;
    match op {
        B::Add => "+",
        B::Sub => "-",
        B::Mul => "*",
        B::Div => "/",
        B::Rem => "%",
        B::And => "&",
        B::Or => "|",
        B::Xor => "^",
        B::Shl => "<<",
        B::Shr => ">>",
        B::Sar => ">>>",
    }
}

const fn cmp_symbol(op: super::microop::CmpKind) -> &'static str {
    use super::microop::CmpKind as C;
    match op {
        C::Eq => "==",
        C::Ne => "!=",
        C::Lt => "<",
        C::Le => "<=",
        C::Gt => ">",
        C::Ge => ">=",
    }
}

#[must_use]
pub fn describe_block(block: &VmBlock) -> String {
    format!(
        "block@0x{:04x} ({} insns, {} succ)",
        block.start_offset,
        block.insns.len(),
        block.successors.len()
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::vm_devirt::microop::BinKind;

    #[test]
    fn listing_renders_ops() {
        let prog: LiftedProgram = LiftedProgram {
            insns: vec![
                VmInsn {
                    offset: 0,
                    opcode: 1,
                    micro_op: MicroOp::PushImm,
                    imm: Some(42),
                    reg: None,
                    branch_target: None,
                },
                VmInsn {
                    offset: 9,
                    opcode: 2,
                    micro_op: MicroOp::Binary { op: BinKind::Add },
                    imm: None,
                    reg: None,
                    branch_target: None,
                },
            ],
            entry_offset: 0,
            max_reg: 0,
            unresolved_opcodes: vec![],
        };
        let listing: String = emit_recovered_listing(&prog);
        assert!(listing.contains("push.imm 42"));
        assert!(listing.contains("add"));
    }

    #[test]
    fn pseudocode_reports_missing_block_offset() {
        let prog: LiftedProgram = LiftedProgram {
            insns: vec![VmInsn {
                offset: 0,
                opcode: 1,
                micro_op: MicroOp::Return,
                imm: None,
                reg: None,
                branch_target: None,
            }],
            entry_offset: 0,
            max_reg: 0,
            unresolved_opcodes: vec![],
        };
        let nodes: Vec<StructuredNode> = vec![StructuredNode::Linear { block_offset: 8 }];
        let pseudocode: String = emit_pseudocode(&prog, &nodes);
        assert!(pseudocode.contains("invalid missing-block 0x0008;"));
        assert!(!pseudocode.contains("return pop();"));
    }

    #[test]
    fn pseudocode_does_not_default_missing_operands_to_zero() {
        let prog: LiftedProgram = LiftedProgram {
            insns: vec![
                VmInsn {
                    offset: 0,
                    opcode: 1,
                    micro_op: MicroOp::PushImm,
                    imm: None,
                    reg: None,
                    branch_target: None,
                },
                VmInsn {
                    offset: 1,
                    opcode: 2,
                    micro_op: MicroOp::PushReg,
                    imm: None,
                    reg: None,
                    branch_target: None,
                },
                VmInsn {
                    offset: 2,
                    opcode: 3,
                    micro_op: MicroOp::PopReg,
                    imm: None,
                    reg: None,
                    branch_target: None,
                },
                VmInsn {
                    offset: 3,
                    opcode: 4,
                    micro_op: MicroOp::Jump,
                    imm: None,
                    reg: None,
                    branch_target: None,
                },
            ],
            entry_offset: 0,
            max_reg: 0,
            unresolved_opcodes: vec![],
        };
        let nodes: Vec<StructuredNode> = vec![StructuredNode::Linear { block_offset: 0 }];
        let pseudocode: String = emit_pseudocode(&prog, &nodes);
        assert!(pseudocode.contains("push <missing-imm@0x0000>;"));
        assert!(pseudocode.contains("push <missing-reg@0x0001>;"));
        assert!(pseudocode.contains("<missing-reg@0x0002> = pop();"));
        assert!(pseudocode.contains("goto <missing-target@0x0003>;"));
        assert!(!pseudocode.contains("push 0;"));
        assert!(!pseudocode.contains("push r0;"));
        assert!(!pseudocode.contains("r0 = pop();"));
        assert!(!pseudocode.contains("goto 0x0000;"));
    }
}
