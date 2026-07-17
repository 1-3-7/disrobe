use std::fmt::{self, Write};

use thiserror::Error;

use crate::surface::{
    SurfaceCase, SurfaceCondition, SurfaceExpr, SurfaceFunction, SurfaceLeaf, SurfaceStatement,
    SurfaceStmt,
};
use crate::types::{BinaryOp, NirClass};

const MAX_EMIT_DEPTH: usize = 4096;

#[derive(Debug, Error)]
pub enum EmitError {
    #[error("surface nesting exceeded the emit depth limit of {limit}")]
    DepthExceeded { limit: usize },
    #[error(transparent)]
    Format(#[from] fmt::Error),
}

pub fn emit_pseudo_source(function: &SurfaceFunction) -> Result<String, EmitError> {
    let mut output: String = String::new();
    write!(
        output,
        "{} {}(",
        function.signature.return_type.label(),
        function.signature.name
    )?;
    for (index, parameter) in function.signature.params.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        write!(output, "{} {}", parameter.ty.label(), parameter.name)?;
    }
    output.push_str(") {\n");
    for local in &function.locals {
        writeln!(output, "    {} {};", local.ty.label(), local.name)?;
    }
    emit_stmt(&function.body, 1, 0, &mut output)?;
    output.push_str("}\n");
    Ok(output)
}

fn emit_stmt(
    stmt: &SurfaceStmt,
    indent: usize,
    depth: usize,
    output: &mut String,
) -> Result<(), EmitError> {
    if depth >= MAX_EMIT_DEPTH {
        return Err(EmitError::DepthExceeded {
            limit: MAX_EMIT_DEPTH,
        });
    }
    match stmt {
        SurfaceStmt::Block { body } => {
            for child in body {
                emit_stmt(child, indent, depth.saturating_add(1), output)?;
            }
        }
        SurfaceStmt::Leaf { statements, .. } => {
            for leaf in statements {
                emit_leaf(leaf, indent, output)?;
            }
        }
        SurfaceStmt::If {
            cond,
            then_branch,
            else_branch,
        } => {
            write_indent(indent, output);
            output.push_str("if (");
            emit_condition(cond, output);
            output.push_str(") {\n");
            emit_stmt(
                then_branch,
                indent.saturating_add(1),
                depth.saturating_add(1),
                output,
            )?;
            write_indent(indent, output);
            output.push('}');
            if !matches!(else_branch.as_ref(), SurfaceStmt::Nop) {
                output.push_str(" else {\n");
                emit_stmt(
                    else_branch,
                    indent.saturating_add(1),
                    depth.saturating_add(1),
                    output,
                )?;
                write_indent(indent, output);
                output.push('}');
            }
            output.push('\n');
        }
        SurfaceStmt::Loop { body, .. } => {
            write_indent(indent, output);
            output.push_str("while (true) {\n");
            emit_stmt(
                body,
                indent.saturating_add(1),
                depth.saturating_add(1),
                output,
            )?;
            write_indent(indent, output);
            output.push_str("}\n");
        }
        SurfaceStmt::Break { .. } => {
            write_indent(indent, output);
            output.push_str("break;\n");
        }
        SurfaceStmt::Continue { .. } => {
            write_indent(indent, output);
            output.push_str("continue;\n");
        }
        SurfaceStmt::Return { value } => {
            write_indent(indent, output);
            output.push_str("return");
            if let Some(value) = value {
                output.push(' ');
                emit_expr(value, 0, output)?;
            }
            output.push_str(";\n");
        }
        SurfaceStmt::Switch { entry, cases } => {
            emit_labeled_graph(*entry, cases, indent, output)?;
        }
        SurfaceStmt::GotoGraph { entry, blocks } => {
            emit_labeled_graph(*entry, blocks, indent, output)?;
        }
        SurfaceStmt::Nop => {}
    }
    Ok(())
}

fn emit_labeled_graph(
    entry: u64,
    blocks: &[SurfaceCase],
    indent: usize,
    output: &mut String,
) -> Result<(), EmitError> {
    write_indent(indent, output);
    writeln!(output, "goto label_{entry:x};")?;
    for block in blocks {
        write_indent(indent, output);
        writeln!(output, "label_{:x}:", block.block_start)?;
        emit_case_statements(block, indent.saturating_add(1), output)?;
        emit_goto_terminator(block, indent.saturating_add(1), output)?;
    }
    Ok(())
}

fn emit_case_statements(
    case: &SurfaceCase,
    indent: usize,
    output: &mut String,
) -> Result<(), EmitError> {
    for leaf in &case.statements {
        emit_leaf(leaf, indent, output)?;
    }
    Ok(())
}

fn emit_goto_terminator(
    case: &SurfaceCase,
    indent: usize,
    output: &mut String,
) -> Result<(), EmitError> {
    let last: Option<&SurfaceLeaf> = case.statements.last();
    match last.map(|leaf: &SurfaceLeaf| leaf.instr.class()) {
        Some(NirClass::ConditionalJump) => {
            let taken: Option<u64> = last.and_then(|leaf: &SurfaceLeaf| leaf.instr.direct_target());
            let fallthrough: Option<u64> = case
                .successors
                .iter()
                .copied()
                .find(|target: &u64| Some(*target) != taken);
            write_indent(indent, output);
            output.push_str("if (");
            if let Some(leaf) = last {
                let condition: SurfaceCondition = SurfaceCondition {
                    at: leaf.instr.address,
                    mnemonic: leaf.instr.mnemonic.clone(),
                    operands: leaf.instr.operands.clone(),
                    taken_target: taken,
                };
                emit_condition(&condition, output);
            } else {
                output.push_str("condition");
            }
            output.push_str(") ");
            match taken {
                Some(taken_target) => emit_transfer(
                    taken_target,
                    case.successors.contains(&taken_target),
                    output,
                )?,
                None => output.push_str("goto_indirect"),
            }
            if let Some(fallthrough_target) = fallthrough {
                output.push_str("; else ");
                emit_transfer(fallthrough_target, true, output)?;
            }
            output.push_str(";\n");
        }
        Some(NirClass::UnconditionalJump) => {
            write_indent(indent, output);
            if let Some(target) = case.successors.first() {
                writeln!(output, "goto label_{target:x};")?;
            } else if let Some(target) =
                last.and_then(|leaf: &SurfaceLeaf| leaf.instr.direct_target())
            {
                writeln!(output, "jump(0x{target:x});")?;
            } else {
                output.push_str("goto_indirect;\n");
            }
        }
        Some(NirClass::Return) => {
            if let Some(leaf) = last {
                write_indent(indent, output);
                output.push_str("return");
                if let Some(value) = leaf.instr.operands.first() {
                    output.push(' ');
                    output.push_str(value);
                }
                output.push_str(";\n");
            }
        }
        Some(NirClass::Call)
            if last.is_some_and(|leaf: &SurfaceLeaf| leaf.instr.op.is_terminal_call()) =>
        {
            if let Some(leaf) = last
                && matches!(leaf.instr.op, crate::types::NirOp::TailCall { .. })
            {
                write_indent(indent, output);
                output.push_str("return ");
                emit_terminal_call(leaf, output);
                output.push_str(";\n");
            }
        }
        Some(NirClass::Call | NirClass::Other) | None => {
            if let Some(target) = case.successors.first() {
                write_indent(indent, output);
                writeln!(output, "goto label_{target:x};")?;
            }
        }
    }
    Ok(())
}

fn emit_terminal_call(leaf: &SurfaceLeaf, output: &mut String) {
    match leaf.instr.operands.first() {
        Some(target) => output.push_str(target),
        None => output.push_str("indirect_call"),
    }
    output.push('(');
    for (index, argument) in leaf.instr.operands.iter().skip(1).enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        output.push_str(argument);
    }
    output.push(')');
}

fn emit_transfer(target: u64, internal: bool, output: &mut String) -> Result<(), EmitError> {
    if internal {
        write!(output, "goto label_{target:x}")?;
    } else {
        write!(output, "jump(0x{target:x})")?;
    }
    Ok(())
}

fn emit_leaf(leaf: &SurfaceLeaf, indent: usize, output: &mut String) -> Result<(), EmitError> {
    match &leaf.stmt {
        SurfaceStatement::Assign { target, value } => {
            write_indent(indent, output);
            emit_expr(target, 0, output)?;
            output.push_str(" = ");
            emit_expr(value, 0, output)?;
            output.push_str(";\n");
        }
        SurfaceStatement::Store { cell, value } => {
            write_indent(indent, output);
            output.push_str("store(");
            emit_expr(cell, 0, output)?;
            output.push_str(", ");
            emit_expr(value, 0, output)?;
            output.push_str(");\n");
        }
        SurfaceStatement::Call { target, args } => {
            write_indent(indent, output);
            emit_call(target.as_deref(), args, output)?;
            output.push_str(";\n");
        }
        SurfaceStatement::Expr { value } => {
            if matches!(value, SurfaceExpr::Raw { text } if text.is_empty()) {
                return Ok(());
            }
            write_indent(indent, output);
            emit_expr(value, 0, output)?;
            output.push_str(";\n");
        }
    }
    Ok(())
}

fn emit_condition(condition: &SurfaceCondition, output: &mut String) {
    match condition.operands.first() {
        Some(value) => output.push_str(value),
        None if condition.mnemonic.is_empty() => output.push_str("condition"),
        None => output.push_str(&condition.mnemonic),
    }
}

fn emit_expr(expr: &SurfaceExpr, depth: usize, output: &mut String) -> Result<(), EmitError> {
    if depth >= MAX_EMIT_DEPTH {
        return Err(EmitError::DepthExceeded {
            limit: MAX_EMIT_DEPTH,
        });
    }
    match expr {
        SurfaceExpr::Literal { text }
        | SurfaceExpr::Local { name: text }
        | SurfaceExpr::Raw { text } => output.push_str(text),
        SurfaceExpr::Field { cell } => {
            output.push_str("mem[");
            output.push_str(cell);
            output.push(']');
        }
        SurfaceExpr::Unary { op, operand } => {
            output.push_str(unary_symbol(*op));
            output.push('(');
            emit_expr(operand, depth.saturating_add(1), output)?;
            output.push(')');
        }
        SurfaceExpr::Binary { op, lhs, rhs } => {
            output.push('(');
            emit_expr(lhs, depth.saturating_add(1), output)?;
            write!(output, " {} ", binary_symbol(*op))?;
            emit_expr(rhs, depth.saturating_add(1), output)?;
            output.push(')');
        }
        SurfaceExpr::Call { target, args } => emit_call(target.as_deref(), args, output)?,
    }
    Ok(())
}

fn emit_call(
    target: Option<&str>,
    args: &[SurfaceExpr],
    output: &mut String,
) -> Result<(), EmitError> {
    output.push_str(target.unwrap_or("indirect_call"));
    output.push('(');
    for (index, argument) in args.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        emit_expr(argument, 1, output)?;
    }
    output.push(')');
    Ok(())
}

const fn unary_symbol(op: BinaryOp) -> &'static str {
    match op {
        BinaryOp::Not => "~",
        BinaryOp::Neg => "-",
        BinaryOp::Add
        | BinaryOp::Sub
        | BinaryOp::Mul
        | BinaryOp::Div
        | BinaryOp::Rem
        | BinaryOp::And
        | BinaryOp::Or
        | BinaryOp::Xor
        | BinaryOp::Shl
        | BinaryOp::Shr
        | BinaryOp::Rol
        | BinaryOp::Ror => "op",
    }
}

const fn binary_symbol(op: BinaryOp) -> &'static str {
    match op {
        BinaryOp::Add => "+",
        BinaryOp::Sub | BinaryOp::Neg => "-",
        BinaryOp::Mul => "*",
        BinaryOp::Div => "/",
        BinaryOp::Rem => "%",
        BinaryOp::And => "&",
        BinaryOp::Or => "|",
        BinaryOp::Xor => "^",
        BinaryOp::Shl => "<<",
        BinaryOp::Shr => ">>",
        BinaryOp::Rol => "rol",
        BinaryOp::Ror => "ror",
        BinaryOp::Not => "~",
    }
}

fn write_indent(indent: usize, output: &mut String) {
    for _index in 0..indent {
        output.push_str("    ");
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::hir::structurize_function;
    use crate::surface::surfacify_function;
    use crate::types::{NirFunction, NirInstr, NirOp, SourceLang, SourceRef};

    fn terminal_source(op: NirOp) -> String {
        let function: NirFunction = NirFunction {
            name: "terminal".to_owned(),
            address: 0,
            end: 1,
            is_export: false,
            instructions: vec![NirInstr {
                address: 0,
                op,
                mnemonic: "CALL".to_owned(),
                operands: vec!["target".to_owned()],
                reads_memory: false,
                writes_memory: false,
                byte_width: false,
                source: SourceRef::new(SourceLang::NativeX86, 0),
            }],
            source: SourceRef::new(SourceLang::NativeX86, 0),
        };
        emit_pseudo_source(&surfacify_function(&structurize_function(&function)))
            .expect("emit terminal call")
    }

    #[test]
    fn unresolved_indirect_flow_emits_labels_and_goto() {
        let function: NirFunction = NirFunction {
            name: "indirect".to_owned(),
            address: 0,
            end: 1,
            is_export: false,
            instructions: vec![NirInstr {
                address: 0,
                op: crate::types::NirOp::Branch { target: None },
                mnemonic: "BRANCHIND".to_owned(),
                operands: vec!["rax".to_owned()],
                reads_memory: false,
                writes_memory: false,
                byte_width: false,
                source: SourceRef::new(SourceLang::NativeX86, 0),
            }],
            source: SourceRef::new(SourceLang::NativeX86, 0),
        };
        let source: String =
            emit_pseudo_source(&surfacify_function(&structurize_function(&function)))
                .expect("emit fallback");
        assert!(source.contains("goto label_0;"));
        assert!(source.contains("label_0:"));
        assert!(source.contains("goto_indirect;"));
        assert!(!source.contains("switch ("));
    }

    #[test]
    fn no_return_call_does_not_gain_a_synthetic_return() {
        let source: String = terminal_source(NirOp::NoReturnCall {
            target: Some(0x4000),
        });
        assert!(source.contains("target();"));
        assert!(!source.contains("return;"));
        assert!(!source.contains("return target();"));
    }

    #[test]
    fn tail_call_emits_as_a_returned_call() {
        let source: String = terminal_source(NirOp::TailCall {
            target: Some(0x4000),
        });
        assert!(source.contains("return target();"));
        assert_eq!(source.matches("target()").count(), 1);
    }

    #[test]
    fn fallback_preserves_a_known_external_jump_target() {
        let function: NirFunction = NirFunction {
            name: "external_jump".to_owned(),
            address: 0,
            end: 1,
            is_export: false,
            instructions: vec![NirInstr {
                address: 0,
                op: NirOp::Branch {
                    target: Some(0x4000),
                },
                mnemonic: "BRANCH".to_owned(),
                operands: vec!["0x4000".to_owned()],
                reads_memory: false,
                writes_memory: false,
                byte_width: false,
                source: SourceRef::new(SourceLang::NativeX86, 0),
            }],
            source: SourceRef::new(SourceLang::NativeX86, 0),
        };
        let source: String =
            emit_pseudo_source(&surfacify_function(&structurize_function(&function)))
                .expect("emit external jump");
        assert!(source.contains("jump(0x4000);"));
        assert!(!source.contains("goto_indirect;"));
        assert!(!source.contains("label_4000"));
    }

    #[test]
    fn fallback_separates_external_and_internal_conditional_targets() {
        let function: NirFunction = NirFunction {
            name: "external_conditional".to_owned(),
            address: 0,
            end: 3,
            is_export: false,
            instructions: vec![
                NirInstr {
                    address: 0,
                    op: NirOp::CondBranch {
                        target: Some(0x4000),
                    },
                    mnemonic: "CBRANCH".to_owned(),
                    operands: vec!["zf".to_owned()],
                    reads_memory: false,
                    writes_memory: false,
                    byte_width: false,
                    source: SourceRef::new(SourceLang::NativeX86, 0),
                },
                NirInstr {
                    address: 2,
                    op: NirOp::Return,
                    mnemonic: "RETURN".to_owned(),
                    operands: Vec::new(),
                    reads_memory: false,
                    writes_memory: false,
                    byte_width: false,
                    source: SourceRef::new(SourceLang::NativeX86, 2),
                },
            ],
            source: SourceRef::new(SourceLang::NativeX86, 0),
        };
        let source: String =
            emit_pseudo_source(&surfacify_function(&structurize_function(&function)))
                .expect("emit external conditional");
        assert!(source.contains("if (zf) jump(0x4000); else goto label_2;"));
        assert!(!source.contains("label_4000"));
        assert!(source.contains("return;"));
    }

    #[test]
    fn fallback_preserves_all_terminal_operations() {
        let function: NirFunction = NirFunction {
            name: "fallback_terminals".to_owned(),
            address: 0,
            end: 4,
            is_export: false,
            instructions: vec![
                NirInstr {
                    address: 0,
                    op: NirOp::CondBranch {
                        target: Some(0x4000),
                    },
                    mnemonic: "CBRANCH".to_owned(),
                    operands: vec!["zf".to_owned()],
                    reads_memory: false,
                    writes_memory: false,
                    byte_width: false,
                    source: SourceRef::new(SourceLang::NativeX86, 0),
                },
                NirInstr {
                    address: 1,
                    op: NirOp::NoReturnCall {
                        target: Some(0x5000),
                    },
                    mnemonic: "CALL".to_owned(),
                    operands: vec!["target_no_return".to_owned()],
                    reads_memory: false,
                    writes_memory: false,
                    byte_width: false,
                    source: SourceRef::new(SourceLang::NativeX86, 1),
                },
                NirInstr {
                    address: 2,
                    op: NirOp::TailCall {
                        target: Some(0x6000),
                    },
                    mnemonic: "BRANCH".to_owned(),
                    operands: vec!["target_tail".to_owned()],
                    reads_memory: false,
                    writes_memory: false,
                    byte_width: false,
                    source: SourceRef::new(SourceLang::NativeX86, 2),
                },
                NirInstr {
                    address: 3,
                    op: NirOp::Return,
                    mnemonic: "RETURN".to_owned(),
                    operands: vec!["rax".to_owned()],
                    reads_memory: false,
                    writes_memory: false,
                    byte_width: false,
                    source: SourceRef::new(SourceLang::NativeX86, 3),
                },
            ],
            source: SourceRef::new(SourceLang::NativeX86, 0),
        };
        let source: String =
            emit_pseudo_source(&surfacify_function(&structurize_function(&function)))
                .expect("emit fallback terminals");
        assert!(source.contains("target_no_return();"));
        assert!(!source.contains("return target_no_return();"));
        assert!(source.contains("return target_tail();"));
        assert!(source.contains("return rax;"));
    }

    #[test]
    fn dispatch_fallback_preserves_control_terminators() {
        let function: NirFunction = NirFunction {
            name: "dispatch_terminals".to_owned(),
            address: 0,
            end: 2,
            is_export: false,
            instructions: vec![
                NirInstr {
                    address: 0,
                    op: NirOp::Branch { target: None },
                    mnemonic: "BRANCHIND".to_owned(),
                    operands: vec!["dynamic".to_owned()],
                    reads_memory: false,
                    writes_memory: false,
                    byte_width: false,
                    source: SourceRef::new(SourceLang::Jvm, 0),
                },
                NirInstr {
                    address: 1,
                    op: NirOp::Return,
                    mnemonic: "RETURN".to_owned(),
                    operands: vec!["value".to_owned()],
                    reads_memory: false,
                    writes_memory: false,
                    byte_width: false,
                    source: SourceRef::new(SourceLang::Jvm, 1),
                },
            ],
            source: SourceRef::new(SourceLang::Jvm, 0),
        };
        let source: String =
            emit_pseudo_source(&surfacify_function(&structurize_function(&function)))
                .expect("emit dispatch terminals");
        assert!(source.contains("goto_indirect;"));
        assert!(source.contains("return value;"));
    }
}
