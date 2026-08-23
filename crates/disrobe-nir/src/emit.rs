use std::fmt::{self, Write};

use thiserror::Error;

use crate::hir::HirConst;
use crate::surface::{
    SurfaceCase, SurfaceCondition, SurfaceConditionExpr, SurfaceConditionTest, SurfaceExpr,
    SurfaceFunction, SurfaceLeaf, SurfaceStatement, SurfaceStmt,
};
use crate::types::{BinaryOp, NirClass};

const MAX_EMIT_DEPTH: usize = 128;
const MAX_EMITTED_BYTES: usize = 1_048_576;
const MAX_INDENT_DEPTH: usize = 32;

#[derive(Debug, Error)]
pub enum EmitError {
    #[error("surface nesting exceeded the emit depth limit of {limit}")]
    DepthExceeded { limit: usize },
    #[error("emitted source exceeded the per-function byte limit of {limit}")]
    OutputLimitExceeded { limit: usize },
    #[error(transparent)]
    Format(#[from] fmt::Error),
}

struct BoundedOutput {
    text: String,
    limit: usize,
    exceeded: bool,
}

impl BoundedOutput {
    fn new(limit: usize) -> Self {
        Self {
            text: String::with_capacity(limit.min(4096)),
            limit,
            exceeded: false,
        }
    }

    fn push_str(&mut self, text: &str) {
        if self.exceeded {
            return;
        }
        let Some(length): Option<usize> = self.text.len().checked_add(text.len()) else {
            self.exceeded = true;
            return;
        };
        if length > self.limit {
            self.exceeded = true;
            return;
        }
        self.text.push_str(text);
    }

    fn push(&mut self, character: char) {
        let mut encoded: [u8; 4] = [0; 4];
        let text: &str = character.encode_utf8(&mut encoded);
        self.push_str(text);
    }

    fn into_string(self) -> String {
        self.text
    }
}

impl Write for BoundedOutput {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.push_str(text);
        if self.exceeded {
            Err(fmt::Error)
        } else {
            Ok(())
        }
    }
}

pub fn emit_pseudo_source(function: &SurfaceFunction) -> Result<String, EmitError> {
    let mut output: BoundedOutput = BoundedOutput::new(MAX_EMITTED_BYTES);
    let result: Result<(), EmitError> = emit_function(function, &mut output);
    if output.exceeded {
        return Err(EmitError::OutputLimitExceeded {
            limit: MAX_EMITTED_BYTES,
        });
    }
    result?;
    Ok(output.into_string())
}

fn emit_function(function: &SurfaceFunction, output: &mut BoundedOutput) -> Result<(), EmitError> {
    write!(
        output,
        "{} {}(",
        function.signature.return_type.label(),
        function.signature.name
    )?;
    for (index, parameter) in function.signature.params.iter().enumerate() {
        if output.exceeded {
            break;
        }
        if index != 0 {
            output.push_str(", ");
        }
        write!(output, "{} {}", parameter.ty.label(), parameter.name)?;
    }
    output.push_str(") {\n");
    for local in &function.locals {
        if output.exceeded {
            break;
        }
        writeln!(output, "    {} {};", local.ty.label(), local.name)?;
    }
    if !function.structured {
        output.push_str("    /* unrecovered: structured control flow */\n");
    }
    emit_stmt(&function.body, 1, 0, output)?;
    output.push_str("}\n");
    Ok(())
}

fn emit_stmt(
    stmt: &SurfaceStmt,
    indent: usize,
    depth: usize,
    output: &mut BoundedOutput,
) -> Result<(), EmitError> {
    if output.exceeded {
        return Ok(());
    }
    if depth >= MAX_EMIT_DEPTH {
        return Err(EmitError::DepthExceeded {
            limit: MAX_EMIT_DEPTH,
        });
    }
    match stmt {
        SurfaceStmt::Block { body } => {
            for child in body {
                emit_stmt(child, indent, depth.saturating_add(1), output)?;
                if output.exceeded {
                    break;
                }
            }
        }
        SurfaceStmt::Leaf { statements, .. } => {
            for leaf in statements {
                emit_leaf(leaf, indent, output);
                if output.exceeded {
                    break;
                }
            }
        }
        SurfaceStmt::If {
            cond,
            then_branch,
            else_branch,
        } => {
            let root_test: Option<&SurfaceConditionTest> = first_condition_test(&cond.expression);
            if let Some(test) = root_test {
                emit_condition_prelude(test, indent, output);
            }
            write_indent(indent, output);
            output.push_str("if (");
            emit_condition(
                cond,
                root_test.map(|test: &SurfaceConditionTest| test.block_start),
                indent,
                depth,
                output,
            )?;
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
                emit_expr(value, output);
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
    output: &mut BoundedOutput,
) -> Result<(), EmitError> {
    write_indent(indent, output);
    writeln!(output, "goto label_{entry:x};")?;
    for block in blocks {
        if output.exceeded {
            break;
        }
        write_indent(indent, output);
        writeln!(output, "label_{:x}:", block.block_start)?;
        emit_case_statements(block, indent.saturating_add(1), output);
        emit_goto_terminator(block, indent.saturating_add(1), output)?;
    }
    Ok(())
}

fn emit_case_statements(case: &SurfaceCase, indent: usize, output: &mut BoundedOutput) {
    for leaf in &case.statements {
        if output.exceeded {
            break;
        }
        emit_leaf(leaf, indent, output);
    }
}

fn emit_goto_terminator(
    case: &SurfaceCase,
    indent: usize,
    output: &mut BoundedOutput,
) -> Result<(), EmitError> {
    if output.exceeded {
        return Ok(());
    }
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
                    expression: SurfaceConditionExpr::Test {
                        test: SurfaceConditionTest {
                            block_start: case.block_start,
                            statements: Vec::new(),
                            at: leaf.instr.address,
                            mnemonic: leaf.instr.mnemonic.clone(),
                            operands: leaf.instr.operands.clone(),
                            taken_target: taken,
                            fallthrough_target: fallthrough,
                            taken_route: Vec::new(),
                            fallthrough_route: Vec::new(),
                        },
                        negated: false,
                    },
                    taken_target: taken,
                    fallthrough_target: fallthrough,
                };
                emit_condition(&condition, None, indent, 0, output)?;
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

fn emit_terminal_call(leaf: &SurfaceLeaf, output: &mut BoundedOutput) {
    match leaf.instr.operands.first() {
        Some(target) => output.push_str(target),
        None => output.push_str("indirect_call"),
    }
    output.push('(');
    for (index, argument) in leaf.instr.operands.iter().skip(1).enumerate() {
        if output.exceeded {
            break;
        }
        if index != 0 {
            output.push_str(", ");
        }
        output.push_str(argument);
    }
    output.push(')');
}

fn emit_transfer(target: u64, internal: bool, output: &mut BoundedOutput) -> Result<(), EmitError> {
    if internal {
        write!(output, "goto label_{target:x}")?;
    } else {
        write!(output, "jump(0x{target:x})")?;
    }
    Ok(())
}

fn emit_leaf(leaf: &SurfaceLeaf, indent: usize, output: &mut BoundedOutput) {
    if output.exceeded {
        return;
    }
    match &leaf.stmt {
        SurfaceStatement::Assign { target, value } => {
            write_indent(indent, output);
            emit_expr(target, output);
            output.push_str(" = ");
            emit_expr(value, output);
            output.push_str(";\n");
        }
        SurfaceStatement::Store { cell, value } => {
            write_indent(indent, output);
            output.push_str("store(");
            emit_expr(cell, output);
            output.push_str(", ");
            emit_expr(value, output);
            output.push_str(");\n");
        }
        SurfaceStatement::Call { target, args } => {
            write_indent(indent, output);
            emit_call(target.as_deref(), args, output);
            output.push_str(";\n");
        }
        SurfaceStatement::Expr { value } => {
            if matches!(value, SurfaceExpr::Raw { text } if text.is_empty()) {
                return;
            }
            write_indent(indent, output);
            emit_expr(value, output);
            output.push_str(";\n");
        }
    }
}

fn first_condition_test(expression: &SurfaceConditionExpr) -> Option<&SurfaceConditionTest> {
    match expression {
        SurfaceConditionExpr::Test { test, .. } => Some(test),
        SurfaceConditionExpr::All { terms } | SurfaceConditionExpr::Any { terms } => {
            terms.iter().find_map(first_condition_test)
        }
    }
}

fn condition_prelude(test: &SurfaceConditionTest) -> &[SurfaceLeaf] {
    match test.statements.split_last() {
        Some((last, preceding)) if last.instr.class() == NirClass::ConditionalJump => preceding,
        _ => &test.statements,
    }
}

fn emit_condition_prelude(test: &SurfaceConditionTest, indent: usize, output: &mut BoundedOutput) {
    for statement in condition_prelude(test) {
        emit_leaf(statement, indent, output);
    }
}

fn emit_condition(
    condition: &SurfaceCondition,
    root_block: Option<u64>,
    indent: usize,
    depth: usize,
    output: &mut BoundedOutput,
) -> Result<(), EmitError> {
    emit_condition_expr(
        &condition.expression,
        root_block,
        indent,
        depth.saturating_add(1),
        0,
        output,
    )
}

fn emit_condition_expr(
    expression: &SurfaceConditionExpr,
    root_block: Option<u64>,
    indent: usize,
    depth: usize,
    parent_precedence: u8,
    output: &mut BoundedOutput,
) -> Result<(), EmitError> {
    if depth >= MAX_EMIT_DEPTH {
        return Err(EmitError::DepthExceeded {
            limit: MAX_EMIT_DEPTH,
        });
    }
    let precedence: u8 = match expression {
        SurfaceConditionExpr::Test { .. } => 3,
        SurfaceConditionExpr::All { .. } => 2,
        SurfaceConditionExpr::Any { .. } => 1,
    };
    let parenthesized: bool = precedence < parent_precedence;
    if parenthesized {
        output.push('(');
    }
    match expression {
        SurfaceConditionExpr::Test { test, negated } => {
            if *negated {
                output.push_str("!(");
            }
            let prelude: &[SurfaceLeaf] = condition_prelude(test);
            let inline_prelude: bool = !prelude.is_empty() && root_block != Some(test.block_start);
            if inline_prelude {
                output.push_str("[&]() {\n");
                for statement in prelude {
                    emit_leaf(statement, indent.saturating_add(1), output);
                }
                write_indent(indent.saturating_add(1), output);
                output.push_str("return ");
                emit_condition_test(test, output);
                output.push_str(";\n");
                write_indent(indent, output);
                output.push_str("}()");
            } else {
                emit_condition_test(test, output);
            }
            if *negated {
                output.push(')');
            }
        }
        SurfaceConditionExpr::All { terms } | SurfaceConditionExpr::Any { terms } => {
            let operator: &str = if matches!(expression, SurfaceConditionExpr::All { .. }) {
                " && "
            } else {
                " || "
            };
            if terms.is_empty() {
                output.push_str("condition");
            }
            for (index, term) in terms.iter().enumerate() {
                if index != 0 {
                    output.push_str(operator);
                }
                emit_condition_expr(
                    term,
                    root_block,
                    indent,
                    depth.saturating_add(1),
                    precedence,
                    output,
                )?;
            }
        }
    }
    if parenthesized {
        output.push(')');
    }
    Ok(())
}

fn emit_condition_test(test: &SurfaceConditionTest, output: &mut BoundedOutput) {
    match test.operands.first() {
        Some(value) => output.push_str(value),
        None if test.mnemonic.is_empty() => output.push_str("condition"),
        None => output.push_str(&test.mnemonic),
    }
}

enum ExprAction<'a> {
    Expr(&'a SurfaceExpr),
    Args(&'a [SurfaceExpr], usize),
    Text(&'a str),
}

fn emit_expr(expr: &SurfaceExpr, output: &mut BoundedOutput) {
    let mut pending: Vec<ExprAction<'_>> = vec![ExprAction::Expr(expr)];
    while !output.exceeded {
        let action: Option<ExprAction<'_>> = pending.pop();
        let Some(action) = action else {
            break;
        };
        match action {
            ExprAction::Text(text) => output.push_str(text),
            ExprAction::Args(args, index) => {
                if let Some(argument) = args.get(index) {
                    if index + 1 < args.len() {
                        pending.push(ExprAction::Args(args, index + 1));
                        pending.push(ExprAction::Text(", "));
                    }
                    pending.push(ExprAction::Expr(argument));
                }
            }
            ExprAction::Expr(expression) => match expression {
                SurfaceExpr::Literal { value } => match value {
                    HirConst::Integer { value } => output.push_str(&value.to_string()),
                    HirConst::Literal { text } => output.push_str(text),
                },
                SurfaceExpr::Local { name: text } | SurfaceExpr::Raw { text } => {
                    output.push_str(text);
                }
                SurfaceExpr::Field { cell } => {
                    output.push_str("mem[");
                    output.push_str(cell);
                    output.push(']');
                }
                SurfaceExpr::Unary { op, operand } => {
                    output.push_str(unary_symbol(*op));
                    output.push('(');
                    pending.push(ExprAction::Text(")"));
                    pending.push(ExprAction::Expr(operand));
                }
                SurfaceExpr::Binary { op, lhs, rhs } => {
                    output.push('(');
                    pending.push(ExprAction::Text(")"));
                    pending.push(ExprAction::Expr(rhs));
                    pending.push(ExprAction::Text(" "));
                    pending.push(ExprAction::Text(binary_symbol(*op)));
                    pending.push(ExprAction::Text(" "));
                    pending.push(ExprAction::Expr(lhs));
                }
                SurfaceExpr::Call { target, args } => {
                    output.push_str(target.as_deref().unwrap_or("indirect_call"));
                    output.push('(');
                    pending.push(ExprAction::Text(")"));
                    pending.push(ExprAction::Args(args, 0));
                }
            },
        }
    }
}

fn emit_call(target: Option<&str>, args: &[SurfaceExpr], output: &mut BoundedOutput) {
    output.push_str(target.unwrap_or("indirect_call"));
    output.push('(');
    for (index, argument) in args.iter().enumerate() {
        if output.exceeded {
            break;
        }
        if index != 0 {
            output.push_str(", ");
        }
        emit_expr(argument, output);
    }
    output.push(')');
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

fn write_indent(indent: usize, output: &mut BoundedOutput) {
    let width: usize = indent.min(MAX_INDENT_DEPTH);
    for _index in 0..width {
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

    fn short_circuit_instruction(
        address: u64,
        op: NirOp,
        mnemonic: &str,
        operands: &[&str],
    ) -> NirInstr {
        NirInstr {
            address,
            op,
            mnemonic: mnemonic.to_owned(),
            operands: operands
                .iter()
                .map(|operand: &&str| (*operand).to_owned())
                .collect(),
            reads_memory: false,
            writes_memory: false,
            byte_width: false,
            source: SourceRef::new(SourceLang::NativeX86, address),
        }
    }

    #[test]
    fn shared_guarded_tail_emits_one_compound_short_circuit_condition() {
        let function: NirFunction = NirFunction {
            name: "short_circuit_or".to_owned(),
            address: 0,
            end: 9,
            is_export: false,
            instructions: vec![
                short_circuit_instruction(
                    0,
                    NirOp::CondBranch { target: Some(6) },
                    "branch_first",
                    &["first"],
                ),
                short_circuit_instruction(
                    2,
                    NirOp::CondBranch { target: Some(6) },
                    "branch_second",
                    &["second"],
                ),
                short_circuit_instruction(4, NirOp::Branch { target: Some(8) }, "skip", &["8"]),
                short_circuit_instruction(6, NirOp::Const, "assign", &["result", "1"]),
                short_circuit_instruction(8, NirOp::Return, "return", &["result"]),
            ],
            source: SourceRef::new(SourceLang::NativeX86, 0),
        };
        let hir: crate::hir::HirFunction = structurize_function(&function);
        assert_eq!(hir.to_nir_function().instructions, function.instructions);
        let surface: SurfaceFunction = surfacify_function(&hir);
        assert_eq!(
            surface.to_nir_function().instructions,
            function.instructions
        );
        let source: String = emit_pseudo_source(&surface).expect("emit short-circuit condition");
        assert_eq!(
            source.matches("if (").count(),
            1,
            "the condition chain must emit one if:\n{source}"
        );
        assert!(
            source.contains("if (first || second)"),
            "the two tests must retain short-circuit order:\n{source}"
        );
        assert_eq!(
            source.matches("result = 1;").count(),
            1,
            "the guarded tail must emit exactly once:\n{source}"
        );
    }

    #[test]
    fn effectful_second_test_keeps_the_existing_nested_recovery() {
        let mut store: NirInstr =
            short_circuit_instruction(2, NirOp::Store, "store", &["mem[cursor]", "value"]);
        store.writes_memory = true;
        let function: NirFunction = NirFunction {
            name: "effectful_short_circuit".to_owned(),
            address: 0,
            end: 10,
            is_export: false,
            instructions: vec![
                short_circuit_instruction(
                    0,
                    NirOp::CondBranch { target: Some(7) },
                    "branch_first",
                    &["first"],
                ),
                store,
                short_circuit_instruction(
                    3,
                    NirOp::CondBranch { target: Some(7) },
                    "branch_second",
                    &["second"],
                ),
                short_circuit_instruction(5, NirOp::Branch { target: Some(9) }, "skip", &["9"]),
                short_circuit_instruction(7, NirOp::Const, "assign", &["result", "1"]),
                short_circuit_instruction(9, NirOp::Return, "return", &["result"]),
            ],
            source: SourceRef::new(SourceLang::NativeX86, 0),
        };
        let source: String =
            emit_pseudo_source(&surfacify_function(&structurize_function(&function)))
                .expect("emit effectful short-circuit condition");
        assert_eq!(
            source.matches("if (").count(),
            2,
            "an effectful test block must retain nested control flow:\n{source}"
        );
        assert_eq!(
            source.matches("result = 1;").count(),
            2,
            "the existing peel must remain authoritative for the refused shape:\n{source}"
        );
    }

    #[test]
    fn calling_second_test_keeps_the_existing_nested_recovery() {
        let function: NirFunction = NirFunction {
            name: "calling_short_circuit".to_owned(),
            address: 0,
            end: 10,
            is_export: false,
            instructions: vec![
                short_circuit_instruction(
                    0,
                    NirOp::CondBranch { target: Some(7) },
                    "branch_first",
                    &["first"],
                ),
                short_circuit_instruction(
                    2,
                    NirOp::Call {
                        target: Some(0x1000),
                    },
                    "call",
                    &["observe"],
                ),
                short_circuit_instruction(
                    3,
                    NirOp::CondBranch { target: Some(7) },
                    "branch_second",
                    &["second"],
                ),
                short_circuit_instruction(5, NirOp::Branch { target: Some(9) }, "skip", &["9"]),
                short_circuit_instruction(7, NirOp::Const, "assign", &["result", "1"]),
                short_circuit_instruction(9, NirOp::Return, "return", &["result"]),
            ],
            source: SourceRef::new(SourceLang::NativeX86, 0),
        };
        let source: String =
            emit_pseudo_source(&surfacify_function(&structurize_function(&function)))
                .expect("emit calling short-circuit condition");
        assert_eq!(source.matches("if (").count(), 2, "{source}");
        assert_eq!(source.matches("result = 1;").count(), 2, "{source}");
        assert_eq!(source.matches("observe();").count(), 1, "{source}");
    }

    #[test]
    fn memory_read_in_second_test_stays_short_circuited_inside_the_condition() {
        let mut load: NirInstr =
            short_circuit_instruction(2, NirOp::Load, "load", &["value", "mem[cursor]"]);
        load.reads_memory = true;
        let function: NirFunction = NirFunction {
            name: "reading_short_circuit".to_owned(),
            address: 0,
            end: 10,
            is_export: false,
            instructions: vec![
                short_circuit_instruction(
                    0,
                    NirOp::CondBranch { target: Some(7) },
                    "branch_first",
                    &["first"],
                ),
                load,
                short_circuit_instruction(
                    3,
                    NirOp::CondBranch { target: Some(7) },
                    "branch_second",
                    &["second"],
                ),
                short_circuit_instruction(5, NirOp::Branch { target: Some(9) }, "skip", &["9"]),
                short_circuit_instruction(7, NirOp::Const, "assign", &["result", "1"]),
                short_circuit_instruction(9, NirOp::Return, "return", &["result"]),
            ],
            source: SourceRef::new(SourceLang::NativeX86, 0),
        };
        let source: String =
            emit_pseudo_source(&surfacify_function(&structurize_function(&function)))
                .expect("emit reading short-circuit condition");
        assert_eq!(source.matches("if (").count(), 1, "{source}");
        assert_eq!(source.matches("result = 1;").count(), 1, "{source}");
        assert!(source.contains("value = mem[mem[cursor]];"), "{source}");
        let first_position: usize = source.find("first ||").expect("first test");
        let load_position: usize = source
            .find("value = mem[mem[cursor]];")
            .expect("memory read");
        assert!(first_position < load_position, "{source}");
    }

    #[test]
    fn three_test_chain_preserves_left_to_right_short_circuit_order() {
        let function: NirFunction = NirFunction {
            name: "short_circuit_three".to_owned(),
            address: 0,
            end: 11,
            is_export: false,
            instructions: vec![
                short_circuit_instruction(
                    0,
                    NirOp::CondBranch { target: Some(8) },
                    "branch_first",
                    &["first"],
                ),
                short_circuit_instruction(
                    2,
                    NirOp::CondBranch { target: Some(8) },
                    "branch_second",
                    &["second"],
                ),
                short_circuit_instruction(
                    4,
                    NirOp::CondBranch { target: Some(8) },
                    "branch_third",
                    &["third"],
                ),
                short_circuit_instruction(6, NirOp::Branch { target: Some(10) }, "skip", &["10"]),
                short_circuit_instruction(8, NirOp::Const, "assign", &["result", "1"]),
                short_circuit_instruction(10, NirOp::Return, "return", &["result"]),
            ],
            source: SourceRef::new(SourceLang::NativeX86, 0),
        };
        let source: String =
            emit_pseudo_source(&surfacify_function(&structurize_function(&function)))
                .expect("emit three-test condition");
        assert!(source.contains("if (first || second || third)"), "{source}");
        assert_eq!(source.matches("if (").count(), 1, "{source}");
        assert_eq!(source.matches("result = 1;").count(), 1, "{source}");
    }

    #[test]
    fn negated_first_test_forms_a_short_circuit_conjunction() {
        let function: NirFunction = NirFunction {
            name: "short_circuit_negated".to_owned(),
            address: 0,
            end: 10,
            is_export: false,
            instructions: vec![
                short_circuit_instruction(
                    0,
                    NirOp::CondBranch { target: Some(8) },
                    "branch_first",
                    &["first"],
                ),
                short_circuit_instruction(
                    2,
                    NirOp::CondBranch { target: Some(6) },
                    "branch_second",
                    &["second"],
                ),
                short_circuit_instruction(4, NirOp::Branch { target: Some(8) }, "skip", &["8"]),
                short_circuit_instruction(6, NirOp::Const, "assign", &["result", "1"]),
                short_circuit_instruction(7, NirOp::Return, "return", &["result"]),
                short_circuit_instruction(8, NirOp::Const, "assign", &["result", "0"]),
                short_circuit_instruction(9, NirOp::Return, "return", &["result"]),
            ],
            source: SourceRef::new(SourceLang::NativeX86, 0),
        };
        let source: String =
            emit_pseudo_source(&surfacify_function(&structurize_function(&function)))
                .expect("emit negated conjunction");
        assert!(source.contains("if (!(first) && second)"), "{source}");
        assert_eq!(source.matches("if (").count(), 1, "{source}");
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

    fn surface_function(body: SurfaceStmt, structured: bool) -> SurfaceFunction {
        SurfaceFunction {
            signature: crate::surface::SurfaceSignature {
                name: "deep".to_owned(),
                params: Vec::new(),
                return_type: crate::surface::SurfaceType::Unknown,
            },
            address: 0,
            end: 1,
            is_export: false,
            locals: Vec::new(),
            body,
            structured,
            source: SourceRef::new(SourceLang::NativeX86, 0),
        }
    }

    fn nested_loops(depth: usize, leaf: SurfaceStmt) -> SurfaceStmt {
        let mut statement: SurfaceStmt = leaf;
        for index in 0..depth {
            statement = SurfaceStmt::Loop {
                label: u64::try_from(index).expect("loop label"),
                body: Box::new(statement),
            };
        }
        statement
    }

    #[test]
    fn expression_renderer_does_not_use_tree_depth_as_call_depth() {
        let handle: std::thread::JoinHandle<()> = std::thread::Builder::new()
            .stack_size(1_048_576)
            .spawn(|| {
                let mut expression: SurfaceExpr = SurfaceExpr::Literal {
                    value: HirConst::counted(1),
                };
                for _index in 0..10_000 {
                    expression = SurfaceExpr::Unary {
                        op: BinaryOp::Neg,
                        operand: Box::new(expression),
                    };
                }
                let mut output: BoundedOutput = BoundedOutput::new(MAX_EMITTED_BYTES);
                emit_expr(&expression, &mut output);
                std::mem::forget(expression);
                assert!(output.text.ends_with(')'));
            })
            .expect("spawn expression render thread");
        handle.join().expect("expression render thread");
    }

    #[test]
    fn maximum_bounded_expression_renders_successfully() {
        let mut expression: SurfaceExpr = SurfaceExpr::Literal {
            value: HirConst::counted(1),
        };
        for _index in 0..127 {
            expression = SurfaceExpr::Unary {
                op: BinaryOp::Neg,
                operand: Box::new(expression),
            };
        }
        let mut output: BoundedOutput = BoundedOutput::new(MAX_EMITTED_BYTES);
        emit_expr(&expression, &mut output);
        assert!(output.text.contains('1'));
    }

    #[test]
    fn maximum_bounded_region_renders_successfully() {
        let statement: SurfaceStmt = nested_loops(127, SurfaceStmt::Break { label: 0 });
        let mut output: BoundedOutput = BoundedOutput::new(MAX_EMITTED_BYTES);
        emit_stmt(&statement, 1, 0, &mut output).expect("emit bounded region");
        assert!(output.text.contains("break;"));
    }

    #[test]
    fn region_past_render_bound_returns_an_error() {
        let statement: SurfaceStmt = nested_loops(128, SurfaceStmt::Break { label: 0 });
        let mut output: BoundedOutput = BoundedOutput::new(MAX_EMITTED_BYTES);
        let result: Result<(), EmitError> = emit_stmt(&statement, 1, 0, &mut output);
        assert!(result.is_err());
    }

    #[test]
    fn indentation_is_clamped_for_nested_regions() {
        let statement: SurfaceStmt = nested_loops(127, SurfaceStmt::Break { label: 0 });
        let mut output: BoundedOutput = BoundedOutput::new(MAX_EMITTED_BYTES);
        emit_stmt(&statement, 1, 0, &mut output).expect("emit bounded region");
        let widest_indent: usize = output
            .text
            .lines()
            .map(|line: &str| line.len() - line.trim_start_matches(' ').len())
            .max()
            .unwrap_or(0);
        assert!(widest_indent <= 128, "widest indent was {widest_indent}");
    }

    #[test]
    fn emission_rejects_a_function_past_the_byte_budget() {
        let function: SurfaceFunction = surface_function(
            SurfaceStmt::Return {
                value: Some(SurfaceExpr::Raw {
                    text: "x".repeat(1_048_576),
                }),
            },
            true,
        );
        let result: Result<String, EmitError> = emit_pseudo_source(&function);
        assert!(matches!(
            result,
            Err(EmitError::OutputLimitExceeded {
                limit: MAX_EMITTED_BYTES
            })
        ));
    }

    #[test]
    fn unstructured_function_is_marked_unrecovered() {
        let function: SurfaceFunction = surface_function(
            SurfaceStmt::GotoGraph {
                entry: 0,
                blocks: Vec::new(),
            },
            false,
        );
        let source: String = emit_pseudo_source(&function).expect("emit fallback");
        assert!(source.contains("unrecovered"), "got:\n{source}");
    }

    #[test]
    fn bounded_output_honors_exact_and_multibyte_boundaries() {
        let mut exact: BoundedOutput = BoundedOutput::new(3);
        exact.push_str("éx");
        assert!(!exact.exceeded);
        assert_eq!(exact.text, "éx");
        exact.push('y');
        assert!(exact.exceeded);
        assert_eq!(exact.text, "éx");

        let mut atomic: BoundedOutput = BoundedOutput::new(3);
        atomic.push_str("ab");
        atomic.push_str("é");
        assert!(atomic.exceeded);
        assert_eq!(atomic.text, "ab");
    }
}
