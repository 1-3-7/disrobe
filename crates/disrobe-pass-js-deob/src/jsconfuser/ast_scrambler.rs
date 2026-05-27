use std::ops::Range;

use oxc_allocator::Allocator;
use oxc_ast::ast::{BinaryOperator, Expression, Program, Statement};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};
use serde::Serialize;

use super::scanner::apply_splice_edits;

#[derive(Debug, Clone, Serialize)]
pub struct AstScramblerResult {
    pub rotations_folded: usize,
    pub rewritten_source: String,
}

#[must_use]
pub fn reverse_ast_scrambler(source: &str) -> AstScramblerResult {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("ast.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if parsed.panicked {
        return passthrough(source);
    }
    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::new();
    walk_program(&parsed.program, source, &mut edits);
    if edits.is_empty() {
        return passthrough(source);
    }
    let (rewritten, folded): (String, usize) = apply_splice_edits(source, &mut edits);
    AstScramblerResult {
        rotations_folded: folded,
        rewritten_source: rewritten,
    }
}

fn passthrough(source: &str) -> AstScramblerResult {
    AstScramblerResult {
        rotations_folded: 0,
        rewritten_source: source.to_owned(),
    }
}

fn walk_program(
    program: &Program<'_>,
    source: &str,
    edits: &mut Vec<(Range<usize>, Option<String>)>,
) {
    for stmt in &program.body {
        walk_stmt(stmt, source, edits);
    }
}

fn walk_stmt(stmt: &Statement<'_>, source: &str, edits: &mut Vec<(Range<usize>, Option<String>)>) {
    match stmt {
        Statement::ExpressionStatement(es) => walk_expr(&es.expression, source, edits),
        Statement::VariableDeclaration(decl) => {
            for d in &decl.declarations {
                if let Some(init) = &d.init {
                    walk_expr(init, source, edits);
                }
            }
        }
        Statement::ReturnStatement(rs) => {
            if let Some(e) = &rs.argument {
                walk_expr(e, source, edits);
            }
        }
        Statement::BlockStatement(bs) => {
            for s in &bs.body {
                walk_stmt(s, source, edits);
            }
        }
        Statement::IfStatement(is) => {
            walk_expr(&is.test, source, edits);
            walk_stmt(&is.consequent, source, edits);
            if let Some(alt) = &is.alternate {
                walk_stmt(alt, source, edits);
            }
        }
        Statement::FunctionDeclaration(fd) => {
            if let Some(body) = fd.body.as_ref() {
                for s in &body.statements {
                    walk_stmt(s, source, edits);
                }
            }
        }
        _ => {}
    }
}

fn walk_expr(expr: &Expression<'_>, source: &str, edits: &mut Vec<(Range<usize>, Option<String>)>) {
    if let Expression::ParenthesizedExpression(p) = expr {
        walk_expr(&p.expression, source, edits);
    }
    let Expression::BinaryExpression(bin) = expr else {
        return;
    };
    let is_associative: bool = matches!(
        bin.operator,
        BinaryOperator::Addition
            | BinaryOperator::Multiplication
            | BinaryOperator::BitwiseAnd
            | BinaryOperator::BitwiseOR
            | BinaryOperator::BitwiseXOR
    );
    if is_associative
        && let Expression::ParenthesizedExpression(p) = &bin.right
        && let Expression::BinaryExpression(inner) = &p.expression
        && inner.operator == bin.operator
    {
        let lhs_text: &str = slice(source, bin.left.span().start, bin.left.span().end);
        let mid_text: &str = slice(source, inner.left.span().start, inner.left.span().end);
        let rhs_text: &str = slice(source, inner.right.span().start, inner.right.span().end);
        let op: &str = op_token(bin.operator);
        let folded: String = format!("({lhs_text} {op} {mid_text}) {op} {rhs_text}");
        let span_start: u32 = bin.left.span().start.min(bin.right.span().start);
        let span_end: u32 = bin.left.span().end.max(bin.right.span().end);
        let start_usize: usize = span_start as usize;
        let end_usize: usize = span_end as usize;
        edits.push((start_usize..end_usize, Some(folded)));
        return;
    }
    walk_expr(&bin.left, source, edits);
    walk_expr(&bin.right, source, edits);
}

fn slice(source: &str, start: u32, end: u32) -> &str {
    source.get(start as usize..end as usize).unwrap_or("")
}

const fn op_token(op: BinaryOperator) -> &'static str {
    match op {
        BinaryOperator::Multiplication => "*",
        BinaryOperator::BitwiseAnd => "&",
        BinaryOperator::BitwiseOR => "|",
        BinaryOperator::BitwiseXOR => "^",
        _ => "+",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_right_leaning_addition() {
        let src: &str = "var x = a + (b + c);";
        let r: AstScramblerResult = reverse_ast_scrambler(src);
        assert!(r.rotations_folded >= 1);
        assert!(r.rewritten_source.contains("(a + b) + c"));
    }

    #[test]
    fn folds_right_leaning_xor() {
        let src: &str = "var y = x ^ (y ^ z);";
        let r: AstScramblerResult = reverse_ast_scrambler(src);
        assert!(r.rotations_folded >= 1);
        assert!(r.rewritten_source.contains("(x ^ y) ^ z"));
    }

    #[test]
    fn leaves_left_leaning_alone() {
        let src: &str = "var z = (a + b) + c;";
        let r: AstScramblerResult = reverse_ast_scrambler(src);
        assert_eq!(r.rotations_folded, 0);
    }
}
