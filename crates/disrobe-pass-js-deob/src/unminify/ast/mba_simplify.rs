use std::collections::BTreeMap;

use disrobe_mba::{
    BinOp as MbaBinOp, Expr as MbaExpr, Simplification, UnOp as MbaUnOp, Width, simplify,
};
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    BinaryExpression, BinaryOperator, Expression, Program, Statement, UnaryOperator,
};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};

use super::{Edit, RuleOutcome};

const JS_WIDTH: Width = Width::W32;
const MAX_PREDICATE_VARS: usize = 3;

#[derive(Debug, Clone, Default)]
pub(super) struct MbaSimplifyStats {
    pub(super) expressions_collapsed: usize,
    pub(super) opaque_branches_folded: usize,
}

pub(super) fn recover(source: &str) -> (RuleOutcome, MbaSimplifyStats) {
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return (RuleOutcome::empty(), MbaSimplifyStats::default());
    }
    let program: &Program<'_> = &parsed.program;

    let mut edits: Vec<Edit> = Vec::new();
    let mut stats: MbaSimplifyStats = MbaSimplifyStats::default();
    for stmt in &program.body {
        walk_statement(stmt, source, &mut edits, &mut stats);
    }

    if edits.is_empty() {
        return (RuleOutcome::empty(), stats);
    }
    (RuleOutcome { edits }, stats)
}

fn walk_statement(
    stmt: &Statement<'_>,
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut MbaSimplifyStats,
) {
    if let Statement::IfStatement(s) = stmt
        && let Some(edit) = try_fold_if(s, source, stats)
    {
        edits.push(edit);
        return;
    }
    match stmt {
        Statement::ExpressionStatement(s) => walk_expression(&s.expression, source, edits, stats),
        Statement::ReturnStatement(s) => {
            if let Some(arg) = s.argument.as_ref() {
                walk_expression(arg, source, edits, stats);
            }
        }
        Statement::VariableDeclaration(s) => {
            for d in &s.declarations {
                if let Some(init) = d.init.as_ref() {
                    walk_expression(init, source, edits, stats);
                }
            }
        }
        Statement::IfStatement(s) => {
            walk_expression(&s.test, source, edits, stats);
            walk_statement(&s.consequent, source, edits, stats);
            if let Some(alt) = s.alternate.as_ref() {
                walk_statement(alt, source, edits, stats);
            }
        }
        Statement::BlockStatement(s) => {
            for inner in &s.body {
                walk_statement(inner, source, edits, stats);
            }
        }
        Statement::ForStatement(s) => {
            if let Some(test) = s.test.as_ref() {
                walk_expression(test, source, edits, stats);
            }
            walk_statement(&s.body, source, edits, stats);
        }
        Statement::WhileStatement(s) => {
            walk_expression(&s.test, source, edits, stats);
            walk_statement(&s.body, source, edits, stats);
        }
        Statement::DoWhileStatement(s) => {
            walk_expression(&s.test, source, edits, stats);
            walk_statement(&s.body, source, edits, stats);
        }
        Statement::FunctionDeclaration(f) => {
            if let Some(body) = f.body.as_ref() {
                for inner in &body.statements {
                    walk_statement(inner, source, edits, stats);
                }
            }
        }
        Statement::ThrowStatement(s) => walk_expression(&s.argument, source, edits, stats),
        Statement::SwitchStatement(s) => {
            walk_expression(&s.discriminant, source, edits, stats);
            for case in &s.cases {
                for inner in &case.consequent {
                    walk_statement(inner, source, edits, stats);
                }
            }
        }
        _ => {}
    }
}

fn walk_expression(
    expr: &Expression<'_>,
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut MbaSimplifyStats,
) {
    match expr {
        Expression::BinaryExpression(b) => {
            let in_int32: bool = is_bitwise_operator(b.operator);
            if !(in_int32 && try_collapse_operand(&b.left, source, edits, stats)) {
                walk_expression(&b.left, source, edits, stats);
            }
            if !(in_int32 && try_collapse_operand(&b.right, source, edits, stats)) {
                walk_expression(&b.right, source, edits, stats);
            }
        }
        Expression::LogicalExpression(b) => {
            walk_expression(&b.left, source, edits, stats);
            walk_expression(&b.right, source, edits, stats);
        }
        Expression::ParenthesizedExpression(p) => {
            walk_expression(&p.expression, source, edits, stats);
        }
        Expression::UnaryExpression(u) => walk_expression(&u.argument, source, edits, stats),
        Expression::ConditionalExpression(c) => {
            walk_expression(&c.test, source, edits, stats);
            walk_expression(&c.consequent, source, edits, stats);
            walk_expression(&c.alternate, source, edits, stats);
        }
        Expression::CallExpression(c) => {
            for arg in &c.arguments {
                if let Some(inner) = arg.as_expression() {
                    walk_expression(inner, source, edits, stats);
                }
            }
        }
        Expression::AssignmentExpression(a) => walk_expression(&a.right, source, edits, stats),
        Expression::SequenceExpression(s) => {
            for inner in &s.expressions {
                walk_expression(inner, source, edits, stats);
            }
        }
        _ => {}
    }
}

struct VarTable<'a> {
    by_source: BTreeMap<String, u32>,
    order: Vec<&'a Expression<'a>>,
}

impl<'a> VarTable<'a> {
    const fn new() -> Self {
        Self {
            by_source: BTreeMap::new(),
            order: Vec::new(),
        }
    }

    fn intern(&mut self, expr: &'a Expression<'a>, source: &str) -> u32 {
        let key: String = normalized_source(expr, source);
        if let Some(index) = self.by_source.get(&key) {
            return *index;
        }
        let index: u32 = self.order.len() as u32;
        self.by_source.insert(key, index);
        self.order.push(expr);
        index
    }

    const fn len(&self) -> usize {
        self.order.len()
    }
}

fn normalized_source(expr: &Expression<'_>, source: &str) -> String {
    expr.span()
        .source_text(source)
        .chars()
        .filter(|c: &char| !c.is_whitespace())
        .collect()
}

fn try_collapse_operand(
    expr: &Expression<'_>,
    source: &str,
    edits: &mut Vec<Edit>,
    stats: &mut MbaSimplifyStats,
) -> bool {
    let Some(edit): Option<Edit> = collapse_int32(expr, source) else {
        return false;
    };
    edits.push(edit);
    stats.expressions_collapsed += 1;
    true
}

fn collapse_int32(expr: &Expression<'_>, source: &str) -> Option<Edit> {
    let inner: &Expression<'_> = unwrap_paren(expr);
    let mut table: VarTable<'_> = VarTable::new();
    let mba: MbaExpr = lower_expression(inner, source, &mut table)?;
    if !mba.is_linear_mba() || table.len() == 0 {
        return None;
    }
    let result: Simplification = simplify(&mba, JS_WIDTH);
    if !result.changed() || !result.verification.is_proven() {
        return None;
    }
    if result.simplified_nodes >= result.original_nodes {
        return None;
    }
    let rendered: String = render_expression(&result.simplified, &table, source)?;
    let span: oxc_span::Span = expr.span();
    Some(Edit {
        start: span.start as usize,
        end: span.end as usize,
        replacement: format!("({rendered} | 0)"),
    })
}

const fn is_bitwise_operator(op: BinaryOperator) -> bool {
    matches!(
        op,
        BinaryOperator::BitwiseAnd
            | BinaryOperator::BitwiseOR
            | BinaryOperator::BitwiseXOR
            | BinaryOperator::ShiftLeft
            | BinaryOperator::ShiftRight
            | BinaryOperator::ShiftRightZeroFill
    )
}

fn try_fold_if(
    stmt: &oxc_ast::ast::IfStatement<'_>,
    source: &str,
    stats: &mut MbaSimplifyStats,
) -> Option<Edit> {
    let verdict: PredicateVerdict = classify_predicate(&stmt.test, source)?;
    let consequent: &str = stmt.consequent.span().source_text(source);
    let replacement: String = match verdict {
        PredicateVerdict::AlwaysTrue => consequent.to_owned(),
        PredicateVerdict::AlwaysFalse => stmt.alternate.as_ref().map_or_else(
            || "{}".to_owned(),
            |alt| alt.span().source_text(source).to_owned(),
        ),
    };
    stats.opaque_branches_folded += 1;
    Some(Edit {
        start: stmt.span.start as usize,
        end: stmt.span.end as usize,
        replacement,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PredicateVerdict {
    AlwaysTrue,
    AlwaysFalse,
}

fn classify_predicate(expr: &Expression<'_>, source: &str) -> Option<PredicateVerdict> {
    let inner: &Expression<'_> = unwrap_paren(expr);
    let Expression::BinaryExpression(bin): &Expression<'_> = inner else {
        return None;
    };
    let negate: bool = match bin.operator {
        BinaryOperator::StrictEquality | BinaryOperator::Equality => false,
        BinaryOperator::StrictInequality | BinaryOperator::Inequality => true,
        _ => return None,
    };
    let left_inner: &Expression<'_> = peel_int32_coercion(&bin.left)?;
    let right_inner: &Expression<'_> = peel_int32_coercion(&bin.right)?;
    let mut table: VarTable<'_> = VarTable::new();
    let left: MbaExpr = lower_expression(left_inner, source, &mut table)?;
    let right: MbaExpr = lower_expression(right_inner, source, &mut table)?;
    if table.len() > MAX_PREDICATE_VARS || table.len() == 0 {
        return None;
    }
    let equal: ConstEquality = prove_difference_constant(&left, &right)?;
    let always_equal: bool = matches!(equal, ConstEquality::AlwaysEqual);
    let truth: bool = always_equal != negate;
    Some(if truth {
        PredicateVerdict::AlwaysTrue
    } else {
        PredicateVerdict::AlwaysFalse
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConstEquality {
    AlwaysEqual,
    AlwaysUnequal,
}

fn prove_difference_constant(left: &MbaExpr, right: &MbaExpr) -> Option<ConstEquality> {
    let difference: MbaExpr = MbaExpr::Binary(
        MbaBinOp::Sub,
        Box::new(left.clone()),
        Box::new(right.clone()),
    );
    if !difference.is_linear_mba() {
        return None;
    }
    let result: Simplification = simplify(&difference, JS_WIDTH);
    if !result.verification.is_proven() {
        return None;
    }
    let MbaExpr::Const(value): &MbaExpr = &result.simplified else {
        return None;
    };
    Some(if *value == 0 {
        ConstEquality::AlwaysEqual
    } else {
        ConstEquality::AlwaysUnequal
    })
}

const MAX_MBA_LOWER_DEPTH: usize = 256;

fn lower_expression<'a>(
    expr: &'a Expression<'a>,
    source: &str,
    table: &mut VarTable<'a>,
) -> Option<MbaExpr> {
    lower_expression_at(expr, source, table, 0)
}

fn lower_expression_at<'a>(
    expr: &'a Expression<'a>,
    source: &str,
    table: &mut VarTable<'a>,
    depth: usize,
) -> Option<MbaExpr> {
    if depth > MAX_MBA_LOWER_DEPTH {
        return None;
    }
    let node: &Expression<'_> = unwrap_paren(expr);
    match node {
        Expression::NumericLiteral(n) => {
            let value: f64 = n.value;
            if value < 0.0 || value.fract() != 0.0 || value > f64::from(u32::MAX) {
                return None;
            }
            Some(MbaExpr::konst(value as u64))
        }
        Expression::Identifier(_) => Some(MbaExpr::var(table.intern(node, source))),
        Expression::BinaryExpression(b) => lower_binary(b, source, table, depth + 1),
        Expression::UnaryExpression(u) => match u.operator {
            UnaryOperator::BitwiseNot => {
                let arg: MbaExpr = lower_expression_at(&u.argument, source, table, depth + 1)?;
                Some(MbaExpr::not(arg))
            }
            UnaryOperator::UnaryNegation => {
                let arg: MbaExpr = lower_expression_at(&u.argument, source, table, depth + 1)?;
                Some(MbaExpr::neg(arg))
            }
            _ => None,
        },
        _ => None,
    }
}

fn lower_binary<'a>(
    bin: &'a BinaryExpression<'a>,
    source: &str,
    table: &mut VarTable<'a>,
    depth: usize,
) -> Option<MbaExpr> {
    let op: MbaBinOp = match bin.operator {
        BinaryOperator::Addition => MbaBinOp::Add,
        BinaryOperator::Subtraction => MbaBinOp::Sub,
        BinaryOperator::Multiplication => MbaBinOp::Mul,
        BinaryOperator::BitwiseAnd => MbaBinOp::And,
        BinaryOperator::BitwiseOR => MbaBinOp::Or,
        BinaryOperator::BitwiseXOR => MbaBinOp::Xor,
        _ => return None,
    };
    let left: MbaExpr = lower_expression_at(&bin.left, source, table, depth + 1)?;
    let right: MbaExpr = lower_expression_at(&bin.right, source, table, depth + 1)?;
    Some(MbaExpr::Binary(op, Box::new(left), Box::new(right)))
}

fn render_expression(expr: &MbaExpr, table: &VarTable<'_>, source: &str) -> Option<String> {
    render_expression_at(expr, table, source, 0)
}

fn render_expression_at(
    expr: &MbaExpr,
    table: &VarTable<'_>,
    source: &str,
    depth: usize,
) -> Option<String> {
    if depth > MAX_MBA_LOWER_DEPTH {
        return None;
    }
    match expr {
        MbaExpr::Const(value) => Some(value.to_string()),
        MbaExpr::Var(index) => {
            let target: &Expression<'_> = table.order.get(*index as usize)?;
            let text: &str = target.span().source_text(source);
            Some(format!("({text} | 0)"))
        }
        MbaExpr::Unary(op, inner) => {
            let rendered: String = render_expression_at(inner, table, source, depth + 1)?;
            let symbol: char = match op {
                MbaUnOp::Neg => '-',
                MbaUnOp::Not => '~',
            };
            Some(format!("{symbol}({rendered})"))
        }
        MbaExpr::Binary(op, left, right) => {
            let lhs: String = render_expression_at(left, table, source, depth + 1)?;
            let rhs: String = render_expression_at(right, table, source, depth + 1)?;
            let symbol: &str = match op {
                MbaBinOp::Add => "+",
                MbaBinOp::Sub => "-",
                MbaBinOp::Mul => "*",
                MbaBinOp::And => "&",
                MbaBinOp::Or => "|",
                MbaBinOp::Xor => "^",
                MbaBinOp::Shl => "<<",
                MbaBinOp::Shr => ">>",
            };
            Some(format!("({lhs} {symbol} {rhs})"))
        }
        MbaExpr::Ite(_, _, _)
        | MbaExpr::Slice(_, _, _)
        | MbaExpr::Compose(_, _, _)
        | MbaExpr::Mem(_, _) => None,
    }
}

fn unwrap_paren<'a>(expr: &'a Expression<'a>) -> &'a Expression<'a> {
    let mut current: &'a Expression<'a> = expr;
    while let Expression::ParenthesizedExpression(p) = current {
        current = &p.expression;
    }
    current
}

fn peel_int32_coercion<'a>(expr: &'a Expression<'a>) -> Option<&'a Expression<'a>> {
    let node: &Expression<'_> = unwrap_paren(expr);
    let Expression::BinaryExpression(bin): &Expression<'_> = node else {
        return None;
    };
    let coercion: bool = match bin.operator {
        BinaryOperator::BitwiseOR | BinaryOperator::ShiftRightZeroFill => {
            is_numeric_constant(&bin.right, 0)
        }
        BinaryOperator::BitwiseAnd => is_numeric_constant(&bin.right, u64::from(u32::MAX)),
        _ => false,
    };
    if !coercion {
        return None;
    }
    let inner: &Expression<'_> = unwrap_paren(&bin.left);
    Some(peel_int32_coercion(inner).unwrap_or(inner))
}

fn is_numeric_constant(expr: &Expression<'_>, target: u64) -> bool {
    let node: &Expression<'_> = unwrap_paren(expr);
    let Expression::NumericLiteral(n): &Expression<'_> = node else {
        return false;
    };
    let value: f64 = n.value;
    value >= 0.0 && value.fract() == 0.0 && value <= f64::from(u32::MAX) && value as u64 == target
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use disrobe_mba::equivalent_exhaustive;

    use super::*;

    fn parse_single_expr_to_mba(js: &str) -> (MbaExpr, usize) {
        let allocator: Allocator = Allocator::default();
        let source_type: SourceType = SourceType::from_path("input.js").unwrap_or_default();
        let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, js, source_type).parse();
        assert!(parsed.errors.is_empty(), "parse failed for `{js}`");
        let program: &Program<'_> = &parsed.program;
        let Statement::ExpressionStatement(stmt) = &program.body[0] else {
            panic!("expected expression statement");
        };
        let mut table: VarTable<'_> = VarTable::new();
        let expr: MbaExpr =
            lower_expression(unwrap_paren(&stmt.expression), js, &mut table).expect("lowered");
        (expr, table.len())
    }

    #[test]
    fn xor_plus_twice_and_lowers_to_linear_mba() {
        let (expr, vars): (MbaExpr, usize) = parse_single_expr_to_mba("(x ^ y) + 2 * (x & y)");
        assert_eq!(vars, 2);
        assert!(expr.is_linear_mba(), "lowered expr should be linear MBA");
        let simplified: Simplification = simplify(&expr, JS_WIDTH);
        assert!(simplified.changed());
        assert!(simplified.verification.is_proven());
        let expected: MbaExpr = MbaExpr::add(MbaExpr::var(0), MbaExpr::var(1));
        assert!(
            equivalent_exhaustive(&simplified.simplified, &expected, Width::W8, 2),
            "simplified `{}` not equal to x + y",
            simplified.simplified
        );
    }

    #[test]
    fn identifier_interning_is_stable() {
        let (expr, vars): (MbaExpr, usize) = parse_single_expr_to_mba("(a & b) | (a & b)");
        assert_eq!(vars, 2, "a and b each interned once across both operands");
        assert!(expr.is_linear_mba());
    }
}
