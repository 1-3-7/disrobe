use std::collections::BTreeMap;
use std::ops::Range;

use disrobe_mba::verify::classify_predicate;
use disrobe_mba::{CmpOp, Expr, OpaqueVerdict, Predicate, Width};
use oxc_allocator::Allocator;
use oxc_ast::Visit;
use oxc_ast::ast as oast;
use oxc_ast::visit::walk;
use oxc_parser::Parser;
use oxc_span::GetSpan;
use oxc_span::SourceType;
use serde::Serialize;

use super::scanner::apply_splice_edits;

const JS_WIDTH: Width = Width::W32;
const MAX_EXACT_MAGNITUDE: u128 = 1u128 << 53;
const INT32_ABS_BOUND: u128 = 1u128 << 31;
const UINT32_BOUND: u128 = (1u128 << 32) - 1;
const MAX_LOWER_DEPTH: usize = 128;
const MAX_FIXPOINT_ROUNDS: usize = 32;

#[derive(Debug, Clone, Serialize)]
pub(super) struct AlgebraicOpaqueResult {
    pub(super) predicates_folded: usize,
    pub(super) rewritten_source: String,
}

#[must_use]
pub(super) fn fold_algebraic_opaque(source: &str) -> AlgebraicOpaqueResult {
    let mut current: String = source.to_owned();
    let mut total: usize = 0;
    for _ in 0..MAX_FIXPOINT_ROUNDS {
        let Some((next, folded)): Option<(String, usize)> = fold_once(&current) else {
            break;
        };
        total += folded;
        current = next;
    }
    AlgebraicOpaqueResult {
        predicates_folded: total,
        rewritten_source: current,
    }
}

fn fold_once(source: &str) -> Option<(String, usize)> {
    let allocator: Allocator = Allocator::default();
    let parsed: oxc_parser::ParserReturn<'_> =
        Parser::new(&allocator, source, SourceType::cjs()).parse();
    if parsed.panicked || !parsed.errors.is_empty() {
        return None;
    }
    let mut collector: Collector<'_> = Collector {
        source,
        edits: Vec::new(),
    };
    collector.visit_program(&parsed.program);
    if collector.edits.is_empty() {
        return None;
    }
    let (rewritten, applied): (String, usize) = apply_splice_edits(source, &mut collector.edits);
    if applied == 0 || !reparses(&rewritten) {
        return None;
    }
    Some((rewritten, applied))
}

fn reparses(source: &str) -> bool {
    let allocator: Allocator = Allocator::default();
    let parsed: oxc_parser::ParserReturn<'_> =
        Parser::new(&allocator, source, SourceType::cjs()).parse();
    !parsed.panicked && parsed.errors.is_empty()
}

struct Collector<'s> {
    source: &'s str,
    edits: Vec<(Range<usize>, Option<String>)>,
}

impl<'a> Visit<'a> for Collector<'_> {
    fn visit_if_statement(&mut self, stmt: &oast::IfStatement<'a>) {
        if let Some(replacement) = self.try_fold_if(stmt) {
            let span: oxc_span::Span = stmt.span;
            self.edits
                .push((span.start as usize..span.end as usize, Some(replacement)));
            return;
        }
        walk::walk_if_statement(self, stmt);
    }

    fn visit_conditional_expression(&mut self, cond: &oast::ConditionalExpression<'a>) {
        if let Some(replacement) = self.try_fold_ternary(cond) {
            let span: oxc_span::Span = cond.span;
            self.edits
                .push((span.start as usize..span.end as usize, Some(replacement)));
            return;
        }
        walk::walk_conditional_expression(self, cond);
    }
}

impl Collector<'_> {
    fn try_fold_if(&self, stmt: &oast::IfStatement<'_>) -> Option<String> {
        let mut table: VarTable = VarTable::new();
        let pred: Predicate = lower_predicate(&stmt.test, false, &mut table, 0)?;
        if verdict(&pred)? {
            if stmt.alternate.as_ref().is_some_and(contains_hoisted_decl) {
                return None;
            }
            Some(self.statement_text(&stmt.consequent))
        } else {
            if contains_hoisted_decl(&stmt.consequent) {
                return None;
            }
            Some(
                stmt.alternate
                    .as_ref()
                    .map_or_else(|| "{}".to_owned(), |alt| self.statement_text(alt)),
            )
        }
    }

    fn try_fold_ternary(&self, cond: &oast::ConditionalExpression<'_>) -> Option<String> {
        let mut table: VarTable = VarTable::new();
        let pred: Predicate = lower_predicate(&cond.test, false, &mut table, 0)?;
        let chosen: &oast::Expression<'_> = if verdict(&pred)? {
            &cond.consequent
        } else {
            &cond.alternate
        };
        Some(format!("({})", chosen.span().source_text(self.source)))
    }

    fn statement_text(&self, stmt: &oast::Statement<'_>) -> String {
        stmt.span().source_text(self.source).to_owned()
    }
}

fn verdict(pred: &Predicate) -> Option<bool> {
    match classify_predicate(pred, JS_WIDTH) {
        OpaqueVerdict::AlwaysTrue { lifted: false, .. } => Some(true),
        OpaqueVerdict::AlwaysFalse { lifted: false, .. } => Some(false),
        _ => None,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Domain {
    Signed,
    Unsigned,
}

struct Value {
    expr: Expr,
    domain: Domain,
}

struct VarTable {
    by_name: BTreeMap<String, u32>,
}

impl VarTable {
    const fn new() -> Self {
        Self {
            by_name: BTreeMap::new(),
        }
    }

    fn intern(&mut self, name: &str) -> u32 {
        if let Some(index) = self.by_name.get(name) {
            return *index;
        }
        let index: u32 = self.by_name.len() as u32;
        self.by_name.insert(name.to_owned(), index);
        index
    }
}

fn lower_predicate(
    expr: &oast::Expression<'_>,
    negate: bool,
    table: &mut VarTable,
    depth: usize,
) -> Option<Predicate> {
    if depth > MAX_LOWER_DEPTH {
        return None;
    }
    let node: &oast::Expression<'_> = unwrap_paren(expr);
    match node {
        oast::Expression::LogicalExpression(logical) => {
            lower_logical(logical, negate, table, depth)
        }
        oast::Expression::UnaryExpression(unary)
            if unary.operator == oast::UnaryOperator::LogicalNot =>
        {
            lower_predicate(&unary.argument, !negate, table, depth + 1)
        }
        oast::Expression::BinaryExpression(binary) if is_comparison(binary.operator) => {
            lower_compare(binary, negate, table, depth)
        }
        _ => {
            let value: Value = lower_value(node, table, depth + 1)?;
            if negate {
                Some(Predicate::eq(value.expr, Expr::konst(0)))
            } else {
                Some(Predicate::nonzero(value.expr))
            }
        }
    }
}

fn lower_logical(
    logical: &oast::LogicalExpression<'_>,
    negate: bool,
    table: &mut VarTable,
    depth: usize,
) -> Option<Predicate> {
    let is_and: bool = match logical.operator {
        oast::LogicalOperator::And => true,
        oast::LogicalOperator::Or => false,
        oast::LogicalOperator::Coalesce => return None,
    };
    let left: Predicate = lower_predicate(&logical.left, negate, table, depth + 1)?;
    let right: Predicate = lower_predicate(&logical.right, negate, table, depth + 1)?;
    let build_and: bool = is_and != negate;
    Some(if build_and {
        Predicate::and(left, right)
    } else {
        Predicate::or(left, right)
    })
}

fn lower_compare(
    binary: &oast::BinaryExpression<'_>,
    negate: bool,
    table: &mut VarTable,
    depth: usize,
) -> Option<Predicate> {
    let left: Value = lower_value(&binary.left, table, depth + 1)?;
    let right: Value = lower_value(&binary.right, table, depth + 1)?;
    if left.domain != right.domain {
        return None;
    }
    let op: CmpOp = compare_op(binary.operator, negate, left.domain)?;
    Some(Predicate::Compare {
        op,
        left: left.expr,
        right: right.expr,
    })
}

const fn is_comparison(op: oast::BinaryOperator) -> bool {
    matches!(
        op,
        oast::BinaryOperator::Equality
            | oast::BinaryOperator::Inequality
            | oast::BinaryOperator::StrictEquality
            | oast::BinaryOperator::StrictInequality
            | oast::BinaryOperator::LessThan
            | oast::BinaryOperator::LessEqualThan
            | oast::BinaryOperator::GreaterThan
            | oast::BinaryOperator::GreaterEqualThan
    )
}

const fn compare_op(op: oast::BinaryOperator, negate: bool, domain: Domain) -> Option<CmpOp> {
    let (positive, negated): (CmpOp, CmpOp) = match op {
        oast::BinaryOperator::Equality | oast::BinaryOperator::StrictEquality => {
            (CmpOp::Eq, CmpOp::Ne)
        }
        oast::BinaryOperator::Inequality | oast::BinaryOperator::StrictInequality => {
            (CmpOp::Ne, CmpOp::Eq)
        }
        oast::BinaryOperator::LessThan => (less_than(domain), greater_equal(domain)),
        oast::BinaryOperator::LessEqualThan => (less_equal(domain), greater_than(domain)),
        oast::BinaryOperator::GreaterThan => (greater_than(domain), less_equal(domain)),
        oast::BinaryOperator::GreaterEqualThan => (greater_equal(domain), less_than(domain)),
        _ => return None,
    };
    Some(if negate { negated } else { positive })
}

const fn less_than(domain: Domain) -> CmpOp {
    match domain {
        Domain::Signed => CmpOp::SignedLt,
        Domain::Unsigned => CmpOp::UnsignedLt,
    }
}

const fn less_equal(domain: Domain) -> CmpOp {
    match domain {
        Domain::Signed => CmpOp::SignedLe,
        Domain::Unsigned => CmpOp::UnsignedLe,
    }
}

const fn greater_than(domain: Domain) -> CmpOp {
    match domain {
        Domain::Signed => CmpOp::SignedGt,
        Domain::Unsigned => CmpOp::UnsignedGt,
    }
}

const fn greater_equal(domain: Domain) -> CmpOp {
    match domain {
        Domain::Signed => CmpOp::SignedGe,
        Domain::Unsigned => CmpOp::UnsignedGe,
    }
}

fn lower_value(expr: &oast::Expression<'_>, table: &mut VarTable, depth: usize) -> Option<Value> {
    if depth > MAX_LOWER_DEPTH {
        return None;
    }
    let node: &oast::Expression<'_> = unwrap_paren(expr);
    match node {
        oast::Expression::NumericLiteral(literal) => literal_value(literal.value),
        oast::Expression::UnaryExpression(unary) => match unary.operator {
            oast::UnaryOperator::BitwiseNot => {
                let inner: Expr = lower_bits(&unary.argument, table, depth + 1)?;
                Some(Value {
                    expr: Expr::not(inner),
                    domain: Domain::Signed,
                })
            }
            oast::UnaryOperator::UnaryNegation => {
                let oast::Expression::NumericLiteral(literal) = unwrap_paren(&unary.argument)
                else {
                    return None;
                };
                neg_literal_value(literal.value)
            }
            _ => None,
        },
        oast::Expression::BinaryExpression(binary) => lower_binary_value(binary, table, depth),
        _ => None,
    }
}

fn lower_binary_value(
    binary: &oast::BinaryExpression<'_>,
    table: &mut VarTable,
    depth: usize,
) -> Option<Value> {
    match binary.operator {
        oast::BinaryOperator::BitwiseAnd
        | oast::BinaryOperator::BitwiseOR
        | oast::BinaryOperator::BitwiseXOR => {
            let left: Expr = lower_bits(&binary.left, table, depth + 1)?;
            let right: Expr = lower_bits(&binary.right, table, depth + 1)?;
            let expr: Expr = match binary.operator {
                oast::BinaryOperator::BitwiseAnd => Expr::and(left, right),
                oast::BinaryOperator::BitwiseOR => Expr::or(left, right),
                _ => Expr::xor(left, right),
            };
            Some(Value {
                expr,
                domain: Domain::Signed,
            })
        }
        oast::BinaryOperator::ShiftLeft => {
            let amount: u64 = literal_shift(&binary.right)?;
            let left: Expr = lower_bits(&binary.left, table, depth + 1)?;
            Some(Value {
                expr: Expr::shl(left, Expr::konst(amount)),
                domain: Domain::Signed,
            })
        }
        oast::BinaryOperator::ShiftRightZeroFill => {
            let amount: u64 = literal_shift(&binary.right)?;
            let left: Expr = lower_bits(&binary.left, table, depth + 1)?;
            Some(Value {
                expr: Expr::shr(left, Expr::konst(amount)),
                domain: Domain::Unsigned,
            })
        }
        _ => None,
    }
}

fn lower_bits(expr: &oast::Expression<'_>, table: &mut VarTable, depth: usize) -> Option<Expr> {
    if depth > MAX_LOWER_DEPTH {
        return None;
    }
    let node: &oast::Expression<'_> = unwrap_paren(expr);
    match node {
        oast::Expression::Identifier(reference) => Some(Expr::var(table.intern(&reference.name))),
        oast::Expression::NumericLiteral(literal) => int_pattern(literal.value),
        oast::Expression::UnaryExpression(unary) => match unary.operator {
            oast::UnaryOperator::BitwiseNot => {
                Some(Expr::not(lower_bits(&unary.argument, table, depth + 1)?))
            }
            oast::UnaryOperator::UnaryNegation => {
                lower_arith(node, table, depth + 1).map(|(expr, _bound): (Expr, u128)| expr)
            }
            _ => None,
        },
        oast::Expression::BinaryExpression(binary) => match binary.operator {
            oast::BinaryOperator::Addition
            | oast::BinaryOperator::Subtraction
            | oast::BinaryOperator::Multiplication => {
                lower_arith(node, table, depth + 1).map(|(expr, _bound): (Expr, u128)| expr)
            }
            _ => lower_value(node, table, depth + 1).map(|value: Value| value.expr),
        },
        _ => None,
    }
}

fn lower_arith(
    expr: &oast::Expression<'_>,
    table: &mut VarTable,
    depth: usize,
) -> Option<(Expr, u128)> {
    if depth > MAX_LOWER_DEPTH {
        return None;
    }
    let node: &oast::Expression<'_> = unwrap_paren(expr);
    match node {
        oast::Expression::NumericLiteral(literal) => {
            let value: f64 = literal.value;
            if !value.is_finite() || value.fract() != 0.0 || value < 0.0 {
                return None;
            }
            let bound: u128 = value as u128;
            if bound > MAX_EXACT_MAGNITUDE {
                return None;
            }
            Some((Expr::konst(value as u64), bound))
        }
        oast::Expression::UnaryExpression(unary)
            if unary.operator == oast::UnaryOperator::UnaryNegation =>
        {
            let (inner, bound): (Expr, u128) = lower_arith(&unary.argument, table, depth + 1)?;
            Some((Expr::neg(inner), bound))
        }
        oast::Expression::BinaryExpression(binary) => match binary.operator {
            oast::BinaryOperator::Addition => {
                arith_combine(binary, table, depth, Expr::add, u128::checked_add)
            }
            oast::BinaryOperator::Subtraction => {
                arith_combine(binary, table, depth, Expr::sub, u128::checked_add)
            }
            oast::BinaryOperator::Multiplication => {
                arith_combine(binary, table, depth, Expr::mul, u128::checked_mul)
            }
            _ => value_as_arith(node, table, depth),
        },
        _ => value_as_arith(node, table, depth),
    }
}

fn arith_combine(
    binary: &oast::BinaryExpression<'_>,
    table: &mut VarTable,
    depth: usize,
    build: fn(Expr, Expr) -> Expr,
    bound: fn(u128, u128) -> Option<u128>,
) -> Option<(Expr, u128)> {
    let (left, left_bound): (Expr, u128) = lower_arith(&binary.left, table, depth + 1)?;
    let (right, right_bound): (Expr, u128) = lower_arith(&binary.right, table, depth + 1)?;
    let total: u128 = bound(left_bound, right_bound)?;
    if total > MAX_EXACT_MAGNITUDE {
        return None;
    }
    Some((build(left, right), total))
}

fn value_as_arith(
    expr: &oast::Expression<'_>,
    table: &mut VarTable,
    depth: usize,
) -> Option<(Expr, u128)> {
    let value: Value = lower_value(expr, table, depth + 1)?;
    let bound: u128 = match value.domain {
        Domain::Signed => INT32_ABS_BOUND,
        Domain::Unsigned => UINT32_BOUND,
    };
    Some((value.expr, bound))
}

fn literal_value(value: f64) -> Option<Value> {
    if !value.is_finite() || value.fract() != 0.0 || value < 0.0 || value > f64::from(u32::MAX) {
        return None;
    }
    let numeric: u64 = value as u64;
    let domain: Domain = if numeric <= 0x7FFF_FFFF {
        Domain::Signed
    } else {
        Domain::Unsigned
    };
    Some(Value {
        expr: Expr::konst(numeric),
        domain,
    })
}

fn neg_literal_value(value: f64) -> Option<Value> {
    if !value.is_finite() || value.fract() != 0.0 || value < 0.0 || value as u128 > INT32_ABS_BOUND
    {
        return None;
    }
    let numeric: u64 = value as u64;
    let pattern: u64 = (1u64 << 32).wrapping_sub(numeric) & 0xFFFF_FFFF;
    Some(Value {
        expr: Expr::konst(pattern),
        domain: Domain::Signed,
    })
}

fn int_pattern(value: f64) -> Option<Expr> {
    if !value.is_finite()
        || value.fract() != 0.0
        || value < 0.0
        || value as u128 > MAX_EXACT_MAGNITUDE
    {
        return None;
    }
    Some(Expr::konst((value as u64) & 0xFFFF_FFFF))
}

fn literal_shift(expr: &oast::Expression<'_>) -> Option<u64> {
    let node: &oast::Expression<'_> = unwrap_paren(expr);
    let oast::Expression::NumericLiteral(literal) = node else {
        return None;
    };
    let value: f64 = literal.value;
    if !value.is_finite() || value.fract() != 0.0 || !(0.0..=31.0).contains(&value) {
        return None;
    }
    Some(value as u64)
}

fn unwrap_paren<'a, 'b>(expr: &'b oast::Expression<'a>) -> &'b oast::Expression<'a> {
    let mut current: &'b oast::Expression<'a> = expr;
    while let oast::Expression::ParenthesizedExpression(paren) = current {
        current = &paren.expression;
    }
    current
}

fn contains_hoisted_decl(stmt: &oast::Statement<'_>) -> bool {
    match stmt {
        oast::Statement::VariableDeclaration(decl) => {
            decl.kind == oast::VariableDeclarationKind::Var
        }
        oast::Statement::FunctionDeclaration(_) => true,
        oast::Statement::BlockStatement(block) => block.body.iter().any(contains_hoisted_decl),
        oast::Statement::IfStatement(inner) => {
            contains_hoisted_decl(&inner.consequent)
                || inner.alternate.as_ref().is_some_and(contains_hoisted_decl)
        }
        oast::Statement::ForStatement(inner) => {
            inner.init.as_ref().is_some_and(for_init_has_var) || contains_hoisted_decl(&inner.body)
        }
        oast::Statement::ForInStatement(inner) => {
            for_left_has_var(&inner.left) || contains_hoisted_decl(&inner.body)
        }
        oast::Statement::ForOfStatement(inner) => {
            for_left_has_var(&inner.left) || contains_hoisted_decl(&inner.body)
        }
        oast::Statement::WhileStatement(inner) => contains_hoisted_decl(&inner.body),
        oast::Statement::DoWhileStatement(inner) => contains_hoisted_decl(&inner.body),
        oast::Statement::SwitchStatement(inner) => inner
            .cases
            .iter()
            .any(|case: &oast::SwitchCase<'_>| case.consequent.iter().any(contains_hoisted_decl)),
        oast::Statement::TryStatement(inner) => {
            inner.block.body.iter().any(contains_hoisted_decl)
                || inner.handler.as_ref().is_some_and(
                    |handler: &oxc_allocator::Box<'_, oast::CatchClause<'_>>| {
                        handler.body.body.iter().any(contains_hoisted_decl)
                    },
                )
                || inner.finalizer.as_ref().is_some_and(
                    |block: &oxc_allocator::Box<'_, oast::BlockStatement<'_>>| {
                        block.body.iter().any(contains_hoisted_decl)
                    },
                )
        }
        oast::Statement::LabeledStatement(inner) => contains_hoisted_decl(&inner.body),
        oast::Statement::WithStatement(inner) => contains_hoisted_decl(&inner.body),
        _ => false,
    }
}

fn for_init_has_var(init: &oast::ForStatementInit<'_>) -> bool {
    matches!(
        init,
        oast::ForStatementInit::VariableDeclaration(decl)
            if decl.kind == oast::VariableDeclarationKind::Var
    )
}

fn for_left_has_var(left: &oast::ForStatementLeft<'_>) -> bool {
    matches!(
        left,
        oast::ForStatementLeft::VariableDeclaration(decl)
            if decl.kind == oast::VariableDeclarationKind::Var
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn fold(source: &str) -> AlgebraicOpaqueResult {
        fold_algebraic_opaque(source)
    }

    #[test]
    fn folds_xor_self_is_zero_to_consequent() {
        let source: &str = "if (((a | 0) ^ (a | 0)) === 0) { keep(); } else { drop(); }";
        let result: AlgebraicOpaqueResult = fold(source);
        assert_eq!(result.predicates_folded, 1);
        assert!(result.rewritten_source.contains("keep()"));
        assert!(!result.rewritten_source.contains("drop()"));
    }

    #[test]
    fn folds_parity_disjunction_to_consequent() {
        let source: &str = "if ((n & 1) === 0 || (n & 1) === 1) { run(); }";
        let result: AlgebraicOpaqueResult = fold(source);
        assert_eq!(result.predicates_folded, 1);
        assert!(result.rewritten_source.contains("run()"));
    }

    #[test]
    fn folds_double_equals_shift_under_coercion() {
        let source: &str = "if ((((a | 0) * 2) | 0) === (a << 1)) { keep(); }";
        let result: AlgebraicOpaqueResult = fold(source);
        assert_eq!(result.predicates_folded, 1);
        assert!(result.rewritten_source.contains("keep()"));
    }

    #[test]
    fn folds_and_self_not_is_false_to_alternate() {
        let source: &str = "if (((a | 0) & (~(a | 0))) !== 0) { drop(); } else { keep(); }";
        let result: AlgebraicOpaqueResult = fold(source);
        assert_eq!(result.predicates_folded, 1);
        assert!(result.rewritten_source.contains("keep()"));
        assert!(!result.rewritten_source.contains("drop()"));
    }

    #[test]
    fn refuses_data_dependent_predicate() {
        let source: &str = "if ((a | 0) === (b | 0)) { maybe(); }";
        let result: AlgebraicOpaqueResult = fold(source);
        assert_eq!(result.predicates_folded, 0);
        assert_eq!(result.rewritten_source, source);
    }

    #[test]
    fn refuses_uncoerced_float_multiply() {
        let source: &str = "if ((a | 0) * 2 === (a << 1)) { maybe(); }";
        let result: AlgebraicOpaqueResult = fold(source);
        assert_eq!(result.predicates_folded, 0);
        assert_eq!(result.rewritten_source, source);
    }

    #[test]
    fn refuses_precision_unsafe_square() {
        let source: &str = "if (((((a | 0) * (a | 0)) | 0) & 1) === 0) { maybe(); }";
        let result: AlgebraicOpaqueResult = fold(source);
        assert_eq!(result.predicates_folded, 0);
        assert_eq!(result.rewritten_source, source);
    }

    #[test]
    fn refuses_side_effecting_predicate() {
        let source: &str = "if ((f() | 0) === (f() | 0)) { maybe(); }";
        let result: AlgebraicOpaqueResult = fold(source);
        assert_eq!(result.predicates_folded, 0);
    }

    #[test]
    fn refuses_signed_unsigned_mismatch() {
        let source: &str = "if ((a | 0) === (a >>> 0)) { maybe(); }";
        let result: AlgebraicOpaqueResult = fold(source);
        assert_eq!(result.predicates_folded, 0);
    }

    #[test]
    fn refuses_dropping_hoisted_declaration() {
        let source: &str = "if (((a | 0) ^ (a | 0)) !== 0) { var leaked = 1; } dump(leaked);";
        let result: AlgebraicOpaqueResult = fold(source);
        assert_eq!(result.predicates_folded, 0);
        assert_eq!(result.rewritten_source, source);
    }

    #[test]
    fn folds_constant_relational_predicate() {
        let source: &str = "if (25 > 10) { big(); }";
        let result: AlgebraicOpaqueResult = fold(source);
        assert_eq!(result.predicates_folded, 1);
        assert!(result.rewritten_source.contains("big()"));
    }
}
