use std::str::FromStr as _;

use ruff_python_ast::{
    AtomicNodeIndex, BytesLiteral, BytesLiteralFlags, BytesLiteralValue, Expr, ExprBooleanLiteral,
    ExprBytesLiteral, ExprList, ExprNoneLiteral, ExprNumberLiteral, ExprStringLiteral, ExprTuple,
    ExprUnaryOp, Int, ModModule, Number, Stmt, StmtAssign, StmtClassDef, StmtExpr, StmtFor,
    StmtFunctionDef, StmtIf, StmtWhile, StringLiteral, StringLiteralFlags, StringLiteralValue,
    UnaryOp,
};
use ruff_text_size::TextRange;

use super::eval::{EvalResult, Scope, eval_expr, is_forbidden};
use super::value::Value;

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct FoldReport {
    pub(crate) bindings_learned: usize,
    pub(crate) exprs_folded: usize,
    pub(crate) bindings_skipped_dynamic: usize,
}

pub(crate) fn fold_module(module: &mut ModModule) -> FoldReport {
    let mut scope: Scope = Scope::new();
    let mut report: FoldReport = FoldReport::default();
    fold_stmts(&mut module.body, &mut scope, &mut report);
    report
}

fn fold_stmts(stmts: &mut [Stmt], scope: &mut Scope, report: &mut FoldReport) {
    for stmt in stmts.iter_mut() {
        fold_stmt(stmt, scope, report);
    }
}

fn fold_stmt(stmt: &mut Stmt, scope: &mut Scope, report: &mut FoldReport) {
    match stmt {
        Stmt::Assign(StmtAssign { targets, value, .. }) => {
            fold_expr_in_place(value, scope, report);
            for target in targets.iter() {
                if let Expr::Name(name_node) = target {
                    if is_forbidden(name_node.id.as_str()) {
                        report.bindings_skipped_dynamic += 1;
                        continue;
                    }
                    if let Ok(val) = eval_expr(value, scope) {
                        let pre: usize = scope.len();
                        scope.bind(name_node.id.to_string(), val);
                        if scope.len() > pre {
                            report.bindings_learned += 1;
                        }
                    }
                }
            }
        }
        Stmt::AnnAssign(a) => {
            if let Some(v) = a.value.as_mut() {
                fold_expr_in_place(v, scope, report);
                if let Expr::Name(name_node) = &*a.target
                    && !is_forbidden(name_node.id.as_str())
                    && let Ok(val) = eval_expr(v, scope)
                {
                    scope.bind(name_node.id.to_string(), val);
                    report.bindings_learned += 1;
                }
            }
        }
        Stmt::AugAssign(a) => {
            fold_expr_in_place(&mut a.value, scope, report);
        }
        Stmt::Expr(StmtExpr { value, .. }) => {
            fold_expr_in_place(value, scope, report);
        }
        Stmt::Return(r) => {
            if let Some(v) = r.value.as_mut() {
                fold_expr_in_place(v, scope, report);
            }
        }
        Stmt::If(StmtIf {
            test,
            body,
            elif_else_clauses,
            ..
        }) => {
            fold_expr_in_place(test, scope, report);
            fold_stmts(body, scope, report);
            for clause in elif_else_clauses.iter_mut() {
                if let Some(t) = clause.test.as_mut() {
                    fold_expr_in_place(t, scope, report);
                }
                fold_stmts(&mut clause.body, scope, report);
            }
        }
        Stmt::While(StmtWhile {
            test, body, orelse, ..
        }) => {
            fold_expr_in_place(test, scope, report);
            fold_stmts(body, scope, report);
            fold_stmts(orelse, scope, report);
        }
        Stmt::For(StmtFor {
            iter, body, orelse, ..
        }) => {
            fold_expr_in_place(iter, scope, report);
            fold_stmts(body, scope, report);
            fold_stmts(orelse, scope, report);
        }
        Stmt::FunctionDef(StmtFunctionDef { body, .. })
        | Stmt::ClassDef(StmtClassDef { body, .. }) => {
            let mut inner_scope: Scope = Scope::new();
            fold_stmts(body, &mut inner_scope, report);
        }
        _ => {}
    }
}

pub(crate) fn fold_expr_in_place(expr: &mut Expr, scope: &Scope, report: &mut FoldReport) {
    walk_children(expr, scope, report);
    let folded: EvalResult = eval_expr(expr, scope);
    let Ok(value) = folded else {
        return;
    };
    if !value_is_simple(&value) {
        return;
    }
    if expr_is_already_literal(expr) {
        return;
    }
    let Some(new_expr) = value_to_expr(value, range_of(expr)) else {
        return;
    };
    *expr = new_expr;
    report.exprs_folded += 1;
}

fn walk_children(expr: &mut Expr, scope: &Scope, report: &mut FoldReport) {
    match expr {
        Expr::BinOp(b) => {
            fold_expr_in_place(&mut b.left, scope, report);
            fold_expr_in_place(&mut b.right, scope, report);
        }
        Expr::UnaryOp(u) => fold_expr_in_place(&mut u.operand, scope, report),
        Expr::Call(c) => {
            fold_expr_in_place(&mut c.func, scope, report);
            for arg in &mut c.arguments.args {
                fold_expr_in_place(arg, scope, report);
            }
            for kw in &mut c.arguments.keywords {
                fold_expr_in_place(&mut kw.value, scope, report);
            }
        }
        Expr::Subscript(s) => {
            fold_expr_in_place(&mut s.value, scope, report);
            fold_expr_in_place(&mut s.slice, scope, report);
        }
        Expr::Compare(c) => {
            fold_expr_in_place(&mut c.left, scope, report);
            for cmp in &mut c.comparators {
                fold_expr_in_place(cmp, scope, report);
            }
        }
        Expr::BoolOp(b) => {
            for child in &mut b.values {
                fold_expr_in_place(child, scope, report);
            }
        }
        Expr::Attribute(a) => fold_expr_in_place(&mut a.value, scope, report),
        Expr::If(i) => {
            fold_expr_in_place(&mut i.test, scope, report);
            fold_expr_in_place(&mut i.body, scope, report);
            fold_expr_in_place(&mut i.orelse, scope, report);
        }
        Expr::List(ExprList { elts, .. }) | Expr::Tuple(ExprTuple { elts, .. }) => {
            for e in elts {
                fold_expr_in_place(e, scope, report);
            }
        }
        Expr::Slice(s) => {
            if let Some(v) = s.lower.as_mut() {
                fold_expr_in_place(v, scope, report);
            }
            if let Some(v) = s.upper.as_mut() {
                fold_expr_in_place(v, scope, report);
            }
            if let Some(v) = s.step.as_mut() {
                fold_expr_in_place(v, scope, report);
            }
        }
        _ => {}
    }
}

fn value_is_simple(v: &Value) -> bool {
    match v {
        Value::None | Value::Bool(_) | Value::Int(_) | Value::Str(_) | Value::Bytes(_) => true,
        Value::List(items) | Value::Tuple(items) => {
            items.len() <= 32 && items.iter().all(value_is_simple)
        }
        Value::Dict(_) => false,
    }
}

const fn expr_is_already_literal(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::NumberLiteral(_)
            | Expr::StringLiteral(_)
            | Expr::BytesLiteral(_)
            | Expr::BooleanLiteral(_)
            | Expr::NoneLiteral(_)
    )
}

fn range_of(expr: &Expr) -> TextRange {
    match expr {
        Expr::BinOp(b) => b.range,
        Expr::UnaryOp(u) => u.range,
        Expr::Call(c) => c.range,
        Expr::Subscript(s) => s.range,
        Expr::Compare(c) => c.range,
        Expr::BoolOp(b) => b.range,
        Expr::Attribute(a) => a.range,
        Expr::If(i) => i.range,
        Expr::List(l) => l.range,
        Expr::Tuple(t) => t.range,
        Expr::Name(n) => n.range,
        Expr::NumberLiteral(n) => n.range,
        Expr::StringLiteral(s) => s.range,
        Expr::BytesLiteral(b) => b.range,
        Expr::BooleanLiteral(b) => b.range,
        Expr::NoneLiteral(n) => n.range,
        _ => TextRange::default(),
    }
}

pub(crate) fn value_to_expr(value: Value, range: TextRange) -> Option<Expr> {
    match value {
        Value::None => Some(Expr::NoneLiteral(ExprNoneLiteral {
            range,
            node_index: AtomicNodeIndex::default(),
        })),
        Value::Bool(b) => Some(Expr::BooleanLiteral(ExprBooleanLiteral {
            range,
            node_index: AtomicNodeIndex::default(),
            value: b,
        })),
        Value::Int(n) => Some(int_to_expr(n, range)),
        Value::Str(s) => Some(Expr::StringLiteral(ExprStringLiteral {
            range,
            node_index: AtomicNodeIndex::default(),
            value: StringLiteralValue::single(StringLiteral {
                range,
                node_index: AtomicNodeIndex::default(),
                value: s.into_boxed_str(),
                flags: StringLiteralFlags::empty(),
            }),
        })),
        Value::Bytes(b) => Some(Expr::BytesLiteral(ExprBytesLiteral {
            range,
            node_index: AtomicNodeIndex::default(),
            value: BytesLiteralValue::single(BytesLiteral {
                range,
                node_index: AtomicNodeIndex::default(),
                value: b.into_boxed_slice(),
                flags: BytesLiteralFlags::empty(),
            }),
        })),
        Value::List(items) => {
            let mut elts: Vec<Expr> = Vec::with_capacity(items.len());
            for v in items {
                elts.push(value_to_expr(v, range)?);
            }
            Some(Expr::List(ExprList {
                range,
                node_index: AtomicNodeIndex::default(),
                elts,
                ctx: ruff_python_ast::ExprContext::Load,
            }))
        }
        Value::Tuple(items) => {
            let mut elts: Vec<Expr> = Vec::with_capacity(items.len());
            for v in items {
                elts.push(value_to_expr(v, range)?);
            }
            Some(Expr::Tuple(ExprTuple {
                range,
                node_index: AtomicNodeIndex::default(),
                elts,
                ctx: ruff_python_ast::ExprContext::Load,
                parenthesized: true,
            }))
        }
        Value::Dict(_) => None,
    }
}

fn int_to_expr(n: i128, range: TextRange) -> Expr {
    let abs: u128 = n.unsigned_abs();
    let int_value: Int = u64::try_from(abs).map_or_else(
        |_| Int::from_str(&abs.to_string()).unwrap_or(Int::ZERO),
        Int::from,
    );
    let int_expr: Expr = Expr::NumberLiteral(ExprNumberLiteral {
        range,
        node_index: AtomicNodeIndex::default(),
        value: Number::Int(int_value),
    });
    if n >= 0 {
        int_expr
    } else {
        Expr::UnaryOp(ExprUnaryOp {
            range,
            node_index: AtomicNodeIndex::default(),
            op: UnaryOp::USub,
            operand: Box::new(int_expr),
        })
    }
}
