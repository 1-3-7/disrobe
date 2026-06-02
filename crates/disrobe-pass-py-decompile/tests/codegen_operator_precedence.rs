#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_const_for_fn
)]

use disrobe_pass_py_decompile::ast::{ConstValue, Expr, ExprCtx};
use disrobe_pass_py_decompile::bytecode::opcode::{BinOp, UnaryOp};
use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::codegen::{CodeEmitter, DefaultEmitter};

#[test]
fn add_then_mul_no_paren_on_natural_precedence() {
    let e: Expr = Expr::BinOp {
        left: Box::new(int_expr(1)),
        op: BinOp::Add,
        right: Box::new(Expr::BinOp {
            left: Box::new(int_expr(2)),
            op: BinOp::Mul,
            right: Box::new(int_expr(3)),
        }),
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_expr(&e, &v);
    assert_eq!(out, "1 + 2 * 3");
}

#[test]
fn paren_inserted_around_add_when_outer_is_mul() {
    let inner: Expr = Expr::BinOp {
        left: Box::new(int_expr(1)),
        op: BinOp::Add,
        right: Box::new(int_expr(2)),
    };
    let e: Expr = Expr::BinOp {
        left: Box::new(inner),
        op: BinOp::Mul,
        right: Box::new(int_expr(3)),
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_expr(&e, &v);
    assert_eq!(out, "(1 + 2) * 3");
}

#[test]
fn pow_is_right_associative() {
    let inner: Expr = Expr::BinOp {
        left: Box::new(int_expr(2)),
        op: BinOp::Pow,
        right: Box::new(int_expr(3)),
    };
    let e: Expr = Expr::BinOp {
        left: Box::new(int_expr(4)),
        op: BinOp::Pow,
        right: Box::new(inner),
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_expr(&e, &v);
    assert_eq!(out, "4 ** 2 ** 3");
}

#[test]
fn unary_negation_binds_tighter_than_add() {
    let e: Expr = Expr::BinOp {
        left: Box::new(Expr::UnaryOp {
            op: UnaryOp::Negative,
            operand: Box::new(int_expr(1)),
        }),
        op: BinOp::Add,
        right: Box::new(int_expr(2)),
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_expr(&e, &v);
    assert_eq!(out, "-1 + 2");
}

#[test]
fn compare_with_logical_and() {
    let lt: Expr = Expr::Compare {
        left: Box::new(name("a")),
        ops: vec![disrobe_pass_py_decompile::bytecode::opcode::CmpOp::Lt],
        comparators: vec![name("b")],
    };
    let gt: Expr = Expr::Compare {
        left: Box::new(name("b")),
        ops: vec![disrobe_pass_py_decompile::bytecode::opcode::CmpOp::Lt],
        comparators: vec![name("c")],
    };
    let e: Expr = Expr::BoolOp {
        op: disrobe_pass_py_decompile::ast::BoolOpKind::And,
        values: vec![lt, gt],
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_expr(&e, &v);
    assert_eq!(out, "a < b and b < c");
}

fn int_expr(v: i128) -> Expr {
    Expr::Constant {
        value: ConstValue::Int(v),
        line: None,
    }
}

fn name(id: &str) -> Expr {
    Expr::Name {
        id: id.to_owned(),
        ctx: ExprCtx::Load,
        line: None,
    }
}
