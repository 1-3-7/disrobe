#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_const_for_fn
)]

use disrobe_pass_py_decompile::ast::{ConstValue, Expr, ExprCtx};
use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::codegen::{CodeEmitter, DefaultEmitter};

#[test]
fn ternary_as_call_argument_emits_inline_if_else() {
    let if_exp: Expr = Expr::IfExp {
        test: Box::new(Expr::Name {
            id: "c".to_owned(),
            ctx: ExprCtx::Load,
            line: None,
        }),
        body: Box::new(Expr::Name {
            id: "a".to_owned(),
            ctx: ExprCtx::Load,
            line: None,
        }),
        orelse: Box::new(Expr::Name {
            id: "b".to_owned(),
            ctx: ExprCtx::Load,
            line: None,
        }),
    };
    let call: Expr = Expr::Call {
        func: Box::new(Expr::Name {
            id: "f".to_owned(),
            ctx: ExprCtx::Load,
            line: None,
        }),
        args: vec![if_exp],
        keywords: Vec::new(),
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_expr(&call, &v);
    assert_eq!(out, "f(a if c else b)");
    assert!(
        !out.contains("if c:"),
        "ternary must not expand into if-statement form"
    );
}

#[test]
fn standalone_ternary_assignment() {
    let e: Expr = Expr::IfExp {
        test: Box::new(Expr::Name {
            id: "ok".to_owned(),
            ctx: ExprCtx::Load,
            line: None,
        }),
        body: Box::new(Expr::Constant {
            value: ConstValue::Int(1),
            line: None,
        }),
        orelse: Box::new(Expr::Constant {
            value: ConstValue::Int(0),
            line: None,
        }),
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_expr(&e, &v);
    assert_eq!(out, "1 if ok else 0");
}
