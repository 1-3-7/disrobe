#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_const_for_fn
)]

use disrobe_pass_py_decompile::ast::{Arguments, Expr, ExprCtx, Stmt};
use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::codegen::{CodeEmitter, DefaultEmitter};

#[test]
fn yield_from_emits_keyword_spelling() {
    let e: Expr = Expr::YieldFrom(Box::new(Expr::Name {
        id: "g".to_owned(),
        ctx: ExprCtx::Load,
        line: None,
    }));
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_expr(&e, &v);
    assert!(out.contains("yield from g"));
}

#[test]
fn generator_function_with_yield_from_preserves_keyword() {
    let body: Stmt = Stmt::Expr(Expr::YieldFrom(Box::new(Expr::Name {
        id: "source".to_owned(),
        ctx: ExprCtx::Load,
        line: None,
    })));
    let fdef: Stmt = Stmt::FunctionDef {
        name: "delegating".to_owned(),
        type_params: Vec::new(),
        args: Arguments::default(),
        body: vec![body],
        decorators: Vec::new(),
        returns: None,
        is_async: false,
        docstring: None,
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_stmt(&fdef, 0, &v);
    assert!(
        out.contains("yield from source"),
        "must emit `yield from`, not drop or alias"
    );
}

#[test]
fn plain_yield_emits_yield_keyword() {
    let e: Expr = Expr::Yield(Some(Box::new(Expr::Name {
        id: "v".to_owned(),
        ctx: ExprCtx::Load,
        line: None,
    })));
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_expr(&e, &v);
    assert!(out.contains("yield v"));
    assert!(!out.contains("yield from"), "plain yield is not yield-from");
}
