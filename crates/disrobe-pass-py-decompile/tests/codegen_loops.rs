#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_const_for_fn
)]

use disrobe_pass_py_decompile::ast::{ConstValue, Expr, ExprCtx, Stmt};
use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::codegen::{CodeEmitter, DefaultEmitter};

#[test]
fn for_with_else_clause() {
    let s: Stmt = Stmt::For {
        target: name("i", ExprCtx::Store),
        iter: name("xs", ExprCtx::Load),
        body: vec![Stmt::Continue],
        orelse: vec![Stmt::Pass],
        is_async: false,
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_stmt(&s, 0, &v);
    assert_eq!(out, "for i in xs:\n    continue\nelse:\n    pass");
}

#[test]
fn while_break_continue() {
    let s: Stmt = Stmt::While {
        test: Expr::Constant {
            value: ConstValue::True,
            line: None,
        },
        body: vec![Stmt::Break, Stmt::Continue],
        orelse: Vec::new(),
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_stmt(&s, 0, &v);
    assert_eq!(out, "while True:\n    break\n    continue");
}

#[test]
fn while_with_else_clause() {
    let s: Stmt = Stmt::While {
        test: Expr::Constant {
            value: ConstValue::True,
            line: None,
        },
        body: vec![Stmt::Pass],
        orelse: vec![Stmt::Pass],
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_stmt(&s, 0, &v);
    assert_eq!(out, "while True:\n    pass\nelse:\n    pass");
}

#[test]
fn async_for_emits_async_keyword() {
    let s: Stmt = Stmt::For {
        target: name("i", ExprCtx::Store),
        iter: name("xs", ExprCtx::Load),
        body: vec![Stmt::Pass],
        orelse: Vec::new(),
        is_async: true,
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_stmt(&s, 0, &v);
    assert!(out.starts_with("async for i in xs:"));
}

fn name(id: &str, ctx: ExprCtx) -> Expr {
    Expr::Name {
        id: id.to_owned(),
        ctx,
        line: None,
    }
}
