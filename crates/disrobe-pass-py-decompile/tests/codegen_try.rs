#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_const_for_fn
)]

use disrobe_pass_py_decompile::ast::{ExceptHandler, Expr, ExprCtx, Stmt};
use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::codegen::{CodeEmitter, DefaultEmitter};

#[test]
fn try_except_else_finally_all_combined() {
    let s: Stmt = Stmt::Try {
        body: vec![Stmt::Pass],
        handlers: vec![ExceptHandler {
            typ: Some(name("ValueError")),
            name: Some("e".to_owned()),
            body: vec![Stmt::Pass],
            line: None,
        }],
        orelse: vec![Stmt::Pass],
        finalbody: vec![Stmt::Pass],
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_stmt(&s, 0, &v);
    assert_eq!(
        out,
        "try:\n    pass\nexcept ValueError as e:\n    pass\nelse:\n    pass\nfinally:\n    pass"
    );
}

#[test]
fn nested_try_finally_emits_both_finally_keywords() {
    let inner: Stmt = Stmt::Try {
        body: vec![Stmt::Pass],
        handlers: Vec::new(),
        orelse: Vec::new(),
        finalbody: vec![Stmt::Pass],
        line: None,
    };
    let outer: Stmt = Stmt::Try {
        body: vec![inner],
        handlers: Vec::new(),
        orelse: Vec::new(),
        finalbody: vec![Stmt::Pass],
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_stmt(&outer, 0, &v);
    assert_eq!(out.matches("finally:").count(), 2);
    assert!(out.contains("try:\n    try:"));
}

#[test]
fn finally_block_with_return_emits_finally_kw() {
    let s: Stmt = Stmt::Try {
        body: vec![Stmt::Pass],
        handlers: Vec::new(),
        orelse: Vec::new(),
        finalbody: vec![Stmt::Return(Some(Expr::Constant {
            value: disrobe_pass_py_decompile::ast::ConstValue::Int(1),
            line: None,
        }))],
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_stmt(&s, 0, &v);
    assert!(out.contains("finally:\n    return 1"));
}

#[test]
fn bare_except_emits_no_type() {
    let s: Stmt = Stmt::Try {
        body: vec![Stmt::Pass],
        handlers: vec![ExceptHandler {
            typ: None,
            name: None,
            body: vec![Stmt::Pass],
            line: None,
        }],
        orelse: Vec::new(),
        finalbody: Vec::new(),
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_stmt(&s, 0, &v);
    assert_eq!(out, "try:\n    pass\nexcept:\n    pass");
}

#[test]
fn multiple_except_handlers() {
    let s: Stmt = Stmt::Try {
        body: vec![Stmt::Pass],
        handlers: vec![
            ExceptHandler {
                typ: Some(name("KeyError")),
                name: None,
                body: vec![Stmt::Pass],
                line: None,
            },
            ExceptHandler {
                typ: Some(name("ValueError")),
                name: None,
                body: vec![Stmt::Pass],
                line: None,
            },
        ],
        orelse: Vec::new(),
        finalbody: Vec::new(),
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_stmt(&s, 0, &v);
    assert!(out.contains("except KeyError:"));
    assert!(out.contains("except ValueError:"));
}

fn name(id: &str) -> Expr {
    Expr::Name {
        id: id.to_owned(),
        ctx: ExprCtx::Load,
        line: None,
    }
}
