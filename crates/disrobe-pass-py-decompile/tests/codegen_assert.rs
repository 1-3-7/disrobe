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
fn assert_without_message_emits_just_test() {
    let s: Stmt = Stmt::Assert {
        test: name("x"),
        msg: None,
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_stmt(&s, 0, &v);
    assert_eq!(out, "assert x");
    assert!(!out.contains("pass"), "assert MUST NOT degrade to pass");
}

#[test]
fn assert_with_message_keeps_both_parts() {
    let s: Stmt = Stmt::Assert {
        test: name("x"),
        msg: Some(Expr::Constant {
            value: ConstValue::Str("bang".to_owned()),
            line: None,
        }),
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_stmt(&s, 0, &v);
    assert_eq!(out, "assert x, \"bang\"");
    assert!(out.contains("bang"), "assert message MUST NOT be dropped");
}

#[test]
fn assert_with_expression_test() {
    let s: Stmt = Stmt::Assert {
        test: Expr::Compare {
            left: Box::new(name("a")),
            ops: vec![disrobe_pass_py_decompile::bytecode::opcode::CmpOp::Eq],
            comparators: vec![Expr::Constant {
                value: ConstValue::Int(1),
                line: None,
            }],
        },
        msg: None,
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_stmt(&s, 0, &v);
    assert_eq!(out, "assert a == 1");
}

fn name(id: &str) -> Expr {
    Expr::Name {
        id: id.to_owned(),
        ctx: ExprCtx::Load,
        line: None,
    }
}
