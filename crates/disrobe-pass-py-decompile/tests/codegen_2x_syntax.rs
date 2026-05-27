#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_const_for_fn
)]

use disrobe_pass_py_decompile::ast::{ConstValue, Expr, ExprCtx, Stmt};
use disrobe_pass_py_decompile::bytecode::opcode::CmpOp;
use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::codegen::{CodeEmitter, DefaultEmitter};

#[test]
fn py2_print_is_statement_form() {
    let call: Expr = Expr::Call {
        func: Box::new(name("print")),
        args: vec![str_expr("hi")],
        keywords: Vec::new(),
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V2_7;
    let out: String = em.emit_expr(&call, &v);
    assert!(
        out.starts_with("print "),
        "py2 print is a statement; got {out:?}"
    );
    assert!(!out.contains("print("), "py2 print MUST NOT use parens");
}

#[test]
fn py3_print_is_call_form() {
    let call: Expr = Expr::Call {
        func: Box::new(name("print")),
        args: vec![str_expr("hi")],
        keywords: Vec::new(),
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_expr(&call, &v);
    assert_eq!(out, "print(\"hi\")");
}

#[test]
fn py2_exec_is_statement_form() {
    let call: Expr = Expr::Call {
        func: Box::new(name("exec")),
        args: vec![str_expr("x = 1")],
        keywords: Vec::new(),
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V2_7;
    let out: String = em.emit_expr(&call, &v);
    assert!(out.starts_with("exec "));
    assert!(!out.contains("exec("));
}

#[test]
fn ne_operator_always_emits_bang_eq() {
    let cmp: Expr = Expr::Compare {
        left: Box::new(Expr::Constant {
            value: ConstValue::Int(1),
            line: None,
        }),
        ops: vec![CmpOp::Ne],
        comparators: vec![Expr::Constant {
            value: ConstValue::Int(2),
            line: None,
        }],
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v3: PyVersion = PyVersion::V3_12;
    assert_eq!(em.emit_expr(&cmp, &v3), "1 != 2");
    let v2: PyVersion = PyVersion::V2_7;
    let py2_out: String = em.emit_expr(&cmp, &v2);
    assert!(
        py2_out.contains("!="),
        "py2 should emit `!=` for canonical compatibility"
    );
}

#[test]
fn py3_does_not_emit_print_as_statement() {
    let call: Expr = Expr::Call {
        func: Box::new(name("print")),
        args: Vec::new(),
        keywords: Vec::new(),
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let s: Stmt = Stmt::Expr(call);
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_stmt(&s, 0, &v);
    assert_eq!(out, "print()");
}

fn name(id: &str) -> Expr {
    Expr::Name {
        id: id.to_owned(),
        ctx: ExprCtx::Load,
        line: None,
    }
}

fn str_expr(s: &str) -> Expr {
    Expr::Constant {
        value: ConstValue::Str(s.to_owned()),
        line: None,
    }
}
