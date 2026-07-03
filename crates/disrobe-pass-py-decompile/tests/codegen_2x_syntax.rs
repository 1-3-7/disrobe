#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_const_for_fn
)]

use disrobe_pass_py_decompile::ast::{BigUint, ConstValue, Expr, ExprCtx, Stmt};
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

#[test]
fn py2_marshal_long_const_renders_l_suffix() {
    let long_const: Expr = Expr::Constant {
        value: ConstValue::BigInt(BigUint {
            sign: 1,
            digits: vec![5],
        }),
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v2: PyVersion = PyVersion::V2_7;
    assert_eq!(
        em.emit_expr(&long_const, &v2),
        "5L",
        "py2 TYPE_LONG const must recover the long spelling"
    );
    let small_int: Expr = Expr::Constant {
        value: ConstValue::Int(5),
        line: None,
    };
    assert_eq!(
        em.emit_expr(&small_int, &v2),
        "5",
        "py2 TYPE_INT const must stay a plain int, no L"
    );
}

#[test]
fn py3_bigint_const_never_renders_l_suffix() {
    let big_const: Expr = Expr::Constant {
        value: ConstValue::BigInt(BigUint {
            sign: 1,
            digits: vec![0, 0, 0, 0, 0, 0, 0, 8],
        }),
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v3: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_expr(&big_const, &v3);
    assert!(
        !out.ends_with('L'),
        "py3 has no long type; a big int must never carry L, got {out:?}"
    );
}

#[test]
fn py2_unicode_const_renders_u_prefix() {
    let uni: Expr = Expr::Constant {
        value: ConstValue::Unicode("x".to_owned()),
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v2: PyVersion = PyVersion::V2_7;
    let out: String = em.emit_expr(&uni, &v2);
    assert!(
        out.starts_with('u'),
        "py2 TYPE_UNICODE const must recover the u prefix, got {out:?}"
    );
    assert!(out.contains('x'));
    let plain: Expr = Expr::Constant {
        value: ConstValue::Str("x".to_owned()),
        line: None,
    };
    let plain_out: String = em.emit_expr(&plain, &v2);
    assert!(
        !plain_out.starts_with('u'),
        "py2 TYPE_STRING const must stay a byte str, no u prefix, got {plain_out:?}"
    );
}

#[test]
fn py3_str_const_never_renders_u_prefix() {
    let uni: Expr = Expr::Constant {
        value: ConstValue::Unicode("x".to_owned()),
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v3: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_expr(&uni, &v3);
    assert_eq!(
        out, "\"x\"",
        "py3 str is unicode by default; no u prefix, got {out:?}"
    );
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
