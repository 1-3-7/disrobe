#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use disrobe_pass_py_decompile::ast::Expr;
use disrobe_pass_py_decompile::bytecode::opcode::CmpOp;
use disrobe_pass_py_decompile::codegen::modern::emit_modern_expr;
use disrobe_pass_py_decompile::codegen::walrus_emit::{emit_walrus, supports_walrus};

use crate::common::{int, name, name_store, ver};

#[test]
fn walrus_simple_assignment() {
    let target: Expr = name_store("n");
    let value: Expr = Expr::Call {
        func: Box::new(name("f")),
        args: Vec::new(),
        keywords: Vec::new(),
    };
    let out: String = emit_walrus(&target, &value, &ver(3, 12));
    assert_eq!(out, "(n := f())");
}

#[test]
fn walrus_dispatched_via_modern_expr() {
    let target: Expr = name_store("y");
    let value: Expr = int(5);
    let expr: Expr = Expr::NamedExpr {
        target: Box::new(target),
        value: Box::new(value),
    };
    let out: Option<String> = emit_modern_expr(&expr, &ver(3, 11));
    assert_eq!(out.as_deref(), Some("(y := 5)"));
}

#[test]
fn walrus_in_membership_test() {
    let walrus: Expr = Expr::NamedExpr {
        target: Box::new(name_store("v")),
        value: Box::new(int(3)),
    };
    let cmp: Expr = Expr::Compare {
        left: Box::new(walrus),
        ops: vec![CmpOp::In],
        comparators: vec![name("xs")],
    };
    let out: String =
        disrobe_pass_py_decompile::codegen::modern_expr_render::render_expr(&cmp, &ver(3, 12));
    assert!(out.contains("(v := 3) in xs"), "got: {out}");
}

#[test]
fn walrus_version_gate() {
    assert!(supports_walrus(&ver(3, 8)));
    assert!(supports_walrus(&ver(3, 12)));
}
