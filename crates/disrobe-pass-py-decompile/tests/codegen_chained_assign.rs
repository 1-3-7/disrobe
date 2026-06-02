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
fn chained_assignment_emits_targets_in_source_order() {
    let s: Stmt = Stmt::Assign {
        targets: vec![name_store("a"), name_store("b"), name_store("c")],
        value: Expr::Constant {
            value: ConstValue::Int(42),
            line: None,
        },
        type_comment: None,
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_stmt(&s, 0, &v);
    assert_eq!(out, "a = b = c = 42");
    let a_pos: usize = out.find('a').unwrap();
    let b_pos: usize = out.find('b').unwrap();
    let c_pos: usize = out.find('c').unwrap();
    assert!(
        a_pos < b_pos && b_pos < c_pos,
        "chained-assign target order must be source order"
    );
}

#[test]
fn single_target_assign() {
    let s: Stmt = Stmt::Assign {
        targets: vec![name_store("x")],
        value: Expr::Constant {
            value: ConstValue::Int(1),
            line: None,
        },
        type_comment: None,
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_stmt(&s, 0, &v);
    assert_eq!(out, "x = 1");
}

fn name_store(id: &str) -> Expr {
    Expr::Name {
        id: id.to_owned(),
        ctx: ExprCtx::Store,
        line: None,
    }
}
