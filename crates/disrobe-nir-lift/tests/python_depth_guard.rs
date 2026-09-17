#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeMap;

use disrobe_nir::NirModule;
use disrobe_nir_lift::lift_python;
use disrobe_pass_py_decompile::ast::node::{BinOpKind, ConstValue};
use disrobe_pass_py_decompile::ast::{AstModule, Expr, Stmt};

const fn int_const(value: i128) -> Expr {
    Expr::Constant {
        value: ConstValue::Int(value),
        line: None,
    }
}

fn nested_binop(depth: usize) -> Expr {
    let mut expr: Expr = int_const(0);
    for _ in 0..depth {
        expr = Expr::BinOp {
            left: Box::new(expr),
            op: BinOpKind::Add,
            right: Box::new(int_const(1)),
        };
    }
    expr
}

const fn module_with(body: Vec<Stmt>) -> AstModule {
    AstModule {
        docstring: None,
        body,
        blank_lines: BTreeMap::new(),
    }
}

#[test]
fn pathologically_deep_expression_returns_bounded_error() {
    let module: AstModule = module_with(vec![Stmt::Expr(nested_binop(5_000))]);
    let result: disrobe_nir_lift::Result<NirModule> = lift_python(&module);
    assert!(
        matches!(
            result,
            Err(disrobe_nir_lift::LiftError::DepthExceeded { limit: 512 })
        ),
        "a 5k-deep binop nest must abort with a bounded DepthExceeded, got {result:?}"
    );
}

#[test]
fn shallow_valid_expression_still_lifts() {
    let module: AstModule = module_with(vec![Stmt::Expr(nested_binop(8))]);
    let nir: NirModule = lift_python(&module).expect("a shallow binop nest lifts cleanly");
    let module_fn: &disrobe_nir::NirFunction = nir
        .functions
        .iter()
        .find(|f: &&disrobe_nir::NirFunction| f.name == "<module>")
        .expect("the module scope must be lifted");
    assert!(
        module_fn
            .instructions
            .iter()
            .any(|i: &disrobe_nir::NirInstr| matches!(i.op, disrobe_nir::NirOp::BinOp { .. })),
        "the add chain must emit BinOp instructions"
    );
}

#[test]
fn just_below_limit_lifts_and_just_above_aborts() {
    let under: AstModule = module_with(vec![Stmt::Expr(nested_binop(500))]);
    assert!(
        lift_python(&under).is_ok(),
        "a 500-deep nest stays under the 512 cap and lifts"
    );

    let over: AstModule = module_with(vec![Stmt::Expr(nested_binop(1_000))]);
    assert!(
        matches!(
            lift_python(&over),
            Err(disrobe_nir_lift::LiftError::DepthExceeded { limit: 512 })
        ),
        "a 1000-deep nest exceeds the 512 cap"
    );
}

#[test]
fn shallow_wide_ast_returns_bounded_error() {
    let body: Vec<Stmt> = (0..131_073).map(|_| Stmt::Expr(int_const(0))).collect();
    let module: AstModule = module_with(body);
    let result: disrobe_nir_lift::Result<NirModule> = lift_python(&module);
    assert!(
        matches!(
            result,
            Err(disrobe_nir_lift::LiftError::AstSizeExceeded { limit: 262_144 })
        ),
        "a shallow AST above the node cap must abort before emission, got {result:?}"
    );
}
