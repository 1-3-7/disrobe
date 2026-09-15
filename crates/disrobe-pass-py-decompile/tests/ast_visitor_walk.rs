#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_const_for_fn,
    clippy::items_after_statements
)]

use disrobe_pass_py_decompile::ast::{
    Arguments, AstModule, ConstValue, Expr, ExprCtx, Stmt, Visitor, VisitorMut,
};
use disrobe_pass_py_decompile::bytecode::opcode::BinOp;

#[derive(Debug, Default)]
struct NodeCounter {
    stmts: usize,
    exprs: usize,
}

impl Visitor for NodeCounter {
    fn visit_stmt(&mut self, stmt: &Stmt) {
        self.stmts += 1;
        disrobe_pass_py_decompile::ast::visitor::walk_stmt(self, stmt);
    }
    fn visit_expr(&mut self, expr: &Expr) {
        self.exprs += 1;
        disrobe_pass_py_decompile::ast::visitor::walk_expr(self, expr);
    }
}

#[test]
fn visitor_counts_function_body_nodes() {
    let module: AstModule = AstModule {
        docstring: None,
        body: vec![Stmt::FunctionDef {
            name: "f".to_owned(),
            type_params: Vec::new(),
            args: Arguments::default(),
            body: vec![
                Stmt::Assign {
                    targets: vec![name_expr("x", ExprCtx::Store)],
                    value: int_expr(1),
                    type_comment: None,
                    line: None,
                },
                Stmt::Return(Some(Expr::BinOp {
                    left: Box::new(name_expr("x", ExprCtx::Load)),
                    op: BinOp::Add,
                    right: Box::new(int_expr(2)),
                })),
            ],
            decorators: Vec::new(),
            returns: None,
            is_async: false,
            docstring: None,
            line: Some(1),
        }],
        blank_lines: std::collections::BTreeMap::new(),
    };
    let mut counter: NodeCounter = NodeCounter::default();
    counter.visit_module(&module);
    assert_eq!(counter.stmts, 3, "FunctionDef + Assign + Return");
    assert_eq!(
        counter.exprs, 5,
        "Assign-target, Assign-value, BinOp-root, BinOp-left, BinOp-right"
    );
}

#[test]
fn visitor_walks_nested_if_else() {
    let module: AstModule = AstModule {
        docstring: None,
        body: vec![Stmt::If {
            test: bool_expr(true),
            body: vec![Stmt::Pass],
            orelse: vec![Stmt::If {
                test: bool_expr(false),
                body: vec![Stmt::Pass],
                orelse: Vec::new(),
                line: None,
            }],
            line: None,
        }],
        blank_lines: std::collections::BTreeMap::new(),
    };
    let mut counter: NodeCounter = NodeCounter::default();
    counter.visit_module(&module);
    assert_eq!(counter.stmts, 4, "If + Pass + If + Pass");
    assert_eq!(counter.exprs, 2, "both test exprs");
}

#[derive(Debug, Default)]
struct IntDoubler;

impl VisitorMut for IntDoubler {
    fn visit_expr_mut(&mut self, expr: &mut Expr) {
        if let Expr::Constant {
            value: ConstValue::Int(i),
            ..
        } = expr
        {
            *i *= 2;
        }
        disrobe_pass_py_decompile::ast::visitor::walk_expr_mut(self, expr);
    }
}

#[test]
fn visitor_mut_can_transform_constants() {
    let mut module: AstModule = AstModule {
        docstring: None,
        body: vec![Stmt::Expr(Expr::BinOp {
            left: Box::new(int_expr(3)),
            op: BinOp::Add,
            right: Box::new(int_expr(4)),
        })],
        blank_lines: std::collections::BTreeMap::new(),
    };
    let mut tr: IntDoubler = IntDoubler;
    tr.visit_module_mut(&mut module);
    let Stmt::Expr(Expr::BinOp { left, right, .. }) = &module.body[0] else {
        panic!("expected BinOp");
    };
    let Expr::Constant {
        value: ConstValue::Int(l),
        ..
    } = left.as_ref()
    else {
        panic!("expected int on left");
    };
    let Expr::Constant {
        value: ConstValue::Int(r),
        ..
    } = right.as_ref()
    else {
        panic!("expected int on right");
    };
    assert_eq!(*l, 6);
    assert_eq!(*r, 8);
}

fn int_expr(v: i128) -> Expr {
    Expr::Constant {
        value: ConstValue::Int(v),
        line: None,
    }
}

fn name_expr(id: &str, ctx: ExprCtx) -> Expr {
    Expr::Name {
        id: id.to_owned(),
        ctx,
        line: None,
    }
}

fn bool_expr(v: bool) -> Expr {
    Expr::Constant {
        value: if v {
            ConstValue::True
        } else {
            ConstValue::False
        },
        line: None,
    }
}
