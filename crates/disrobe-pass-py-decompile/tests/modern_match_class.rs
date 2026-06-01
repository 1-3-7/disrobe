#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod common;

use disrobe_pass_py_decompile::ast::{Expr, ExprCtx, MatchCase, Pattern, Stmt};
use disrobe_pass_py_decompile::codegen::match_emit::emit_match;

use crate::common::{int, name, name_store, ver};

#[test]
fn match_class_pattern_with_kwd_attr() {
    let radius_capture: Pattern = Pattern::MatchAs {
        pattern: None,
        name: Some("r".to_owned()),
    };
    let class_pat: Pattern = Pattern::MatchClass {
        cls: name("Circle"),
        patterns: Vec::new(),
        kwd_attrs: vec!["radius".to_owned()],
        kwd_patterns: vec![radius_capture],
    };
    let cases: Vec<MatchCase> = vec![MatchCase {
        pattern: class_pat,
        guard: None,
        body: vec![Stmt::Expr(name("r"))],
    }];
    let out: String = emit_match(&name("shape"), &cases, 0, &ver(3, 12));
    assert!(out.contains("case Circle(radius=r):"), "got: {out}");
}

#[test]
fn match_class_pattern_positional() {
    let cls_pat: Pattern = Pattern::MatchClass {
        cls: name("Point"),
        patterns: vec![
            Pattern::MatchAs {
                pattern: None,
                name: Some("x".to_owned()),
            },
            Pattern::MatchAs {
                pattern: None,
                name: Some("y".to_owned()),
            },
        ],
        kwd_attrs: Vec::new(),
        kwd_patterns: Vec::new(),
    };
    let cases: Vec<MatchCase> = vec![MatchCase {
        pattern: cls_pat,
        guard: None,
        body: vec![Stmt::Assign {
            targets: vec![name_store("z")],
            value: Expr::BinOp {
                left: Box::new(name("x")),
                op: disrobe_pass_py_decompile::bytecode::opcode::BinOp::Add,
                right: Box::new(name("y")),
            },
            type_comment: None,
            line: None,
        }],
    }];
    let _: ExprCtx = ExprCtx::Load;
    let _ = int(0);
    let out: String = emit_match(&name("p"), &cases, 0, &ver(3, 11));
    assert!(out.contains("case Point(x, y):"), "got: {out}");
    assert!(out.contains("z = x + y"), "got: {out}");
}
