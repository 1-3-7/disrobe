#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use disrobe_pass_py_decompile::ast::{Expr, MatchCase, Pattern, Stmt};
use disrobe_pass_py_decompile::bytecode::opcode::CmpOp;
use disrobe_pass_py_decompile::codegen::match_emit::emit_match;

use crate::common::{int, name, ver};

#[test]
fn match_or_pattern_with_guard() {
    let pat: Pattern = Pattern::MatchOr(vec![
        Pattern::MatchValue(name("A")),
        Pattern::MatchValue(name("B")),
    ]);
    let guard: Expr = Expr::Compare {
        left: Box::new(name("flag")),
        ops: vec![CmpOp::Gt],
        comparators: vec![int(0)],
    };
    let cases: Vec<MatchCase> = vec![MatchCase {
        pattern: pat,
        guard: Some(guard),
        body: vec![Stmt::Pass],
    }];
    let out: String = emit_match(&name("kind"), &cases, 0, &ver(3, 11));
    assert!(out.contains("case A | B if flag > 0:"), "got: {out}");
}
