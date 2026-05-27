#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod common;

use disrobe_pass_py_decompile::ast::{MatchCase, Pattern, Stmt};
use disrobe_pass_py_decompile::codegen::match_emit::emit_match;

use crate::common::{name, str_lit, ver};

#[test]
fn match_literal_string() {
    let cases: Vec<MatchCase> = vec![
        MatchCase {
            pattern: Pattern::MatchValue(str_lit("start")),
            guard: None,
            body: vec![Stmt::Pass],
        },
        MatchCase {
            pattern: Pattern::MatchAs {
                pattern: None,
                name: None,
            },
            guard: None,
            body: vec![Stmt::Pass],
        },
    ];
    let out: String = emit_match(&name("x"), &cases, 0, &ver(3, 12));
    assert!(out.starts_with("match x:"), "got: {out}");
    assert!(out.contains("case \"start\":"), "got: {out}");
    assert!(out.contains("case _:"), "got: {out}");
    assert!(out.contains("pass"), "got: {out}");
}
