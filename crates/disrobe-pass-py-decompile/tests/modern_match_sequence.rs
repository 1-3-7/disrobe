#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod common;

use disrobe_pass_py_decompile::ast::{MatchCase, Pattern, Stmt};
use disrobe_pass_py_decompile::codegen::match_emit::emit_match;

use crate::common::{name, ver};

#[test]
fn match_sequence_with_star_rest() {
    let pat: Pattern = Pattern::MatchSequence(vec![
        Pattern::MatchAs {
            pattern: None,
            name: Some("first".to_owned()),
        },
        Pattern::MatchStar(Some("rest".to_owned())),
    ]);
    let cases: Vec<MatchCase> = vec![MatchCase {
        pattern: pat,
        guard: None,
        body: vec![Stmt::Pass],
    }];
    let out: String = emit_match(&name("xs"), &cases, 0, &ver(3, 12));
    assert!(out.contains("case [first, *rest]:"), "got: {out}");
}

#[test]
fn match_sequence_empty_star() {
    let pat: Pattern = Pattern::MatchSequence(vec![Pattern::MatchStar(None)]);
    let cases: Vec<MatchCase> = vec![MatchCase {
        pattern: pat,
        guard: None,
        body: vec![Stmt::Pass],
    }];
    let out: String = emit_match(&name("xs"), &cases, 0, &ver(3, 10));
    assert!(out.contains("case [*_]:"), "got: {out}");
}
