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
fn flat_elif_chain_no_nesting() {
    let three: Stmt = Stmt::If {
        test: name("c"),
        body: vec![Stmt::Pass],
        orelse: vec![Stmt::Pass],
        line: None,
    };
    let two: Stmt = Stmt::If {
        test: name("b"),
        body: vec![Stmt::Pass],
        orelse: vec![three],
        line: None,
    };
    let one: Stmt = Stmt::If {
        test: name("a"),
        body: vec![Stmt::Pass],
        orelse: vec![two],
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_stmt(&one, 0, &v);
    let first_word_if: usize = usize::from(out.starts_with("if "));
    assert_eq!(first_word_if, 1, "leading `if` exactly once");
    assert_eq!(out.matches("\nelif ").count(), 2, "should be two `elif`");
    assert_eq!(
        out.matches("\nelse:").count(),
        1,
        "should be one trailing `else:`"
    );
    assert_eq!(
        out,
        "if a:\n    pass\nelif b:\n    pass\nelif c:\n    pass\nelse:\n    pass"
    );
}

#[test]
fn simple_if_without_else() {
    let s: Stmt = Stmt::If {
        test: Expr::Constant {
            value: ConstValue::True,
            line: None,
        },
        body: vec![Stmt::Pass],
        orelse: Vec::new(),
        line: None,
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;
    let out: String = em.emit_stmt(&s, 0, &v);
    assert_eq!(out, "if True:\n    pass");
}

fn name(id: &str) -> Expr {
    Expr::Name {
        id: id.to_owned(),
        ctx: ExprCtx::Load,
        line: None,
    }
}
