#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_const_for_fn,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::many_single_char_names
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use disrobe_pass_py_decompile::ast::{Expr, ExprCtx};
use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::codegen::{CodeEmitter, DefaultEmitter};

fn name(id: &str) -> Expr {
    Expr::Name {
        id: id.to_owned(),
        ctx: ExprCtx::Load,
        line: None,
    }
}

fn ifexp(test: Expr, body: Expr, orelse: Expr) -> Expr {
    Expr::IfExp {
        test: Box::new(test),
        body: Box::new(body),
        orelse: Box::new(orelse),
    }
}

#[test]
fn nested_ternary_in_body_is_parenthesized() {
    let inner: Expr = ifexp(name("b"), name("a"), name("c"));
    let outer: Expr = ifexp(name("d"), inner, name("e"));
    let em: DefaultEmitter = DefaultEmitter::new();
    let out: String = em.emit_expr(&outer, &PyVersion::V3_12);
    assert_eq!(out, "(a if b else c) if d else e");
}

#[test]
fn nested_ternary_in_test_is_parenthesized() {
    let inner: Expr = ifexp(name("b"), name("a"), name("c"));
    let outer: Expr = ifexp(inner, name("x"), name("y"));
    let em: DefaultEmitter = DefaultEmitter::new();
    let out: String = em.emit_expr(&outer, &PyVersion::V3_12);
    assert_eq!(out, "x if (a if b else c) else y");
}

#[test]
fn nested_ternary_in_orelse_omits_redundant_parens() {
    let inner: Expr = ifexp(name("d2"), name("c"), name("e"));
    let outer: Expr = ifexp(name("d1"), name("a"), inner);
    let em: DefaultEmitter = DefaultEmitter::new();
    let out: String = em.emit_expr(&outer, &PyVersion::V3_12);
    assert_eq!(out, "a if d1 else c if d2 else e");
}

#[test]
fn lambda_in_ternary_body_is_parenthesized() {
    let lam: Expr = Expr::Lambda {
        args: Box::new(disrobe_pass_py_decompile::ast::Arguments::default()),
        body: Box::new(name("z")),
    };
    let outer: Expr = ifexp(name("d"), lam, name("e"));
    let em: DefaultEmitter = DefaultEmitter::new();
    let out: String = em.emit_expr(&outer, &PyVersion::V3_12);
    assert_eq!(out, "(lambda: z) if d else e");
}

fn find_interpreter(alias: &str) -> Option<PathBuf> {
    let output: std::process::Output = Command::new("uv")
        .args(["python", "find", alias])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let path: PathBuf = PathBuf::from(raw);
    path.is_file().then_some(path)
}

fn eval_via_cpython(interpreter: &Path, params: &[&str], expr_src: &str, args: &[i64]) -> i64 {
    let signature: String = params.join(", ");
    let call_args: String = args
        .iter()
        .map(i64::to_string)
        .collect::<Vec<String>>()
        .join(", ");
    let driver: String = format!(
        "def f({signature}):\n    return {expr_src}\nimport sys\nsys.stdout.write('RESULT='+str(f({call_args})))\n"
    );
    let output: std::process::Output = Command::new(interpreter)
        .args(["-c", &driver])
        .stdin(Stdio::null())
        .output()
        .expect("spawn interpreter");
    assert!(
        output.status.success(),
        "CPython rejected emitted source (parse/eval failure):\n{driver}\n--- stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let marker: &str = stdout.rsplit("RESULT=").next().unwrap_or("").trim();
    marker
        .parse::<i64>()
        .unwrap_or_else(|_| panic!("f did not print an int, got {stdout:?}\nsource:\n{driver}"))
}

#[test]
fn emitted_nested_ternary_reparses_to_intended_semantics() {
    let Some(interpreter): Option<PathBuf> = find_interpreter("3.14") else {
        eprintln!(
            "skip emitted_nested_ternary_reparses_to_intended_semantics: no 3.14 interpreter"
        );
        return;
    };
    let em: DefaultEmitter = DefaultEmitter::new();
    let v: PyVersion = PyVersion::V3_12;

    let body_nested: Expr = ifexp(name("d"), ifexp(name("b"), name("a"), name("c")), name("e"));
    let body_src: String = em.emit_expr(&body_nested, &v);
    let test_nested: Expr = ifexp(ifexp(name("b"), name("a"), name("c")), name("x"), name("y"));
    let test_src: String = em.emit_expr(&test_nested, &v);

    let intended_body = |a: i64, b: i64, c: i64, d: i64, e: i64| -> i64 {
        let inner: i64 = if b != 0 { a } else { c };
        if d != 0 { inner } else { e }
    };
    let intended_test = |a: i64, b: i64, c: i64, x: i64, y: i64| -> i64 {
        let cond: i64 = if b != 0 { a } else { c };
        if cond != 0 { x } else { y }
    };

    let mut checked: usize = 0;
    for b in [0_i64, 1] {
        for d in [0_i64, 1] {
            let a: i64 = 7;
            let c: i64 = 0;
            let e: i64 = 9;
            let got: i64 = eval_via_cpython(
                &interpreter,
                &["a", "b", "c", "d", "e"],
                &body_src,
                &[a, b, c, d, e],
            );
            assert_eq!(
                got,
                intended_body(a, b, c, d, e),
                "body-nested ternary mis-associates for (b={b}, d={d}); emitted `{body_src}` re-parses \
                 differently than the intended AST (a if b else c) if d else e"
            );
            checked += 1;
        }
    }
    for b in [0_i64, 1] {
        let a: i64 = 1;
        let c: i64 = 0;
        let x: i64 = 5;
        let y: i64 = 6;
        let got: i64 = eval_via_cpython(
            &interpreter,
            &["a", "b", "c", "x", "y"],
            &test_src,
            &[a, b, c, x, y],
        );
        assert_eq!(
            got,
            intended_test(a, b, c, x, y),
            "test-nested ternary mis-associates for (b={b}); emitted `{test_src}` re-parses \
             differently than the intended AST x if (a if b else c) else y"
        );
        checked += 1;
    }
    assert!(
        checked >= 6,
        "expected at least 6 truth-table probes, ran {checked}"
    );
}
