#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use disrobe_mba::{
    BinOp, Expr, Predicate, Simplification, Width, equivalence_query, simplify,
    tautology_refutation_query,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    Sat,
    Unsat,
    Unknown,
}

#[derive(Debug, Clone, Copy)]
enum SolverKind {
    Z3,
    Bitwuzla,
}

#[derive(Debug, Clone)]
struct Solver {
    program: &'static str,
    kind: SolverKind,
    version: String,
}

fn probe_version(program: &str) -> Option<String> {
    let output: std::process::Output = Command::new(program).arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&output.stdout);
    let first: String = text.lines().next().unwrap_or("").trim().to_owned();
    if first.is_empty() {
        Some(program.to_owned())
    } else {
        Some(first)
    }
}

fn detect_solver() -> Option<Solver> {
    const CANDIDATES: [(&str, SolverKind); 2] =
        [("z3", SolverKind::Z3), ("bitwuzla", SolverKind::Bitwuzla)];
    CANDIDATES
        .into_iter()
        .find_map(|(program, kind): (&'static str, SolverKind)| {
            probe_version(program).map(|version: String| Solver {
                program,
                kind,
                version,
            })
        })
}

static QUERY_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn parse_answer(text: &str) -> Answer {
    for line in text.lines() {
        match line.trim() {
            "unsat" => return Answer::Unsat,
            "sat" => return Answer::Sat,
            "unknown" => return Answer::Unknown,
            _ => {}
        }
    }
    panic!("solver produced no sat/unsat/unknown verdict: {text:?}");
}

fn run_solver(solver: &Solver, script: &str) -> Answer {
    let unique: usize = QUERY_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut path: PathBuf = std::env::temp_dir();
    path.push(format!(
        "disrobe_mba_smt_{}_{unique}.smt2",
        std::process::id()
    ));
    std::fs::write(&path, script).expect("write smt2 query to a temp file");
    let mut command: Command = Command::new(solver.program);
    match solver.kind {
        SolverKind::Z3 => {
            command.arg("-smt2").arg(&path);
        }
        SolverKind::Bitwuzla => {
            command.arg(&path);
        }
    }
    let output: std::process::Output = command.output().expect("invoke the external solver");
    let _ = std::fs::remove_file(&path);
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&output.stdout);
    parse_answer(&stdout)
}

const fn var(index: u32) -> Expr {
    Expr::var(index)
}

fn xor_carry_add(a: u32, b: u32) -> Expr {
    Expr::add(
        Expr::xor(var(a), var(b)),
        Expr::mul(Expr::konst(2), Expr::and(var(a), var(b))),
    )
}

fn corpus() -> Vec<(&'static str, Expr, Width)> {
    vec![
        ("ollvm_xor_carry_add_w8", xor_carry_add(0, 1), Width::W8),
        ("ollvm_xor_carry_add_w32", xor_carry_add(0, 1), Width::W32),
        ("ollvm_xor_carry_add_w64", xor_carry_add(0, 1), Width::W64),
        (
            "ollvm_xor_substitution_w8",
            Expr::or(
                Expr::and(var(0), Expr::not(var(1))),
                Expr::and(Expr::not(var(0)), var(1)),
            ),
            Width::W8,
        ),
        (
            "or_identity_w16",
            Expr::add(Expr::xor(var(0), var(1)), Expr::and(var(0), var(1))),
            Width::W16,
        ),
        (
            "sub_disguise_w32",
            Expr::sub(
                Expr::xor(var(0), var(1)),
                Expr::mul(Expr::konst(2), Expr::and(Expr::not(var(0)), var(1))),
            ),
            Width::W32,
        ),
        (
            "linear_four_var_w16",
            Expr::add(
                Expr::add(Expr::or(var(0), var(1)), Expr::and(var(0), var(1))),
                Expr::add(Expr::or(var(2), var(3)), Expr::and(var(2), var(3))),
            ),
            Width::W16,
        ),
        (
            "poly_distributive_w64",
            Expr::sub(
                Expr::mul(var(0), Expr::add(var(1), Expr::konst(1))),
                Expr::mul(var(0), var(1)),
            ),
            Width::W64,
        ),
        (
            "poly_scaled_w8",
            Expr::sub(
                Expr::mul(var(0), Expr::add(var(1), Expr::konst(2))),
                Expr::mul(var(0), var(1)),
            ),
            Width::W8,
        ),
        (
            "poly_three_var_zero_w8",
            Expr::sub(
                Expr::sub(
                    Expr::mul(var(0), Expr::add(var(1), var(2))),
                    Expr::mul(var(0), var(1)),
                ),
                Expr::mul(var(0), var(2)),
            ),
            Width::W8,
        ),
        (
            "mixed_cancel_w16",
            Expr::xor(xor_carry_add(0, 1), Expr::add(var(0), var(1))),
            Width::W16,
        ),
        (
            "mixed_nested_w8",
            Expr::xor(
                Expr::add(Expr::and(var(0), var(1)), Expr::xor(var(0), var(1))),
                var(2),
            ),
            Width::W8,
        ),
    ]
}

const fn flip_op(op: BinOp) -> BinOp {
    match op {
        BinOp::Add => BinOp::Sub,
        BinOp::Sub | BinOp::Mul => BinOp::Add,
        BinOp::And => BinOp::Or,
        BinOp::Or | BinOp::Xor => BinOp::And,
        BinOp::Shl => BinOp::Shr,
        BinOp::Shr => BinOp::Shl,
    }
}

fn perturb_one_operator(expr: &Expr) -> Option<Expr> {
    match expr {
        Expr::Binary(op, left, right) => {
            Some(Expr::Binary(flip_op(*op), left.clone(), right.clone()))
        }
        Expr::Unary(op, inner) => {
            perturb_one_operator(inner).map(|flipped: Expr| Expr::Unary(*op, Box::new(flipped)))
        }
        _ => None,
    }
}

#[test]
fn simplifications_match_an_external_bitvector_solver() {
    let Some(solver): Option<Solver> = detect_solver() else {
        eprintln!(
            "external_smt_differential: neither z3 nor bitwuzla found on PATH; skipping cleanly"
        );
        return;
    };
    eprintln!(
        "external_smt_differential: grading against {} ({})",
        solver.program, solver.version
    );

    let entries: Vec<(&'static str, Expr, Width)> = corpus();
    let mut changed: usize = 0;
    for (name, expr, width) in &entries {
        let result: Simplification = simplify(expr, *width);
        if result.changed() {
            changed += 1;
        }
        let script: String = equivalence_query(expr, &result.simplified, *width);
        let answer: Answer = run_solver(&solver, &script);
        assert_eq!(
            answer,
            Answer::Unsat,
            "{name} at {width:?}: solver did not prove simplify(e) equivalent to e; expected UNSAT, got {answer:?}\nsimplified = {}\nscript:\n{script}",
            result.simplified
        );
    }
    assert!(
        changed >= 6,
        "the differential corpus must exercise real rewrites, only {changed} of {} changed",
        entries.len()
    );

    let seed_source: Expr = xor_carry_add(0, 1);
    let seed_simplified: Expr = simplify(&seed_source, Width::W8).simplified;
    let wrong: Expr = perturb_one_operator(&seed_simplified)
        .expect("the reduced form must contain an operator to perturb");
    assert_ne!(
        wrong, seed_simplified,
        "the perturbation must produce a different expression"
    );
    let seed_script: String = equivalence_query(&seed_source, &wrong, Width::W8);
    let seed_answer: Answer = run_solver(&solver, &seed_script);
    assert_eq!(
        seed_answer,
        Answer::Sat,
        "the seeded wrong rewrite must be refuted (SAT), got {seed_answer:?}\nwrong = {wrong}\nscript:\n{seed_script}"
    );

    let tautology: Predicate = Predicate::eq(
        Expr::and(Expr::add(Expr::mul(var(0), var(0)), var(0)), Expr::konst(1)),
        Expr::konst(0),
    );
    let tautology_script: String = tautology_refutation_query(&tautology, Width::W8);
    assert_eq!(
        run_solver(&solver, &tautology_script),
        Answer::Unsat,
        "x*x + x is always even, so refuting the parity predicate must be UNSAT"
    );

    let data_dependent: Predicate = Predicate::eq(var(0), Expr::konst(7));
    let data_dependent_script: String = tautology_refutation_query(&data_dependent, Width::W8);
    assert_eq!(
        run_solver(&solver, &data_dependent_script),
        Answer::Sat,
        "x == 7 is not a tautology, so its refutation must be SAT"
    );
}
