#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use disrobe_mba::{Expr, PermutationPolynomial, Width, equivalence_query};

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
    let purpose: String = format!("disrobe_mba_perm_{}_{}", std::process::id(), unique);
    let (scratch, mut file): (disrobe_core::scratch::ScratchFile, std::fs::File) =
        disrobe_core::scratch::ScratchFile::create(&purpose, "smt2")
            .expect("write smt2 query to a temp file");
    let path: PathBuf = scratch.path().to_path_buf();
    std::io::Write::write_all(&mut file, script.as_bytes())
        .expect("write smt2 query to a temp file");
    drop(file);
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
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&output.stdout);
    parse_answer(&stdout)
}

fn compose_at(coeffs: &[u64], inner: &Expr) -> Expr {
    let Some(top): Option<usize> = coeffs.iter().rposition(|coeff: &u64| *coeff != 0) else {
        return Expr::konst(0);
    };
    let mut acc: Expr = Expr::konst(coeffs[top]);
    for index in (0..top).rev() {
        acc = Expr::mul(acc, inner.clone());
        if coeffs[index] != 0 {
            acc = Expr::add(acc, Expr::konst(coeffs[index]));
        }
    }
    acc
}

fn full_image(coeffs: &[u64], width: Width) -> bool {
    let poly: PermutationPolynomial = PermutationPolynomial::new(width, coeffs);
    let expr: Expr = poly.to_expr(0);
    let modulus: u64 = width.mask().wrapping_add(1);
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    for x in 0..modulus {
        seen.insert(expr.eval(&[x], width));
    }
    seen.len() as u64 == modulus
}

fn permutations() -> Vec<(&'static str, Vec<u64>, Width)> {
    vec![
        ("affine_w8", vec![5, 3], Width::W8),
        ("quadratic_w8", vec![0, 1, 2], Width::W8),
        ("quadratic_offset_w8", vec![7, 3, 4], Width::W8),
        ("cubic_w8", vec![1, 3, 4, 6], Width::W8),
        ("quadratic_w16", vec![9, 5, 6], Width::W16),
        ("cubic_w16", vec![3, 7, 8, 2], Width::W16),
        ("affine_w32", vec![0x1234_5678, 0x9ABC_DEF1], Width::W32),
        ("quadratic_w32", vec![11, 7, 0x0001_0000], Width::W32),
        (
            "cubic_w32",
            vec![5, 3, 0x0001_0000, 0x0002_0000],
            Width::W32,
        ),
        (
            "affine_w64",
            vec![0xDEAD_BEEF_0BAD_F00D, 0x1F2E_3D4C_5B6A_7981],
            Width::W64,
        ),
        (
            "quadratic_w64",
            vec![123, 9, 0x0000_0001_0000_0000],
            Width::W64,
        ),
        (
            "cubic_w64",
            vec![7, 5, 0x0000_0001_0000_0000, 0x0000_0002_0000_0000],
            Width::W64,
        ),
    ]
}

fn non_permutations() -> Vec<(&'static str, Vec<u64>, Width)> {
    vec![
        ("even_linear_w8", vec![1, 2, 4], Width::W8),
        ("odd_square_w8", vec![0, 1, 1], Width::W8),
        ("odd_cubic_w16", vec![0, 1, 0, 1], Width::W16),
        ("even_leading_w32", vec![3, 4, 8], Width::W32),
    ]
}

#[test]
fn permutation_inverses_are_proven_by_an_external_bitvector_solver() {
    let identity: Expr = Expr::var(0);

    for (name, coeffs, width) in non_permutations() {
        let poly: PermutationPolynomial = PermutationPolynomial::new(width, &coeffs);
        assert!(
            !poly.is_permutation(),
            "{name}: Rivest detection must reject a non-permutation {coeffs:?}"
        );
        assert!(
            poly.inverse().is_none(),
            "{name}: no inverse may be emitted for a non-permutation"
        );
        if width.is_exhaustible() {
            assert!(
                !full_image(&coeffs, width),
                "{name}: a rejected polynomial must genuinely fail to be a bijection"
            );
        }
    }

    for (name, coeffs, width) in permutations() {
        let poly: PermutationPolynomial = PermutationPolynomial::new(width, &coeffs);
        assert!(
            poly.is_permutation(),
            "{name}: Rivest detection must accept a permutation {coeffs:?}"
        );
        if width.is_exhaustible() {
            assert!(
                full_image(&coeffs, width),
                "{name}: an accepted narrow polynomial must be a bijection"
            );
        }
    }

    let Some(solver): Option<Solver> = detect_solver() else {
        eprintln!("perm_poly_smt: neither z3 nor bitwuzla found on PATH; skipping the solver leg");
        return;
    };
    eprintln!(
        "perm_poly_smt: grading against {} ({})",
        solver.program, solver.version
    );

    for (name, coeffs, width) in permutations() {
        let poly: PermutationPolynomial = PermutationPolynomial::new(width, &coeffs);
        let inverse: PermutationPolynomial = poly
            .inverse()
            .unwrap_or_else(|| panic!("{name}: a detected permutation must invert"));
        let inverse_coeffs: Vec<u64> = inverse.coefficients().to_vec();

        let forward: Expr = compose_at(&coeffs, &inverse.to_expr(0));
        let forward_script: String = equivalence_query(&forward, &identity, width);
        assert_eq!(
            run_solver(&solver, &forward_script),
            Answer::Unsat,
            "{name} at {width:?}: P(P_inv(x)) == x must be proven for all x (UNSAT of the negation); inverse {inverse_coeffs:?}"
        );

        let backward: Expr = compose_at(&inverse_coeffs, &poly.to_expr(0));
        let backward_script: String = equivalence_query(&backward, &identity, width);
        assert_eq!(
            run_solver(&solver, &backward_script),
            Answer::Unsat,
            "{name} at {width:?}: P_inv(P(x)) == x must be proven for all x; inverse {inverse_coeffs:?}"
        );
    }
}
