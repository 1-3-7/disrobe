#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

mod common;

use std::path::PathBuf;

use crate::common::band::{
    BandInterpreter, BandOutcome, band_scratch, recompile_equiv_inline, resolve_band,
};

const STABLE_VERSIONS: &[&str] = &["3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14"];
const PRERELEASE: &[&str] = &["3.15"];

fn assert_recompiles(label: &str, program: &str) {
    let band: Vec<BandInterpreter> = resolve_band(STABLE_VERSIONS, PRERELEASE);
    assert!(
        !band.is_empty(),
        "{label}: no requested CPython interpreter installed; cannot prove recompile-equivalence"
    );
    let scratch: PathBuf = band_scratch(label);
    let mut checked_stable: usize = 0;
    for interp in &band {
        let (outcome, source): (BandOutcome, String) =
            recompile_equiv_inline(interp, program, label, &scratch);
        match outcome {
            BandOutcome::RecompileEquiv => {
                if !interp.is_prerelease {
                    checked_stable += 1;
                }
            }
            BandOutcome::Tolerated(_) if interp.is_prerelease => {}
            BandOutcome::Failed(reason) if interp.is_prerelease => {
                eprintln!("SKIP prerelease {label} py{}: {reason}", interp.alias);
            }
            other => panic!(
                "{label} py{}: expected recompile-equivalence, got {other:?}\n--- recovered:\n{source}",
                interp.alias
            ),
        }
        assert!(
            !source.contains("__DR_"),
            "{label} py{}: unrecovered marker leaked in:\n{source}",
            interp.alias
        );
    }
    assert!(
        checked_stable > 0,
        "{label}: no stable interpreter validated the recovery (vacuous)"
    );
}

#[test]
fn lambda_ternary_body_keeps_both_arms() {
    assert_recompiles("lambda_ternary_body", "f = lambda x: a if x else b\n");
}

#[test]
fn lambda_ternary_inside_a_larger_expression() {
    assert_recompiles(
        "lambda_ternary_operand",
        "f = lambda x, y: (x if y else -x) + 1\n",
    );
}

#[test]
fn lambda_nested_ternary_body() {
    assert_recompiles(
        "lambda_nested_ternary",
        "f = lambda x: 'pos' if x > 0 else ('neg' if x < 0 else 'zero')\n",
    );
}

#[test]
fn lambda_ternary_as_call_argument() {
    assert_recompiles(
        "lambda_ternary_call_argument",
        "g = sorted(items, key=lambda k: k.lower() if k else '')\n",
    );
}

#[test]
fn lambda_short_circuit_bodies_stay_expressions() {
    assert_recompiles(
        "lambda_short_circuit",
        "f = lambda x, y: x and y\ng = lambda x: x or default\nh = lambda x, y: not x and y(x)\n",
    );
}

#[test]
fn lambda_ternary_over_a_short_circuit_test() {
    assert_recompiles(
        "lambda_ternary_boolop_test",
        "f = lambda x, y: x if x and y else y\n",
    );
}
