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
    assert_recompiles_on(label, program, STABLE_VERSIONS, PRERELEASE);
}

fn assert_recompiles_on(
    label: &str,
    program: &str,
    versions: &[&'static str],
    prerelease: &[&'static str],
) {
    let band: Vec<BandInterpreter> = resolve_band(versions, prerelease);
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
fn if_else_before_a_with_keeps_one_arm() {
    assert_recompiles(
        "if_else_before_with",
        "def f(x, m, g, h):\n    if x:\n        g()\n    else:\n        h()\n    with m:\n        g()\n",
    );
}

#[test]
fn a_conditional_context_expression_is_recovered_or_refused() {
    let program: &str = "def f(x, a, b, g):\n    with (a if x else b):\n        g()\n";
    let label: &str = "conditional_context_expression";
    let band: Vec<BandInterpreter> = resolve_band(STABLE_VERSIONS, &[]);
    assert!(
        !band.is_empty(),
        "{label}: no CPython interpreter installed"
    );
    let scratch: PathBuf = band_scratch(label);
    for interp in &band {
        let (outcome, source): (BandOutcome, String) =
            recompile_equiv_inline(interp, program, label, &scratch);
        if matches!(outcome, BandOutcome::RecompileEquiv) {
            continue;
        }
        assert!(
            !source.contains("with b:") && !source.contains("with a:"),
            "{label} py{}: one arm of the context expression was published as the whole: {outcome:?}\n{source}",
            interp.alias
        );
    }
}

#[test]
fn statements_after_a_with_are_kept() {
    assert_recompiles(
        "statements_after_with",
        "def f(m, g):\n    with m as v:\n        g(v)\n    g(3)\n    return v\n",
    );
}

#[test]
fn a_with_inside_a_try_keeps_the_try_and_its_handler() {
    assert_recompiles_on(
        "with_inside_try",
        "def f(name, g):
    try:
        with open(name) as fp:
            data = fp.read()
        g(data)
    except OSError:
        data = None
    return data
",
        &["3.8", "3.9", "3.10"],
        &[],
    );
}

#[test]
fn a_statement_after_a_with_inside_a_try_is_kept_on_311() {
    assert_recompiles_on(
        "statement_after_with_inside_try_311",
        "def f(name, g):\n    try:\n        with open(name) as fp:\n            data = fp.read()\n        g(data)\n    except OSError:\n        data = None\n    return data\n",
        &["3.11"],
        &[],
    );
}
