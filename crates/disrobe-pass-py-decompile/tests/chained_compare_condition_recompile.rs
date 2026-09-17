#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_lines
)]

mod common;

use std::path::PathBuf;

use crate::common::band::{
    BandInterpreter, BandOutcome, band_scratch, recompile_equiv_inline, resolve_band,
};

const TARGET_VERSIONS: &[&str] = &["3.12", "3.13", "3.14"];
const PRERELEASE: &[&str] = &["3.15"];

fn assert_recompiles(label: &str, program: &str) {
    let band: Vec<BandInterpreter> = resolve_band(TARGET_VERSIONS, PRERELEASE);
    assert!(
        !band.is_empty(),
        "{label}: no 3.12-3.15 interpreter installed; cannot prove recompile-equivalence. \
         Install one (uv python install 3.14) - never silently pass."
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
            BandOutcome::SourceTokenMatch | BandOutcome::Tolerated(_) => {
                assert!(
                    interp.is_prerelease,
                    "{label} py{}: non-equivalent outcome from a stable interpreter\n\
                     --- recovered:\n{source}",
                    interp.alias
                );
            }
            BandOutcome::Failed(reason) => {
                if interp.is_prerelease {
                    eprintln!("SKIP prerelease {label} py{}: {reason}", interp.alias);
                } else {
                    panic!(
                        "{label} py{}: {reason}\n--- recovered:\n{source}",
                        interp.alias
                    );
                }
            }
        }
    }
    assert!(
        checked_stable > 0,
        "{label}: no stable interpreter validated the recovery (vacuous)"
    );
}

fn assert_condition_recovered(label: &str, program: &str, needle: &str) {
    let band: Vec<BandInterpreter> = resolve_band(TARGET_VERSIONS, PRERELEASE);
    assert!(
        !band.is_empty(),
        "{label}: no 3.12-3.15 interpreter installed; cannot exercise the recovery."
    );
    let scratch: PathBuf = band_scratch(label);
    let mut checked: usize = 0;
    for interp in &band {
        if interp.is_prerelease {
            continue;
        }
        let (_outcome, source): (BandOutcome, String) =
            recompile_equiv_inline(interp, program, label, &scratch);
        assert!(
            source.contains(needle),
            "{label} py{}: chained-compare condition not recovered; expected `{needle}`\n\
             --- recovered:\n{source}",
            interp.alias
        );
        checked += 1;
    }
    assert!(
        checked > 0,
        "{label}: no stable interpreter validated the recovery (vacuous)"
    );
}

#[test]
fn if_chained_compare_condition() {
    assert_recompiles(
        "if_chain_cmp",
        "def f(j, n):\n    if 0 <= j < n:\n        return 1\n    return 2\n",
    );
}

#[test]
fn rvalue_chained_compare_guard() {
    assert_recompiles(
        "rvalue_chain_cmp",
        "def f(a, b, c):\n    x = a < b < c\n    return x\n",
    );
}

#[test]
fn chained_compare_feeding_or_with_not() {
    assert_recompiles(
        "chain_or_not",
        "def f(c, ESCAPE):\n    return c == ESCAPE or not (b' ' <= c <= b'~')\n",
    );
}

#[test]
fn chained_compare_negated_alone() {
    assert_recompiles(
        "chain_not_alone",
        "def f(c):\n    return not (b' ' <= c <= b'~')\n",
    );
}

#[test]
fn triple_equality_chain_return() {
    assert_recompiles(
        "chain_eq_triple",
        "def f(a, b, c):\n    return a == b == c\n",
    );
}

#[test]
fn while_chained_compare_condition_recovers() {
    assert_condition_recovered(
        "while_chain_cmp",
        "def f(j, n):\n    while 0 <= j < n:\n        j += 1\n",
        "while 0 <= j < n:",
    );
}
