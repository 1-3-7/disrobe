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
            BandOutcome::SourceTokenMatch | BandOutcome::Tolerated(_) if interp.is_prerelease => {}
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
fn nested_conditional_break_before_a_returning_loop_exit() {
    assert_recompiles(
        "nested_conditional_break_return_tail",
        "def f(xs, a, b, c):\n    for x in xs:\n        if a(x):\n            if b(x):\n                break\n            c(x)\n    return 0\n",
    );
}

#[test]
fn trailing_conditional_break_after_a_statement() {
    assert_recompiles(
        "statement_then_conditional_break_return_tail",
        "def f(xs, b, c):\n    for x in xs:\n        c(x)\n        if b(x):\n            break\n    c(0)\n",
    );
}

#[test]
fn conditional_break_in_a_while_loop_before_a_returning_exit() {
    assert_recompiles(
        "while_conditional_break_return_tail",
        "def f(it, b, c):\n    while it.more():\n        v = it.next()\n        if b(v):\n            break\n        c(v)\n    return it.total\n",
    );
}
