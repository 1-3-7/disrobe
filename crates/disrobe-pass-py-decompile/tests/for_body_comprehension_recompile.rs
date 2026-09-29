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
    let mut failures: Vec<String> = Vec::new();
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
            other => failures.push(format!(
                "py{}: expected recompile-equivalence, got {other:?}\n--- recovered:\n{source}",
                interp.alias
            )),
        }
        assert!(
            !source.contains("__DR_"),
            "{label} py{}: unrecovered marker leaked in:\n{source}",
            interp.alias
        );
    }
    assert!(failures.is_empty(), "{label}:\n{}", failures.join("\n\n"));
    assert!(
        checked_stable > 0,
        "{label}: no stable interpreter validated the recovery (vacuous)"
    );
}

#[test]
fn a_for_body_holding_a_list_comprehension_stays_a_loop() {
    assert_recompiles(
        "for_body_list_comprehension",
        "def f(xs):\n    total = 0\n    for x in xs:\n        total += len([y for y in x])\n    return total\n",
    );
}

#[test]
fn a_for_body_statement_after_a_comprehension_stays_in_the_loop() {
    assert_recompiles(
        "for_body_comprehension_then_call",
        "def f(xs, g):\n    for x in xs:\n        ys = {y: 1 for y in x}\n        g(ys)\n    return 0\n",
    );
}

#[test]
fn a_while_body_holding_a_set_comprehension_stays_a_loop() {
    assert_recompiles(
        "while_body_set_comprehension",
        "def f(it, g):\n    while it.more():\n        g({y for y in it.next()})\n    return it\n",
    );
}
