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
    BandInterpreter, BandOutcome, band_scratch, find_interpreter, recompile_equiv_inline,
};

const STABLE_VERSIONS: &[&str] = &["3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14"];
const LOOP_COUNT: usize = 30;
const BUDGET_REFUSAL: &str = "structuring step budget";

fn assert_recovers_within_budget(label: &str, program: &str) {
    let scratch: PathBuf = band_scratch(label);
    let mut failures: Vec<String> = Vec::new();
    for &alias in STABLE_VERSIONS {
        let path: PathBuf = find_interpreter(alias)
            .unwrap_or_else(|| panic!("{label}: CPython {alias} interpreter not found"));
        let interp: BandInterpreter = BandInterpreter {
            alias,
            path,
            is_prerelease: false,
        };
        let (outcome, source): (BandOutcome, String) =
            recompile_equiv_inline(&interp, program, label, &scratch);
        if source.is_empty() || source.contains(BUDGET_REFUSAL) {
            failures.push(format!(
                "py{alias}: decompile refused or failed, got {outcome:?}\n--- recovered:\n{source}"
            ));
            continue;
        }
        if !matches!(outcome, BandOutcome::RecompileEquiv) {
            failures.push(format!(
                "py{alias}: expected recompile-equivalence, got {outcome:?}\n--- recovered:\n{source}"
            ));
        }
    }
    assert!(failures.is_empty(), "{label}:\n{}", failures.join("\n\n"));
}

fn sequential_loops_program() -> String {
    let mut program: String = String::from("def f(xs, g, n):\n    total = 0\n");
    for index in 0..LOOP_COUNT {
        if index % 2 == 0 {
            program.push_str("    for x in xs:\n        total += g(x)\n");
        } else {
            program.push_str("    while n > total:\n        total += g(n)\n");
        }
    }
    program.push_str("    return total\n");
    program
}

#[test]
fn thirty_sequential_loops_recover_within_the_exit_probe_budget() {
    assert_recovers_within_budget("thirty_sequential_loops", &sequential_loops_program());
}
