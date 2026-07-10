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
            BandOutcome::SourceTokenMatch => {
                assert!(
                    interp.is_prerelease,
                    "{label} py{}: token-match where recompile-equivalence is required\n\
                     --- recovered:\n{source}",
                    interp.alias
                );
            }
            BandOutcome::Tolerated(detail) => {
                assert!(
                    interp.is_prerelease,
                    "{label} py{}: Tolerated outcome from a stable interpreter is a real failure: \
                     {detail}\n--- recovered:\n{source}",
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

#[test]
fn while_true_break_and_return_coexist() {
    assert_recompiles(
        "while_true_break_return",
        "def scan(data, j):\n    while True:\n        c = data[j]\n        if not c:\n            return -1\n        if c.isspace():\n            j = j + 1\n        else:\n            break\n    data.mark(j)\n    return j\n",
    );
}

#[test]
fn while_true_bare_continue_not_wrapped() {
    assert_recompiles(
        "while_true_bare_continue",
        "def scan(data, j):\n    while True:\n        c = data[j]\n        if not c:\n            return -1\n        if c.isspace():\n            j = j + 1\n            continue\n        break\n    return j\n",
    );
}

#[test]
fn while_true_only_returns_no_break() {
    assert_recompiles(
        "while_true_only_returns",
        "def peek(stream, j):\n    while True:\n        c = stream[j]\n        if not c:\n            return -1\n        if c in \"'\\\"\":\n            j = j + 1\n        elif c == \">\":\n            return j + 1\n        else:\n            j, ok = stream.scan(j)\n            if not ok:\n                return j\n",
    );
}

#[test]
fn while_cond_loop_else_raise_recovered() {
    assert_recompiles(
        "while_cond_else_raise",
        "def g(n, check):\n    i = 0\n    while i < n:\n        if check(i):\n            break\n        i = i + 1\n    else:\n        raise RuntimeError('not found')\n    return i\n",
    );
}

#[test]
fn nested_loop_break_targets_own_loop() {
    assert_recompiles(
        "nested_break_own_loop",
        "def h(matrix, target):\n    found = None\n    for row in matrix:\n        for val in row:\n            if val == target:\n                found = val\n                break\n        if found is not None:\n            break\n    return found\n",
    );
}
