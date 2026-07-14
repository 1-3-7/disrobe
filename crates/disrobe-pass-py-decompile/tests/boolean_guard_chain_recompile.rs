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
                    "{label} py{}: token-match in an interpreter-present band is not allowed; \
                     expected recompile-equivalence\n--- recovered:\n{source}",
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
fn guard_and_two_operands() {
    assert_recompiles(
        "guard_and2",
        "def f(a, b):\n    if a and b:\n        return 1\n    return 0\n",
    );
}

#[test]
fn guard_or_two_operands() {
    assert_recompiles(
        "guard_or2",
        "def f(a, b):\n    if a or b:\n        return 1\n    return 0\n",
    );
}

#[test]
fn guard_and_then_or() {
    assert_recompiles(
        "guard_and_or",
        "def f(a, b, c):\n    if a and b or c:\n        return 1\n    return 0\n",
    );
}

#[test]
fn guard_or_then_and() {
    assert_recompiles(
        "guard_or_and",
        "def f(a, b, c):\n    if a or b and c:\n        return 1\n    return 0\n",
    );
}

#[test]
fn guard_nested_parenthesized() {
    assert_recompiles(
        "guard_nested",
        "def f(a, b, c, d):\n    if (a or b) and (c or d):\n        return 1\n    return 0\n",
    );
}

#[test]
fn guard_left_nested_group_then_and() {
    assert_recompiles(
        "guard_left_nested_and",
        "def f(a, b, c, d):\n    if (a and b or c) and d:\n        return 1\n    return 0\n",
    );
}

#[test]
fn while_guard_mixed_and_or_keeps_body() {
    assert_recompiles(
        "while_guard_mixed",
        "def f(a, b, c):\n    n = 0\n    while a and b or c:\n        n += 1\n    return n\n",
    );
}

#[test]
fn guard_and_or_with_body_statements() {
    assert_recompiles(
        "guard_body_stmts",
        "def f(items, x):\n    out = []\n    for it in items:\n        if it > 0 and x or it == -1:\n            out.append(it)\n    return out\n",
    );
}

#[test]
fn loop_body_and_two_operands() {
    assert_recompiles(
        "loop_and2",
        "def f(items):\n    out = []\n    for x in items:\n        if x and x.ok:\n            out.append(x)\n    return out\n",
    );
}

#[test]
fn loop_body_and_three_operands_nested_arm() {
    assert_recompiles(
        "loop_and3_nested",
        "def f(args):\n    idx = None\n    for k in args:\n        sub = getattr(k, 'x', None)\n        if sub and len(sub) == 2 and sub[0]:\n            idx = k\n    return idx\n",
    );
}

#[test]
fn loop_body_and_three_operands_early_return() {
    assert_recompiles(
        "loop_and3_return",
        "def f(items):\n    for x in items:\n        if x and x.ok and x.ready:\n            return x\n    return None\n",
    );
}

#[test]
fn refuse_merge_statement_between_guards() {
    assert_recompiles(
        "refuse_stmt_between",
        "def f(items, log):\n    for x in items:\n        if x:\n            log.append(x)\n        if x.ok:\n            log.append(1)\n    return log\n",
    );
}

#[test]
fn refuse_merge_nested_guard_with_trailing_statement() {
    assert_recompiles(
        "refuse_nested_trailing",
        "def f(items):\n    out = []\n    for x in items:\n        if x:\n            if x.ok:\n                out.append(x)\n            out.append(9)\n    return out\n",
    );
}

#[test]
fn refuse_merge_second_guard_to_third_target() {
    assert_recompiles(
        "refuse_third_target",
        "def f(items):\n    out = []\n    for x in items:\n        if x and x.ok:\n            out.append(x)\n        if x.done:\n            break\n    return out\n",
    );
}
