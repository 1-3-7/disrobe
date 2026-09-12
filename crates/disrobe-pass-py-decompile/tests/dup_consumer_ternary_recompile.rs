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
const PRE311_STABLE_VERSIONS: &[&str] = &["3.8", "3.9", "3.10"];

fn assert_recompiles_on(
    label: &str,
    program: &str,
    target_versions: &[&'static str],
    prerelease: &[&'static str],
) {
    let band: Vec<BandInterpreter> = resolve_band(target_versions, prerelease);
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
        assert!(
            !source.contains("None(None"),
            "{label} py{}: stack-underflow placeholder leaked in:\n{source}",
            interp.alias
        );
    }
    assert!(
        checked_stable > 0,
        "{label}: no stable interpreter validated the recovery (vacuous)"
    );
}

fn assert_recompiles(label: &str, program: &str) {
    assert_recompiles_on(label, program, TARGET_VERSIONS, PRERELEASE);
}

#[test]
fn setattr_trailing_ternary_argument() {
    assert_recompiles(
        "dup_ternary_setattr",
        "def f(self, state):\n    object.__setattr__(self, 'x', state['x'])\n    object.__setattr__(self, 'y', G(state['y']) if 'y' in state else H.unknown)\n",
    );
}

#[test]
fn return_call_trailing_ternary_argument() {
    assert_recompiles(
        "dup_ternary_return_call",
        "def f(a, cond, x, y):\n    return foo(a, x if cond else y)\n",
    );
}

#[test]
fn expr_call_trailing_ternary_argument() {
    assert_recompiles(
        "dup_ternary_expr_call",
        "def f(logger, cond, x, y):\n    logger.log(1, x if cond else y)\n",
    );
}

#[test]
fn sequential_ternary_call_arguments_with_starred_tail() {
    assert_recompiles_on(
        "sequential_ternary_call_args",
        "def f(cafile, capath, parts):\n    return Result(cafile if is_file(cafile) else None, capath if is_dir(capath) else None, *parts)\n",
        PRE311_STABLE_VERSIONS,
        &[],
    );
}

#[test]
fn plain_if_else_statement_unchanged() {
    assert_recompiles(
        "dup_ternary_guard_plain_if",
        "def f(cond, a, b):\n    if cond:\n        a.append(1)\n    else:\n        b.append(2)\n    return 0\n",
    );
}
