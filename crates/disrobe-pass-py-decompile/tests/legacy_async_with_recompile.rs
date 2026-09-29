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

const STABLE_VERSIONS: &[&str] = &["3.8", "3.9", "3.10", "3.11"];
const PRERELEASE: &[&str] = &[];
const EXCEPTION_TABLE_VERSIONS: &[&str] = &["3.12", "3.13", "3.14", "3.15"];
const EXCEPTION_TABLE_PRERELEASE: &[&str] = &["3.15"];

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
fn await_inside_an_async_with_body_stays_in_the_body() {
    assert_recompiles(
        "await_inside_async_with",
        "async def f(m, g):\n    async with m:\n        await g(1)\n        g(2)\n",
    );
}

#[test]
fn statements_after_an_async_with_are_kept() {
    assert_recompiles(
        "statements_after_async_with",
        "async def f(m, g):\n    async with m as v:\n        g(v)\n    g(3)\n",
    );
}

#[test]
fn statements_after_an_async_with_are_kept_with_an_exception_table() {
    assert_recompiles_on(
        "statements_after_async_with_exception_table",
        "async def f(m, g):\n    async with m:\n        g(1)\n    g(2)\n    return 0\n",
        EXCEPTION_TABLE_VERSIONS,
        EXCEPTION_TABLE_PRERELEASE,
    );
}

#[test]
fn a_bound_async_with_keeps_the_statements_after_it_with_an_exception_table() {
    assert_recompiles_on(
        "bound_async_with_tail_exception_table",
        "async def f(m, g):\n    async with m as v:\n        g(v)\n    g(2)\n    g(3)\n",
        EXCEPTION_TABLE_VERSIONS,
        EXCEPTION_TABLE_PRERELEASE,
    );
}
