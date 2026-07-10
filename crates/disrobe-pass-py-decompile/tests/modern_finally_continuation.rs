#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use crate::common::band::{
    BandInterpreter, BandOutcome, band_scratch, recompile_equiv_inline, resolve_band,
};

const TARGET_VERSIONS: &[&str] = &["3.12", "3.14"];
const PRERELEASE: &[&str] = &["3.15"];

fn assert_single_finally(label: &str, program: &str, must_contain: &[&str]) {
    let band: Vec<BandInterpreter> = resolve_band(TARGET_VERSIONS, PRERELEASE);
    if band.is_empty() {
        return;
    }
    let scratch: PathBuf = band_scratch(label);
    let mut checked: usize = 0usize;
    for interp in &band {
        let (outcome, source): (BandOutcome, String) =
            recompile_equiv_inline(interp, program, label, &scratch);
        match outcome {
            BandOutcome::RecompileEquiv => {}
            BandOutcome::SourceTokenMatch => panic!(
                "{label} py{}: token-match, not recompile-equivalent:\n{source}",
                interp.alias
            ),
            BandOutcome::Tolerated(detail) => {
                assert!(
                    interp.is_prerelease,
                    "{label} py{}: Tolerated from a stable interpreter is a real failure: \
                     {detail}\n{source}",
                    interp.alias
                );
                eprintln!("{detail}");
            }
            BandOutcome::Failed(reason) => {
                panic!(
                    "{label} py{}: {reason}\n--- recovered:\n{source}",
                    interp.alias
                )
            }
        }
        let finally_blocks: usize = source.matches("finally:").count();
        assert_eq!(
            finally_blocks, 1,
            "{label} py{}: expected exactly one finally block (the duplicated normal-path copy \
             must be collapsed), found {finally_blocks}:\n{source}",
            interp.alias
        );
        for needle in must_contain {
            assert!(
                source.contains(needle),
                "{label} py{}: expected `{needle}` in recovered source:\n{source}",
                interp.alias
            );
        }
        checked += 1;
    }
    assert!(
        checked > 0,
        "{label}: no interpreter validated the recovery"
    );
}

#[test]
fn try_finally_recovers_trailing_continuation() {
    let program: &str = "\
def f(x):
    try:
        y = x + 1
    finally:
        record(x)
    return y
";
    assert_single_finally("try_finally_cont", program, &["finally:", "return y"]);
}

#[test]
fn try_finally_control_flow_body_recovers_continuation() {
    let program: &str = "\
def f(x):
    try:
        if x:
            a = 1
        else:
            a = 2
    finally:
        release()
    return a
";
    assert_single_finally("try_finally_if_cont", program, &["finally:", "return a"]);
}

#[test]
fn try_except_finally_recovers_trailing_continuation() {
    let program: &str = "\
def f(x):
    try:
        y = compute(x)
    except ValueError:
        y = 0
    finally:
        cleanup()
    return y
";
    assert_single_finally(
        "try_except_finally_cont",
        program,
        &["except ValueError", "finally:", "return y"],
    );
}
