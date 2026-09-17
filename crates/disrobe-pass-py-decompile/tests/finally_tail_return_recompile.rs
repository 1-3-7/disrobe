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

const FINALLY_TAIL_GUARDED_CLEANUP: &str = "def timed_run(inner, timer, flag):\n    it = build_iter()\n    disable_gc()\n    try:\n        timing = inner(it, timer)\n    finally:\n        if flag:\n            enable_gc()\n    return timing\n";

const FINALLY_TAIL_NEGATED_GUARD: &str = "def traced_call(func, args, kw, quiet):\n    result = None\n    if not quiet:\n        set_trace(on_hook)\n    try:\n        result = func(*args, **kw)\n    finally:\n        if not quiet:\n            set_trace(off_hook)\n    return result\n";

fn recover_and_recompile(label: &str, program: &str) -> String {
    let band: Vec<BandInterpreter> = resolve_band(TARGET_VERSIONS, PRERELEASE);
    assert!(
        !band.is_empty(),
        "{label}: no 3.12-3.15 interpreter installed; cannot prove recompile-equivalence. \
         Install one (uv python install 3.14) - never silently pass."
    );
    let scratch: PathBuf = band_scratch(label);
    let mut checked_stable: usize = 0;
    let mut stable_source: Option<String> = None;
    for interp in &band {
        let (outcome, source): (BandOutcome, String) =
            recompile_equiv_inline(interp, program, label, &scratch);
        match outcome {
            BandOutcome::RecompileEquiv => {
                if !interp.is_prerelease {
                    checked_stable += 1;
                    if stable_source.is_none() {
                        stable_source = Some(source);
                    }
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
    stable_source.unwrap_or_default()
}

#[test]
fn finally_tail_return_survives_guarded_cleanup() {
    let recovered: String =
        recover_and_recompile("finally_tail_guarded_cleanup", FINALLY_TAIL_GUARDED_CLEANUP);
    assert!(
        recovered.contains("\n    return timing"),
        "the return that runs after a try/finally whose finally body branches must be recovered, \
         not dropped to an implicit return None\n--- recovered:\n{recovered}"
    );
    assert!(
        recovered.contains("\n    finally:\n        if flag:"),
        "the guarded finally body must stay intact\n--- recovered:\n{recovered}"
    );
}

#[test]
fn finally_tail_return_survives_negated_guard_cleanup() {
    let recovered: String =
        recover_and_recompile("finally_tail_negated_guard", FINALLY_TAIL_NEGATED_GUARD);
    assert!(
        recovered.contains("\n    return result"),
        "the return after a try/finally whose finally body branches on a negated guard must be \
         recovered, not dropped\n--- recovered:\n{recovered}"
    );
}
