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

const GUARD_ELSE_WITH_COLD_TRY: &str = "def guard_else_with_cold_try(flag, payload, fallback):\n    try:\n        head = parse_head(payload)\n    except ValueError:\n        raise ValueError(\"bad head\") from None\n    if flag:\n        try:\n            body, extra, stale = parse_body(payload)\n        except ValueError:\n            raise ValueError(\"bad body\") from None\n        else:\n            if stale:\n                raise ValueError(\"stale body\")\n            if extra:\n                head = refresh(head)\n    else:\n        body = default_body(fallback)\n    return combine(head, body)\n";

const GUARD_NO_ELSE_WITH_COLD_TRY: &str = "def guard_no_else_with_cold_try(flag, payload):\n    try:\n        head = parse_head(payload)\n    except ValueError:\n        raise ValueError(\"bad head\") from None\n    if flag:\n        try:\n            head = parse_body(payload, head)\n        except ValueError:\n            raise ValueError(\"bad body\") from None\n    tail = finalize(head)\n    return tail\n";

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
fn cold_sibling_guard_keeps_default_else_attached() {
    let recovered: String =
        recover_and_recompile("cold_sibling_guard_else", GUARD_ELSE_WITH_COLD_TRY);
    assert!(
        recovered.contains("\n    else:\n        body = default_body(fallback)"),
        "the guard's else that sets the fall-through default must stay attached to the guard, not \
         relocate to the function tail\n--- recovered:\n{recovered}"
    );
    assert!(
        recovered.contains("\n        if extra:") && recovered.contains("\n        if stale:"),
        "the try's else-arm statements belong inside the guard's then-arm (8-space indent), not at \
         function-body level\n--- recovered:\n{recovered}"
    );
}

#[test]
fn cold_sibling_guard_without_else_keeps_tail_as_sibling() {
    let recovered: String =
        recover_and_recompile("cold_sibling_guard_no_else", GUARD_NO_ELSE_WITH_COLD_TRY);
    assert!(
        recovered.contains("\n    tail = finalize(head)"),
        "a fall-through continuation after a guarded cold-sibling try must stay a sibling at \
         function-body level, never be pulled into an else the source never wrote\n\
         --- recovered:\n{recovered}"
    );
    assert!(
        !recovered.contains("else:"),
        "the guard has no else in the source, so none may appear in the recovery\n--- recovered:\n\
         {recovered}"
    );
}
