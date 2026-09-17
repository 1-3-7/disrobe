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

const TARGET_VERSIONS: &[&str] = &["3.13", "3.14"];
const PRERELEASE: &[&str] = &["3.15"];

const ELIF_AFTER_GUARDED_COLD_TRY: &str = "def elif_after_guarded_cold_try(system, release, version):\n    if system == 'SunOS':\n        parts = release.split('.')\n        if parts:\n            try:\n                major = int(parts[0])\n            except ValueError:\n                pass\n            else:\n                major = major - 3\n        if release < '6':\n            system = 'Solaris'\n        else:\n            system = 'Solaris'\n    elif system in ('win32', 'win16'):\n        system = 'Windows'\n    return system, release, version\n";

const GENUINE_NESTED_ELIF_ARM: &str = "def genuine_nested_elif_after_cold_try(system, release, version):\n    if system == 'SunOS':\n        parts = release.split('.')\n        if parts:\n            try:\n                major = int(parts[0])\n            except ValueError:\n                pass\n            else:\n                major = major - 3\n        if release < '6':\n            system = 'Solaris'\n        else:\n            system = 'Solaris'\n    elif system in ('win32', 'win16'):\n        if release:\n            system = 'Windows'\n        else:\n            system = 'DOS'\n    return system, release, version\n";

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
fn inner_else_does_not_absorb_following_elif() {
    let recovered: String =
        recover_and_recompile("elif_after_guarded_cold_try", ELIF_AFTER_GUARDED_COLD_TRY);
    assert_eq!(
        recovered
            .matches("system in (\"win32\", \"win16\")")
            .count(),
        1,
        "the win32/win16 membership test must appear once as the outer elif; a second occurrence \
         means the inner else absorbed the elif into itself\n--- recovered:\n{recovered}"
    );
    assert!(
        recovered.contains("except ValueError:"),
        "the guarded cold try must survive; capping the then-arm at the elif boundary must not \
         drop the tail handler\n--- recovered:\n{recovered}"
    );
    assert!(
        recovered
            .contains("\n    elif system in (\"win32\", \"win16\"):\n        system = \"Windows\""),
        "the elif belongs to the outer guard, not nested inside the inner else\n--- recovered:\n\
         {recovered}"
    );
}

#[test]
fn genuinely_nested_elif_arm_stays_intact() {
    let recovered: String = recover_and_recompile(
        "genuine_nested_elif_after_cold_try",
        GENUINE_NESTED_ELIF_ARM,
    );
    assert!(
        recovered.contains("\n    elif system in (\"win32\", \"win16\"):\n        if release:"),
        "a genuinely nested if inside the elif arm must be preserved, proving the then-arm cap \
         does not truncate legitimate sibling-arm content\n--- recovered:\n{recovered}"
    );
    assert!(
        recovered.contains("system = \"DOS\""),
        "the elif arm's else branch must survive intact\n--- recovered:\n{recovered}"
    );
}
