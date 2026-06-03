#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_lines,
    clippy::doc_markdown
)]

mod common;

use std::path::PathBuf;

use common::band::{
    BandInterpreter, BandOutcome, band_scratch, find_interpreter, legacy_pycs_in_range,
    legacy_source_for, recompile_equiv_construct, recompile_equiv_legacy_pyc, resolve_band,
    source_token_match_legacy,
};

/// Band [3.0, 3.8]: the WORDCODE-but-pre-3.9 era. 3.6/3.7/3.8 ship on this machine and are proven by
/// real recompile-equivalence (construct cases at 3.8 + vendored legacy `.pyc` at 3.6/3.7/3.8). 3.0-3.5
/// have NO Windows interpreter, so those vendored legacy `.pyc` fall back to token-match vs the
/// ORIGINAL `.py` with a loud SKIP for the recompile leg - never silently passed.
const RECOMPILE_ALIASES: &[&str] = &["3.6", "3.7", "3.8"];

/// In-band construct subset that compiles on 3.8 (the construct corpus floor). Recompiled on the
/// 3.8 interpreter for a real round-trip proof at the top of the band.
const CASES_38: &[&str] = &[
    "assign_chained",
    "assign_starred_unpack",
    "call_star_double_mix",
    "class_inheritance",
    "comp_nested",
    "decorator_stacked",
    "def_full_signature",
    "def_kwonly",
    "fstring_simple",
    "try_except_else_finally",
    "with_multi",
];

/// Vendored legacy fixtures whose recovered source is value-equivalent but NOT byte-identical to the
/// ORIGINAL: either token-diff vs the `.py` (LOST_LITERAL spelling / STALE source revision) or
/// recompile-diff vs the `.pyc` (irreducible const fold). All are authoritatively documented in
/// `.claude/lost-literal-ledger.md` and proven irreducible by the `legacy_recompile` oracle. They are
/// recorded by name and skipped from the proof floors - never silently counted as a pass, never fudged
/// into a match. `nan_inf.3.8` is the const-fold case (source `1e300*1e300*0` folds to a `nan` const at
/// compile; no Python float literal folds to nan, so `float('-nan')` - a `CALL`, not the original
/// `LOAD_CONST` - is the irreducible best). Every other in-band fixture MUST recompile-equiv or
/// token-match.
const LOST_LITERAL_3X: &[&str] = &[
    "nan_inf.3.8",
    "op_precedence.3.5",
    "test_functions_py3.3.0",
    "test_functions_py3.3.4",
    "test_integers_py3.3.5",
    "unicode_future.3.3",
    "unicode_py3.3.3",
    "unpack_assign.3.0",
];

#[test]
fn py_decompile_band_3_0_to_3_8() {
    let interpreters: Vec<BandInterpreter> = resolve_band(RECOMPILE_ALIASES, &[]);
    println!("=== BAND 3.0-3.8 RECOMPILE INTERPRETERS (3.6/3.7/3.8) ===");
    for i in &interpreters {
        println!("  {} -> {}", i.alias, i.path.display());
    }
    let scratch: PathBuf = band_scratch("band_38");

    let mut recompiled: usize = 0;
    let mut token_matched: usize = 0;
    let mut lost_literal_skipped: usize = 0;
    let mut failures: Vec<String> = Vec::new();

    let interp_38: Option<&BandInterpreter> = interpreters.iter().find(|i| i.alias == "3.8");
    if let Some(interp) = interp_38 {
        for &construct in CASES_38 {
            match recompile_equiv_construct(interp, construct, &scratch) {
                BandOutcome::RecompileEquiv => recompiled += 1,
                BandOutcome::SourceTokenMatch => {
                    failures.push(format!(
                        "py3.8 {construct}: unexpected token-match in recompile leg"
                    ));
                }
                BandOutcome::Failed(e) => failures.push(e),
            }
        }
    } else {
        eprintln!("SKIP: no 3.8 interpreter for the construct-case recompile leg of band 3.0-3.8");
    }

    for (pyc, ver, stem) in legacy_pycs_in_range((3, 6), (3, 8)) {
        let alias: String = format!("{}.{}", ver.0, ver.1);
        let label: String = format!("{stem}.{alias}");
        let Some(interp): Option<BandInterpreter> =
            find_interpreter(&alias).map(|path: PathBuf| BandInterpreter {
                alias: leak_alias(ver),
                path,
                is_prerelease: false,
            })
        else {
            eprintln!("SKIP recompile {label}: no {alias} interpreter installed");
            continue;
        };
        match recompile_equiv_legacy_pyc(&interp, &pyc, &label, &scratch) {
            BandOutcome::RecompileEquiv => recompiled += 1,
            BandOutcome::SourceTokenMatch => {}
            BandOutcome::Failed(e) => {
                if LOST_LITERAL_3X.contains(&label.as_str()) {
                    eprintln!("SKIP lost-literal {label}: {e}");
                    lost_literal_skipped += 1;
                } else {
                    failures.push(e);
                }
            }
        }
    }

    for (pyc, ver, stem) in legacy_pycs_in_range((3, 0), (3, 5)) {
        let alias: String = format!("{}.{}", ver.0, ver.1);
        let label: String = format!("{stem}.{alias}");
        eprintln!(
            "SKIP recompile {label}: no {alias} interpreter on Windows - falling back to token-match vs ORIGINAL source"
        );
        let Some(source_path): Option<PathBuf> = legacy_source_for(&stem) else {
            failures.push(format!(
                "{label}: no vendored ORIGINAL source for token-match fallback"
            ));
            continue;
        };
        match source_token_match_legacy(&pyc, &source_path, &label) {
            BandOutcome::SourceTokenMatch => token_matched += 1,
            BandOutcome::RecompileEquiv => {}
            BandOutcome::Failed(e) => {
                if LOST_LITERAL_3X.contains(&label.as_str()) {
                    eprintln!("SKIP lost-literal {label}: {e}");
                    lost_literal_skipped += 1;
                } else {
                    failures.push(e);
                }
            }
        }
    }

    println!(
        "=== BAND 3.0-3.8 SUMMARY: recompile-equiv={recompiled}, token-match={token_matched}, \
         lost-literal-skipped={lost_literal_skipped} ==="
    );
    assert!(
        failures.is_empty(),
        "{} band 3.0-3.8 failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(
        recompiled >= 1,
        "band 3.0-3.8 proved 0 fixtures by recompile-equivalence; need >= 1 hard floor (3.6/3.7/3.8 \
         interpreter required)"
    );
    assert!(
        token_matched >= 1,
        "band 3.0-3.8 proved 0 pre-3.6 fixtures by token-match; the 3.0-3.5 fallback is vacuous"
    );
}

const fn leak_alias(ver: (u8, u8)) -> &'static str {
    match ver {
        (3, 6) => "3.6",
        (3, 7) => "3.7",
        (3, 8) => "3.8",
        _ => "3.x",
    }
}
