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
    legacy_source_for, recompile_equiv_legacy_pyc, source_token_match_legacy,
};

/// Band [1.0, 2.7]: the pre-wordcode Python-2 / Python-1 era. Only 2.7 ships on this machine, so 2.7
/// vendored legacy `.pyc` are proven by real recompile-equivalence (decompile -> recompile on CPython
/// 2.7 -> `semantic_equiv` against the ORIGINAL `.pyc`). 1.0-2.6 have NO interpreter anywhere, so their
/// vendored `.pyc` fall back to token-match vs the ORIGINAL `.py` with a loud SKIP for the recompile
/// leg - honest, never silently passed. This is the interpreter-blocked floor of the matrix.
const RECOMPILE_ALIAS: &str = "2.7";

/// Vendored 1.0-2.7 legacy fixtures whose recovered source is value-equivalent but NOT byte-identical
/// to the ORIGINAL: token-diff vs the `.py` (Python-2 print-statement spelling, hex/`L` int suffix,
/// `u`/`b` prefix, trailing-comma print merge, bare-vs-parenthesized unpack target) or recompile-diff
/// vs the `.pyc` (`nan_inf.2.7`: the irreducible `nan` const fold - `float('-nan')` is a `CALL`, not the
/// original `LOAD_CONST`). All are LOST_LITERAL surface the marshalled bytecode physically cannot carry,
/// authoritatively documented in `.claude/lost-literal-ledger.md` and proven irreducible by the
/// `legacy_recompile` oracle. Recorded by name and skipped from the proof floors - never fudged into a
/// match. Everything else MUST recompile-equiv (2.7) or token-match (1.0-2.6).
const LOST_LITERAL_PRE_27: &[&str] = &[
    "nan_inf.2.7",
    "test_class.1.5",
    "test_class.2.2",
    "test_class.2.5",
    "test_class_method.2.2",
    "test_class_method.2.5",
    "test_global.2.2",
    "test_global.2.5",
    "test_integers.1.5",
    "test_integers.2.2",
    "test_integers.2.5",
    "test_misc.1.5",
    "test_misc.2.2",
    "test_misc.2.5",
    "test_yield.2.2",
    "test_yield.2.5",
    "unicode.2.6",
    "unicode_future.2.6",
    "unpack_assign.1.0",
    "unpack_assign.1.5",
    "unpack_assign.2.2",
    "unpack_assign.2.5",
];

#[test]
fn py_decompile_band_1_0_to_2_7() {
    let scratch: PathBuf = band_scratch("band_27");
    let interp_27: Option<BandInterpreter> =
        find_interpreter(RECOMPILE_ALIAS).map(|path: PathBuf| BandInterpreter {
            alias: RECOMPILE_ALIAS,
            path,
            is_prerelease: false,
        });
    match &interp_27 {
        Some(i) => println!(
            "=== BAND 1.0-2.7 RECOMPILE INTERPRETER 2.7 -> {} ===",
            i.path.display()
        ),
        None => eprintln!("SKIP: no 2.7 interpreter; the 2.7 recompile leg is unavailable"),
    }

    let mut recompiled: usize = 0;
    let mut token_matched: usize = 0;
    let mut lost_literal_skipped: usize = 0;
    let mut failures: Vec<String> = Vec::new();

    if let Some(interp) = interp_27.as_ref() {
        for (pyc, ver, stem) in legacy_pycs_in_range((2, 7), (2, 7)) {
            let label: String = format!("{stem}.{}.{}", ver.0, ver.1);
            match recompile_equiv_legacy_pyc(interp, &pyc, &label, &scratch) {
                BandOutcome::RecompileEquiv => recompiled += 1,
                BandOutcome::SourceTokenMatch => {}
                BandOutcome::Failed(e) => {
                    if LOST_LITERAL_PRE_27.contains(&label.as_str()) {
                        eprintln!("SKIP lost-literal {label}: {e}");
                        lost_literal_skipped += 1;
                    } else {
                        failures.push(e);
                    }
                }
            }
        }
    }

    for (pyc, ver, stem) in legacy_pycs_in_range((1, 0), (2, 6)) {
        let label: String = format!("{stem}.{}.{}", ver.0, ver.1);
        eprintln!(
            "SKIP recompile {label}: no {}.{} interpreter exists - falling back to token-match vs ORIGINAL source",
            ver.0, ver.1
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
                if LOST_LITERAL_PRE_27.contains(&label.as_str()) {
                    eprintln!("SKIP lost-literal {label}: {e}");
                    lost_literal_skipped += 1;
                } else {
                    failures.push(e);
                }
            }
        }
    }

    println!(
        "=== BAND 1.0-2.7 SUMMARY: recompile-equiv={recompiled}, token-match={token_matched}, \
         lost-literal-skipped={lost_literal_skipped} ==="
    );
    assert!(
        failures.is_empty(),
        "{} band 1.0-2.7 failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(
        token_matched >= 1,
        "band 1.0-2.7 proved 0 pre-2.7 fixtures by token-match; the interpreter-blocked fallback is \
         vacuous - the vendored 1.0-2.6 corpus must drive at least one real fixture"
    );
    if interp_27.is_some() {
        assert!(
            recompiled >= 1,
            "band 1.0-2.7 has a 2.7 interpreter but proved 0 fixtures by recompile-equivalence; the \
             2.7 recompile leg is vacuous"
        );
    } else {
        eprintln!(
            "SKIP recompile-floor: no 2.7 interpreter; band proven by token-match only ({token_matched} matched)"
        );
    }
}
