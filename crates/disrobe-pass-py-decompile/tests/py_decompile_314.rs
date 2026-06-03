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
    BandInterpreter, BandOutcome, band_scratch, recompile_equiv_construct, resolve_band,
};

/// Band [3.12, 3.15]: the exception-table / `type` statement / PEP-695 generics / PEP-750 t-string
/// era. 3.12-3.14 ship as GA builds and are gated hard; 3.15 ships only as a `3.15.0b1` pre-release
/// whose `LOAD_FAST_BORROW`/`FOR_ITER` jump indexing still drifts from the GA-frozen 3.14 shapes, so it
/// is driven jump-index-aware: a residual `CodeDiff` on 3.15 is reported (loud SKIP) but never lowers
/// the gate, exactly as the construct matrix treats the beta.
const BAND_ALIASES: &[&str] = &["3.12", "3.13", "3.14", "3.15"];
const PRERELEASE_ALIASES: &[&str] = &["3.15"];

/// In-band construct subset: general control/data constructs plus the era-defining features. `floor`
/// is the minimum minor a fixture compiles on (`type`/PEP-695 generics at 3.12, value-defaulted
/// generics and t-strings at 3.14), so a 3.14 t-string is never driven on 3.12.
const CASES: &[(&str, (u8, u8))] = &[
    ("assign_chained", (3, 12)),
    ("comp_nested", (3, 12)),
    ("for_nested", (3, 12)),
    ("try_except_else_finally", (3, 12)),
    ("with_multi", (3, 12)),
    ("match_class", (3, 12)),
    ("except_star", (3, 12)),
    ("type_alias", (3, 12)),
    ("type_params_func", (3, 12)),
    ("type_params_class", (3, 12)),
    ("type_params_bound", (3, 12)),
    ("type_params_paramspec", (3, 12)),
    ("generic_typevar_default", (3, 14)),
    ("generic_func_value_default", (3, 14)),
    ("generic_class_method_default", (3, 14)),
    ("tstr_plain", (3, 14)),
    ("tstr_conv_and_spec", (3, 14)),
    ("tstr_nested_fstring", (3, 14)),
];

#[test]
fn py_decompile_band_3_12_to_3_15() {
    let interpreters: Vec<BandInterpreter> = resolve_band(BAND_ALIASES, PRERELEASE_ALIASES);
    println!("=== BAND 3.12-3.15 INTERPRETERS ===");
    for i in &interpreters {
        println!(
            "  {} -> {} {}",
            i.alias,
            i.path.display(),
            if i.is_prerelease {
                "(prerelease, jump-index-aware)"
            } else {
                ""
            }
        );
    }
    assert!(
        !interpreters.is_empty(),
        "no 3.12-3.15 interpreter installed; this band cannot prove recompile-equivalence. Install \
         one (uv python install 3.14) or remove the band from the matrix - never silently pass."
    );

    let scratch: PathBuf = band_scratch("band_314");
    let mut checked_stable: usize = 0;
    let mut recompiled_stable: usize = 0;
    let mut prerelease_evaluated: usize = 0;
    let mut failures: Vec<String> = Vec::new();

    for interp in &interpreters {
        let (maj, min): (u8, u8) = parse_alias(interp.alias);
        for &(construct, floor) in CASES {
            if (maj, min) < floor {
                continue;
            }
            if interp.is_prerelease {
                prerelease_evaluated += 1;
            } else {
                checked_stable += 1;
            }
            match recompile_equiv_construct(interp, construct, &scratch) {
                BandOutcome::RecompileEquiv => {
                    if !interp.is_prerelease {
                        recompiled_stable += 1;
                    }
                }
                BandOutcome::SourceTokenMatch => failures.push(format!(
                    "py{} {construct}: token-match in an interpreter-present band is not allowed",
                    interp.alias
                )),
                BandOutcome::Failed(e) => failures.push(e),
            }
        }
    }

    println!(
        "=== BAND 3.12-3.15 SUMMARY: stable {recompiled_stable}/{checked_stable} recompile-equiv; \
         prerelease {prerelease_evaluated} evaluated (jump-index-aware, non-gating) ==="
    );
    assert!(
        failures.is_empty(),
        "{} band 3.12-3.15 stable recompile-equivalence failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(
        checked_stable > 0,
        "band 3.12-3.15 evaluated 0 stable fixtures (vacuous); a GA 3.12-3.14 interpreter must run"
    );
    assert!(
        recompiled_stable >= 1,
        "band 3.12-3.15 proved 0 stable fixtures by recompile-equivalence; need >= 1 hard floor"
    );
}

fn parse_alias(alias: &str) -> (u8, u8) {
    let (maj, min): (&str, &str) = alias.split_once('.').expect("alias is X.Y");
    (
        maj.parse::<u8>().expect("major"),
        min.parse::<u8>().expect("minor"),
    )
}
