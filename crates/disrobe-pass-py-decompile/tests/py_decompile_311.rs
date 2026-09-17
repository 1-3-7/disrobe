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

const BAND_ALIASES: &[&str] = &["3.9", "3.10", "3.11"];

const CASES: &[(&str, (u8, u8))] = &[
    ("assign_chained", (3, 9)),
    ("assign_starred_unpack", (3, 9)),
    ("call_star_double_mix", (3, 9)),
    ("class_inheritance", (3, 9)),
    ("comp_nested", (3, 9)),
    ("decorator_stacked", (3, 9)),
    ("def_full_signature", (3, 9)),
    ("def_kwonly", (3, 9)),
    ("fstring_simple", (3, 9)),
    ("if_shortcircuit_terminating", (3, 9)),
    ("try_except_else_finally", (3, 9)),
    ("try_except_reraise_finally", (3, 9)),
    ("try_finally", (3, 9)),
    ("try_finally_single_stmt", (3, 9)),
    ("try_import_star_module", (3, 9)),
    ("with_multi", (3, 9)),
    ("match_literal", (3, 10)),
    ("match_capture", (3, 10)),
    ("match_sequence", (3, 10)),
    ("match_mapping", (3, 10)),
    ("match_class", (3, 10)),
    ("match_or", (3, 10)),
    ("match_guard", (3, 10)),
    ("match_as", (3, 10)),
    ("except_star", (3, 11)),
];

#[test]
fn py_decompile_band_3_9_to_3_11() {
    let interpreters: Vec<BandInterpreter> = resolve_band(BAND_ALIASES, &[]);
    println!("=== BAND 3.9-3.11 INTERPRETERS ===");
    for i in &interpreters {
        println!("  {} -> {}", i.alias, i.path.display());
    }
    assert!(
        !interpreters.is_empty(),
        "no 3.9-3.11 interpreter installed; this band cannot prove recompile-equivalence. Install \
         one (uv python install 3.11) or remove the band from the matrix - never silently pass."
    );

    let scratch: PathBuf = band_scratch("band_311");
    let mut checked: usize = 0;
    let mut recompiled: usize = 0;
    let mut failures: Vec<String> = Vec::new();

    for interp in &interpreters {
        let (maj, min): (u8, u8) = parse_alias(interp.alias);
        for &(construct, floor) in CASES {
            if (maj, min) < floor {
                continue;
            }
            checked += 1;
            match recompile_equiv_construct(interp, construct, &scratch) {
                BandOutcome::RecompileEquiv => recompiled += 1,
                BandOutcome::SourceTokenMatch => {
                    failures.push(format!(
                        "py{} {construct}: token-match in an interpreter-present band is not allowed",
                        interp.alias
                    ));
                }
                BandOutcome::Tolerated(detail) => {
                    failures.push(format!(
                        "py{} {construct}: Tolerated outcome in a stable-only band is a real failure: {detail}",
                        interp.alias
                    ));
                }
                BandOutcome::Failed(e) => failures.push(e),
            }
        }
    }

    println!("=== BAND 3.9-3.11 SUMMARY: {recompiled}/{checked} recompile-equiv ===");
    assert!(
        failures.is_empty(),
        "{} band 3.9-3.11 recompile-equivalence failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(
        checked > 0,
        "band 3.9-3.11 evaluated 0 fixtures (vacuous); interpreters present but no in-band case ran"
    );
    assert!(
        recompiled >= 1,
        "band 3.9-3.11 proved 0 fixtures by recompile-equivalence; need >= 1 hard floor"
    );
}

fn parse_alias(alias: &str) -> (u8, u8) {
    let (maj, min): (&str, &str) = alias.split_once('.').expect("alias is X.Y");
    (
        maj.parse::<u8>().expect("major"),
        min.parse::<u8>().expect("minor"),
    )
}
