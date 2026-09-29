#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::doc_markdown
)]

mod common;

use std::path::PathBuf;

use common::band::{
    BandInterpreter, BandOutcome, band_scratch, recompile_equiv_construct, resolve_band,
};

const RECOMPILE_ALIASES: &[&str] = &["3.8"];

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

#[test]
fn py_decompile_band_3_8() {
    let interpreters: Vec<BandInterpreter> = resolve_band(RECOMPILE_ALIASES, &[]);
    let scratch: PathBuf = band_scratch("band_38");

    let mut recompiled: usize = 0;
    let mut failures: Vec<String> = Vec::new();

    let Some(interp): Option<&BandInterpreter> = interpreters.iter().find(|i| i.alias == "3.8")
    else {
        panic!(
            "CPython 3.8 is required for the construct-case recompile leg of band 3.8 (probed \
             `uv python find 3.8` and the known install paths); CI provisions it"
        );
    };
    println!(
        "=== BAND 3.8 RECOMPILE INTERPRETER -> {} ===",
        interp.path.display()
    );
    for &construct in CASES_38 {
        match recompile_equiv_construct(interp, construct, &scratch) {
            BandOutcome::RecompileEquiv => recompiled += 1,
            BandOutcome::Tolerated(detail) => {
                failures.push(format!(
                    "py3.8 {construct}: Tolerated outcome in a stable-only band is a real failure: {detail}"
                ));
            }
            BandOutcome::Failed(e) => failures.push(e),
        }
    }

    println!("=== BAND 3.8 SUMMARY: recompile-equiv={recompiled} ===");
    assert!(
        failures.is_empty(),
        "{} band 3.8 failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
