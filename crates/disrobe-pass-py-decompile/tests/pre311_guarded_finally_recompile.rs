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

const BAND: &[&str] = &["3.8", "3.9", "3.10"];

struct GuardedFinallyCase {
    label: &'static str,
    program: &'static str,
    required: &'static [&'static str],
}

const CASES: &[GuardedFinallyCase] = &[
    GuardedFinallyCase {
        label: "guard_only_finally",
        program: concat!(
            "def f(module):\n",
            "    if module is None:\n",
            "        try:\n",
            "            module = g(1)\n",
            "        finally:\n",
            "            h()\n",
            "    return module\n",
        ),
        required: &["if module is None:", "try:", "finally:"],
    },
    GuardedFinallyCase {
        label: "sibling_if_then_guarded_finally",
        program: concat!(
            "def f(a, module):\n",
            "    if a:\n",
            "        a = a.strip()\n",
            "    if module is None:\n",
            "        try:\n",
            "            module = g(1)\n",
            "        finally:\n",
            "            h()\n",
            "    return module\n",
        ),
        required: &["if a:", "if module is None:", "try:", "finally:"],
    },
    GuardedFinallyCase {
        label: "sibling_if_then_guarded_finally_no_tail",
        program: concat!(
            "def f(a, module):\n",
            "    if a:\n",
            "        a = a.strip()\n",
            "    if module is None:\n",
            "        try:\n",
            "            module = g(1)\n",
            "        finally:\n",
            "            h()\n",
        ),
        required: &["if a:", "if module is None:", "try:", "finally:"],
    },
    GuardedFinallyCase {
        label: "sibling_if_else_then_guarded_finally",
        program: concat!(
            "def f(a, module):\n",
            "    if a:\n",
            "        a = a.strip()\n",
            "    else:\n",
            "        a = None\n",
            "    if module is None:\n",
            "        try:\n",
            "            module = g(1)\n",
            "        finally:\n",
            "            h()\n",
            "    return module\n",
        ),
        required: &["if a:", "else:", "if module is None:", "finally:"],
    },
];

#[test]
fn a_leading_guard_survives_the_pre311_try_finally_it_encloses() {
    let band: Vec<BandInterpreter> = resolve_band(BAND, &[]);
    let resolved: Vec<&str> = band.iter().map(|b: &BandInterpreter| b.alias).collect();
    assert_eq!(
        band.len(),
        BAND.len(),
        "every interpreter in {BAND:?} is required to prove that a guard around a pre-3.11 \
         try/finally is not absorbed by the region it guards; resolved {resolved:?}"
    );
    let scratch: PathBuf = band_scratch("pre311-guarded-finally");
    let mut failures: Vec<String> = Vec::new();
    for interp in &band {
        for case in CASES {
            let (outcome, source): (BandOutcome, String) =
                recompile_equiv_inline(interp, case.program, case.label, &scratch);
            if !matches!(outcome, BandOutcome::RecompileEquiv) {
                failures.push(format!(
                    "{}/{}: did not recompile equivalently: {outcome:?}\n--- recovered:\n{source}",
                    interp.alias, case.label
                ));
                continue;
            }
            for needle in case.required {
                if !source.contains(needle) {
                    failures.push(format!(
                        "{}/{}: recovered source lost `{needle}`:\n{source}",
                        interp.alias, case.label
                    ));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "a pre-3.11 try/finally that sits inside an if statement must keep that if statement, \
         because the false arm of the guard lands between the inline finally copy and the handler \
         copy rather than after the whole region: {}",
        failures.join("\n\n")
    );
}
