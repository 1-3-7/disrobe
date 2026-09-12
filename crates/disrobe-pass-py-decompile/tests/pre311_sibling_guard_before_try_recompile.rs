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

const CPYTHON_310: &[&str] = &["3.10"];

struct SiblingGuardCase {
    label: &'static str,
    program: &'static str,
    required: &'static [&'static str],
}

const CASES: &[SiblingGuardCase] = &[
    SiblingGuardCase {
        label: "sibling_guard_tail_try",
        program: concat!(
            "def f(a, module):\n",
            "    if a:\n",
            "        a = a.strip()\n",
            "    if module is None:\n",
            "        try:\n",
            "            module = g(1)\n",
            "        except ValueError:\n",
            "            pass\n",
        ),
        required: &["if a:", "if module is None:", "try:", "except ValueError:"],
    },
    SiblingGuardCase {
        label: "sibling_guard_try_then_tail",
        program: concat!(
            "def f(a, module):\n",
            "    if a:\n",
            "        a = a.strip()\n",
            "    if module is None:\n",
            "        try:\n",
            "            module = g(1)\n",
            "        except ValueError:\n",
            "            pass\n",
            "    return module\n",
        ),
        required: &["if a:", "if module is None:", "return module"],
    },
    SiblingGuardCase {
        label: "sibling_guard_after_if_else",
        program: concat!(
            "def f(a, module):\n",
            "    if a:\n",
            "        a = a.strip()\n",
            "    else:\n",
            "        a = None\n",
            "    if module is None:\n",
            "        try:\n",
            "            module = g(1)\n",
            "        except ValueError:\n",
            "            pass\n",
        ),
        required: &["if a:", "else:", "if module is None:"],
    },
    SiblingGuardCase {
        label: "sibling_guard_after_elif_chain",
        program: concat!(
            "def f(a, b, module):\n",
            "    if a:\n",
            "        a = a.strip()\n",
            "    elif b:\n",
            "        a = b\n",
            "    if module is None:\n",
            "        try:\n",
            "            module = g(1)\n",
            "        except ValueError:\n",
            "            module = 0\n",
            "    return module\n",
        ),
        required: &[
            "if a:",
            "elif b:",
            "if module is None:",
            "except ValueError:",
        ],
    },
];

#[test]
fn a_guard_after_a_sibling_if_keeps_its_try_region_on_310() {
    let band: Vec<BandInterpreter> = resolve_band(CPYTHON_310, &[]);
    assert_eq!(
        band.len(),
        1,
        "CPython 3.10 is required to prove pre-3.11 recovery of a guarded try that follows a \
         sibling if statement"
    );
    let scratch: PathBuf = band_scratch("pre311-sibling-guard-before-try");
    let mut failures: Vec<String> = Vec::new();
    for case in CASES {
        let (outcome, source): (BandOutcome, String) =
            recompile_equiv_inline(&band[0], case.program, case.label, &scratch);
        if !matches!(outcome, BandOutcome::RecompileEquiv) {
            failures.push(format!(
                "{}: did not recompile equivalently: {outcome:?}\n--- recovered:\n{source}",
                case.label
            ));
            continue;
        }
        for needle in case.required {
            assert!(
                source.contains(needle),
                "{}: recovered source lost `{needle}`:\n{source}",
                case.label
            );
        }
    }
    assert!(
        failures.is_empty(),
        "a leading sibling `if` must not absorb the guard of the try or with region that follows \
         it: {}",
        failures.join("\n\n")
    );
}
