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

const LEGACY_WITH_BAND: &[&str] = &["3.8", "3.9", "3.10", "3.11", "3.12", "3.13"];

#[derive(Debug, PartialEq, Eq)]
enum Emission {
    Recovered,
    Refused,
    NotEquivalent,
}

struct GuardCase {
    label: &'static str,
    program: &'static str,
    required: &'static [&'static str],
    forbidden: &'static [&'static str],
    open_on: &'static [&'static str],
    open_reason: &'static str,
}

const CPYTHON_38_WITH_TAIL: &str = concat!(
    "CPython 3.8 lowers the with epilogue through BEGIN_FINALLY and END_FINALLY, which decode to ",
    "no operation, so the statement after the region has no jump to anchor it and is still ",
    "dropped. This predates the guard work and an unguarded with loses its tail the same way."
);

const CASES: &[GuardCase] = &[
    GuardCase {
        label: "guard_with_after_sibling_if",
        program: concat!(
            "def f(a, m, p):\n",
            "    if a:\n",
            "        a = a.strip()\n",
            "    if m is None:\n",
            "        with open(p) as h:\n",
            "            m = h.read()\n",
            "    return m\n",
        ),
        required: &["if a:", "if m is None:", "with open(p) as h:", "return m"],
        forbidden: &[],
        open_on: &[],
        open_reason: "",
    },
    GuardCase {
        label: "guard_with_without_sibling",
        program: concat!(
            "def f(m, p):\n",
            "    if m is None:\n",
            "        with open(p) as h:\n",
            "            m = h.read()\n",
            "    return m\n",
        ),
        required: &["if m is None:", "with open(p) as h:", "return m"],
        forbidden: &[],
        open_on: &[],
        open_reason: "",
    },
    GuardCase {
        label: "guard_with_after_sibling_if_no_tail",
        program: concat!(
            "def f(a, m, p):\n",
            "    if a:\n",
            "        a = a.strip()\n",
            "    if m is None:\n",
            "        with open(p) as h:\n",
            "            m = h.read()\n",
        ),
        required: &["if a:", "if m is None:", "with open(p) as h:"],
        forbidden: &[],
        open_on: &[],
        open_reason: "",
    },
    GuardCase {
        label: "guard_with_after_if_else",
        program: concat!(
            "def f(a, m, p):\n",
            "    if a:\n",
            "        a = a.strip()\n",
            "    else:\n",
            "        a = None\n",
            "    if m is None:\n",
            "        with open(p) as h:\n",
            "            m = h.read()\n",
            "    return m\n",
        ),
        required: &["if a:", "else:", "if m is None:", "with open(p) as h:"],
        forbidden: &[],
        open_on: &[],
        open_reason: "",
    },
    GuardCase {
        label: "guard_with_after_elif_chain",
        program: concat!(
            "def f(a, b, m, p):\n",
            "    if a:\n",
            "        a = a.strip()\n",
            "    elif b:\n",
            "        a = b\n",
            "    if m is None:\n",
            "        with open(p) as h:\n",
            "            m = h.read()\n",
            "    return m\n",
        ),
        required: &["if a:", "elif b:", "if m is None:", "with open(p) as h:"],
        forbidden: &[],
        open_on: &[],
        open_reason: "",
    },
    GuardCase {
        label: "guard_with_nested_guards",
        program: concat!(
            "def f(a, m, p):\n",
            "    if a:\n",
            "        if m is None:\n",
            "            with open(p) as h:\n",
            "                m = h.read()\n",
            "    return m\n",
        ),
        required: &["m is None", "with open(p) as h:", "return m"],
        forbidden: &[],
        open_on: &[],
        open_reason: "",
    },
    GuardCase {
        label: "guard_with_side_effect_test",
        program: concat!(
            "def f(a, m, p):\n",
            "    if a:\n",
            "        a = a.strip()\n",
            "    if g(m):\n",
            "        with open(p) as h:\n",
            "            m = h.read()\n",
            "    return m\n",
        ),
        required: &["if a:", "if g(m):", "with open(p) as h:"],
        forbidden: &[],
        open_on: &[],
        open_reason: "",
    },
    GuardCase {
        label: "terminating_guard_after_sibling_if",
        program: concat!(
            "def f(a, gz, p):\n",
            "    if a:\n",
            "        a = a.strip()\n",
            "    if not gz:\n",
            "        raise NotImplementedError\n",
            "    with open(p) as h:\n",
            "        m = h.read()\n",
            "    return m\n",
        ),
        required: &[
            "if a:",
            "if not gz:",
            "raise NotImplementedError",
            "with open(p) as h:",
        ],
        forbidden: &[],
        open_on: &["3.8"],
        open_reason: CPYTHON_38_WITH_TAIL,
    },
    GuardCase {
        label: "terminating_guard_without_sibling",
        program: concat!(
            "def f(a, p):\n",
            "    if a:\n",
            "        return None\n",
            "    with open(p) as h:\n",
            "        m = h.read()\n",
            "    return m\n",
        ),
        required: &["if a:", "with open(p) as h:", "return m"],
        forbidden: &[],
        open_on: &["3.8"],
        open_reason: CPYTHON_38_WITH_TAIL,
    },
    GuardCase {
        label: "guard_with_else_arm",
        program: concat!(
            "def f(m, p):\n",
            "    if m is None:\n",
            "        with open(p) as h:\n",
            "            m = h.read()\n",
            "    else:\n",
            "        m = m.strip()\n",
            "    return m\n",
        ),
        required: &["if m is None:", "with open(p) as h:", "m.strip()"],
        forbidden: &[],
        open_on: &[],
        open_reason: "",
    },
    GuardCase {
        label: "with_then_trailing_statement",
        program: concat!(
            "def f(p):\n",
            "    with open(p) as h:\n",
            "        m = h.read()\n",
            "    m = m.strip()\n",
            "    return m\n",
        ),
        required: &["with open(p) as h:", "m = m.strip()", "return m"],
        forbidden: &["if "],
        open_on: &["3.8"],
        open_reason: CPYTHON_38_WITH_TAIL,
    },
    GuardCase {
        label: "unguarded_with_invents_no_guard",
        program: concat!(
            "def f(p):\n",
            "    m = None\n",
            "    with open(p) as h:\n",
            "        m = h.read()\n",
            "    return m\n",
        ),
        required: &["with open(p) as h:", "return m"],
        forbidden: &["if ", "else:", "elif "],
        open_on: &["3.8"],
        open_reason: CPYTHON_38_WITH_TAIL,
    },
    GuardCase {
        label: "guard_finally_after_sibling_if",
        program: concat!(
            "def f(a, m):\n",
            "    if a:\n",
            "        a = a.strip()\n",
            "    if m is None:\n",
            "        try:\n",
            "            m = g(1)\n",
            "        finally:\n",
            "            h(2)\n",
            "    return m\n",
        ),
        required: &["if a:", "if m is None:", "try:", "finally:", "return m"],
        forbidden: &[],
        open_on: &[],
        open_reason: "",
    },
    GuardCase {
        label: "guard_finally_without_sibling",
        program: concat!(
            "def f(m):\n",
            "    if m is None:\n",
            "        try:\n",
            "            m = g(1)\n",
            "        finally:\n",
            "            h(2)\n",
            "    return m\n",
        ),
        required: &["if m is None:", "try:", "finally:", "return m"],
        forbidden: &[],
        open_on: &[],
        open_reason: "",
    },
    GuardCase {
        label: "guard_except_after_sibling_if",
        program: concat!(
            "def f(a, m):\n",
            "    if a:\n",
            "        a = a.strip()\n",
            "    if m is None:\n",
            "        try:\n",
            "            m = g(1)\n",
            "        except ValueError:\n",
            "            pass\n",
            "    return m\n",
        ),
        required: &["if a:", "if m is None:", "except ValueError:"],
        forbidden: &[],
        open_on: &[],
        open_reason: "",
    },
];

fn classify(outcome: &BandOutcome, source: &str) -> Emission {
    match outcome {
        BandOutcome::RecompileEquiv => Emission::Recovered,
        BandOutcome::Failed(_) if source.trim().is_empty() || source.contains("__DR_") => {
            Emission::Refused
        }
        BandOutcome::Failed(detail) if detail.contains("compile failed") => Emission::Refused,
        BandOutcome::SourceTokenMatch | BandOutcome::Tolerated(_) | BandOutcome::Failed(_) => {
            Emission::NotEquivalent
        }
    }
}

#[test]
fn a_guarded_with_or_try_region_keeps_its_guard_across_the_legacy_band() {
    let band: Vec<BandInterpreter> = resolve_band(LEGACY_WITH_BAND, &[]);
    assert_eq!(
        band.len(),
        LEGACY_WITH_BAND.len(),
        "every interpreter in {LEGACY_WITH_BAND:?} is required: the guard of a with or try region \
         is encoded differently before and after CPython 3.11, and a missing band would leave one \
         encoding ungraded"
    );
    for case in CASES {
        assert!(
            case.open_on.is_empty() == case.open_reason.is_empty(),
            "{}: an interpreter left out of this pin needs a recorded reason, and a case with no \
             exclusions must not carry one",
            case.label
        );
        for alias in case.open_on {
            assert!(
                LEGACY_WITH_BAND.contains(alias),
                "{}: open_on names {alias}, which this test never measures",
                case.label
            );
        }
    }
    let scratch: PathBuf = band_scratch("guarded-with-region");
    let mut failures: Vec<String> = Vec::new();
    for interp in &band {
        for case in CASES {
            let (outcome, source): (BandOutcome, String) =
                recompile_equiv_inline(interp, case.program, case.label, &scratch);
            let emission: Emission = classify(&outcome, &source);
            let pinned_open: bool = case.open_on.contains(&interp.alias);
            for needle in case.forbidden {
                if source.contains(needle) {
                    failures.push(format!(
                        "{} {}: recovered source invented `{needle}` that the original does not \
                         contain\n--- recovered:\n{source}",
                        interp.alias, case.label
                    ));
                }
            }
            if pinned_open {
                if emission == Emission::Recovered {
                    failures.push(format!(
                        "{} {}: pinned open and now recovers, so remove {} from open_on. The \
                         recorded reason was: {}",
                        interp.alias, case.label, interp.alias, case.open_reason
                    ));
                }
                continue;
            }
            if emission != Emission::Recovered {
                failures.push(format!(
                    "{} {}: {emission:?} ({outcome:?})\n--- recovered:\n{source}",
                    interp.alias, case.label
                ));
                continue;
            }
            for needle in case.required {
                if !source.contains(needle) {
                    failures.push(format!(
                        "{} {}: recovered source recompiles but lost `{needle}`, which is the \
                         shape this case exists to pin\n--- recovered:\n{source}",
                        interp.alias, case.label
                    ));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "a with or try region that a conditional encloses must recover with that conditional, and \
         a region no conditional encloses must not gain one. `NotEquivalent` marks source that \
         was emitted and is wrong, which the band figure counts as a plain miss: {}",
        failures.join("\n\n")
    );
}
