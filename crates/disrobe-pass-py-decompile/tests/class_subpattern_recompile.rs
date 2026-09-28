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

const MATCH_VERSIONS: &[&str] = &["3.10", "3.11", "3.12", "3.13", "3.14"];
const PRERELEASE: &[&str] = &["3.15"];
const REFUSAL: &str = "decompile-error: ast builder desync";
const MATCH_REFUSAL: &str = "a match case holds a sub-pattern the recovery cannot read";

fn assert_graded(label: &str, program: &str, refusal_allowed: bool) {
    assert_graded_on(MATCH_VERSIONS, label, program, refusal_allowed);
}

fn assert_graded_on(
    versions: &'static [&'static str],
    label: &str,
    program: &str,
    refusal_allowed: bool,
) {
    let band: Vec<BandInterpreter> = resolve_band(versions, PRERELEASE);
    assert!(
        !band.is_empty(),
        "{label}: no CPython 3.10+ interpreter installed; cannot grade class patterns"
    );
    let scratch: PathBuf = band_scratch(label);
    let mut graded_stable: usize = 0;
    let mut failures: Vec<String> = Vec::new();
    for interp in &band {
        let (outcome, source): (BandOutcome, String) =
            recompile_equiv_inline(interp, program, label, &scratch);
        match outcome {
            BandOutcome::RecompileEquiv => {}
            BandOutcome::Failed(_)
                if refusal_allowed
                    && source.contains(REFUSAL)
                    && source.contains(MATCH_REFUSAL) => {}
            other if interp.is_prerelease => {
                eprintln!("SKIP prerelease {label} py{}: {other:?}", interp.alias);
                continue;
            }
            other => {
                failures.push(format!(
                    "py{}: {other:?}\n--- recovered:\n{source}",
                    interp.alias
                ));
                continue;
            }
        }
        if !interp.is_prerelease {
            graded_stable += 1;
        }
    }
    assert!(
        failures.is_empty(),
        "{label}: a class sub-pattern must recover or be refused, never be widened or invented:\n{}",
        failures.join("\n\n")
    );
    assert!(
        graded_stable > 0,
        "{label}: no stable interpreter graded the case (vacuous)"
    );
}

#[test]
fn a_nested_class_pattern_in_a_keyword_slot_is_not_widened() {
    assert_graded(
        "class_subpattern_nested_keyword",
        "def f(p):\n    match p:\n        case Point(x=Point(y=0)):\n            return 1\n        \
         case _:\n            return 2\n",
        true,
    );
}

#[test]
fn a_sequence_pattern_in_a_positional_slot_is_not_widened() {
    assert_graded(
        "class_subpattern_sequence_positional",
        "def f(p):\n    match p:\n        case Point(0, [a, b]):\n            return a + b\n        \
         case _:\n            return 0\n",
        true,
    );
}

#[test]
fn an_or_pattern_in_a_keyword_slot_is_not_widened() {
    assert_graded(
        "class_subpattern_or_keyword",
        "def f(p):\n    match p:\n        case Point(x=1 | 2, y=v):\n            return v\n        \
         case _:\n            return 0\n",
        true,
    );
}

#[test]
fn a_lone_class_case_keeps_its_subject_wildcards_and_captures() {
    assert_graded(
        "class_subpattern_wildcard_capture",
        "def f(p):\n    match p:\n        case Point(_, y, z=_):\n            return y\n        \
         case _:\n            return 0\n",
        false,
    );
}

#[test]
fn class_cases_with_literal_slots_recover_when_the_subject_is_copied() {
    assert_graded(
        "class_subpattern_literal_slots",
        "def f(p):\n    match p:\n        case Point(0, y=1):\n            return 1\n        \
         case Point(x, y=2):\n            return x\n        case _:\n            return 0\n",
        false,
    );
}

#[test]
fn a_dotted_class_keeps_its_attribute_path() {
    assert_graded(
        "class_subpattern_dotted_class",
        "import collections\n\ndef f(p):\n    match p:\n        case collections.OrderedDict():\n            \
         return 1\n        case _:\n            return 0\n",
        false,
    );
}

#[test]
fn a_class_held_in_a_parameter_is_not_rendered_as_none() {
    assert_graded(
        "class_subpattern_local_class",
        "def f(p, C):\n    match p:\n        case C(x=v):\n            return v\n        case _:\n            \
         return 0\n",
        true,
    );
}

#[test]
fn a_class_pattern_inside_a_sequence_is_recovered_or_refused() {
    assert_graded_on(
        MATCH_VERSIONS,
        "class_subpattern_inside_sequence",
        "def f(x):\n    match x:\n        case [Response(status=200), *_]:\n            return 1\n        \
         case _:\n            return 0\n",
        true,
    );
}
