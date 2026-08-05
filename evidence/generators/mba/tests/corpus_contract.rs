#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use disrobe_evidence_mba::corpus::{Case, Entry, Provenance, Truth, build_entry, render};
use disrobe_evidence_mba::equiv::equivalent;
use disrobe_evidence_mba::error::GeneratorError;
use disrobe_evidence_mba::parse::{VarMap, parse_infix, parse_prefix, scan_identifiers};
use disrobe_evidence_mba::plan::generate_in_house;
use disrobe_evidence_mba::term::{Term, Width};
use disrobe_evidence_mba::{CASES_FILE, TRUTH_FILE, assemble, corpus_dir};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
}

fn committed(name: &str) -> String {
    let path: PathBuf = corpus_dir(&repository_root()).join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

#[test]
fn regeneration_is_byte_identical_from_the_recorded_seeds() {
    let root: PathBuf = repository_root();
    let (first, _): (Vec<Entry>, Vec<String>) = assemble(&root, 1).expect("assemble at one worker");
    let (second, _): (Vec<Entry>, Vec<String>) =
        assemble(&root, 4).expect("assemble at four workers");
    let (first_cases, first_truths): (String, String) = render(&first).expect("render");
    let (second_cases, second_truths): (String, String) = render(&second).expect("render");
    assert_eq!(
        first_cases, second_cases,
        "case output differs between one and four workers"
    );
    assert_eq!(
        first_truths, second_truths,
        "truth output differs between one and four workers"
    );
    assert_eq!(
        first_cases,
        committed(CASES_FILE),
        "the committed cases file is not what the recorded seeds regenerate"
    );
    assert_eq!(
        first_truths,
        committed(TRUTH_FILE),
        "the committed truth file is not what the recorded seeds regenerate"
    );
}

#[test]
fn repeated_generation_is_stable_within_a_single_worker_count() {
    let first: Vec<Entry> = generate_in_house(2).expect("generate");
    let second: Vec<Entry> = generate_in_house(2).expect("generate");
    assert_eq!(
        first, second,
        "generation is not reproducible from its seeds"
    );
}

#[test]
fn a_broken_pair_is_refused_before_it_reaches_the_corpus() {
    let original: Term = Term::add(Term::var(0), Term::var(1));
    let wrong: Term = Term::xor(Term::var(0), Term::var(1));
    let provenance: Provenance<'_> = Provenance {
        source: "in-house",
        generator: "contract test",
        transform: "broken",
        seed: 7,
    };
    let refused: Result<Entry, GeneratorError> =
        build_entry("broken", provenance, &original, &wrong, Width::W8);
    assert!(
        matches!(refused, Err(GeneratorError::NotAnIdentity { .. })),
        "an expression that is not an identity of the original must be refused, got {refused:?}"
    );

    let identical: Result<Entry, GeneratorError> =
        build_entry("degenerate", provenance, &original, &original, Width::W8);
    assert!(
        matches!(identical, Err(GeneratorError::DegenerateEntry { .. })),
        "a transform that changed nothing must be refused, got {identical:?}"
    );
}

#[test]
fn every_committed_entry_is_an_identity_at_its_declared_width() {
    let cases: Vec<Case> = committed(CASES_FILE)
        .lines()
        .filter(|line: &&str| !line.trim().is_empty())
        .map(|line: &str| serde_json::from_str::<Case>(line).expect("case record"))
        .collect();
    let truths: Vec<Truth> = committed(TRUTH_FILE)
        .lines()
        .filter(|line: &&str| !line.trim().is_empty())
        .map(|line: &str| serde_json::from_str::<Truth>(line).expect("truth record"))
        .collect();
    assert_eq!(cases.len(), truths.len());
    assert!(!cases.is_empty(), "the committed corpus is empty");

    let mut identifiers: BTreeSet<&str> = BTreeSet::new();
    for (case, truth) in cases.iter().zip(truths.iter()) {
        assert_eq!(case.id, truth.id, "case and truth records are misaligned");
        assert!(
            identifiers.insert(case.id.as_str()),
            "duplicate id {}",
            case.id
        );
        let width: Width = Width::from_bits(case.width)
            .unwrap_or_else(|| panic!("{}: unsupported width {}", case.id, case.width));
        let obfuscated: Term = parse_prefix(&case.obfuscated).expect("obfuscated term parses");
        let original: Term = parse_prefix(&truth.original).expect("original term parses");
        assert_ne!(
            obfuscated, original,
            "{}: the transform is degenerate",
            case.id
        );
        let var_count: u32 = original.var_count().max(obfuscated.var_count());
        assert!(
            equivalent(&original, &obfuscated, width, var_count),
            "{}: the committed pair is not an identity",
            case.id
        );
        for check in &truth.checks {
            assert_eq!(
                original.eval(&check.inputs, width),
                check.output,
                "{}: a committed check vector does not match the original",
                case.id
            );
        }
    }
}

#[test]
fn infix_parsing_follows_the_published_operator_precedence() {
    let names: BTreeSet<String> = scan_identifiers("x y z");
    let vars: VarMap = VarMap::from_names(&names);
    let cases: [(&str, &str); 6] = [
        ("x|y&z", "(v0 | (v1 & v2))"),
        ("x^y&z", "(v0 ^ (v1 & v2))"),
        ("x&y+z", "(v0 & (v1 + v2))"),
        ("x+y*z", "(v0 + (v1 * v2))"),
        ("~x+y", "((~v0) + v1)"),
        ("x-y-z", "((v0 - v1) - v2)"),
    ];
    for (text, expected) in cases {
        let parsed: Term = parse_infix(text, &vars, "precedence").expect("parse");
        assert_eq!(
            parsed.to_string(),
            expected,
            "precedence differs for {text}"
        );
    }
}

#[test]
fn prefix_rendering_round_trips() {
    for entry in generate_in_house(2).expect("generate").iter().take(64) {
        let parsed: Term = parse_prefix(&entry.case.obfuscated).expect("prefix parses");
        assert_eq!(
            parsed.to_prefix(),
            entry.case.obfuscated,
            "{}: prefix rendering does not round trip",
            entry.case.id
        );
    }
}
