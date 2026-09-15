#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

const GATE_FILE: &str = "real_hermes_correctness.rs";
const DESCRIPTOR: &str = "evidence/descriptors/hermes-opcoverage.toml";

const FUNCTIONS_CONST: &str = "PINNED_FUNCTIONS";
const CORRECT_CONST: &str = "PINNED_BEHAVIORALLY_CORRECT";
const FLOOR_CONST: &str = "CORRECTNESS_FLOOR_PERCENT";

const PROSE_SECTION: &str = "[correctness_oracle]";
const FIGURE_SECTION: &str = "[correctness_source]";

const VALUE_EPSILON: f64 = 0.005;

fn repo_root() -> PathBuf {
    let manifest: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(root): Option<&Path> = manifest.parent().and_then(Path::parent) else {
        panic!(
            "the hermes decompile-correctness figure is published in {DESCRIPTOR}, two directories \
             above {}, so a manifest path with no grandparent leaves the published figure checked \
             against nothing",
            manifest.display()
        )
    };
    root.to_path_buf()
}

fn gate_source() -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(GATE_FILE);
    fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{GATE_FILE} declares the counts {DESCRIPTOR} publishes, so a run that cannot read it \
             must fail rather than report a green that compared nothing: {error} at {}",
            path.display()
        )
    })
}

fn descriptor() -> String {
    let path: PathBuf = repo_root().join(DESCRIPTOR);
    fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{DESCRIPTOR} is the surface that publishes the hermes decompile-correctness figure, so \
             a run that cannot read it must fail rather than report a green that checked no \
             document: {error} at {}",
            path.display()
        )
    })
}

fn declared(source: &str, name: &str) -> usize {
    let needle: String = format!("const {name}: usize = ");
    let Some(at): Option<usize> = source.find(&needle) else {
        panic!(
            "{GATE_FILE} no longer declares `{name}`, so the number {DESCRIPTOR} publishes is bound \
             to nothing this check can read"
        )
    };
    let Some(tail): Option<&str> = source.get(at.saturating_add(needle.len())..) else {
        panic!("`{name}` in {GATE_FILE} starts mid-character, so its value cannot be read")
    };
    let digits: String = tail.chars().take_while(char::is_ascii_digit).collect();
    let Ok(value): Result<usize, core::num::ParseIntError> = digits.parse::<usize>() else {
        panic!("`{name}` in {GATE_FILE} is not declared as a plain integer literal")
    };
    value
}

fn section<'doc>(doc: &'doc str, heading: &str) -> &'doc str {
    let Some(at): Option<usize> = doc.find(heading) else {
        panic!(
            "{DESCRIPTOR} carries no `{heading}` table, so the hermes decompile-correctness figure \
             is published nowhere this check can read"
        )
    };
    let Some(body): Option<&str> = doc.get(at.saturating_add(heading.len())..) else {
        panic!("`{heading}` in {DESCRIPTOR} starts mid-character, so its body cannot be read")
    };
    body.find("\n[")
        .and_then(|end: usize| body.get(..end))
        .unwrap_or(body)
}

fn numeric_field(body: &str, field: &str) -> f64 {
    let needle: String = format!("\n{field} = ");
    let Some(at): Option<usize> = body.find(&needle) else {
        panic!(
            "the `{FIGURE_SECTION}` table in {DESCRIPTOR} states no `{field}`, so the figure it \
             publishes is checked against nothing"
        )
    };
    let Some(tail): Option<&str> = body.get(at.saturating_add(needle.len())..) else {
        panic!("`{field}` in {DESCRIPTOR} starts mid-character, so its value cannot be read")
    };
    let literal: String = tail
        .chars()
        .take_while(|c: &char| c.is_ascii_digit() || *c == '.')
        .collect();
    let Ok(value): Result<f64, core::num::ParseFloatError> = literal.parse::<f64>() else {
        panic!("`{field}` in {DESCRIPTOR} is not stated as a plain decimal literal")
    };
    value
}

fn measured_percent(correct: usize, functions: usize) -> f64 {
    100.0 * correct as f64 / functions as f64
}

#[test]
fn the_descriptor_states_the_correctness_figure_this_gate_enforces() {
    let source: String = gate_source();
    let functions: usize = declared(&source, FUNCTIONS_CONST);
    let correct: usize = declared(&source, CORRECT_CONST);
    let floor: usize = declared(&source, FLOOR_CONST);

    assert!(
        functions > 0 && correct > 0,
        "{GATE_FILE} declares a zero population, so every comparison below would check the \
         published figure against a gate that grades nothing"
    );
    assert_eq!(
        correct, functions,
        "{DESCRIPTOR} publishes this row as a complete behavioral recovery, so the gate's \
         behaviorally-correct count and its population are pinned equal; {GATE_FILE} now declares \
         {correct} of {functions} and the published figure would overstate it"
    );

    let doc: String = descriptor();
    let figures: &str = section(&doc, FIGURE_SECTION);
    let expected: f64 = measured_percent(correct, functions);

    let published: f64 = numeric_field(figures, "measured");
    assert!(
        (published - expected).abs() < VALUE_EPSILON,
        "{DESCRIPTOR} publishes a measured decompile-correctness of {published}, but {GATE_FILE} \
         pins {correct} of {functions} functions behaviorally correct, which is {expected}"
    );

    let published_floor: f64 = numeric_field(figures, "floor");
    assert!(
        (published_floor - floor as f64).abs() < VALUE_EPSILON,
        "{DESCRIPTOR} publishes a floor of {published_floor}, but {FLOOR_CONST} in {GATE_FILE} is \
         {floor}; a descriptor floor beneath the one the gate enforces understates the guarantee \
         and one above it overstates the guarantee"
    );
    assert!(
        (published_floor - expected).abs() < VALUE_EPSILON,
        "the committed HBC v96 sample is fixed and the differential over it is deterministic, so \
         the published floor of {published_floor} must equal the measured {expected} rather than \
         trail it; slack between the two is how a figure goes stale without any run noticing"
    );

    let prose: &str = section(&doc, PROSE_SECTION);
    let headline: String = format!("{correct} of {functions} functions");
    assert!(
        prose.contains(&headline),
        "the `{PROSE_SECTION}` table in {DESCRIPTOR} does not state `{headline}`, so the page \
         describes a population the gate does not grade"
    );
}

#[test]
fn the_descriptor_check_rejects_a_figure_the_gate_does_not_measure() {
    let source: String = gate_source();
    let functions: usize = declared(&source, FUNCTIONS_CONST);
    let correct: usize = declared(&source, CORRECT_CONST);
    let doc: String = descriptor();

    let understated: String = format!("{} of {functions} functions", correct.saturating_sub(1));
    assert!(
        !doc.contains(&understated),
        "{DESCRIPTOR} still states `{understated}`, a population the gate does not grade, so the \
         containment assertion above would pass on a stale figure"
    );

    let overstated: String = format!("{} of {functions} functions", correct.saturating_add(1));
    assert!(
        !doc.contains(&overstated),
        "{DESCRIPTOR} states `{overstated}`, which claims more than {GATE_FILE} measures"
    );

    let figures: &str = section(&doc, FIGURE_SECTION);
    let published: f64 = numeric_field(figures, "measured");
    for behind in [1usize, 2, 3] {
        let Some(fewer): Option<usize> = correct.checked_sub(behind) else {
            continue;
        };
        let stale: f64 = measured_percent(fewer, functions);
        assert!(
            (published - stale).abs() > VALUE_EPSILON,
            "{DESCRIPTOR} publishes {published}, which is what {fewer} of {functions} functions \
             would measure rather than the {correct} of {functions} the gate now grades"
        );
    }
}
