#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use disrobe_pass_dotnet::cil::{MethodBody, parse_method_body};
use disrobe_pass_dotnet::devirt::extract::{ExtractedVmModel, models_from_eazvm_image};
use disrobe_pass_dotnet::devirt::oracle::{OracleReport, Outcome, check_against_reference};
use disrobe_pass_dotnet::devirt::{Budget, PrimitiveEffect, SyntheticVmModel};
use disrobe_pass_dotnet::metadata::{MetadataRoot, parse_metadata_root};
use disrobe_pass_dotnet::model::{AssemblyModel, Resolver};
use disrobe_pass_dotnet::pe::{ClrHeader, PeImage, parse, parse_clr_header};

const BUDGET_CAP: u64 = 4_000_000;
const POPULATION_FLOOR: usize = 5;
const EQUIVALENT_FLOOR: u64 = 2;
const REJECTED_CEILING: u64 = 3;
const EQUIVALENT_METHODS: [&str; 2] = ["Add", "Poly"];

fn corpus_path(name: &str) -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../corpus/dotnet/eazvm");
    path.push(name);
    path
}

fn virtualized_image() -> Vec<u8> {
    std::fs::read(corpus_path("EazSample.eazvm.dll")).expect("virtualized corpus image")
}

fn clean_image() -> Vec<u8> {
    std::fs::read(corpus_path("EazSample.clean.dll")).expect("clean corpus baseline")
}

fn clean_body(image: &[u8], method_name: &str) -> Option<MethodBody> {
    let pe: PeImage = parse(image).ok()?;
    let clr: ClrHeader = parse_clr_header(image, &pe).ok()?;
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr).ok()?;
    let resolver: Resolver = Resolver::build(image, &pe, &clr, &root).ok()?;
    let model: AssemblyModel = resolver.model();
    for ty in &model.types {
        for method in &ty.methods {
            if method.name != method_name || method.rva == 0 {
                continue;
            }
            let offset: usize = pe.rva_to_offset(method.rva)?;
            return parse_method_body(image.get(offset..)?).ok();
        }
    }
    None
}

fn grade(model: &SyntheticVmModel, reference: &MethodBody) -> OracleReport {
    let mut budget: Budget = Budget::new(BUDGET_CAP);
    check_against_reference(model, reference, &mut budget)
}

fn outcome_label(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Equivalent { samples } => format!("equivalent over {samples} inputs"),
        Outcome::Rejected(reject) => format!("rejected: {}", reject.reason),
        Outcome::Skipped(cause) => format!("skipped: {cause:?}"),
        Outcome::Failed(divergence) => format!("failed: {:?}", divergence.first_diff),
        Outcome::FailedHalting(_) => "failed: halting asymmetry".to_owned(),
        Outcome::FailedEmulation(failure) => format!("failed: emulation {:?}", failure.error),
    }
}

fn extracted_models() -> Vec<ExtractedVmModel> {
    let virtualized: Vec<u8> = virtualized_image();
    models_from_eazvm_image(&virtualized).expect("models extracted from the virtualized corpus")
}

fn model_for(models: &[ExtractedVmModel], method_name: &str) -> SyntheticVmModel {
    models
        .iter()
        .find(|candidate: &&ExtractedVmModel| candidate.method_name == method_name)
        .map(|candidate: &ExtractedVmModel| candidate.model.clone())
        .expect("extracted model for the requested method")
}

#[test]
fn corpus_extraction_covers_every_virtualized_method() {
    let models: Vec<ExtractedVmModel> = extracted_models();
    assert_eq!(
        models.len(),
        POPULATION_FLOOR,
        "the extractor must derive a model for every virtualized body in the corpus"
    );
    for extracted in &models {
        assert!(
            !extracted.model.instructions.is_empty(),
            "{} extracted to an empty virtual program",
            extracted.method_name
        );
        assert!(
            !extracted.model.handlers.is_empty(),
            "{} extracted to an empty handler table",
            extracted.method_name
        );
    }
}

#[test]
fn corpus_grade_holds_the_pinned_floor() {
    let clean: Vec<u8> = clean_image();
    let models: Vec<ExtractedVmModel> = extracted_models();
    let mut equivalent: u64 = 0;
    let mut failed: u64 = 0;
    let mut skipped: u64 = 0;
    let mut rejected: u64 = 0;
    for extracted in &models {
        let reference: MethodBody = clean_body(&clean, &extracted.method_name)
            .expect("clean baseline body for the graded method");
        let report: OracleReport = grade(&extracted.model, &reference);
        equivalent += report.equivalent;
        failed += report.failed;
        skipped += report.skipped;
        rejected += report.rejected;
        println!(
            "{}: {} (handlers={} instructions={} args={} locals={})",
            extracted.method_name,
            outcome_label(&report.outcome),
            extracted.model.handlers.len(),
            extracted.model.instructions.len(),
            extracted.model.argument_count,
            extracted.model.local_count
        );
    }
    println!(
        "totals: equivalent={equivalent} failed={failed} skipped={skipped} rejected={rejected} \
         population={}",
        models.len()
    );
    assert_eq!(
        failed, 0,
        "no extracted model may diverge from the baseline"
    );
    assert_eq!(
        skipped, 0,
        "no extracted model may be graded away as a skip"
    );
    assert!(
        equivalent >= EQUIVALENT_FLOOR,
        "equivalence floor regressed: {equivalent} < {EQUIVALENT_FLOOR}"
    );
    assert!(
        rejected <= REJECTED_CEILING,
        "rejection ceiling regressed: {rejected} > {REJECTED_CEILING}"
    );
}

#[test]
fn methods_at_the_floor_are_named() {
    let clean: Vec<u8> = clean_image();
    let models: Vec<ExtractedVmModel> = extracted_models();
    for name in EQUIVALENT_METHODS {
        let model: SyntheticVmModel = model_for(&models, name);
        let reference: MethodBody = clean_body(&clean, name).expect("clean baseline body");
        let report: OracleReport = grade(&model, &reference);
        assert!(
            matches!(report.outcome, Outcome::Equivalent { .. }),
            "{name} must stay equivalent to the compiled baseline; got {}",
            outcome_label(&report.outcome)
        );
    }
}

#[test]
fn corrupting_an_argument_index_is_reported_as_a_failure() {
    let clean: Vec<u8> = clean_image();
    let models: Vec<ExtractedVmModel> = extracted_models();
    let mut model: SyntheticVmModel = model_for(&models, "Add");
    let reference: MethodBody = clean_body(&clean, "Add").expect("clean baseline body");
    assert!(
        matches!(
            grade(&model, &reference).outcome,
            Outcome::Equivalent { .. }
        ),
        "the unmutated Add model must grade as equivalent before the mutation is applied"
    );

    let second_argument: u16 = model
        .handlers
        .iter()
        .find(|(_, handler): &(&u16, &_)| {
            handler.effects.as_slice() == [PrimitiveEffect::PushArgument(1)]
        })
        .map(|(id, _): (&u16, &_)| *id)
        .expect("Add loads its second argument");
    let first_argument: u16 = model
        .handlers
        .iter()
        .find(|(_, handler): &(&u16, &_)| {
            handler.effects.as_slice() == [PrimitiveEffect::PushArgument(0)]
        })
        .map(|(id, _): (&u16, &_)| *id)
        .expect("Add loads its first argument");
    let mutated: usize = model
        .instructions
        .iter()
        .position(|instruction: &_| instruction.handler_id == second_argument)
        .expect("the second-argument load is present in the virtual program");
    model.instructions[mutated].handler_id = first_argument;

    let report: OracleReport = grade(&model, &reference);
    assert_eq!(
        report.failed,
        1,
        "an argument-index mutation must be counted as a failure; got {}",
        outcome_label(&report.outcome)
    );
    assert!(
        matches!(report.outcome, Outcome::Failed(_)),
        "the mutation must surface as a divergence; got {}",
        outcome_label(&report.outcome)
    );
    assert_eq!(report.equivalent, 0, "a mutated model may not grade green");
    assert_eq!(report.skipped, 0, "a mutated model may not be skipped away");
}
