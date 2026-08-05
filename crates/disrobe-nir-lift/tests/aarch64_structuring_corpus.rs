#![allow(clippy::expect_used, clippy::panic, clippy::print_stdout)]

use std::collections::{BTreeMap, BTreeSet};

use disrobe_nir::{
    HirFunction, HirStmt, NirFunction, NirInstr, SplitBudget, structurize_function_with_budget,
};
use disrobe_nir_lift::lower_aarch64;

const CORPUS: &[(&str, &str, &[u8])] =
    &include!("../../disrobe-pass-native/tests/aarch64_recovery_corpus.inc");

const CORPUS_ENTRIES: usize = 1225;
const LOAD_ADDRESS: u64 = 0x1000;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CaseId {
    optimization: String,
    name: String,
}

fn lift(bytes: &[u8], name: &str) -> Option<NirFunction> {
    lower_aarch64(bytes, LOAD_ADDRESS, name).ok()
}

const fn is_flat(body: &HirStmt) -> bool {
    matches!(body, HirStmt::GotoGraph { .. } | HirStmt::Dispatch { .. })
}

fn source_addresses(function: &NirFunction) -> BTreeSet<u64> {
    function
        .instructions
        .iter()
        .map(|instruction: &NirInstr| instruction.address)
        .collect()
}

fn survey(budget: SplitBudget) -> (Vec<CaseId>, usize) {
    let mut flat: Vec<CaseId> = Vec::new();
    let mut lifted: usize = 0;
    for (optimization, name, bytes) in CORPUS {
        let Some(function): Option<NirFunction> = lift(bytes, name) else {
            continue;
        };
        lifted = lifted.saturating_add(1);
        let hir: HirFunction = structurize_function_with_budget(&function, budget);
        if is_flat(&hir.body) {
            flat.push(CaseId {
                optimization: (*optimization).to_owned(),
                name: (*name).to_owned(),
            });
        }
    }
    (flat, lifted)
}

#[test]
fn the_committed_corpus_is_the_size_this_survey_reports_over() {
    assert_eq!(
        CORPUS.len(),
        CORPUS_ENTRIES,
        "the corpus roster changed, so the recorded structuring counts must be re-measured"
    );
}

#[test]
fn capped_splitting_never_flattens_a_function_that_already_structured() {
    let (without_splitting, lifted_without): (Vec<CaseId>, usize) = survey(SplitBudget::Disabled);
    let (with_splitting, lifted_with): (Vec<CaseId>, usize) = survey(SplitBudget::TightForGraph);
    assert_eq!(
        lifted_without, lifted_with,
        "both surveys must cover the same lifted functions"
    );

    let recovered: Vec<&CaseId> = without_splitting
        .iter()
        .filter(|case: &&CaseId| !with_splitting.contains(case))
        .collect();
    let regressed: Vec<&CaseId> = with_splitting
        .iter()
        .filter(|case: &&CaseId| !without_splitting.contains(case))
        .collect();

    println!(
        "aarch64 corpus: {lifted_with}/{} functions lifted to nir",
        CORPUS.len()
    );
    println!(
        "structured without splitting: {}/{lifted_without}",
        lifted_without.saturating_sub(without_splitting.len())
    );
    println!(
        "structured with capped splitting: {}/{lifted_with}",
        lifted_with.saturating_sub(with_splitting.len())
    );
    println!("newly structured: {}", recovered.len());
    for case in &recovered {
        println!("  recovered {} {}", case.optimization, case.name);
    }
    for case in &regressed {
        println!("  regressed {} {}", case.optimization, case.name);
    }

    assert!(
        regressed.is_empty(),
        "capped splitting must never turn a structured function into a goto graph: {regressed:?}"
    );
    assert!(
        with_splitting.is_empty(),
        "every corpus function is expected to structure; these did not: {with_splitting:?}"
    );
}

#[test]
fn splitting_never_drops_or_invents_an_instruction() {
    for (optimization, name, bytes) in CORPUS {
        let Some(function): Option<NirFunction> = lift(bytes, name) else {
            continue;
        };
        let expected: BTreeSet<u64> = source_addresses(&function);
        let hir: HirFunction =
            structurize_function_with_budget(&function, SplitBudget::TightForGraph);
        assert_eq!(
            hir.instruction_addresses(),
            expected,
            "{optimization} {name} lost or invented an instruction while structuring"
        );
    }
}

#[test]
fn duplication_stays_bounded_against_the_original_block_count() {
    let mut worst: (usize, usize, String) = (0, 0, String::new());
    let mut histogram: BTreeMap<usize, usize> = BTreeMap::new();
    for (optimization, name, bytes) in CORPUS {
        let Some(function): Option<NirFunction> = lift(bytes, name) else {
            continue;
        };
        let original: usize = disrobe_nir::basic_blocks(&function).len();
        let hir: HirFunction =
            structurize_function_with_budget(&function, SplitBudget::TightForGraph);
        let emitted: usize = hir.block_starts().len();
        *histogram
            .entry(emitted.saturating_sub(original))
            .or_default() += 1;
        if emitted.saturating_sub(original) > worst.1.saturating_sub(worst.0) {
            worst = (original, emitted, format!("{optimization} {name}"));
        }
    }
    println!("added-block histogram (added -> functions): {histogram:?}");
    println!(
        "worst growth: {} from {} to {} blocks",
        worst.2, worst.0, worst.1
    );
    assert!(
        worst.1 <= worst.0.saturating_mul(3).saturating_add(8),
        "block duplication grew past three times the original plus eight: {worst:?}"
    );
}
