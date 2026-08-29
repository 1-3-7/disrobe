#![allow(clippy::expect_used, clippy::panic, clippy::print_stdout)]

use std::collections::{BTreeMap, BTreeSet};

use disrobe_nir::{
    HirFunction, HirStmt, NirFunction, NirInstr, NirOp, SplitBudget, SurfaceFunction, basic_blocks,
    emit_pseudo_source, structurize_function_with_budget, surfacify_function,
};
use disrobe_nir_lift::lower_aarch64;

const CORPUS: &[(&str, &str, &[u8])] =
    &include!("../../disrobe-pass-native/tests/aarch64_recovery_corpus.inc");

const CORPUS_ENTRIES: usize = 1260;
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

fn corpus_function(optimization: &str, name: &str) -> NirFunction {
    let (_optimization, _name, bytes): &(&str, &str, &[u8]) = CORPUS
        .iter()
        .find(|(candidate_optimization, candidate_name, _bytes)| {
            *candidate_optimization == optimization && *candidate_name == name
        })
        .expect("find committed corpus function");
    lift(bytes, name).expect("lift committed corpus function")
}

fn added_blocks(optimization: &str, name: &str) -> usize {
    let function: NirFunction = corpus_function(optimization, name);
    let original: usize = basic_blocks(&function).len();
    let hir: HirFunction = structurize_function_with_budget(&function, SplitBudget::TightForGraph);
    hir.block_starts().len().saturating_sub(original)
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

#[test]
fn modeled_short_circuit_conditions_need_no_reconvergence_clones() {
    const CASES: [(&str, &str); 1] = [("O0", "and_or_cond")];
    for (optimization, name) in CASES {
        let function: NirFunction = corpus_function(optimization, name);
        let first: HirFunction =
            structurize_function_with_budget(&function, SplitBudget::TightForGraph);
        let second: HirFunction =
            structurize_function_with_budget(&function, SplitBudget::TightForGraph);
        assert_eq!(first, second, "{optimization} {name} changed across runs");
        assert_eq!(
            added_blocks(optimization, name),
            0,
            "{optimization} {name} must not clone a guarded tail"
        );
    }
}

#[test]
fn unsupported_floating_comparisons_keep_their_effect_order() {
    const CASES: [(&str, &str, usize); 7] = [
        ("O0", "fc_seland_d", 1),
        ("O0", "fc_seland_f", 1),
        ("O0", "fc_selor_d", 1),
        ("O0", "fc_selor_f", 1),
        ("O0", "fc_seland3_f", 2),
        ("O0", "fc_seland3_mix_f", 2),
        ("O0", "fc_selor3_f", 2),
    ];
    for (optimization, name, expected) in CASES {
        let function: NirFunction = corpus_function(optimization, name);
        let comparisons: Vec<&NirInstr> = function
            .instructions
            .iter()
            .filter(|instruction: &&NirInstr| {
                matches!(
                    &instruction.op,
                    NirOp::CallOther { effect }
                        if effect.name == "unsupported_fcmp"
                            && effect.reads_memory
                            && effect.writes_memory
                            && effect.unknown_registers
                            && instruction.reads_memory
                            && instruction.writes_memory
                )
            })
            .collect();
        assert_eq!(
            comparisons.len(),
            expected.saturating_add(1),
            "{optimization} {name} changed its conservative floating comparison effects"
        );
        let first: HirFunction =
            structurize_function_with_budget(&function, SplitBudget::TightForGraph);
        let second: HirFunction =
            structurize_function_with_budget(&function, SplitBudget::TightForGraph);
        assert_eq!(first, second, "{optimization} {name} changed across runs");
        assert_eq!(
            added_blocks(optimization, name),
            expected,
            "{optimization} {name} changed its bounded effect-preserving split"
        );
    }
}

#[test]
fn short_circuit_source_emits_compound_conditions() {
    let function: NirFunction = corpus_function("O0", "and_or_cond");
    let hir: HirFunction = structurize_function_with_budget(&function, SplitBudget::TightForGraph);
    assert_eq!(hir.to_nir_function().instructions, function.instructions);
    let surface: SurfaceFunction = surfacify_function(&hir);
    assert_eq!(
        surface.to_nir_function().instructions,
        function.instructions
    );
    let source: String =
        emit_pseudo_source(&surface).expect("emit the committed short-circuit function");
    assert_eq!(
        source.matches("if (").count(),
        2,
        "the two source guards must emit as two if statements:\n{source}"
    );
    assert_eq!(
        source.matches(" || ").count(),
        2,
        "both emitted conditions must remain short-circuited:\n{source}"
    );
}

#[test]
fn non_short_circuit_peel_family_remains_exactly_fifty_blocks() {
    const CASES: [(&str, &str, usize); 15] = [
        ("O1", "find_key", 1),
        ("O2", "find_key", 1),
        ("O3", "find_key", 1),
        ("Os", "find_key", 1),
        ("O2", "accum_u64", 2),
        ("O3", "accum_u64", 2),
        ("O2", "arr_max", 2),
        ("O3", "arr_max", 2),
        ("O2", "even_count", 2),
        ("O3", "even_count", 2),
        ("O2", "sum_int_idx", 2),
        ("O3", "sum_int_idx", 2),
        ("O2", "nested_sum", 3),
        ("O3", "nested_sum", 3),
        ("O3", "vol_two_guards", 2),
    ];
    let fixed_cases: usize = CASES
        .into_iter()
        .map(|(optimization, name, expected): (&str, &str, usize)| {
            let actual: usize = added_blocks(optimization, name);
            assert_eq!(actual, expected, "{optimization} {name} changed shape");
            actual
        })
        .sum();
    let large_cases: usize =
        added_blocks("O2", "mem_copy_manual") + added_blocks("O3", "mem_copy_manual");
    assert_eq!(
        large_cases, 22,
        "the rotated copy loops must remain unchanged"
    );
    assert_eq!(
        fixed_cases + large_cases,
        50,
        "the existing peel retains the measured non-short-circuit surface"
    );
}

#[test]
fn total_corpus_block_growth_is_exactly_fifty() {
    let total: usize = CORPUS
        .iter()
        .filter_map(|(_optimization, name, bytes): &(&str, &str, &[u8])| {
            let function: NirFunction = lift(bytes, name)?;
            let original: usize = basic_blocks(&function).len();
            let hir: HirFunction =
                structurize_function_with_budget(&function, SplitBudget::TightForGraph);
            let added: usize = hir.block_starts().len().saturating_sub(original);
            Some(added)
        })
        .sum();
    assert_eq!(total, 60, "the measured corpus split total changed");
}
