#![cfg(feature = "yaml_rules")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_capabilities::eval::CapabilityMatch;
use disrobe_capabilities::extract::ScopedFeatures;
use disrobe_capabilities::imports::ImportMap;
use disrobe_capabilities::yaml_rules::{EvaluationOutcome, LoadedRuleSet, load_rules};
use disrobe_ir::payload::{
    DisasmInstruction, DisasmPayload, DisasmSymbol, DisasmSymbolKind, InsnFlow,
};
use disrobe_pass_native::build_disasm_payload;
use disrobe_query::Module;

const YAML_SCOPE: &[u8] = include_bytes!("fixtures/yaml_scope.exe");
const YAML_STRINGS: &[u8] = include_bytes!("fixtures/yaml_strings.exe");

const AND_OR_NOT: &str = include_str!("yaml_rules/and_or_not.yaml");
const SCOPE_DESCENT_NEGATIVE: &str = include_str!("yaml_rules/scope_descent_negative.yaml");
const SCOPE_DESCENT_POSITIVE: &str = include_str!("yaml_rules/scope_descent_positive.yaml");
const COUNT_MOV: &str = include_str!("yaml_rules/count_mov.yaml");
const CALLS_TO_AND_FROM: &str = include_str!("yaml_rules/calls_to_and_from.yaml");
const OS_ARCH_FORMAT: &str = include_str!("yaml_rules/os_arch_format.yaml");
const STRING_FEATURES: &str = include_str!("yaml_rules/string_features.yaml");
const OPTIONAL_NODE: &str = include_str!("yaml_rules/optional_node.yaml");
const N_OF_NODE: &str = include_str!("yaml_rules/n_of_node.yaml");
const API_PLACEHOLDER: &str = include_str!("yaml_rules/api_placeholder.yaml");
const MATCH_BASE: &str = include_str!("yaml_rules/match_base.yaml");
const MATCH_DEPENDENT: &str = include_str!("yaml_rules/match_dependent.yaml");
const BYTES_UNSUPPORTED: &str = include_str!("yaml_rules/bytes_unsupported.yaml");

fn load_scoped(bytes: &[u8]) -> (Module, ScopedFeatures) {
    let payload: DisasmPayload = build_disasm_payload(bytes).expect("disassemble fixture");
    let module: Module = Module::from_disasm(&payload);
    let imports: ImportMap = ImportMap::from_bytes(bytes);
    let scoped: ScopedFeatures = disrobe_capabilities::extract::extract(&module, bytes, &imports);
    (module, scoped)
}

fn run_rule_names(sources: &[&str], module: &Module, scoped: &ScopedFeatures) -> Vec<String> {
    let ruleset: LoadedRuleSet = load_rules(sources).expect("rules load");
    assert!(
        ruleset.unsupported.is_empty(),
        "unexpected unsupported rules: {:?}",
        ruleset.unsupported
    );
    let outcome: EvaluationOutcome =
        disrobe_capabilities::yaml_rules::evaluate(&ruleset, module, scoped);
    let mut names: Vec<String> = outcome
        .matches
        .into_iter()
        .map(|m: CapabilityMatch| m.rule)
        .collect();
    names.sort_unstable();
    names
}

fn function_names_matching(
    sources: &[&str],
    module: &Module,
    scoped: &ScopedFeatures,
    rule: &str,
) -> Vec<String> {
    let ruleset: LoadedRuleSet = load_rules(sources).expect("rules load");
    let outcome: EvaluationOutcome =
        disrobe_capabilities::yaml_rules::evaluate(&ruleset, module, scoped);
    let mut names: Vec<String> = outcome
        .matches
        .into_iter()
        .filter(|m: &CapabilityMatch| m.rule == rule)
        .filter_map(|m: CapabilityMatch| m.function)
        .collect();
    names.sort_unstable();
    names
}

#[test]
fn and_or_not_matches_only_the_function_carrying_the_disjunct() {
    let (module, scoped): (Module, ScopedFeatures) = load_scoped(YAML_SCOPE);
    let names: Vec<String> =
        function_names_matching(&[AND_OR_NOT], &module, &scoped, "tag-alpha and-or-not");
    assert_eq!(names, vec!["sub_140001020".to_owned()]);
}

#[test]
fn scope_descent_negative_control_rejects_the_cross_block_union() {
    let (module, scoped): (Module, ScopedFeatures) = load_scoped(YAML_SCOPE);
    let names: Vec<String> = run_rule_names(&[SCOPE_DESCENT_NEGATIVE], &module, &scoped);
    assert!(
        names.is_empty(),
        "must not over-match across blocks: {names:?}"
    );
}

#[test]
fn scope_descent_positive_control_accepts_the_real_single_block_cooccurrence() {
    let (module, scoped): (Module, ScopedFeatures) = load_scoped(YAML_SCOPE);
    let ruleset: LoadedRuleSet = load_rules(&[SCOPE_DESCENT_POSITIVE]).expect("rules load");
    let outcome: EvaluationOutcome =
        disrobe_capabilities::yaml_rules::evaluate(&ruleset, &module, &scoped);
    assert_eq!(outcome.matches.len(), 1, "{:?}", outcome.matches);
    let hit: &CapabilityMatch = &outcome.matches[0];
    assert_eq!(hit.function.as_deref(), Some("sub_140001020"));
    assert_eq!(hit.address, 5_368_713_356);
}

#[test]
fn count_node_matches_the_function_with_at_least_four_movs() {
    let (module, scoped): (Module, ScopedFeatures) = load_scoped(YAML_STRINGS);
    let names: Vec<String> = run_rule_names(&[COUNT_MOV], &module, &scoped);
    assert_eq!(names, vec!["tag-beta count node".to_owned()]);
}

#[test]
fn calls_to_and_calls_from_each_resolve_a_distinct_function() {
    let (module, scoped): (Module, ScopedFeatures) = load_scoped(YAML_SCOPE);
    let names: Vec<String> = function_names_matching(
        &[CALLS_TO_AND_FROM],
        &module,
        &scoped,
        "tag-gamma call graph adapter",
    );
    assert_eq!(
        names,
        vec!["sub_140001000".to_owned(), "sub_140001020".to_owned()]
    );
}

#[test]
fn os_arch_format_and_section_fire_once_at_file_scope() {
    let (module, scoped): (Module, ScopedFeatures) = load_scoped(YAML_SCOPE);
    let ruleset: LoadedRuleSet = load_rules(&[OS_ARCH_FORMAT]).expect("rules load");
    let outcome: EvaluationOutcome =
        disrobe_capabilities::yaml_rules::evaluate(&ruleset, &module, &scoped);
    assert_eq!(outcome.matches.len(), 1, "{:?}", outcome.matches);
    assert_eq!(outcome.matches[0].function, None);
}

#[test]
fn string_tags_fire_on_the_real_carried_literal() {
    let (module, scoped): (Module, ScopedFeatures) = load_scoped(YAML_STRINGS);
    let names: Vec<String> = run_rule_names(&[STRING_FEATURES], &module, &scoped);
    assert_eq!(names, vec!["tag-epsilon string tags".to_owned()]);
}

#[test]
fn optional_node_never_gates_the_surrounding_and() {
    let (module, scoped): (Module, ScopedFeatures) = load_scoped(YAML_SCOPE);
    let names: Vec<String> =
        function_names_matching(&[OPTIONAL_NODE], &module, &scoped, "tag-zeta optional node");
    assert_eq!(names, vec!["sub_140001000".to_owned()]);
}

#[test]
fn n_of_node_accepts_two_of_three_in_both_functions() {
    let (module, scoped): (Module, ScopedFeatures) = load_scoped(YAML_SCOPE);
    let names: Vec<String> =
        function_names_matching(&[N_OF_NODE], &module, &scoped, "tag-eta n-of node");
    assert_eq!(
        names,
        vec!["sub_140001000".to_owned(), "sub_140001020".to_owned()]
    );
}

fn synthetic_api_payload() -> DisasmPayload {
    DisasmPayload {
        source_hash: [0u8; 32],
        instructions: vec![
            DisasmInstruction {
                offset: 0x10,
                bytes: vec![0xe8],
                mnemonic: "call".to_owned(),
                operands: vec!["0x100".to_owned()],
                flow: InsnFlow::Call,
                branch_target: Some(0x100),
                ..DisasmInstruction::default()
            },
            DisasmInstruction {
                offset: 0x15,
                bytes: vec![0xc3],
                mnemonic: "ret".to_owned(),
                operands: vec![],
                flow: InsnFlow::Return,
                branch_target: None,
                ..DisasmInstruction::default()
            },
            DisasmInstruction {
                offset: 0x30,
                bytes: vec![0x90],
                mnemonic: "nop".to_owned(),
                operands: vec![],
                flow: InsnFlow::Sequential,
                branch_target: None,
                ..DisasmInstruction::default()
            },
            DisasmInstruction {
                offset: 0x31,
                bytes: vec![0xc3],
                mnemonic: "ret".to_owned(),
                operands: vec![],
                flow: InsnFlow::Return,
                branch_target: None,
                ..DisasmInstruction::default()
            },
        ],
        symbol_table: vec![
            DisasmSymbol {
                address: 0x10,
                name: "example_caller".to_owned(),
                kind: DisasmSymbolKind::Function,
            },
            DisasmSymbol {
                address: 0x30,
                name: "example_clean".to_owned(),
                kind: DisasmSymbolKind::Function,
            },
            DisasmSymbol {
                address: 0x100,
                name: "ExampleLibrary.ExampleFunction".to_owned(),
                kind: DisasmSymbolKind::Import,
            },
        ],
    }
}

#[test]
fn api_placeholder_matches_only_the_calling_function() {
    let module: Module = Module::from_disasm(&synthetic_api_payload());
    let scoped: ScopedFeatures =
        disrobe_capabilities::extract::extract(&module, b"", &ImportMap::default());
    let names: Vec<String> = function_names_matching(
        &[API_PLACEHOLDER],
        &module,
        &scoped,
        "tag-theta api placeholder",
    );
    assert_eq!(names, vec!["example_caller".to_owned()]);
}

#[test]
fn cross_rule_match_resolves_per_function_instance_not_globally() {
    let (module, scoped): (Module, ScopedFeatures) = load_scoped(YAML_SCOPE);
    let base_hits: Vec<String> = function_names_matching(
        &[MATCH_BASE, MATCH_DEPENDENT],
        &module,
        &scoped,
        "tag-iota base rule",
    );
    assert_eq!(base_hits, vec!["sub_140001000".to_owned()]);

    let dependent_hits: Vec<String> = function_names_matching(
        &[MATCH_BASE, MATCH_DEPENDENT],
        &module,
        &scoped,
        "tag-kappa dependent rule",
    );
    assert!(
        dependent_hits.is_empty(),
        "a naive global flatten would incorrectly match sub_140001020 here: {dependent_hits:?}"
    );
}

#[test]
fn bytes_feature_is_marked_unsupported_and_excluded_from_evaluation() {
    let ruleset: LoadedRuleSet = load_rules(&[BYTES_UNSUPPORTED]).expect("rules load");
    assert!(ruleset.rules.is_empty());
    assert_eq!(ruleset.unsupported.len(), 1);
    assert_eq!(ruleset.unsupported[0].name, "tag-lambda unsupported bytes");
}
