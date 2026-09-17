#![cfg(feature = "yaml_rules")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_capabilities::extract::ScopedFeatures;
use disrobe_capabilities::feature::Scope;
use disrobe_capabilities::imports::ImportMap;
use disrobe_capabilities::yaml_rules::{
    EvaluationOutcome, IndeterminateMatch, LoadedRuleSet, load_rules,
};
use disrobe_ir::payload::{
    DisasmInstruction, DisasmPayload, DisasmSymbol, DisasmSymbolKind, InsnFlow,
};
use disrobe_query::Module;

const DESCENT_CAP: usize = 50_000;

fn nop_instruction(offset: u64, mnemonic: &str) -> DisasmInstruction {
    DisasmInstruction {
        offset,
        bytes: vec![0x90],
        mnemonic: mnemonic.to_owned(),
        operands: vec![],
        flow: InsnFlow::Sequential,
        branch_target: None,
        ..DisasmInstruction::default()
    }
}

fn func_symbol(address: u64, name: &str) -> DisasmSymbol {
    DisasmSymbol {
        address,
        name: name.to_owned(),
        kind: DisasmSymbolKind::Function,
    }
}

fn one_function_many_instructions_payload(
    total: usize,
    marker_index: usize,
    marker_mnemonic: &str,
) -> DisasmPayload {
    let base: u64 = 0x1000;
    let instructions: Vec<DisasmInstruction> = (0..total)
        .map(|idx: usize| {
            let mnemonic: &str = if idx == marker_index {
                marker_mnemonic
            } else {
                "nop"
            };
            let offset: u64 = base + u64::try_from(idx).expect("fits u64");
            nop_instruction(offset, mnemonic)
        })
        .collect();
    DisasmPayload {
        source_hash: [0u8; 32],
        instructions,
        symbol_table: vec![func_symbol(base, "solo")],
    }
}

fn load_scoped(payload: &DisasmPayload) -> (Module, ScopedFeatures) {
    let module: Module = Module::from_disasm(payload);
    let scoped: ScopedFeatures =
        disrobe_capabilities::extract::extract(&module, b"", &ImportMap::default());
    (module, scoped)
}

const NOT_SCOPE_DESCENT_TRUNCATION: &str = "rule:
  meta:
    name: tag-mu not scope descent truncation
    namespace: internal/example
    scope: function
    description: placeholder fixture demonstrating scope descent truncation must not flip through not
  features:
    - not:
        - scope:
            at: instruction
            of:
              - mnemonic: int3
";

#[test]
fn not_wrapped_scope_descent_truncation_cannot_flip_a_missed_instance_into_a_spurious_match() {
    let total: usize = DESCENT_CAP + 1;
    let marker_index: usize = total - 1;
    let payload: DisasmPayload =
        one_function_many_instructions_payload(total, marker_index, "int3");
    let (module, scoped): (Module, ScopedFeatures) = load_scoped(&payload);

    let ruleset: LoadedRuleSet = load_rules(&[NOT_SCOPE_DESCENT_TRUNCATION]).expect("rule loads");
    assert!(ruleset.unsupported.is_empty(), "{:?}", ruleset.unsupported);

    let outcome: EvaluationOutcome =
        disrobe_capabilities::yaml_rules::evaluate(&ruleset, &module, &scoped);
    assert!(
        outcome.matches.is_empty(),
        "a truncated scope descent under not: must never report a confident match \
         (the marker instruction sits beyond the visit cap, so the honest full-scope \
         answer is unknown, not a match): {:?}",
        outcome.matches
    );
    assert_eq!(
        outcome.indeterminate.len(),
        1,
        "the truncated position must be flagged, not silently dropped: {:?}",
        outcome.indeterminate
    );
    let flagged: &IndeterminateMatch = &outcome.indeterminate[0];
    assert_eq!(flagged.rule, "tag-mu not scope descent truncation");
    assert_eq!(flagged.scope, Scope::Function);
    assert_eq!(flagged.function.as_deref(), Some("solo"));
    assert!(
        flagged.reason.contains("cap") || flagged.reason.contains("visit"),
        "{}",
        flagged.reason
    );
}

fn budget_exhaustion_rule_source(leaf_count: usize) -> String {
    let mut source: String = String::from(
        "rule:\n  meta:\n    name: tag-nu not step budget exhaustion\n    namespace: internal/example\n    scope: file\n    description: placeholder fixture demonstrating step-budget exhaustion must not flip through not\n  features:\n    - not:\n        - scope:\n            at: function\n            of:\n",
    );
    for _ in 0..leaf_count.saturating_sub(1) {
        source.push_str("              - mnemonic: nop\n");
    }
    source.push_str("              - mnemonic: never-present-marker\n");
    source
}

fn three_function_payload() -> DisasmPayload {
    DisasmPayload {
        source_hash: [0u8; 32],
        instructions: vec![
            nop_instruction(0x10, "nop"),
            nop_instruction(0x20, "nop"),
            nop_instruction(0x30, "nop"),
        ],
        symbol_table: vec![
            func_symbol(0x10, "alpha"),
            func_symbol(0x20, "beta"),
            func_symbol(0x30, "gamma"),
        ],
    }
}

#[test]
fn not_wrapped_rule_under_step_budget_exhaustion_reports_indeterminate_not_a_silent_absence() {
    let leaf_count: usize = 90_000;
    let source: String = budget_exhaustion_rule_source(leaf_count);
    let payload: DisasmPayload = three_function_payload();
    let (module, scoped): (Module, ScopedFeatures) = load_scoped(&payload);

    let ruleset: LoadedRuleSet = load_rules(&[source.as_str()]).expect("rule loads");
    assert!(ruleset.unsupported.is_empty(), "{:?}", ruleset.unsupported);

    let outcome: EvaluationOutcome =
        disrobe_capabilities::yaml_rules::evaluate(&ruleset, &module, &scoped);
    assert!(
        outcome.matches.is_empty(),
        "an exhausted evaluation must never assert a confident match it never finished \
         computing: {:?}",
        outcome.matches
    );
    assert_eq!(
        outcome.indeterminate.len(),
        1,
        "budget exhaustion must be flagged explicitly, never silently collapsed into an \
         empty (looks-like-non-match) result: {:?}",
        outcome.indeterminate
    );
    let flagged: &IndeterminateMatch = &outcome.indeterminate[0];
    assert_eq!(flagged.rule, "tag-nu not step budget exhaustion");
    assert_eq!(flagged.scope, Scope::File);
    assert!(
        flagged.reason.contains("budget") || flagged.reason.contains("step"),
        "{}",
        flagged.reason
    );
}

const NOT_INVALID_STRING_REGEX: &str = "rule:
  meta:
    name: tag-xi not invalid string regex
    namespace: internal/example
    scope: function
    description: placeholder fixture demonstrating an unparseable regex must be rejected at load time
  features:
    - not:
        - string-regex: \"(\"
";

const VALID_STRING_REGEX_CONTROL: &str = "rule:
  meta:
    name: tag-omicron valid string regex control
    namespace: internal/example
    scope: function
    description: placeholder fixture proving a syntactically valid pattern still loads alongside a rejected one
  features:
    - string-regex: \"^ok$\"
";

#[test]
#[allow(clippy::invalid_regex)]
fn not_wrapped_invalid_regex_is_rejected_at_load_time_instead_of_always_matching() {
    assert!(
        regex::Regex::new("(").is_err(),
        "the fixture pattern must be genuinely unparseable"
    );

    let ruleset: LoadedRuleSet =
        load_rules(&[NOT_INVALID_STRING_REGEX, VALID_STRING_REGEX_CONTROL]).expect("rules load");
    assert_eq!(ruleset.rules.len(), 1, "{:?}", ruleset.rules);
    assert_eq!(
        ruleset.rules[0].name, "tag-omicron valid string regex control",
        "the syntactically valid sibling rule must still load"
    );
    assert_eq!(ruleset.unsupported.len(), 1, "{:?}", ruleset.unsupported);
    assert_eq!(
        ruleset.unsupported[0].name,
        "tag-xi not invalid string regex"
    );
    assert!(
        ruleset.unsupported[0].reason.contains("regex"),
        "{}",
        ruleset.unsupported[0].reason
    );

    let payload: DisasmPayload = one_function_many_instructions_payload(1, 0, "nop");
    let (module, scoped): (Module, ScopedFeatures) = load_scoped(&payload);
    let outcome: EvaluationOutcome =
        disrobe_capabilities::yaml_rules::evaluate(&ruleset, &module, &scoped);
    assert!(
        outcome
            .matches
            .iter()
            .all(|m: &disrobe_capabilities::eval::CapabilityMatch| {
                m.rule != "tag-xi not invalid string regex"
            }),
        "an unparseable regex under not: must never universally fire: {:?}",
        outcome.matches
    );
}
