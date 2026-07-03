use std::collections::BTreeSet;

use serde::Serialize;

use crate::extract::{BlockFeatures, FunctionFeatures, InstructionFeatures, ScopedFeatures};
use crate::feature::{FeatureSet, Scope};
use crate::rule::{Evidence, Rule};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CapabilityMatch {
    pub rule: String,
    pub namespace: String,
    pub scope: Scope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_address: Option<u64>,
    pub address: u64,
    pub attack: Vec<String>,
    pub mbc: Vec<String>,
    pub description: String,
    pub evidence: Vec<Evidence>,
}

#[must_use]
pub fn evaluate(scoped: &ScopedFeatures, rules: &[Rule]) -> Vec<CapabilityMatch> {
    let mut leaf: Vec<&Rule> = Vec::new();
    let mut composite: Vec<&Rule> = Vec::new();
    for rule in rules {
        if rule.expr.references_rules() {
            composite.push(rule);
        } else {
            leaf.push(rule);
        }
    }

    let empty: BTreeSet<String> = BTreeSet::new();
    let mut out: Vec<CapabilityMatch> = Vec::new();
    for rule in &leaf {
        evaluate_rule(rule, scoped, &empty, &mut out);
    }

    let matched: BTreeSet<String> = out
        .iter()
        .map(|m: &CapabilityMatch| m.rule.clone())
        .collect();
    for rule in &composite {
        evaluate_rule(rule, scoped, &matched, &mut out);
    }

    out.sort_by(|a: &CapabilityMatch, b: &CapabilityMatch| {
        a.address.cmp(&b.address).then_with(|| a.rule.cmp(&b.rule))
    });
    out
}

fn evaluate_rule(
    rule: &Rule,
    scoped: &ScopedFeatures,
    matched: &BTreeSet<String>,
    out: &mut Vec<CapabilityMatch>,
) {
    match rule.scope {
        Scope::File => evaluate_file(rule, scoped, matched, out),
        Scope::Function => evaluate_functions(rule, scoped, matched, out),
        Scope::BasicBlock => evaluate_blocks(rule, scoped, matched, out),
        Scope::Instruction => evaluate_instructions(rule, scoped, matched, out),
    }
}

fn evaluate_file(
    rule: &Rule,
    scoped: &ScopedFeatures,
    matched: &BTreeSet<String>,
    out: &mut Vec<CapabilityMatch>,
) {
    if let Some(evidence) = fired(rule, &scoped.file, matched) {
        let address: u64 = anchor(&evidence);
        out.push(make_match(rule, None, None, address, evidence));
    }
}

fn evaluate_functions(
    rule: &Rule,
    scoped: &ScopedFeatures,
    matched: &BTreeSet<String>,
    out: &mut Vec<CapabilityMatch>,
) {
    for function in &scoped.functions {
        if let Some(evidence) = fired(rule, &function.features, matched) {
            let address: u64 = anchor_in(&evidence, function);
            out.push(make_match(
                rule,
                Some(function.name.clone()),
                Some(function.address),
                address,
                evidence,
            ));
        }
    }
}

fn evaluate_blocks(
    rule: &Rule,
    scoped: &ScopedFeatures,
    matched: &BTreeSet<String>,
    out: &mut Vec<CapabilityMatch>,
) {
    for function in &scoped.functions {
        for block in &function.blocks {
            if let Some(evidence) = fired(rule, &block.features, matched) {
                let address: u64 = anchor_block(&evidence, block);
                out.push(make_match(
                    rule,
                    Some(function.name.clone()),
                    Some(function.address),
                    address,
                    evidence,
                ));
            }
        }
    }
}

fn evaluate_instructions(
    rule: &Rule,
    scoped: &ScopedFeatures,
    matched: &BTreeSet<String>,
    out: &mut Vec<CapabilityMatch>,
) {
    for function in &scoped.functions {
        for block in &function.blocks {
            for instruction in &block.instructions {
                if let Some(evidence) = fired(rule, &instruction.features, matched) {
                    let address: u64 = anchor_instruction(&evidence, instruction);
                    out.push(make_match(
                        rule,
                        Some(function.name.clone()),
                        Some(function.address),
                        address,
                        evidence,
                    ));
                }
            }
        }
    }
}

fn fired(rule: &Rule, set: &FeatureSet, matched: &BTreeSet<String>) -> Option<Vec<Evidence>> {
    let mut evidence: Vec<Evidence> = Vec::new();
    if rule.expr.evaluate(set, matched, &mut evidence) {
        evidence.sort_by(|a: &Evidence, b: &Evidence| {
            a.address
                .cmp(&b.address)
                .then_with(|| a.feature.cmp(&b.feature))
        });
        evidence.dedup();
        Some(evidence)
    } else {
        None
    }
}

fn anchor(evidence: &[Evidence]) -> u64 {
    evidence
        .iter()
        .map(|e: &Evidence| e.address)
        .min()
        .map_or(0, |value: u64| value)
}

fn anchor_in(evidence: &[Evidence], function: &FunctionFeatures) -> u64 {
    evidence
        .iter()
        .map(|e: &Evidence| e.address)
        .min()
        .map_or(function.address, |value: u64| value)
}

fn anchor_block(evidence: &[Evidence], block: &BlockFeatures) -> u64 {
    evidence
        .iter()
        .map(|e: &Evidence| e.address)
        .min()
        .map_or(block.start, |value: u64| value)
}

fn anchor_instruction(evidence: &[Evidence], instruction: &InstructionFeatures) -> u64 {
    evidence
        .iter()
        .map(|e: &Evidence| e.address)
        .min()
        .map_or(instruction.address, |value: u64| value)
}

fn make_match(
    rule: &Rule,
    function: Option<String>,
    function_address: Option<u64>,
    address: u64,
    evidence: Vec<Evidence>,
) -> CapabilityMatch {
    CapabilityMatch {
        rule: rule.name.to_owned(),
        namespace: rule.namespace.to_owned(),
        scope: rule.scope,
        function,
        function_address,
        address,
        attack: rule.attack.iter().map(|s: &&str| (*s).to_owned()).collect(),
        mbc: rule.mbc.iter().map(|s: &&str| (*s).to_owned()).collect(),
        description: rule.description.to_owned(),
        evidence,
    }
}
