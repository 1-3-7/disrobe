use std::collections::{BTreeMap, BTreeSet};

use disrobe_query::Module;

use crate::eval::CapabilityMatch;
use crate::extract::{BlockFeatures, FunctionFeatures, InstructionFeatures, ScopedFeatures};
use crate::feature::{Feature, FeatureSet, Scope};
use crate::rule::{CountBound, Evidence};

use super::callgraph::CallIndex;
use super::node::{LoadedRule, Node};

struct EvalCaps {
    steps: usize,
    work: usize,
    descend_instances: usize,
}

impl EvalCaps {
    const fn production() -> Self {
        Self {
            steps: 200_000,
            work: 1_000_000,
            descend_instances: 50_000,
        }
    }
}

#[derive(Clone, Copy)]
enum Position<'a> {
    File(&'a ScopedFeatures),
    Function(&'a FunctionFeatures),
    Block(&'a FunctionFeatures, &'a BlockFeatures),
    Instruction(&'a FunctionFeatures, &'a InstructionFeatures),
}

impl<'a> Position<'a> {
    const fn features(self) -> &'a FeatureSet {
        match self {
            Self::File(s) => &s.file,
            Self::Function(f) => &f.features,
            Self::Block(_, b) => &b.features,
            Self::Instruction(_, i) => &i.features,
        }
    }

    const fn enclosing_function_address(self) -> Option<u64> {
        match self {
            Self::File(_) => None,
            Self::Function(f) | Self::Block(f, _) | Self::Instruction(f, _) => Some(f.address),
        }
    }

    const fn enclosing_function_name(self) -> Option<&'a str> {
        match self {
            Self::File(_) => None,
            Self::Function(f) | Self::Block(f, _) | Self::Instruction(f, _) => {
                Some(f.name.as_str())
            }
        }
    }

    const fn anchor(self) -> u64 {
        match self {
            Self::File(_) => 0,
            Self::Function(f) => f.address,
            Self::Block(_, b) => b.start,
            Self::Instruction(_, i) => i.address,
        }
    }

    fn descend(self, target: Scope, cap: usize) -> Vec<Self> {
        match (self, target) {
            (Self::File(s), Scope::Function) => s
                .functions
                .iter()
                .map(Position::Function)
                .take(cap)
                .collect(),
            (Self::File(s), Scope::BasicBlock) => s
                .functions
                .iter()
                .flat_map(|f: &'a FunctionFeatures| {
                    f.blocks
                        .iter()
                        .map(move |b: &'a BlockFeatures| Position::Block(f, b))
                })
                .take(cap)
                .collect(),
            (Self::File(s), Scope::Instruction) => s
                .functions
                .iter()
                .flat_map(|f: &'a FunctionFeatures| {
                    f.blocks.iter().flat_map(move |b: &'a BlockFeatures| {
                        b.instructions
                            .iter()
                            .map(move |i: &'a InstructionFeatures| Position::Instruction(f, i))
                    })
                })
                .take(cap)
                .collect(),
            (Self::Function(f), Scope::BasicBlock) => f
                .blocks
                .iter()
                .map(|b: &'a BlockFeatures| Position::Block(f, b))
                .take(cap)
                .collect(),
            (Self::Function(f), Scope::Instruction) => f
                .blocks
                .iter()
                .flat_map(|b: &'a BlockFeatures| {
                    b.instructions
                        .iter()
                        .map(move |i: &'a InstructionFeatures| Position::Instruction(f, i))
                })
                .take(cap)
                .collect(),
            (Self::Block(f, b), Scope::Instruction) => b
                .instructions
                .iter()
                .map(|i: &'a InstructionFeatures| Position::Instruction(f, i))
                .take(cap)
                .collect(),
            _ => Vec::new(),
        }
    }
}

#[derive(Debug, Default)]
struct MatchIndex {
    file_level: BTreeSet<String>,
    per_function: BTreeMap<u64, BTreeSet<String>>,
}

impl MatchIndex {
    fn record(&mut self, name: &str, scope: Scope, function_address: Option<u64>) {
        if matches!(scope, Scope::File) {
            self.file_level.insert(name.to_owned());
        } else if let Some(fa) = function_address {
            self.per_function
                .entry(fa)
                .or_default()
                .insert(name.to_owned());
        }
    }

    fn resolves(&self, name: &str, enclosing_function: Option<u64>) -> bool {
        if self.file_level.contains(name) {
            return true;
        }
        enclosing_function.map_or_else(
            || {
                self.per_function
                    .values()
                    .any(|set: &BTreeSet<String>| set.contains(name))
            },
            |fa: u64| {
                self.per_function
                    .get(&fa)
                    .is_some_and(|set: &BTreeSet<String>| set.contains(name))
            },
        )
    }
}

type Outcome = Option<Vec<Evidence>>;

enum Task<'a> {
    Eval(&'a Node, Position<'a>),
    CombineAnd(usize),
    CombineOr(usize),
    CombineNot,
    CombineNOf(usize, usize),
    CombineOptional,
}

fn pop_results(results: &mut Vec<Outcome>, n: usize) -> Vec<Outcome> {
    let at: usize = results.len().saturating_sub(n);
    results.split_off(at)
}

fn combine_and(parts: Vec<Outcome>) -> Outcome {
    let mut evidence: Vec<Evidence> = Vec::new();
    for part in parts {
        match part {
            Some(e) => evidence.extend(e),
            None => return None,
        }
    }
    Some(evidence)
}

fn combine_or(parts: Vec<Outcome>) -> Outcome {
    let mut any: bool = false;
    let mut evidence: Vec<Evidence> = Vec::new();
    for e in parts.into_iter().flatten() {
        any = true;
        evidence.extend(e);
    }
    any.then_some(evidence)
}

fn combine_n_of(parts: Vec<Outcome>, n: usize) -> Outcome {
    let mut satisfied: usize = 0;
    let mut evidence: Vec<Evidence> = Vec::new();
    for e in parts.into_iter().flatten() {
        satisfied += 1;
        evidence.extend(e);
    }
    (satisfied >= n).then_some(evidence)
}

fn eval_feature(feature: &Feature, pos: Position<'_>) -> Outcome {
    let addrs: Vec<u64> = pos.features().matches(feature);
    if addrs.is_empty() {
        return None;
    }
    Some(
        addrs
            .into_iter()
            .map(|address: u64| Evidence {
                feature: feature.render(),
                address,
            })
            .collect(),
    )
}

fn eval_count(feature: &Feature, bound: CountBound, pos: Position<'_>) -> Outcome {
    let addrs: Vec<u64> = pos.features().matches(feature);
    if !bound.satisfied_by(addrs.len()) {
        return None;
    }
    Some(vec![Evidence {
        feature: format!("count({} {})", feature.render(), bound.render()),
        address: addrs.first().copied().unwrap_or_default(),
    }])
}

fn eval_calls_to(pattern: &str, pos: Position<'_>, call_index: &CallIndex) -> Outcome {
    let fa: Option<u64> = pos.enclosing_function_address();
    call_index
        .calls_to(fa, pattern)
        .map(|(address, callee): (u64, String)| {
            vec![Evidence {
                feature: format!("calls-to({callee})"),
                address,
            }]
        })
}

fn eval_calls_from(pattern: &str, pos: Position<'_>, call_index: &CallIndex) -> Outcome {
    let fa: Option<u64> = pos.enclosing_function_address();
    call_index
        .calls_from(fa, pattern)
        .map(|(address, caller): (u64, String)| {
            vec![Evidence {
                feature: format!("calls-from({caller})"),
                address,
            }]
        })
}

fn eval_match(name: &str, pos: Position<'_>, match_index: &MatchIndex) -> Outcome {
    if match_index.resolves(name, pos.enclosing_function_address()) {
        Some(vec![Evidence {
            feature: format!("match({name})"),
            address: 0,
        }])
    } else {
        None
    }
}

fn evaluate_at<'a>(
    root: &'a Node,
    position: Position<'a>,
    call_index: &CallIndex,
    match_index: &MatchIndex,
    caps: &EvalCaps,
) -> Outcome {
    let mut work: Vec<Task<'a>> = vec![Task::Eval(root, position)];
    let mut results: Vec<Outcome> = Vec::new();
    let mut steps: usize = 0;

    while let Some(task) = work.pop() {
        steps += 1;
        if steps > caps.steps || work.len() > caps.work {
            return None;
        }
        match task {
            Task::Eval(node, pos) => match node {
                Node::Feature(feature) => results.push(eval_feature(feature, pos)),
                Node::CallsTo(pattern) => results.push(eval_calls_to(pattern, pos, call_index)),
                Node::CallsFrom(pattern) => results.push(eval_calls_from(pattern, pos, call_index)),
                Node::Match(name) => results.push(eval_match(name, pos, match_index)),
                Node::Count { feature, bound } => results.push(eval_count(feature, *bound, pos)),
                Node::And(children) => {
                    work.push(Task::CombineAnd(children.len()));
                    for child in children.iter().rev() {
                        work.push(Task::Eval(child, pos));
                    }
                }
                Node::Or(children) => {
                    work.push(Task::CombineOr(children.len()));
                    for child in children.iter().rev() {
                        work.push(Task::Eval(child, pos));
                    }
                }
                Node::Not(child) => {
                    work.push(Task::CombineNot);
                    work.push(Task::Eval(child, pos));
                }
                Node::NOf { n, of } => {
                    work.push(Task::CombineNOf(of.len(), *n));
                    for child in of.iter().rev() {
                        work.push(Task::Eval(child, pos));
                    }
                }
                Node::Optional(child) => {
                    work.push(Task::CombineOptional);
                    work.push(Task::Eval(child, pos));
                }
                Node::Descend { at, of } => {
                    let instances: Vec<Position<'a>> = pos.descend(*at, caps.descend_instances);
                    work.push(Task::CombineOr(instances.len()));
                    for instance in instances {
                        work.push(Task::CombineAnd(of.len()));
                        for child in of.iter().rev() {
                            work.push(Task::Eval(child, instance));
                        }
                    }
                }
            },
            Task::CombineAnd(n) => {
                let parts: Vec<Outcome> = pop_results(&mut results, n);
                results.push(combine_and(parts));
            }
            Task::CombineOr(n) => {
                let parts: Vec<Outcome> = pop_results(&mut results, n);
                results.push(combine_or(parts));
            }
            Task::CombineNot => {
                let inner: Outcome = results.pop().flatten();
                results.push(if inner.is_some() {
                    None
                } else {
                    Some(Vec::new())
                });
            }
            Task::CombineNOf(total, n) => {
                let parts: Vec<Outcome> = pop_results(&mut results, total);
                results.push(combine_n_of(parts, n));
            }
            Task::CombineOptional => {
                let inner: Outcome = results.pop().flatten();
                results.push(Some(inner.unwrap_or_default()));
            }
        }
    }
    results.pop().flatten()
}

fn fire(
    rule: &LoadedRule,
    pos: Position<'_>,
    call_index: &CallIndex,
    match_index: &MatchIndex,
    caps: &EvalCaps,
) -> Option<CapabilityMatch> {
    let mut evidence: Vec<Evidence> = evaluate_at(&rule.root, pos, call_index, match_index, caps)?;
    evidence.sort_by(|a: &Evidence, b: &Evidence| {
        a.address
            .cmp(&b.address)
            .then_with(|| a.feature.cmp(&b.feature))
    });
    evidence.dedup();
    let address: u64 = evidence
        .iter()
        .map(|e: &Evidence| e.address)
        .min()
        .unwrap_or_else(|| pos.anchor());
    Some(CapabilityMatch {
        rule: rule.name.clone(),
        namespace: rule.namespace.clone(),
        scope: rule.scope,
        function: pos.enclosing_function_name().map(str::to_owned),
        function_address: pos.enclosing_function_address(),
        address,
        attack: rule.attack.clone(),
        mbc: rule.mbc.clone(),
        description: rule.description.clone(),
        evidence,
    })
}

fn evaluate_rule(
    rule: &LoadedRule,
    scoped: &ScopedFeatures,
    call_index: &CallIndex,
    match_index: &MatchIndex,
    caps: &EvalCaps,
) -> Vec<CapabilityMatch> {
    match rule.scope {
        Scope::File => fire(rule, Position::File(scoped), call_index, match_index, caps)
            .into_iter()
            .collect(),
        Scope::Function => scoped
            .functions
            .iter()
            .filter_map(|f: &FunctionFeatures| {
                fire(rule, Position::Function(f), call_index, match_index, caps)
            })
            .collect(),
        Scope::BasicBlock => scoped
            .functions
            .iter()
            .flat_map(|f: &FunctionFeatures| {
                f.blocks.iter().filter_map(move |b: &BlockFeatures| {
                    fire(rule, Position::Block(f, b), call_index, match_index, caps)
                })
            })
            .collect(),
        Scope::Instruction => scoped
            .functions
            .iter()
            .flat_map(|f: &FunctionFeatures| {
                f.blocks.iter().flat_map(move |b: &BlockFeatures| {
                    b.instructions
                        .iter()
                        .filter_map(move |i: &InstructionFeatures| {
                            fire(
                                rule,
                                Position::Instruction(f, i),
                                call_index,
                                match_index,
                                caps,
                            )
                        })
                })
            })
            .collect(),
    }
}

#[must_use]
pub(super) fn run(
    rules: &[LoadedRule],
    module: &Module,
    scoped: &ScopedFeatures,
) -> Vec<CapabilityMatch> {
    let call_index: CallIndex = CallIndex::build(module);
    let caps: EvalCaps = EvalCaps::production();
    let mut match_index: MatchIndex = MatchIndex::default();
    let mut out: Vec<CapabilityMatch> = Vec::new();

    for rule in rules {
        let hits: Vec<CapabilityMatch> =
            evaluate_rule(rule, scoped, &call_index, &match_index, &caps);
        for hit in &hits {
            match_index.record(&rule.name, rule.scope, hit.function_address);
        }
        out.extend(hits);
    }

    out.sort_by(|a: &CapabilityMatch, b: &CapabilityMatch| {
        a.address.cmp(&b.address).then_with(|| a.rule.cmp(&b.rule))
    });
    out
}
