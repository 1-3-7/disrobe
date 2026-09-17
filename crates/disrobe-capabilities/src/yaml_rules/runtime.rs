use std::collections::{BTreeMap, BTreeSet};

use disrobe_query::Module;

use crate::eval::CapabilityMatch;
use crate::extract::{BlockFeatures, FunctionFeatures, InstructionFeatures, ScopedFeatures};
use crate::feature::{Feature, FeatureSet, Scope};
use crate::rule::{CountBound, Evidence};

use super::callgraph::CallIndex;
use super::node::{EvaluationOutcome, IndeterminateMatch, LoadedRule, Node};

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

const DESCENT_TRUNCATED_REASON: &str =
    "scope descent exceeded the instance visit cap before every real instance was visited";
const EVAL_BUDGET_EXHAUSTED_REASON: &str =
    "rule evaluation exceeded its step or work budget before reaching a verdict";

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

    fn descend(self, target: Scope, cap: usize) -> (Vec<Self>, bool) {
        let probe_cap: usize = cap.saturating_add(1);
        let mut instances: Vec<Self> = match (self, target) {
            (Self::File(s), Scope::Function) => s
                .functions
                .iter()
                .map(Position::Function)
                .take(probe_cap)
                .collect(),
            (Self::File(s), Scope::BasicBlock) => s
                .functions
                .iter()
                .flat_map(|f: &'a FunctionFeatures| {
                    f.blocks
                        .iter()
                        .map(move |b: &'a BlockFeatures| Position::Block(f, b))
                })
                .take(probe_cap)
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
                .take(probe_cap)
                .collect(),
            (Self::Function(f), Scope::BasicBlock) => f
                .blocks
                .iter()
                .map(|b: &'a BlockFeatures| Position::Block(f, b))
                .take(probe_cap)
                .collect(),
            (Self::Function(f), Scope::Instruction) => f
                .blocks
                .iter()
                .flat_map(|b: &'a BlockFeatures| {
                    b.instructions
                        .iter()
                        .map(move |i: &'a InstructionFeatures| Position::Instruction(f, i))
                })
                .take(probe_cap)
                .collect(),
            (Self::Block(f, b), Scope::Instruction) => b
                .instructions
                .iter()
                .map(|i: &'a InstructionFeatures| Position::Instruction(f, i))
                .take(probe_cap)
                .collect(),
            _ => Vec::new(),
        };
        let truncated: bool = instances.len() > cap;
        if truncated {
            instances.truncate(cap);
        }
        (instances, truncated)
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

#[derive(Debug)]
enum Outcome {
    Match(Vec<Evidence>),
    NoMatch,
    Indeterminate(&'static str),
}

enum Task<'a> {
    Eval(&'a Node, Position<'a>),
    CombineAnd(usize),
    CombineOr(usize),
    CombineDescend(usize, bool),
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
    let mut indeterminate_reason: Option<&'static str> = None;
    for part in parts {
        match part {
            Outcome::Match(e) => evidence.extend(e),
            Outcome::NoMatch => return Outcome::NoMatch,
            Outcome::Indeterminate(reason) => {
                indeterminate_reason.get_or_insert(reason);
            }
        }
    }
    indeterminate_reason.map_or_else(|| Outcome::Match(evidence), Outcome::Indeterminate)
}

fn combine_or(parts: Vec<Outcome>) -> Outcome {
    let mut evidence: Vec<Evidence> = Vec::new();
    let mut any_match: bool = false;
    let mut indeterminate_reason: Option<&'static str> = None;
    for part in parts {
        match part {
            Outcome::Match(e) => {
                any_match = true;
                evidence.extend(e);
            }
            Outcome::NoMatch => {}
            Outcome::Indeterminate(reason) => {
                indeterminate_reason.get_or_insert(reason);
            }
        }
    }
    if any_match {
        Outcome::Match(evidence)
    } else if let Some(reason) = indeterminate_reason {
        Outcome::Indeterminate(reason)
    } else {
        Outcome::NoMatch
    }
}

fn combine_n_of(parts: Vec<Outcome>, n: usize) -> Outcome {
    let mut evidence: Vec<Evidence> = Vec::new();
    let mut satisfied: usize = 0;
    let mut unknown: usize = 0;
    let mut indeterminate_reason: Option<&'static str> = None;
    for part in parts {
        match part {
            Outcome::Match(e) => {
                satisfied += 1;
                evidence.extend(e);
            }
            Outcome::NoMatch => {}
            Outcome::Indeterminate(reason) => {
                unknown += 1;
                indeterminate_reason.get_or_insert(reason);
            }
        }
    }
    if satisfied >= n {
        Outcome::Match(evidence)
    } else if satisfied + unknown >= n {
        Outcome::Indeterminate(indeterminate_reason.unwrap_or(EVAL_BUDGET_EXHAUSTED_REASON))
    } else {
        Outcome::NoMatch
    }
}

fn combine_not(inner: Outcome) -> Outcome {
    match inner {
        Outcome::Match(_) => Outcome::NoMatch,
        Outcome::NoMatch => Outcome::Match(Vec::new()),
        Outcome::Indeterminate(reason) => Outcome::Indeterminate(reason),
    }
}

fn combine_optional(inner: Outcome) -> Outcome {
    match inner {
        Outcome::Match(e) => Outcome::Match(e),
        Outcome::NoMatch | Outcome::Indeterminate(_) => Outcome::Match(Vec::new()),
    }
}

fn eval_feature(feature: &Feature, pos: Position<'_>) -> Outcome {
    let addrs: Vec<u64> = pos.features().matches(feature);
    if addrs.is_empty() {
        return Outcome::NoMatch;
    }
    Outcome::Match(
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
        return Outcome::NoMatch;
    }
    Outcome::Match(vec![Evidence {
        feature: format!("count({} {})", feature.render(), bound.render()),
        address: addrs.first().copied().unwrap_or_default(),
    }])
}

fn eval_calls_to(pattern: &str, pos: Position<'_>, call_index: &CallIndex) -> Outcome {
    let fa: Option<u64> = pos.enclosing_function_address();
    match call_index.calls_to(fa, pattern) {
        Some((address, callee)) => Outcome::Match(vec![Evidence {
            feature: format!("calls-to({callee})"),
            address,
        }]),
        None => Outcome::NoMatch,
    }
}

fn eval_calls_from(pattern: &str, pos: Position<'_>, call_index: &CallIndex) -> Outcome {
    let fa: Option<u64> = pos.enclosing_function_address();
    match call_index.calls_from(fa, pattern) {
        Some((address, caller)) => Outcome::Match(vec![Evidence {
            feature: format!("calls-from({caller})"),
            address,
        }]),
        None => Outcome::NoMatch,
    }
}

fn eval_match(name: &str, pos: Position<'_>, match_index: &MatchIndex) -> Outcome {
    if match_index.resolves(name, pos.enclosing_function_address()) {
        Outcome::Match(vec![Evidence {
            feature: format!("match({name})"),
            address: 0,
        }])
    } else {
        Outcome::NoMatch
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
            return Outcome::Indeterminate(EVAL_BUDGET_EXHAUSTED_REASON);
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
                    let (instances, truncated): (Vec<Position<'a>>, bool) =
                        pos.descend(*at, caps.descend_instances);
                    work.push(Task::CombineDescend(instances.len(), truncated));
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
            Task::CombineDescend(n, truncated) => {
                let mut parts: Vec<Outcome> = pop_results(&mut results, n);
                if truncated {
                    parts.push(Outcome::Indeterminate(DESCENT_TRUNCATED_REASON));
                }
                results.push(combine_or(parts));
            }
            Task::CombineNot => {
                let inner: Outcome = results.pop().unwrap_or(Outcome::NoMatch);
                results.push(combine_not(inner));
            }
            Task::CombineNOf(total, n) => {
                let parts: Vec<Outcome> = pop_results(&mut results, total);
                results.push(combine_n_of(parts, n));
            }
            Task::CombineOptional => {
                let inner: Outcome = results.pop().unwrap_or(Outcome::NoMatch);
                results.push(combine_optional(inner));
            }
        }
    }
    results.pop().unwrap_or(Outcome::NoMatch)
}

enum RuleVerdict {
    Match(CapabilityMatch),
    NoMatch,
    Indeterminate(&'static str),
}

fn fire(
    rule: &LoadedRule,
    pos: Position<'_>,
    call_index: &CallIndex,
    match_index: &MatchIndex,
    caps: &EvalCaps,
) -> RuleVerdict {
    match evaluate_at(&rule.root, pos, call_index, match_index, caps) {
        Outcome::Match(mut evidence) => {
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
            RuleVerdict::Match(CapabilityMatch {
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
        Outcome::NoMatch => RuleVerdict::NoMatch,
        Outcome::Indeterminate(reason) => RuleVerdict::Indeterminate(reason),
    }
}

fn record_verdict(
    rule: &LoadedRule,
    pos: Position<'_>,
    verdict: RuleVerdict,
    matches: &mut Vec<CapabilityMatch>,
    indeterminate: &mut Vec<IndeterminateMatch>,
) {
    match verdict {
        RuleVerdict::Match(hit) => matches.push(hit),
        RuleVerdict::NoMatch => {}
        RuleVerdict::Indeterminate(reason) => indeterminate.push(IndeterminateMatch {
            rule: rule.name.clone(),
            namespace: rule.namespace.clone(),
            scope: rule.scope,
            function: pos.enclosing_function_name().map(str::to_owned),
            function_address: pos.enclosing_function_address(),
            reason: reason.to_owned(),
        }),
    }
}

fn evaluate_rule(
    rule: &LoadedRule,
    scoped: &ScopedFeatures,
    call_index: &CallIndex,
    match_index: &MatchIndex,
    caps: &EvalCaps,
    matches: &mut Vec<CapabilityMatch>,
    indeterminate: &mut Vec<IndeterminateMatch>,
) {
    match rule.scope {
        Scope::File => {
            let pos: Position<'_> = Position::File(scoped);
            let verdict: RuleVerdict = fire(rule, pos, call_index, match_index, caps);
            record_verdict(rule, pos, verdict, matches, indeterminate);
        }
        Scope::Function => {
            for f in &scoped.functions {
                let pos: Position<'_> = Position::Function(f);
                let verdict: RuleVerdict = fire(rule, pos, call_index, match_index, caps);
                record_verdict(rule, pos, verdict, matches, indeterminate);
            }
        }
        Scope::BasicBlock => {
            for f in &scoped.functions {
                for b in &f.blocks {
                    let pos: Position<'_> = Position::Block(f, b);
                    let verdict: RuleVerdict = fire(rule, pos, call_index, match_index, caps);
                    record_verdict(rule, pos, verdict, matches, indeterminate);
                }
            }
        }
        Scope::Instruction => {
            for f in &scoped.functions {
                for b in &f.blocks {
                    for i in &b.instructions {
                        let pos: Position<'_> = Position::Instruction(f, i);
                        let verdict: RuleVerdict = fire(rule, pos, call_index, match_index, caps);
                        record_verdict(rule, pos, verdict, matches, indeterminate);
                    }
                }
            }
        }
    }
}

#[must_use]
pub(super) fn run(
    rules: &[LoadedRule],
    module: &Module,
    scoped: &ScopedFeatures,
) -> EvaluationOutcome {
    let call_index: CallIndex = CallIndex::build(module);
    let caps: EvalCaps = EvalCaps::production();
    let mut match_index: MatchIndex = MatchIndex::default();
    let mut matches: Vec<CapabilityMatch> = Vec::new();
    let mut indeterminate: Vec<IndeterminateMatch> = Vec::new();

    for rule in rules {
        let before: usize = matches.len();
        evaluate_rule(
            rule,
            scoped,
            &call_index,
            &match_index,
            &caps,
            &mut matches,
            &mut indeterminate,
        );
        for hit in &matches[before..] {
            match_index.record(&rule.name, rule.scope, hit.function_address);
        }
    }

    matches.sort_by(|a: &CapabilityMatch, b: &CapabilityMatch| {
        a.address.cmp(&b.address).then_with(|| a.rule.cmp(&b.rule))
    });
    indeterminate.sort_by(|a: &IndeterminateMatch, b: &IndeterminateMatch| {
        a.rule
            .cmp(&b.rule)
            .then_with(|| a.function_address.cmp(&b.function_address))
    });
    EvaluationOutcome {
        matches,
        indeterminate,
    }
}
