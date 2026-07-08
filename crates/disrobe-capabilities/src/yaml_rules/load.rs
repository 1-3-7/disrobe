use std::collections::{BTreeMap, BTreeSet};

use crate::feature::{Characteristic, Feature, OperandFeature, Scope};
use crate::rule::CountBound;

use super::node::{LoadedRule, LoadedRuleSet, Node, UnsupportedRule};
use super::schema::{RawCount, RawFile, RawNOf, RawNode, RawOperand, RawScope};
use super::vocab::{characteristic_from_tag, feature_is_supported};

const MAX_NODE_DEPTH: usize = 24;
const MAX_LOWER_STEPS: usize = 100_000;
const MAX_REGEX_PATTERN_LEN: usize = 512;

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("document {0}: {1}")]
    Yaml(usize, String),
    #[error("unknown scope tag: {0}")]
    UnknownScope(String),
    #[error("not requires exactly one child, got {0}")]
    NotArity(usize),
    #[error("optional requires exactly one child, got {0}")]
    OptionalArity(usize),
    #[error("n-of requires at least one candidate")]
    EmptyNOf,
    #[error("n-of requires 1 <= n ({n}) <= available ({available})")]
    NOfOutOfRange { n: usize, available: usize },
    #[error("scope descent requires at least one condition")]
    EmptyScope,
    #[error("scope descent from {from:?} to {to:?} does not narrow the scope")]
    NonDescendingScope { from: Scope, to: Scope },
    #[error("count feature must be a plain feature leaf")]
    CountFeatureMustBeLeaf,
    #[error("count bound must set exactly one of exact / at-least / at-most / range")]
    AmbiguousCountBound,
    #[error("count range lower bound {0} exceeds upper bound {1}")]
    InvalidRange(usize, usize),
    #[error("invalid operand node: set exactly one of number / offset")]
    InvalidOperand,
    #[error("invalid bytes hex literal: {0}")]
    InvalidBytesHex(String),
    #[error("string-regex pattern exceeds the {0}-byte bound")]
    RegexTooLong(usize),
    #[error("unknown characteristic tag: {0}")]
    UnknownCharacteristic(String),
    #[error("rule tree exceeds the maximum nesting depth of {max}")]
    TooDeep { max: usize },
    #[error("rule tree exceeds the maximum node budget")]
    TooComplex,
    #[error("duplicate rule name: {0}")]
    DuplicateRuleName(String),
    #[error("rule {rule} references an unresolved rule name: {reference}")]
    UnresolvedMatch { rule: String, reference: String },
    #[error("cyclic match reference among rules: {0:?}")]
    CyclicMatch(Vec<String>),
    #[error("internal lowering stack underflow")]
    Internal,
}

struct StagedRule {
    name: String,
    namespace: String,
    scope: Scope,
    attack: Vec<String>,
    mbc: Vec<String>,
    description: String,
    root: Node,
    refs: Vec<String>,
    unsupported_reasons: Vec<String>,
}

pub fn load_rules(sources: &[&str]) -> Result<LoadedRuleSet, LoadError> {
    let mut staged: Vec<StagedRule> = Vec::with_capacity(sources.len());
    for (doc_index, source) in sources.iter().enumerate() {
        let raw: RawFile = serde_yaml_ng::from_str(source)
            .map_err(|e: serde_yaml_ng::Error| LoadError::Yaml(doc_index, e.to_string()))?;
        let scope: Scope = parse_scope(&raw.rule.meta.scope)?;
        let mut refs: Vec<String> = Vec::new();
        let mut unsupported_reasons: Vec<String> = Vec::new();
        let root: Node = lower_root(
            raw.rule.features,
            scope,
            &mut refs,
            &mut unsupported_reasons,
        )?;
        staged.push(StagedRule {
            name: raw.rule.meta.name,
            namespace: raw.rule.meta.namespace,
            scope,
            attack: raw.rule.meta.attack,
            mbc: raw.rule.meta.mbc,
            description: raw.rule.meta.description,
            root,
            refs,
            unsupported_reasons,
        });
    }

    let mut seen_names: BTreeSet<String> = BTreeSet::new();
    for staged_rule in &staged {
        if !seen_names.insert(staged_rule.name.clone()) {
            return Err(LoadError::DuplicateRuleName(staged_rule.name.clone()));
        }
    }
    for staged_rule in &staged {
        for reference in &staged_rule.refs {
            if !seen_names.contains(reference) {
                return Err(LoadError::UnresolvedMatch {
                    rule: staged_rule.name.clone(),
                    reference: reference.clone(),
                });
            }
        }
    }

    let order: Vec<usize> = topological_order(&staged)?;

    let mut supported: BTreeMap<String, bool> = BTreeMap::new();
    let mut rules: Vec<LoadedRule> = Vec::new();
    let mut unsupported: Vec<UnsupportedRule> = Vec::new();
    let mut slots: Vec<Option<StagedRule>> = staged.into_iter().map(Some).collect();
    for idx in order {
        let staged_rule: StagedRule = slots[idx].take().ok_or(LoadError::Internal)?;
        let dependency_unsupported: bool = staged_rule
            .refs
            .iter()
            .any(|r: &String| supported.get(r).copied() == Some(false));
        let is_supported: bool =
            staged_rule.unsupported_reasons.is_empty() && !dependency_unsupported;
        supported.insert(staged_rule.name.clone(), is_supported);
        if is_supported {
            rules.push(LoadedRule {
                name: staged_rule.name,
                namespace: staged_rule.namespace,
                scope: staged_rule.scope,
                attack: staged_rule.attack,
                mbc: staged_rule.mbc,
                description: staged_rule.description,
                root: staged_rule.root,
            });
        } else {
            let reason: String = if staged_rule.unsupported_reasons.is_empty() {
                "depends on an unsupported rule".to_owned()
            } else {
                staged_rule.unsupported_reasons.join("; ")
            };
            unsupported.push(UnsupportedRule {
                name: staged_rule.name,
                reason,
            });
        }
    }

    Ok(LoadedRuleSet { rules, unsupported })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Color {
    White,
    Gray,
    Black,
}

fn topological_order(staged: &[StagedRule]) -> Result<Vec<usize>, LoadError> {
    let index_of: BTreeMap<&str, usize> = staged
        .iter()
        .enumerate()
        .map(|(i, r): (usize, &StagedRule)| (r.name.as_str(), i))
        .collect();
    let depends_on: Vec<Vec<usize>> = staged
        .iter()
        .map(|r: &StagedRule| {
            r.refs
                .iter()
                .filter_map(|name: &String| index_of.get(name.as_str()).copied())
                .collect()
        })
        .collect();

    let n: usize = staged.len();
    let mut color: Vec<Color> = vec![Color::White; n];
    let mut order: Vec<usize> = Vec::with_capacity(n);

    for start in 0..n {
        if color[start] != Color::White {
            continue;
        }
        let mut stack: Vec<(usize, usize)> = vec![(start, 0)];
        color[start] = Color::Gray;
        while let Some(&mut (node, ref mut next)) = stack.last_mut() {
            if *next < depends_on[node].len() {
                let child: usize = depends_on[node][*next];
                *next += 1;
                match color[child] {
                    Color::White => {
                        color[child] = Color::Gray;
                        stack.push((child, 0));
                    }
                    Color::Gray => {
                        let cycle_names: Vec<String> = stack
                            .iter()
                            .map(|(idx, _): &(usize, usize)| staged[*idx].name.clone())
                            .collect();
                        return Err(LoadError::CyclicMatch(cycle_names));
                    }
                    Color::Black => {}
                }
            } else {
                color[node] = Color::Black;
                order.push(node);
                stack.pop();
            }
        }
    }
    Ok(order)
}

fn parse_scope(raw: &str) -> Result<Scope, LoadError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "file" => Ok(Scope::File),
        "function" => Ok(Scope::Function),
        "basic-block" | "basic_block" | "block" => Ok(Scope::BasicBlock),
        "instruction" => Ok(Scope::Instruction),
        other => Err(LoadError::UnknownScope(other.to_owned())),
    }
}

const fn scope_rank(scope: Scope) -> u8 {
    match scope {
        Scope::File => 0,
        Scope::Function => 1,
        Scope::BasicBlock => 2,
        Scope::Instruction => 3,
    }
}

const fn resolve_bound(
    exact: Option<usize>,
    at_least: Option<usize>,
    at_most: Option<usize>,
    range: Option<(usize, usize)>,
) -> Result<CountBound, LoadError> {
    match (exact, at_least, at_most, range) {
        (Some(n), None, None, None) => Ok(CountBound::Exact(n)),
        (None, Some(lo), None, None) => Ok(CountBound::AtLeast(lo)),
        (None, None, Some(hi), None) => Ok(CountBound::AtMost(hi)),
        (None, None, None, Some((lo, hi))) => {
            if lo > hi {
                return Err(LoadError::InvalidRange(lo, hi));
            }
            Ok(CountBound::Range(lo, hi))
        }
        _ => Err(LoadError::AmbiguousCountBound),
    }
}

fn decode_hex(raw: &str) -> Result<Vec<u8>, LoadError> {
    let compact: String = raw
        .chars()
        .filter(|c: &char| !c.is_ascii_whitespace())
        .collect();
    if compact.is_empty() || !compact.len().is_multiple_of(2) {
        return Err(LoadError::InvalidBytesHex(raw.to_owned()));
    }
    let digits: &[u8] = compact.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(compact.len() / 2);
    let mut i: usize = 0;
    while i < digits.len() {
        let hi: u32 = (digits[i] as char)
            .to_digit(16)
            .ok_or_else(|| LoadError::InvalidBytesHex(raw.to_owned()))?;
        let lo: u32 = (digits[i + 1] as char)
            .to_digit(16)
            .ok_or_else(|| LoadError::InvalidBytesHex(raw.to_owned()))?;
        out.push(
            u8::try_from((hi << 4) | lo).map_err(|_| LoadError::InvalidBytesHex(raw.to_owned()))?,
        );
        i += 2;
    }
    Ok(out)
}

fn lower_root(
    features: Vec<RawNode>,
    scope: Scope,
    refs: &mut Vec<String>,
    unsupported: &mut Vec<String>,
) -> Result<Node, LoadError> {
    lower_single(RawNode::And { and: features }, scope, refs, unsupported)
}

enum LowerFrame {
    Visit(RawNode, Scope, usize),
    FinishAnd(usize),
    FinishOr(usize),
    FinishNot,
    FinishNOf(usize, usize),
    FinishOptional,
    FinishScope(Scope, usize),
    FinishCountFeature(CountBound),
}

fn pop_n(out: &mut Vec<Node>, n: usize) -> Vec<Node> {
    let at: usize = out.len().saturating_sub(n);
    out.split_off(at)
}

fn lower_single(
    root: RawNode,
    scope: Scope,
    refs: &mut Vec<String>,
    unsupported: &mut Vec<String>,
) -> Result<Node, LoadError> {
    let mut work: Vec<LowerFrame> = vec![LowerFrame::Visit(root, scope, 0)];
    let mut out: Vec<Node> = Vec::new();
    let mut steps: usize = 0;

    while let Some(frame) = work.pop() {
        steps += 1;
        if steps > MAX_LOWER_STEPS {
            return Err(LoadError::TooComplex);
        }
        match frame {
            LowerFrame::Visit(raw, scope, depth) => {
                if depth > MAX_NODE_DEPTH {
                    return Err(LoadError::TooDeep {
                        max: MAX_NODE_DEPTH,
                    });
                }
                lower_visit(raw, scope, depth, &mut work, &mut out, refs, unsupported)?;
            }
            LowerFrame::FinishAnd(n) => {
                let children: Vec<Node> = pop_n(&mut out, n);
                out.push(Node::And(children));
            }
            LowerFrame::FinishOr(n) => {
                let children: Vec<Node> = pop_n(&mut out, n);
                out.push(Node::Or(children));
            }
            LowerFrame::FinishNot => {
                let child: Node = out.pop().ok_or(LoadError::Internal)?;
                out.push(Node::Not(Box::new(child)));
            }
            LowerFrame::FinishNOf(total, n) => {
                let of: Vec<Node> = pop_n(&mut out, total);
                out.push(Node::NOf { n, of });
            }
            LowerFrame::FinishOptional => {
                let child: Node = out.pop().ok_or(LoadError::Internal)?;
                out.push(Node::Optional(Box::new(child)));
            }
            LowerFrame::FinishScope(at, n) => {
                let of: Vec<Node> = pop_n(&mut out, n);
                out.push(Node::Descend { at, of });
            }
            LowerFrame::FinishCountFeature(bound) => {
                let feature_node: Node = out.pop().ok_or(LoadError::Internal)?;
                let Node::Feature(feature) = feature_node else {
                    return Err(LoadError::CountFeatureMustBeLeaf);
                };
                if !feature_is_supported(&feature) {
                    unsupported.push(format!(
                        "count over feature kind {} has no static producer",
                        feature.kind()
                    ));
                }
                out.push(Node::Count { feature, bound });
            }
        }
    }
    out.pop().ok_or(LoadError::Internal)
}

fn lower_visit(
    raw: RawNode,
    scope: Scope,
    depth: usize,
    work: &mut Vec<LowerFrame>,
    out: &mut Vec<Node>,
    refs: &mut Vec<String>,
    unsupported: &mut Vec<String>,
) -> Result<(), LoadError> {
    match raw {
        RawNode::And { and: children } => push_container(
            work,
            LowerFrame::FinishAnd(children.len()),
            children,
            scope,
            depth,
        ),
        RawNode::Or { or: children } => push_container(
            work,
            LowerFrame::FinishOr(children.len()),
            children,
            scope,
            depth,
        ),
        RawNode::Not { not: children } => {
            if children.len() != 1 {
                return Err(LoadError::NotArity(children.len()));
            }
            push_container(work, LowerFrame::FinishNot, children, scope, depth);
        }
        RawNode::Optional { optional: children } => {
            if children.len() != 1 {
                return Err(LoadError::OptionalArity(children.len()));
            }
            push_container(work, LowerFrame::FinishOptional, children, scope, depth);
        }
        RawNode::NOf {
            n_of: RawNOf { n, of },
        } => {
            if of.is_empty() {
                return Err(LoadError::EmptyNOf);
            }
            if n == 0 || n > of.len() {
                return Err(LoadError::NOfOutOfRange {
                    n,
                    available: of.len(),
                });
            }
            push_container(work, LowerFrame::FinishNOf(of.len(), n), of, scope, depth);
        }
        RawNode::Scope {
            scope: RawScope { at, of },
        } => {
            let target: Scope = parse_scope(&at)?;
            if scope_rank(target) <= scope_rank(scope) {
                return Err(LoadError::NonDescendingScope {
                    from: scope,
                    to: target,
                });
            }
            if of.is_empty() {
                return Err(LoadError::EmptyScope);
            }
            push_container(
                work,
                LowerFrame::FinishScope(target, of.len()),
                of,
                target,
                depth,
            );
        }
        RawNode::Count {
            count:
                RawCount {
                    feature,
                    exact,
                    at_least,
                    at_most,
                    range,
                },
        } => {
            let bound: CountBound = resolve_bound(exact, at_least, at_most, range)?;
            work.push(LowerFrame::FinishCountFeature(bound));
            work.push(LowerFrame::Visit(*feature, scope, depth + 1));
        }
        RawNode::Match { rule_name } => {
            refs.push(rule_name.clone());
            out.push(Node::Match(rule_name));
        }
        RawNode::Api { api: v } => out.push(Node::Feature(Feature::Api(v))),
        RawNode::Number { number: v } => out.push(Node::Feature(Feature::Number(v))),
        RawNode::String { string: v } => out.push(Node::Feature(Feature::StringSubstring(v))),
        RawNode::StringExact { string_exact: v } => {
            out.push(Node::Feature(Feature::StringExact(v)));
        }
        RawNode::StringRegex { string_regex: v } => {
            if v.len() > MAX_REGEX_PATTERN_LEN {
                return Err(LoadError::RegexTooLong(MAX_REGEX_PATTERN_LEN));
            }
            out.push(Node::Feature(Feature::StringRegex(v)));
        }
        RawNode::Bytes { bytes: hex } => {
            let bytes: Vec<u8> = decode_hex(&hex)?;
            let feature: Feature = Feature::Bytes(bytes);
            if !feature_is_supported(&feature) {
                unsupported.push("bytes pattern feature has no static producer".to_owned());
            }
            out.push(Node::Feature(feature));
        }
        RawNode::Mnemonic { mnemonic: v } => out.push(Node::Feature(Feature::Mnemonic(v))),
        RawNode::Offset { offset: v } => out.push(Node::Feature(Feature::Offset(v))),
        RawNode::Characteristic {
            characteristic: tag,
        } => {
            let c: Characteristic = characteristic_from_tag(&tag)
                .ok_or_else(|| LoadError::UnknownCharacteristic(tag.clone()))?;
            out.push(Node::Feature(Feature::Characteristic(c)));
        }
        RawNode::Operand {
            operand:
                RawOperand {
                    index,
                    number,
                    offset,
                },
        } => {
            let inner: OperandFeature = match (number, offset) {
                (Some(n), None) => OperandFeature::Number(n),
                (None, Some(o)) => OperandFeature::Offset(o),
                _ => return Err(LoadError::InvalidOperand),
            };
            let feature: Feature = Feature::Operand { index, inner };
            if !feature_is_supported(&feature) {
                unsupported.push("operand offset feature has no static producer".to_owned());
            }
            out.push(Node::Feature(feature));
        }
        RawNode::Os { os: v } => out.push(Node::Feature(Feature::Os(v))),
        RawNode::Arch { arch: v } => out.push(Node::Feature(Feature::Arch(v))),
        RawNode::Format { format: v } => out.push(Node::Feature(Feature::Format(v))),
        RawNode::Import { import: v } => out.push(Node::Feature(Feature::Import(v))),
        RawNode::Export { export: v } => out.push(Node::Feature(Feature::Export(v))),
        RawNode::Section { section: v } => out.push(Node::Feature(Feature::Section(v))),
        RawNode::CallsTo { calls_to: v } => out.push(Node::CallsTo(v)),
        RawNode::CallsFrom { calls_from: v } => out.push(Node::CallsFrom(v)),
    }
    Ok(())
}

fn push_container(
    work: &mut Vec<LowerFrame>,
    finish: LowerFrame,
    children: Vec<RawNode>,
    scope: Scope,
    depth: usize,
) {
    work.push(finish);
    for child in children.into_iter().rev() {
        work.push(LowerFrame::Visit(child, scope, depth + 1));
    }
}
