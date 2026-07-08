use crate::eval::CapabilityMatch;
use crate::feature::{Feature, Scope};
use crate::rule::CountBound;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    Feature(Feature),
    CallsTo(String),
    CallsFrom(String),
    And(Vec<Self>),
    Or(Vec<Self>),
    Not(Box<Self>),
    NOf { n: usize, of: Vec<Self> },
    Optional(Box<Self>),
    Count { feature: Feature, bound: CountBound },
    Match(String),
    Descend { at: Scope, of: Vec<Self> },
}

#[derive(Debug, Clone)]
pub struct LoadedRule {
    pub name: String,
    pub namespace: String,
    pub scope: Scope,
    pub attack: Vec<String>,
    pub mbc: Vec<String>,
    pub description: String,
    pub root: Node,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedRule {
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default)]
pub struct LoadedRuleSet {
    pub rules: Vec<LoadedRule>,
    pub unsupported: Vec<UnsupportedRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndeterminateMatch {
    pub rule: String,
    pub namespace: String,
    pub scope: Scope,
    pub function: Option<String>,
    pub function_address: Option<u64>,
    pub reason: String,
}

#[derive(Debug, Clone, Default)]
pub struct EvaluationOutcome {
    pub matches: Vec<CapabilityMatch>,
    pub indeterminate: Vec<IndeterminateMatch>,
}
