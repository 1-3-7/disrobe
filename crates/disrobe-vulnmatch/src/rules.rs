use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::PredicateEvaluation;
use crate::adapters::{AbstractArgument, DirectCall, ResolvedCallee};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub(crate) const fn score(self) -> u32 {
        match self {
            Self::Critical => 400,
            Self::High => 300,
            Self::Medium => 200,
            Self::Low => 100,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceClass {
    UserControlled,
    Environment,
    Network,
    File,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SinkSignature {
    ResolvedSymbol {
        canonical_name: String,
        #[serde(default)]
        aliases: BTreeSet<String>,
    },
}

impl SinkSignature {
    pub(crate) fn matches(&self, callee: &ResolvedCallee) -> bool {
        match self {
            Self::ResolvedSymbol {
                canonical_name,
                aliases,
            } => {
                canonical_name == &callee.canonical_name || aliases.contains(&callee.canonical_name)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "arg_index")]
pub enum ArgPredicate {
    IsConstant(usize),
    IsNotConstant(usize),
}

impl ArgPredicate {
    pub(crate) fn evaluate(&self, site: &DirectCall) -> PredicateEvaluation {
        match (self, site.arguments.get(self.index())) {
            (Self::IsConstant(_), Some(AbstractArgument::Constant))
            | (Self::IsNotConstant(_), Some(AbstractArgument::NonConstant)) => {
                PredicateEvaluation::Match
            }
            (Self::IsConstant(_), Some(AbstractArgument::NonConstant))
            | (Self::IsNotConstant(_), Some(AbstractArgument::Constant)) => {
                PredicateEvaluation::NoMatch
            }
            (_, Some(AbstractArgument::Unknown) | None) => PredicateEvaluation::Indeterminate,
        }
    }

    const fn index(&self) -> usize {
        match self {
            Self::IsConstant(index) | Self::IsNotConstant(index) => *index,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub cwe: String,
    pub severity: Severity,
    pub sink: SinkSignature,
    pub requires_source: Option<SourceClass>,
    #[serde(default)]
    pub arg_constraints: Vec<ArgPredicate>,
}

#[derive(Debug, Error)]
pub enum RuleStoreError {
    #[error("rule data is invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("rule identifier is empty")]
    EmptyIdentifier,
    #[error("rule identifier is duplicated: {0}")]
    DuplicateIdentifier(String),
    #[error("rule CWE is empty for {0}")]
    EmptyCwe(String),
    #[error("resolved sink symbol is empty for {0}")]
    EmptySinkSymbol(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleStore {
    rules: BTreeMap<String, Rule>,
}

impl RuleStore {
    pub fn from_json(data: &str) -> Result<Self, RuleStoreError> {
        let parsed: Vec<Rule> = serde_json::from_str(data)?;
        Self::from_rules(parsed)
    }

    pub fn from_rules(rules: Vec<Rule>) -> Result<Self, RuleStoreError> {
        let mut entries: BTreeMap<String, Rule> = BTreeMap::new();
        for rule in rules {
            Self::validate_rule(&rule)?;
            let identifier: String = rule.id.clone();
            if entries.contains_key(&identifier) {
                return Err(RuleStoreError::DuplicateIdentifier(identifier));
            }
            entries.insert(identifier, rule);
        }
        Ok(Self { rules: entries })
    }

    pub fn embedded() -> Self {
        let rules: Vec<Rule> = vec![
            Rule {
                id: String::from("cwe-134-nonconstant-printf"),
                cwe: String::from("CWE-134"),
                severity: Severity::High,
                sink: SinkSignature::ResolvedSymbol {
                    canonical_name: String::from("printf"),
                    aliases: BTreeSet::from([String::from("__printf_chk")]),
                },
                requires_source: Some(SourceClass::UserControlled),
                arg_constraints: vec![ArgPredicate::IsNotConstant(0)],
            },
            Rule {
                id: String::from("cwe-78-command-argument"),
                cwe: String::from("CWE-78"),
                severity: Severity::Critical,
                sink: SinkSignature::ResolvedSymbol {
                    canonical_name: String::from("system"),
                    aliases: BTreeSet::from([
                        String::from("execv"),
                        String::from("execl"),
                        String::from("execve"),
                    ]),
                },
                requires_source: Some(SourceClass::UserControlled),
                arg_constraints: vec![ArgPredicate::IsNotConstant(0)],
            },
            Rule {
                id: String::from("cwe-120-strcpy"),
                cwe: String::from("CWE-120"),
                severity: Severity::High,
                sink: SinkSignature::ResolvedSymbol {
                    canonical_name: String::from("strcpy"),
                    aliases: BTreeSet::from([String::from("__strcpy_chk")]),
                },
                requires_source: None,
                arg_constraints: vec![ArgPredicate::IsNotConstant(1)],
            },
            Rule {
                id: String::from("cwe-242-gets"),
                cwe: String::from("CWE-242"),
                severity: Severity::High,
                sink: SinkSignature::ResolvedSymbol {
                    canonical_name: String::from("gets"),
                    aliases: BTreeSet::new(),
                },
                requires_source: None,
                arg_constraints: Vec::new(),
            },
            Rule {
                id: String::from("cwe-120-sprintf"),
                cwe: String::from("CWE-120"),
                severity: Severity::High,
                sink: SinkSignature::ResolvedSymbol {
                    canonical_name: String::from("sprintf"),
                    aliases: BTreeSet::from([String::from("vsprintf")]),
                },
                requires_source: None,
                arg_constraints: vec![ArgPredicate::IsNotConstant(1)],
            },
        ];
        let mut entries: BTreeMap<String, Rule> = BTreeMap::new();
        for rule in rules {
            entries.insert(rule.id.clone(), rule);
        }
        Self { rules: entries }
    }

    pub fn rules(&self) -> impl Iterator<Item = &Rule> {
        self.rules.values()
    }

    fn validate_rule(rule: &Rule) -> Result<(), RuleStoreError> {
        if rule.id.is_empty() {
            return Err(RuleStoreError::EmptyIdentifier);
        }
        if rule.cwe.is_empty() {
            return Err(RuleStoreError::EmptyCwe(rule.id.clone()));
        }
        match &rule.sink {
            SinkSignature::ResolvedSymbol { canonical_name, .. } if canonical_name.is_empty() => {
                Err(RuleStoreError::EmptySinkSymbol(rule.id.clone()))
            }
            SinkSignature::ResolvedSymbol { .. } => Ok(()),
        }
    }
}
