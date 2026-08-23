mod context_source;
mod corpus_source;
mod heuristic_source;
mod registry;

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use serde::Serialize;

pub use context_source::ContextNameSource;
pub use corpus_source::{CorpusEntry, CorpusNameSource};
pub use heuristic_source::HeuristicNameSource;
pub use registry::NameRegistry;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct ScopeKey(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum SymbolRole {
    Function,
    Class,
    Method,
    Variable,
    Parameter,
    Property,
}

#[derive(Debug, Clone, Serialize)]
pub struct Context {
    pub original: String,
    pub role: SymbolRole,
    pub scope: ScopeKey,
    pub callees: BTreeSet<String>,
    pub callers: BTreeSet<String>,
    pub member_accesses: BTreeSet<String>,
    pub nearby_strings: BTreeSet<String>,
    pub assigned_from: BTreeSet<String>,
}

impl Context {
    #[must_use]
    pub fn new(original: impl Into<String>, role: SymbolRole, scope: ScopeKey) -> Self {
        Self {
            original: original.into(),
            role,
            scope,
            callees: BTreeSet::new(),
            callers: BTreeSet::new(),
            member_accesses: BTreeSet::new(),
            nearby_strings: BTreeSet::new(),
            assigned_from: BTreeSet::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Confidence(pub u8);

impl Confidence {
    pub const LOW: Self = Self(25);
    pub const MEDIUM: Self = Self(50);
    pub const HIGH: Self = Self(80);
    pub const EXACT: Self = Self(100);

    #[must_use]
    pub const fn tier(self) -> ConfidenceTier {
        match self.0 {
            100..=u8::MAX => ConfidenceTier::Exact,
            80..=99 => ConfidenceTier::High,
            50..=79 => ConfidenceTier::Medium,
            _ => ConfidenceTier::Low,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum ConfidenceTier {
    Low,
    Medium,
    High,
    Exact,
}

impl ConfidenceTier {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Exact => "exact",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct NameDecision {
    pub restored: String,
    pub confidence: Confidence,
    pub tier: ConfidenceTier,
    pub source_label: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct RestoredName {
    pub original: String,
    pub restored: String,
    pub confidence: Confidence,
    pub tier: ConfidenceTier,
    pub source_label: &'static str,
    pub declaration_offset: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Suggestion {
    pub name: String,
    pub confidence: Confidence,
    pub source_label: &'static str,
}

pub trait NameSource: core::fmt::Debug + Send + Sync {
    fn suggest(&self, scope: ScopeKey, context: &Context) -> Option<Suggestion>;

    fn label(&self) -> &'static str;
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RestoreStats {
    pub suggestions_made: usize,
    pub conflicts_resolved: usize,
    pub fallback_to_original: usize,
    pub by_source: BTreeMap<String, usize>,
}
