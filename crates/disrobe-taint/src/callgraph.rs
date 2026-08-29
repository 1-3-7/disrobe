use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

pub(crate) use disrobe_core::graph::scc as scc_bottom_up;

pub const CALL_EDGE_TARGET_CAP: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct NonEmptyCallTargets(Vec<u64>);

impl NonEmptyCallTargets {
    #[must_use]
    pub fn as_slice(&self) -> &[u64] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallEdgeBuildError {
    EmptyFiniteSet,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CallEdgeEvidence {
    DirectCall,
    NavigationFunctionStart,
    NavigationFunctionInterior {
        target_address: u64,
    },
    NavigationAmbiguousFunction,
    NavigationSymbol {
        target_address: u64,
    },
    NavigationUnresolved {
        target_address: u64,
    },
    NavigationIndirect,
    NamedExternal {
        symbol: String,
    },
    CandidateSetLimit {
        observed_candidate_count: usize,
        limit: usize,
    },
    NonInternalCandidates {
        targets: NonEmptyCallTargets,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CallEdgeLabel {
    Definite { target: u64 },
    FiniteSet { targets: NonEmptyCallTargets },
    Symbolic,
    Unresolved,
}

impl CallEdgeLabel {
    pub(crate) const fn path_kind(&self) -> &'static str {
        match self {
            Self::Definite { .. } => "call-definite",
            Self::FiniteSet { .. } => "call-finite-set",
            Self::Symbolic => "call-symbolic",
            Self::Unresolved => "call-unresolved",
        }
    }

    pub(crate) fn targets(&self) -> &[u64] {
        match self {
            Self::Definite { target } => core::slice::from_ref(target),
            Self::FiniteSet { targets } => targets.as_slice(),
            Self::Symbolic | Self::Unresolved => &[],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct CallEdge {
    pub site: u64,
    pub label: CallEdgeLabel,
    evidence: BTreeSet<CallEdgeEvidence>,
}

impl CallEdge {
    #[must_use]
    pub fn definite(site: u64, target: u64, evidence: CallEdgeEvidence) -> Self {
        Self::with_evidence(site, CallEdgeLabel::Definite { target }, [evidence])
    }

    pub fn finite_set<I>(
        site: u64,
        targets: I,
        evidence: CallEdgeEvidence,
    ) -> Result<Self, CallEdgeBuildError>
    where
        I: IntoIterator<Item = u64>,
    {
        let mut unique: BTreeSet<u64> = BTreeSet::new();
        for target in targets {
            unique.insert(target);
            if unique.len() > CALL_EDGE_TARGET_CAP {
                return Ok(Self::with_evidence(
                    site,
                    CallEdgeLabel::Symbolic,
                    [
                        evidence,
                        CallEdgeEvidence::CandidateSetLimit {
                            observed_candidate_count: unique.len(),
                            limit: CALL_EDGE_TARGET_CAP,
                        },
                    ],
                ));
            }
        }
        if unique.is_empty() {
            return Err(CallEdgeBuildError::EmptyFiniteSet);
        }
        Ok(Self::with_evidence(
            site,
            CallEdgeLabel::FiniteSet {
                targets: NonEmptyCallTargets(unique.into_iter().collect()),
            },
            [evidence],
        ))
    }

    #[must_use]
    pub fn symbolic(site: u64, evidence: CallEdgeEvidence) -> Self {
        Self::with_evidence(site, CallEdgeLabel::Symbolic, [evidence])
    }

    #[must_use]
    pub fn unresolved(site: u64, evidence: CallEdgeEvidence) -> Self {
        Self::with_evidence(site, CallEdgeLabel::Unresolved, [evidence])
    }

    #[must_use]
    pub fn evidence(&self) -> &BTreeSet<CallEdgeEvidence> {
        &self.evidence
    }

    fn with_evidence<I>(site: u64, label: CallEdgeLabel, evidence: I) -> Self
    where
        I: IntoIterator<Item = CallEdgeEvidence>,
    {
        Self {
            site,
            label,
            evidence: evidence.into_iter().collect(),
        }
    }
}

#[derive(Default)]
struct CallSiteAccumulator {
    targets: BTreeSet<u64>,
    concrete_evidence: BTreeSet<CallEdgeEvidence>,
    symbolic_evidence: BTreeSet<CallEdgeEvidence>,
    unresolved_evidence: BTreeSet<CallEdgeEvidence>,
    over_cap: bool,
}

pub(crate) fn normalize_call_edges<I>(edges: I) -> Vec<CallEdge>
where
    I: IntoIterator<Item = CallEdge>,
{
    let mut by_site: BTreeMap<u64, CallSiteAccumulator> = BTreeMap::new();
    for edge in edges {
        let accumulator: &mut CallSiteAccumulator = by_site.entry(edge.site).or_default();
        match edge.label {
            CallEdgeLabel::Definite { target } => {
                insert_target(accumulator, target);
                accumulator.concrete_evidence.extend(edge.evidence);
            }
            CallEdgeLabel::FiniteSet { targets } => {
                for target in targets.0 {
                    insert_target(accumulator, target);
                }
                accumulator.concrete_evidence.extend(edge.evidence);
            }
            CallEdgeLabel::Symbolic => accumulator.symbolic_evidence.extend(edge.evidence),
            CallEdgeLabel::Unresolved => accumulator.unresolved_evidence.extend(edge.evidence),
        }
    }

    let mut normalized: Vec<CallEdge> = Vec::new();
    for (site, mut accumulator) in by_site {
        if accumulator.over_cap {
            accumulator
                .symbolic_evidence
                .extend(accumulator.concrete_evidence);
            accumulator
                .symbolic_evidence
                .insert(CallEdgeEvidence::CandidateSetLimit {
                    observed_candidate_count: CALL_EDGE_TARGET_CAP + 1,
                    limit: CALL_EDGE_TARGET_CAP,
                });
        } else if let Some(first) = accumulator.targets.pop_first() {
            let label: CallEdgeLabel = if accumulator.targets.is_empty() {
                CallEdgeLabel::Definite { target: first }
            } else {
                accumulator.targets.insert(first);
                CallEdgeLabel::FiniteSet {
                    targets: NonEmptyCallTargets(accumulator.targets.into_iter().collect()),
                }
            };
            normalized.push(CallEdge::with_evidence(
                site,
                label,
                accumulator.concrete_evidence,
            ));
        }
        if !accumulator.symbolic_evidence.is_empty() {
            normalized.push(CallEdge::with_evidence(
                site,
                CallEdgeLabel::Symbolic,
                accumulator.symbolic_evidence,
            ));
        }
        if !accumulator.unresolved_evidence.is_empty() {
            normalized.push(CallEdge::with_evidence(
                site,
                CallEdgeLabel::Unresolved,
                accumulator.unresolved_evidence,
            ));
        }
    }
    normalized
}

fn insert_target(accumulator: &mut CallSiteAccumulator, target: u64) {
    if accumulator.over_cap {
        return;
    }
    accumulator.targets.insert(target);
    if accumulator.targets.len() > CALL_EDGE_TARGET_CAP {
        accumulator.targets.clear();
        accumulator.over_cap = true;
    }
}

pub(crate) fn unresolved_non_internal_edge(site: u64, targets: BTreeSet<u64>) -> Option<CallEdge> {
    (!targets.is_empty()).then(|| {
        CallEdge::unresolved(
            site,
            CallEdgeEvidence::NonInternalCandidates {
                targets: NonEmptyCallTargets(targets.into_iter().collect()),
            },
        )
    })
}
