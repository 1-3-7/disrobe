use serde::{Deserialize, Serialize};

use crate::adapters::{CallSiteId, TaintOracle, TaintStatus};
use crate::matcher::CandidateSink;
use crate::reach::{EdgeSoundness, PathWitness, ReachabilityResult, ReachabilityState};
use crate::rules::{ArgPredicate, Severity, SourceClass};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingTier {
    Confirmed,
    Reachable,
    ReachabilityUnknown,
    Present,
    Unknown,
}

impl FindingTier {
    pub(crate) const fn score_band(self) -> u32 {
        match self {
            Self::Confirmed => 4_000,
            Self::Reachable => 3_000,
            Self::ReachabilityUnknown => 2_000,
            Self::Present => 1_000,
            Self::Unknown => 0,
        }
    }

    pub(crate) const fn output_rank(self) -> u8 {
        match self {
            Self::Confirmed => 5,
            Self::Reachable => 4,
            Self::ReachabilityUnknown => 3,
            Self::Present => 2,
            Self::Unknown => 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingEvidence {
    pub cwe: String,
    pub severity: Severity,
    pub matched_constraints: Vec<ArgPredicate>,
    pub required_source: Option<SourceClass>,
    pub taint_status: Option<TaintStatus>,
    pub reachability: ReachabilityEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReachabilityEvidence {
    Unreachable,
    Reachable {
        distance: usize,
        weakest_edge_soundness: EdgeSoundness,
    },
    ReachabilityUnknown {
        distance: usize,
        weakest_edge_soundness: EdgeSoundness,
        unresolved_call_site: CallSiteId,
    },
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RankedFinding {
    pub rule_id: String,
    pub sink_site: crate::adapters::DirectCall,
    pub tier: FindingTier,
    pub score: u32,
    pub witness_path: Option<PathWitness>,
    pub evidence: FindingEvidence,
}

pub fn rank_candidates<T: TaintOracle>(
    candidates: &[CandidateSink],
    reachability: &ReachabilityResult,
    taint: &T,
) -> Vec<RankedFinding> {
    let mut ranked: Vec<RankedFinding> = Vec::new();
    for candidate in candidates {
        let reachability_state: ReachabilityState = reachability.state(&candidate.sink_site.caller);
        let taint_status: Option<TaintStatus> =
            match (&candidate.requires_source, &reachability_state) {
                (Some(source), ReachabilityState::Reachable(_)) => {
                    Some(taint.taint_status(source, &candidate.sink_site))
                }
                _ => None,
            };
        let (tier, witness_path, reachability_evidence): (
            FindingTier,
            Option<PathWitness>,
            ReachabilityEvidence,
        ) = match reachability_state {
            ReachabilityState::Reachable(witness) => (
                FindingTier::Reachable,
                Some(witness.clone()),
                ReachabilityEvidence::Reachable {
                    distance: witness.distance,
                    weakest_edge_soundness: witness.weakest_edge_soundness,
                },
            ),
            ReachabilityState::ReachabilityUnknown(witness) => {
                match witness.terminal_unresolved_call.clone() {
                    Some(unresolved_call_site) => (
                        FindingTier::ReachabilityUnknown,
                        Some(witness.clone()),
                        ReachabilityEvidence::ReachabilityUnknown {
                            distance: witness.distance,
                            weakest_edge_soundness: witness.weakest_edge_soundness,
                            unresolved_call_site,
                        },
                    ),
                    None => (FindingTier::Unknown, None, ReachabilityEvidence::Unknown),
                }
            }
            ReachabilityState::Unreachable => (
                FindingTier::Present,
                None,
                ReachabilityEvidence::Unreachable,
            ),
            ReachabilityState::Unknown => {
                (FindingTier::Unknown, None, ReachabilityEvidence::Unknown)
            }
        };
        let distance: Option<usize> = witness_path
            .as_ref()
            .map(|path: &PathWitness| path.distance);
        let score: u32 = score(tier, candidate.severity, distance);
        ranked.push(RankedFinding {
            rule_id: candidate.rule_id.clone(),
            sink_site: candidate.sink_site.clone(),
            tier,
            score,
            witness_path,
            evidence: FindingEvidence {
                cwe: candidate.cwe.clone(),
                severity: candidate.severity,
                matched_constraints: candidate.matched_constraints.clone(),
                required_source: candidate.requires_source.clone(),
                taint_status,
                reachability: reachability_evidence,
            },
        });
    }
    ranked
}

fn score(tier: FindingTier, severity: Severity, distance: Option<usize>) -> u32 {
    let capped_distance: usize = distance.unwrap_or(99).min(99);
    let distance_score: u32 = 99_u32.saturating_sub(capped_distance as u32);
    tier.score_band()
        .saturating_add(severity.score())
        .saturating_add(distance_score)
}
