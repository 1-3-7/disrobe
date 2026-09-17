use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EdgeGuard {
    Direct,
    Branch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DevirtEdge {
    pub from: u64,
    pub to: u64,
    pub guard: EdgeGuard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockRole {
    Resolved,
    Terminal,
    Unresolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DegradeReason {
    NextStateNotConstant,
    NextStateOutsideCaseMap,
    StateVarNotAssigned,
    RegionUnbounded,
    SolverUnknown,
    FellIntoCase,
    RequiresSolver,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DevirtNote {
    pub block: u64,
    pub reason: DegradeReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredCfg {
    pub entry: u64,
    pub state_var: String,
    pub cases: Vec<u64>,
    pub edges: Vec<DevirtEdge>,
    pub scaffolding: Vec<u64>,
    pub roles: BTreeMap<u64, BlockRole>,
    pub notes: Vec<DevirtNote>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CanaryViolation {
    EdgeFromUnknownBlock { from: u64, to: u64 },
    EdgeToUnknownBlock { from: u64, to: u64 },
    EdgeFromUnresolvedBlock { from: u64, to: u64 },
    EdgeIntoScaffolding { from: u64, to: u64 },
    ResolvedBlockHasNoEdge { block: u64 },
    TerminalBlockHasEdge { block: u64 },
    EntryNotACase { entry: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CffAbstain {
    NotFlattened,
    DispatcherNotFound,
    StateVarNotUnique,
    CaseMapTooSmall,
    InitialStateUnknown,
    Budget,
    TooManyBlocks,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CffOutcome {
    Recovered(RecoveredCfg),
    Abstain(CffAbstain),
}

impl CffOutcome {
    #[must_use]
    pub const fn is_abstain(&self) -> bool {
        matches!(self, Self::Abstain(_))
    }

    #[must_use]
    pub const fn recovered(&self) -> Option<&RecoveredCfg> {
        match self {
            Self::Recovered(cfg) => Some(cfg),
            Self::Abstain(_) => None,
        }
    }
}

impl RecoveredCfg {
    #[must_use]
    pub fn edge_set(&self) -> BTreeSet<(u64, u64)> {
        self.edges
            .iter()
            .map(|edge: &DevirtEdge| (edge.from, edge.to))
            .collect()
    }

    #[must_use]
    pub fn successors(&self, block: u64) -> Vec<u64> {
        self.edges
            .iter()
            .filter(|edge: &&DevirtEdge| edge.from == block)
            .map(|edge: &DevirtEdge| edge.to)
            .collect()
    }

    pub fn canary(&self) -> Result<(), CanaryViolation> {
        let cases: BTreeSet<u64> = self.cases.iter().copied().collect();
        let scaffold: BTreeSet<u64> = self.scaffolding.iter().copied().collect();
        if !cases.contains(&self.entry) {
            return Err(CanaryViolation::EntryNotACase { entry: self.entry });
        }
        for edge in &self.edges {
            if !cases.contains(&edge.from) {
                return Err(CanaryViolation::EdgeFromUnknownBlock {
                    from: edge.from,
                    to: edge.to,
                });
            }
            if !cases.contains(&edge.to) {
                return Err(CanaryViolation::EdgeToUnknownBlock {
                    from: edge.from,
                    to: edge.to,
                });
            }
            if scaffold.contains(&edge.to) {
                return Err(CanaryViolation::EdgeIntoScaffolding {
                    from: edge.from,
                    to: edge.to,
                });
            }
            if self.roles.get(&edge.from) != Some(&BlockRole::Resolved) {
                return Err(CanaryViolation::EdgeFromUnresolvedBlock {
                    from: edge.from,
                    to: edge.to,
                });
            }
        }
        for (&block, role) in &self.roles {
            let outgoing: usize = self
                .edges
                .iter()
                .filter(|e: &&DevirtEdge| e.from == block)
                .count();
            match role {
                BlockRole::Resolved if outgoing == 0 => {
                    return Err(CanaryViolation::ResolvedBlockHasNoEdge { block });
                }
                BlockRole::Terminal if outgoing != 0 => {
                    return Err(CanaryViolation::TerminalBlockHasEdge { block });
                }
                BlockRole::Resolved | BlockRole::Terminal | BlockRole::Unresolved => {}
            }
        }
        Ok(())
    }
}
