use std::collections::{BTreeMap, BTreeSet};

use crate::features::{DataReference, FunctionFeatures, FunctionId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnmatchedCause {
    NoAnchor,
    NoCandidate,
    DuplicateFunctionId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Exact {
        counterpart: FunctionId,
        shared_references: BTreeSet<DataReference>,
    },
    Ambiguous {
        candidates: BTreeSet<FunctionId>,
        own_side: usize,
        other_side: usize,
    },
    Unmatched {
        cause: UnmatchedCause,
    },
}

impl Verdict {
    #[must_use]
    pub const fn counterpart(&self) -> Option<FunctionId> {
        match self {
            Self::Exact { counterpart, .. } => Some(*counterpart),
            Self::Ambiguous { .. } | Self::Unmatched { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionVerdict {
    pub subject: FunctionId,
    pub verdict: Verdict,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MatchReport {
    pub left: Vec<FunctionVerdict>,
    pub right: Vec<FunctionVerdict>,
}

impl MatchReport {
    #[must_use]
    pub fn exact_pairs(&self) -> Vec<(FunctionId, FunctionId)> {
        self.left
            .iter()
            .filter_map(|entry: &FunctionVerdict| {
                entry
                    .verdict
                    .counterpart()
                    .map(|counterpart: FunctionId| (entry.subject, counterpart))
            })
            .collect()
    }

    #[must_use]
    pub fn exact_count(&self) -> usize {
        self.left
            .iter()
            .filter(|entry: &&FunctionVerdict| entry.verdict.counterpart().is_some())
            .count()
    }

    #[must_use]
    pub fn left_verdict(&self, subject: FunctionId) -> Option<&Verdict> {
        lookup(&self.left, subject)
    }

    #[must_use]
    pub fn right_verdict(&self, subject: FunctionId) -> Option<&Verdict> {
        lookup(&self.right, subject)
    }
}

fn lookup(entries: &[FunctionVerdict], subject: FunctionId) -> Option<&Verdict> {
    entries
        .binary_search_by_key(&subject, |entry: &FunctionVerdict| entry.subject)
        .ok()
        .and_then(|position: usize| entries.get(position))
        .map(|entry: &FunctionVerdict| &entry.verdict)
}

type AnchorIndex<'a> = BTreeMap<&'a BTreeSet<DataReference>, BTreeSet<FunctionId>>;

#[derive(Debug)]
struct SideIndex<'a> {
    unique: BTreeMap<FunctionId, &'a FunctionFeatures>,
    duplicated: BTreeSet<FunctionId>,
    anchors: AnchorIndex<'a>,
}

#[must_use]
pub fn match_functions(left: &[FunctionFeatures], right: &[FunctionFeatures]) -> MatchReport {
    let left_index: SideIndex<'_> = index_side(left);
    let right_index: SideIndex<'_> = index_side(right);
    MatchReport {
        left: verdicts(&left_index, &right_index),
        right: verdicts(&right_index, &left_index),
    }
}

fn index_side(side: &[FunctionFeatures]) -> SideIndex<'_> {
    let mut unique: BTreeMap<FunctionId, &FunctionFeatures> = BTreeMap::new();
    let mut duplicated: BTreeSet<FunctionId> = BTreeSet::new();
    for features in side {
        if unique.insert(features.id(), features).is_some() {
            duplicated.insert(features.id());
        }
    }
    for id in &duplicated {
        unique.remove(id);
    }

    let mut anchors: AnchorIndex<'_> = AnchorIndex::new();
    for features in side {
        if features.has_anchor() && !duplicated.contains(&features.id()) {
            anchors
                .entry(features.references())
                .or_default()
                .insert(features.id());
        }
    }

    SideIndex {
        unique,
        duplicated,
        anchors,
    }
}

fn verdicts(own: &SideIndex<'_>, other: &SideIndex<'_>) -> Vec<FunctionVerdict> {
    let mut entries: Vec<FunctionVerdict> =
        Vec::with_capacity(own.unique.len() + own.duplicated.len());
    for features in own.unique.values() {
        entries.push(FunctionVerdict {
            subject: features.id(),
            verdict: decide(features, own, other),
        });
    }
    for id in own.duplicated.iter().copied() {
        entries.push(FunctionVerdict {
            subject: id,
            verdict: Verdict::Unmatched {
                cause: UnmatchedCause::DuplicateFunctionId,
            },
        });
    }
    entries.sort_unstable_by_key(|entry: &FunctionVerdict| entry.subject);
    entries
}

fn decide(features: &FunctionFeatures, own: &SideIndex<'_>, other: &SideIndex<'_>) -> Verdict {
    let anchor: &BTreeSet<DataReference> = features.references();
    if anchor.is_empty() {
        return Verdict::Unmatched {
            cause: UnmatchedCause::NoAnchor,
        };
    }
    let own_side: usize = own.anchors.get(anchor).map_or(0, BTreeSet::len);
    other.anchors.get(anchor).map_or_else(
        || Verdict::Unmatched {
            cause: UnmatchedCause::NoCandidate,
        },
        |candidates: &BTreeSet<FunctionId>| forced_or_ambiguous(anchor, own_side, candidates),
    )
}

fn forced_or_ambiguous(
    anchor: &BTreeSet<DataReference>,
    own_side: usize,
    candidates: &BTreeSet<FunctionId>,
) -> Verdict {
    let other_side: usize = candidates.len();
    if own_side == 1 && other_side == 1 {
        return candidates.first().map_or_else(
            || Verdict::Unmatched {
                cause: UnmatchedCause::NoCandidate,
            },
            |counterpart: &FunctionId| Verdict::Exact {
                counterpart: *counterpart,
                shared_references: anchor.clone(),
            },
        );
    }
    Verdict::Ambiguous {
        candidates: candidates.clone(),
        own_side,
        other_side,
    }
}
