use std::collections::{BTreeMap, BTreeSet};

use crate::features::{
    AnchorStrength, DataReference, FunctionFeatures, FunctionId, anchor_strength,
};
use crate::fingerprint::ControlFlowFingerprint;
use crate::structure::{InstructionMix, StructuralKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnmatchedCause {
    NoAnchor,
    NoCandidate,
    DuplicateFunctionId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MatchStage {
    DataReference,
    ControlFlow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Exact {
        counterpart: FunctionId,
        shared_references: BTreeSet<DataReference>,
        strength: AnchorStrength,
    },
    Structural {
        counterpart: FunctionId,
        fingerprint: ControlFlowFingerprint,
        instruction_mix: InstructionMix,
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
            Self::Exact { counterpart, .. } | Self::Structural { counterpart, .. } => {
                Some(*counterpart)
            }
            Self::Ambiguous { .. } | Self::Unmatched { .. } => None,
        }
    }

    #[must_use]
    pub const fn stage(&self) -> Option<MatchStage> {
        match self {
            Self::Exact { .. } => Some(MatchStage::DataReference),
            Self::Structural { .. } => Some(MatchStage::ControlFlow),
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
        self.pairs_from(Some(MatchStage::DataReference))
    }

    #[must_use]
    pub fn exact_count(&self) -> usize {
        self.exact_pairs().len()
    }

    #[must_use]
    pub fn structural_pairs(&self) -> Vec<(FunctionId, FunctionId)> {
        self.pairs_from(Some(MatchStage::ControlFlow))
    }

    #[must_use]
    pub fn structural_count(&self) -> usize {
        self.structural_pairs().len()
    }

    #[must_use]
    pub fn matched_pairs(&self) -> Vec<(FunctionId, FunctionId)> {
        self.pairs_from(None)
    }

    #[must_use]
    pub fn matched_count(&self) -> usize {
        self.matched_pairs().len()
    }

    fn pairs_from(&self, wanted: Option<MatchStage>) -> Vec<(FunctionId, FunctionId)> {
        self.left
            .iter()
            .filter(|entry: &&FunctionVerdict| {
                wanted.is_none_or(|stage: MatchStage| entry.verdict.stage() == Some(stage))
            })
            .filter_map(|entry: &FunctionVerdict| {
                entry
                    .verdict
                    .counterpart()
                    .map(|counterpart: FunctionId| (entry.subject, counterpart))
            })
            .collect()
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
    let mut report: MatchReport = MatchReport {
        left: verdicts(&left_index, &right_index),
        right: verdicts(&right_index, &left_index),
    };
    let left_shapes: ShapeIndex = unresolved_shapes(&report.left, &left_index);
    let right_shapes: ShapeIndex = unresolved_shapes(&report.right, &right_index);
    resolve_by_shape(&mut report.left, &left_shapes, &right_shapes);
    resolve_by_shape(&mut report.right, &right_shapes, &left_shapes);
    report
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
                strength: anchor_strength(anchor),
            },
        );
    }
    Verdict::Ambiguous {
        candidates: candidates.clone(),
        own_side,
        other_side,
    }
}

#[derive(Debug, Default)]
struct ShapeIndex {
    key_of: BTreeMap<FunctionId, StructuralKey>,
    holders: BTreeMap<StructuralKey, BTreeSet<FunctionId>>,
}

fn unresolved_shapes(entries: &[FunctionVerdict], side: &SideIndex<'_>) -> ShapeIndex {
    let mut shapes: ShapeIndex = ShapeIndex::default();
    for entry in entries {
        if entry.verdict.counterpart().is_some() {
            continue;
        }
        let Some(features): Option<&&FunctionFeatures> = side.unique.get(&entry.subject) else {
            continue;
        };
        let Some(key): Option<StructuralKey> = features.structural_key() else {
            continue;
        };
        shapes.key_of.insert(entry.subject, key);
        shapes.holders.entry(key).or_default().insert(entry.subject);
    }
    shapes
}

fn resolve_by_shape(entries: &mut [FunctionVerdict], own: &ShapeIndex, other: &ShapeIndex) {
    for entry in entries {
        if entry.verdict.counterpart().is_some() {
            continue;
        }
        let Some(key): Option<&StructuralKey> = own.key_of.get(&entry.subject) else {
            continue;
        };
        let own_side: usize = own.holders.get(key).map_or(0, BTreeSet::len);
        let Some(candidates): Option<&BTreeSet<FunctionId>> = other.holders.get(key) else {
            continue;
        };
        entry.verdict = shape_verdict(key, own_side, candidates, &entry.verdict);
    }
}

fn shape_verdict(
    key: &StructuralKey,
    own_side: usize,
    candidates: &BTreeSet<FunctionId>,
    carried: &Verdict,
) -> Verdict {
    let other_side: usize = candidates.len();
    if own_side == 1
        && other_side == 1
        && let Some(counterpart) = candidates.first()
    {
        return Verdict::Structural {
            counterpart: *counterpart,
            fingerprint: key.fingerprint,
            instruction_mix: key.instruction_mix,
        };
    }
    if matches!(carried, Verdict::Ambiguous { .. }) {
        return carried.clone();
    }
    Verdict::Ambiguous {
        candidates: candidates.clone(),
        own_side,
        other_side,
    }
}
