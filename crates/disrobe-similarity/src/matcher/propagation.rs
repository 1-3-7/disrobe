use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

use super::{FunctionVerdict, MatchReport, MatchStage, Verdict, lookup_mut};
use crate::features::{FunctionFeatures, FunctionId};
use crate::structure::StructuralKey;

pub const MAXIMUM_PROPAGATION_HOPS: u32 = 2;

const PROPAGATION_ROUND_CAP: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CallRelation {
    Callee,
    Caller,
}

impl CallRelation {
    const BOTH: [Self; 2] = [Self::Callee, Self::Caller];
}

pub(super) type FunctionIndex<'a> = BTreeMap<FunctionId, &'a FunctionFeatures>;

pub(super) fn propagate(
    report: &mut MatchReport,
    left: &FunctionIndex<'_>,
    right: &FunctionIndex<'_>,
) {
    let mut locked: Locked = seed(report);
    if locked.anchors.is_empty() {
        return;
    }
    let own: CallGraph<'_> = CallGraph::of(left);
    let other: CallGraph<'_> = CallGraph::of(right);
    for _ in 0..PROPAGATION_ROUND_CAP {
        let round: Vec<Proposal> = gather(&locked, &own, &other);
        if admit(&mut locked, round) == 0 {
            break;
        }
    }
    let beyond: Vec<Proposal> = gather(&locked, &own, &other);
    let deferred: Vec<Proposal> = defer(&locked, beyond);
    write_back(report, &locked, &deferred);
}

#[derive(Debug)]
struct CallGraph<'a> {
    functions: &'a FunctionIndex<'a>,
    callers: BTreeMap<FunctionId, BTreeSet<FunctionId>>,
}

impl<'a> CallGraph<'a> {
    fn of(functions: &'a FunctionIndex<'a>) -> Self {
        let mut callers: BTreeMap<FunctionId, BTreeSet<FunctionId>> = BTreeMap::new();
        for (caller, features) in functions {
            for target in features.call_targets() {
                if functions.contains_key(target) {
                    callers.entry(*target).or_default().insert(*caller);
                }
            }
        }
        Self { functions, callers }
    }

    fn neighbours(
        &self,
        subject: FunctionId,
        relation: CallRelation,
    ) -> Option<&BTreeSet<FunctionId>> {
        match relation {
            CallRelation::Callee => self
                .functions
                .get(&subject)
                .map(|features: &&FunctionFeatures| features.call_targets()),
            CallRelation::Caller => self.callers.get(&subject),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Anchor {
    counterpart: FunctionId,
    hops: u32,
    rank: u8,
}

#[derive(Debug, Default)]
struct Locked {
    anchors: BTreeMap<FunctionId, Anchor>,
    claimed: BTreeSet<FunctionId>,
    settled: Vec<Proposal>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Proposal {
    subject: FunctionId,
    counterpart: FunctionId,
    anchor: FunctionId,
    anchor_counterpart: FunctionId,
    relation: CallRelation,
    hops: u32,
    anchor_rank: u8,
    agreement: StructuralKey,
}

type ProposalRank = (u32, u8, Reverse<u64>, CallRelation, FunctionId, FunctionId);

impl Proposal {
    fn rank(&self) -> ProposalRank {
        (
            self.hops,
            self.anchor_rank,
            Reverse(self.agreement.instruction_mix.total()),
            self.relation,
            self.subject,
            self.counterpart,
        )
    }

    const fn matched(&self) -> Verdict {
        Verdict::Propagated {
            counterpart: self.counterpart,
            anchor: self.anchor,
            anchor_counterpart: self.anchor_counterpart,
            relation: self.relation,
            hops: self.hops,
            agreement: self.agreement,
        }
    }

    const fn mirrored(&self) -> Verdict {
        Verdict::Propagated {
            counterpart: self.subject,
            anchor: self.anchor_counterpart,
            anchor_counterpart: self.anchor,
            relation: self.relation,
            hops: self.hops,
            agreement: self.agreement,
        }
    }
}

const fn stage_rank(stage: MatchStage) -> u8 {
    match stage {
        MatchStage::DataReference => 0,
        MatchStage::ControlFlow => 1,
        MatchStage::Propagation => 2,
    }
}

fn seed(report: &MatchReport) -> Locked {
    let mut locked: Locked = Locked::default();
    for entry in &report.left {
        let entry: &FunctionVerdict = entry;
        let (Some(counterpart), Some(stage)): (Option<FunctionId>, Option<MatchStage>) =
            (entry.verdict.counterpart(), entry.verdict.stage())
        else {
            continue;
        };
        locked.anchors.insert(
            entry.subject,
            Anchor {
                counterpart,
                hops: 0,
                rank: stage_rank(stage),
            },
        );
        locked.claimed.insert(counterpart);
    }
    locked
}

fn forced_neighbours(
    graph: &CallGraph<'_>,
    subject: FunctionId,
    relation: CallRelation,
    taken: impl Fn(FunctionId) -> bool,
) -> BTreeMap<StructuralKey, FunctionId> {
    let Some(neighbours): Option<&BTreeSet<FunctionId>> = graph.neighbours(subject, relation)
    else {
        return BTreeMap::new();
    };
    let mut holders: BTreeMap<StructuralKey, Vec<FunctionId>> = BTreeMap::new();
    for id in neighbours.iter().copied() {
        if taken(id) {
            continue;
        }
        let Some(features): Option<&&FunctionFeatures> = graph.functions.get(&id) else {
            continue;
        };
        let Some(key): Option<StructuralKey> = features.corroborating_key() else {
            continue;
        };
        holders.entry(key).or_default().push(id);
    }
    holders
        .into_iter()
        .filter_map(
            |(key, held): (StructuralKey, Vec<FunctionId>)| match held.as_slice() {
                [only] => Some((key, *only)),
                _ => None,
            },
        )
        .collect()
}

fn gather(locked: &Locked, own: &CallGraph<'_>, other: &CallGraph<'_>) -> Vec<Proposal> {
    let mut out: Vec<Proposal> = Vec::new();
    for (anchor, held) in &locked.anchors {
        let Some(hops): Option<u32> = held.hops.checked_add(1) else {
            continue;
        };
        for relation in CallRelation::BOTH {
            let mine: BTreeMap<StructuralKey, FunctionId> =
                forced_neighbours(own, *anchor, relation, |id: FunctionId| {
                    locked.anchors.contains_key(&id)
                });
            if mine.is_empty() {
                continue;
            }
            let theirs: BTreeMap<StructuralKey, FunctionId> =
                forced_neighbours(other, held.counterpart, relation, |id: FunctionId| {
                    locked.claimed.contains(&id)
                });
            for (agreement, subject) in mine {
                let Some(counterpart): Option<FunctionId> = theirs.get(&agreement).copied() else {
                    continue;
                };
                out.push(Proposal {
                    subject,
                    counterpart,
                    anchor: *anchor,
                    anchor_counterpart: held.counterpart,
                    relation,
                    hops,
                    anchor_rank: held.rank,
                    agreement,
                });
            }
        }
    }
    out
}

fn admit(locked: &mut Locked, proposals: Vec<Proposal>) -> usize {
    let mut ordered: Vec<Proposal> = proposals;
    ordered.sort_unstable_by_key(Proposal::rank);
    let mut taken: usize = 0;
    for proposal in ordered {
        if proposal.hops > MAXIMUM_PROPAGATION_HOPS
            || locked.anchors.contains_key(&proposal.subject)
            || locked.claimed.contains(&proposal.counterpart)
        {
            continue;
        }
        locked.anchors.insert(
            proposal.subject,
            Anchor {
                counterpart: proposal.counterpart,
                hops: proposal.hops,
                rank: stage_rank(MatchStage::Propagation),
            },
        );
        locked.claimed.insert(proposal.counterpart);
        locked.settled.push(proposal);
        taken += 1;
    }
    taken
}

fn defer(locked: &Locked, proposals: Vec<Proposal>) -> Vec<Proposal> {
    let mut ordered: Vec<Proposal> = proposals;
    ordered.sort_unstable_by_key(Proposal::rank);
    let mut subjects: BTreeSet<FunctionId> = BTreeSet::new();
    let mut counterparts: BTreeSet<FunctionId> = BTreeSet::new();
    let mut out: Vec<Proposal> = Vec::new();
    for proposal in ordered {
        if proposal.hops <= MAXIMUM_PROPAGATION_HOPS
            || locked.anchors.contains_key(&proposal.subject)
            || locked.claimed.contains(&proposal.counterpart)
            || subjects.contains(&proposal.subject)
            || counterparts.contains(&proposal.counterpart)
        {
            continue;
        }
        subjects.insert(proposal.subject);
        counterparts.insert(proposal.counterpart);
        out.push(proposal);
    }
    out
}

fn write_back(report: &mut MatchReport, locked: &Locked, deferred: &[Proposal]) {
    for proposal in &locked.settled {
        assign(&mut report.left, proposal.subject, proposal.matched());
        assign(&mut report.right, proposal.counterpart, proposal.mirrored());
    }
    for proposal in deferred {
        name_candidate(&mut report.left, proposal.subject, proposal.counterpart);
        name_candidate(&mut report.right, proposal.counterpart, proposal.subject);
    }
}

fn assign(entries: &mut [FunctionVerdict], subject: FunctionId, verdict: Verdict) {
    if let Some(slot) = lookup_mut(entries, subject) {
        *slot = verdict;
    }
}

fn name_candidate(entries: &mut [FunctionVerdict], subject: FunctionId, candidate: FunctionId) {
    let Some(slot): Option<&mut Verdict> = lookup_mut(entries, subject) else {
        return;
    };
    if matches!(*slot, Verdict::Ambiguous { .. }) {
        return;
    }
    *slot = Verdict::Ambiguous {
        candidates: BTreeSet::from([candidate]),
        own_side: 1,
        other_side: 1,
    };
}
