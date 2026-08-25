use serde::Serialize;
use serde::ser::{SerializeSeq, Serializer};

use crate::{
    AnchorStrength, CallRelation, DataReference, FunctionFeatures, FunctionId, FunctionVerdict,
    InstructionCategory, InstructionMix, MatchReport, MatchStage, UnmatchedCause, Verdict,
};

pub const MATCH_REPORT_SCHEMA: &str = "disrobe.native.match/v2";
pub const DEFAULT_LISTING_LIMIT: usize = 25;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListingStage {
    DataReference,
    ControlFlow,
    Propagation,
    Refused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selector {
    Function(u64),
    Stage(ListingStage),
    Listing,
    All,
}

impl Selector {
    const fn admits(self, verdict: &Verdict, subject: u64, side: Side) -> bool {
        match self {
            Self::Function(address) => subject == address,
            Self::Stage(stage) => admits_stage(verdict, Some(stage), side),
            Self::Listing => admits_stage(verdict, None, side),
            Self::All => true,
        }
    }

    const fn lists(self, verdict: &Verdict, side: Side) -> bool {
        match self {
            Self::Function(_) => true,
            Self::Stage(stage) => admits_stage(verdict, Some(stage), side),
            Self::Listing | Self::All => admits_stage(verdict, None, side),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Side {
    A,
    B,
}

impl Side {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::A => "a",
            Self::B => "b",
        }
    }

    #[must_use]
    pub const fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ReferenceRow {
    StringLiteral { value: String },
    UnusualConstant { value: u64 },
    ImportedCall { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MixRow {
    pub category: &'static str,
    pub count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "verdict", rename_all = "kebab-case")]
pub enum VerdictBody {
    DataReference {
        counterpart: u64,
        anchor_strength: &'static str,
        shared_references: Vec<ReferenceRow>,
    },
    ControlFlow {
        counterpart: u64,
        fingerprint: u64,
        instructions: u64,
        instruction_mix: Vec<MixRow>,
    },
    Propagation {
        counterpart: u64,
        anchor: u64,
        anchor_counterpart: u64,
        relation: &'static str,
        hops: u32,
        fingerprint: u64,
        instructions: u64,
    },
    Ambiguous {
        candidates: Vec<u64>,
        own_side: usize,
        other_side: usize,
    },
    Unmatched {
        cause: &'static str,
    },
}

impl VerdictBody {
    #[must_use]
    pub const fn counterpart(&self) -> Option<u64> {
        match self {
            Self::DataReference { counterpart, .. }
            | Self::ControlFlow { counterpart, .. }
            | Self::Propagation { counterpart, .. } => Some(*counterpart),
            Self::Ambiguous { .. } | Self::Unmatched { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerdictRow {
    pub side: Side,
    pub subject: u64,
    #[serde(skip)]
    pub listed: bool,
    #[serde(flatten)]
    pub verdict: VerdictBody,
}

impl VerdictRow {
    #[must_use]
    pub const fn counterpart(&self) -> Option<u64> {
        self.verdict.counterpart()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct StageCounts {
    pub data_reference: usize,
    pub control_flow: usize,
    pub propagation: usize,
}

impl StageCounts {
    #[must_use]
    pub const fn total(&self) -> usize {
        self.data_reference + self.control_flow + self.propagation
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SideSummary {
    pub functions: usize,
    pub refused: usize,
    pub ambiguous: usize,
    pub no_anchor: usize,
    pub no_candidate: usize,
    pub duplicate_function_id: usize,
    pub without_evidence: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ListingWindow {
    pub limit: Option<usize>,
    pub stage: Option<&'static str>,
    pub function: Option<u64>,
    pub shown: usize,
    pub withheld: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MatchSummary {
    pub schema: &'static str,
    pub a: String,
    pub b: String,
    pub pairs: usize,
    pub by_stage: StageCounts,
    pub a_side: SideSummary,
    pub b_side: SideSummary,
    pub listing: ListingWindow,
    pub a_verdicts: Vec<VerdictRow>,
    pub b_verdicts: Vec<VerdictRow>,
}

#[derive(Debug)]
pub struct VerdictStream<'a> {
    entries: &'a [FunctionVerdict],
    selector: Selector,
    side: Side,
}

impl Serialize for VerdictStream<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence: S::SerializeSeq = serializer.serialize_seq(None)?;
        for entry in self.entries {
            if !self
                .selector
                .admits(&entry.verdict, entry.subject.0, self.side)
            {
                continue;
            }
            sequence.serialize_element(&VerdictRow {
                side: self.side,
                subject: entry.subject.0,
                listed: self.selector.lists(&entry.verdict, self.side),
                verdict: body_of(&entry.verdict),
            })?;
            if matches!(self.selector, Selector::Function(_)) {
                break;
            }
        }
        sequence.end()
    }
}

#[derive(Debug, Serialize)]
pub struct StreamingMatchSummary<'a> {
    pub schema: &'static str,
    pub a: String,
    pub b: String,
    pub pairs: usize,
    pub by_stage: StageCounts,
    pub a_side: SideSummary,
    pub b_side: SideSummary,
    pub listing: ListingWindow,
    pub a_verdicts: VerdictStream<'a>,
    pub b_verdicts: VerdictStream<'a>,
}

#[derive(Debug)]
pub struct Listing {
    pub limit: Option<usize>,
    pub stage: Option<&'static str>,
    pub function: Option<u64>,
    pub a: Vec<VerdictRow>,
    pub b: Vec<VerdictRow>,
    pub withheld: usize,
}

struct Budget {
    ceiling: usize,
    taken: usize,
    withheld: usize,
}

#[must_use]
pub fn streaming_summary<'a>(
    a: &str,
    b: &str,
    left: &[FunctionFeatures],
    right: &[FunctionFeatures],
    report: &'a MatchReport,
    selector: Selector,
) -> StreamingMatchSummary<'a> {
    let by_stage: StageCounts = stage_counts(&report.left);
    let pairs: usize = by_stage.total();
    let shown: usize = stream_count(&report.left, selector, Side::A)
        + stream_count(&report.right, selector, Side::B);
    StreamingMatchSummary {
        schema: MATCH_REPORT_SCHEMA,
        a: a.to_owned(),
        b: b.to_owned(),
        pairs,
        by_stage,
        a_side: side_summary(left, &report.left),
        b_side: side_summary(right, &report.right),
        listing: ListingWindow {
            limit: None,
            stage: match selector {
                Selector::Stage(stage) => Some(stage_label(stage)),
                Selector::Function(_) | Selector::Listing | Selector::All => None,
            },
            function: match selector {
                Selector::Function(address) => Some(address),
                Selector::Stage(_) | Selector::Listing | Selector::All => None,
            },
            shown,
            withheld: 0,
        },
        a_verdicts: VerdictStream {
            entries: &report.left,
            selector,
            side: Side::A,
        },
        b_verdicts: VerdictStream {
            entries: &report.right,
            selector,
            side: Side::B,
        },
    }
}

#[must_use]
pub fn summarize(
    a: &str,
    b: &str,
    left: &[FunctionFeatures],
    right: &[FunctionFeatures],
    report: &MatchReport,
    listing: Listing,
) -> MatchSummary {
    let by_stage: StageCounts = stage_counts(&report.left);
    let pairs: usize = by_stage.total();
    let window: ListingWindow = ListingWindow {
        limit: listing.limit,
        stage: listing.stage,
        function: listing.function,
        shown: listing.a.len() + listing.b.len(),
        withheld: listing.withheld,
    };
    MatchSummary {
        schema: MATCH_REPORT_SCHEMA,
        a: a.to_owned(),
        b: b.to_owned(),
        pairs,
        by_stage,
        a_side: side_summary(left, &report.left),
        b_side: side_summary(right, &report.right),
        listing: window,
        a_verdicts: listing.a,
        b_verdicts: listing.b,
    }
}

#[must_use]
pub fn collect_listing(report: &MatchReport, selector: Selector, limit: Option<usize>) -> Listing {
    if let Selector::Function(address) = selector {
        let a: Vec<VerdictRow> = point_row(&report.left, address, Side::A);
        let b: Vec<VerdictRow> = point_row(&report.right, address, Side::B);
        return Listing {
            limit,
            stage: None,
            function: Some(address),
            a,
            b,
            withheld: 0,
        };
    }
    let mut budget: Budget = Budget {
        ceiling: limit.unwrap_or(usize::MAX),
        taken: 0,
        withheld: 0,
    };
    let mut a: Vec<VerdictRow> = Vec::with_capacity(budget.ceiling.min(report.left.len()));
    collect_side(&mut a, &mut budget, Side::A, &report.left, selector);
    let mut b: Vec<VerdictRow> = Vec::with_capacity(
        budget
            .ceiling
            .saturating_sub(budget.taken)
            .min(report.right.len()),
    );
    collect_side(&mut b, &mut budget, Side::B, &report.right, selector);
    Listing {
        limit,
        stage: match selector {
            Selector::Stage(stage) => Some(stage_label(stage)),
            Selector::Listing | Selector::All | Selector::Function(_) => None,
        },
        function: None,
        a,
        b,
        withheld: budget.withheld,
    }
}

fn point_row(entries: &[FunctionVerdict], address: u64, side: Side) -> Vec<VerdictRow> {
    entries
        .iter()
        .find(|entry: &&FunctionVerdict| entry.subject.0 == address)
        .map(|entry: &FunctionVerdict| {
            vec![VerdictRow {
                side,
                subject: entry.subject.0,
                listed: true,
                verdict: body_of(&entry.verdict),
            }]
        })
        .unwrap_or_default()
}

fn collect_side(
    into: &mut Vec<VerdictRow>,
    budget: &mut Budget,
    side: Side,
    entries: &[FunctionVerdict],
    selector: Selector,
) {
    for entry in entries {
        if !selector.admits(&entry.verdict, entry.subject.0, side) {
            continue;
        }
        if budget.taken < budget.ceiling {
            into.push(VerdictRow {
                side,
                subject: entry.subject.0,
                listed: selector.lists(&entry.verdict, side),
                verdict: body_of(&entry.verdict),
            });
            budget.taken += 1;
        } else {
            budget.withheld += 1;
        }
    }
}

#[must_use]
pub const fn admits_stage(verdict: &Verdict, stage: Option<ListingStage>, side: Side) -> bool {
    match stage {
        None => match side {
            Side::A => !matches!(verdict, Verdict::Unmatched { .. }),
            Side::B => matches!(verdict, Verdict::Ambiguous { .. }),
        },
        Some(ListingStage::DataReference) => {
            matches!(side, Side::A) && matches!(verdict, Verdict::Exact { .. })
        }
        Some(ListingStage::ControlFlow) => {
            matches!(side, Side::A) && matches!(verdict, Verdict::Structural { .. })
        }
        Some(ListingStage::Propagation) => {
            matches!(side, Side::A) && matches!(verdict, Verdict::Propagated { .. })
        }
        Some(ListingStage::Refused) => matches!(
            verdict,
            Verdict::Ambiguous { .. } | Verdict::Unmatched { .. }
        ),
    }
}

#[must_use]
pub const fn stage_label(stage: ListingStage) -> &'static str {
    match stage {
        ListingStage::DataReference => "data-reference",
        ListingStage::ControlFlow => "control-flow",
        ListingStage::Propagation => "propagation",
        ListingStage::Refused => "refused",
    }
}

#[must_use]
pub fn body_of(verdict: &Verdict) -> VerdictBody {
    match verdict {
        Verdict::Exact {
            counterpart,
            shared_references,
            strength,
        } => VerdictBody::DataReference {
            counterpart: counterpart.0,
            anchor_strength: strength_label(*strength),
            shared_references: shared_references.iter().map(reference_row).collect(),
        },
        Verdict::Structural {
            counterpart,
            fingerprint,
            instruction_mix,
        } => VerdictBody::ControlFlow {
            counterpart: counterpart.0,
            fingerprint: fingerprint.value(),
            instructions: instruction_mix.total(),
            instruction_mix: mix_rows(instruction_mix),
        },
        Verdict::Propagated {
            counterpart,
            anchor,
            anchor_counterpart,
            relation,
            hops,
            agreement,
        } => VerdictBody::Propagation {
            counterpart: counterpart.0,
            anchor: anchor.0,
            anchor_counterpart: anchor_counterpart.0,
            relation: relation_label(*relation),
            hops: *hops,
            fingerprint: agreement.fingerprint.value(),
            instructions: agreement.instruction_mix.total(),
        },
        Verdict::Ambiguous {
            candidates,
            own_side,
            other_side,
        } => VerdictBody::Ambiguous {
            candidates: candidates.iter().map(|id: &FunctionId| id.0).collect(),
            own_side: *own_side,
            other_side: *other_side,
        },
        Verdict::Unmatched { cause } => VerdictBody::Unmatched {
            cause: cause_label(*cause),
        },
    }
}

fn reference_row(reference: &DataReference) -> ReferenceRow {
    match reference {
        DataReference::StringLiteral(value) => ReferenceRow::StringLiteral {
            value: value.clone(),
        },
        DataReference::UnusualConstant(value) => ReferenceRow::UnusualConstant { value: *value },
        DataReference::ImportedCall(name) => ReferenceRow::ImportedCall { name: name.clone() },
    }
}

fn mix_rows(mix: &InstructionMix) -> Vec<MixRow> {
    InstructionCategory::ALL
        .into_iter()
        .filter_map(|category: InstructionCategory| {
            let count: u32 = mix.count(category);
            (count > 0).then(|| MixRow {
                category: category_label(category),
                count,
            })
        })
        .collect()
}

const fn strength_label(strength: AnchorStrength) -> &'static str {
    match strength {
        AnchorStrength::Distinctive => "distinctive",
        AnchorStrength::SingleImportedCall => "single-imported-call",
    }
}

const fn relation_label(relation: CallRelation) -> &'static str {
    match relation {
        CallRelation::Callee => "callee",
        CallRelation::Caller => "caller",
    }
}

const fn cause_label(cause: UnmatchedCause) -> &'static str {
    match cause {
        UnmatchedCause::NoAnchor => "no-anchor",
        UnmatchedCause::NoCandidate => "no-candidate",
        UnmatchedCause::DuplicateFunctionId => "duplicate-function-id",
    }
}

const fn category_label(category: InstructionCategory) -> &'static str {
    match category {
        InstructionCategory::Arithmetic => "arithmetic",
        InstructionCategory::Logic => "logic",
        InstructionCategory::Shift => "shift",
        InstructionCategory::Move => "move",
        InstructionCategory::Compare => "compare",
        InstructionCategory::Load => "load",
        InstructionCategory::Store => "store",
        InstructionCategory::Branch => "branch",
        InstructionCategory::Call => "call",
        InstructionCategory::Return => "return",
        InstructionCategory::Stack => "stack",
        InstructionCategory::FloatingPoint => "floating-point",
        InstructionCategory::Vector => "vector",
        InstructionCategory::System => "system",
        InstructionCategory::Other => "other",
    }
}

fn stage_counts(entries: &[FunctionVerdict]) -> StageCounts {
    let mut counts: StageCounts = StageCounts::default();
    for entry in entries {
        match entry.verdict.stage() {
            Some(MatchStage::DataReference) => counts.data_reference += 1,
            Some(MatchStage::ControlFlow) => counts.control_flow += 1,
            Some(MatchStage::Propagation) => counts.propagation += 1,
            None => {}
        }
    }
    counts
}

fn side_summary(features: &[FunctionFeatures], entries: &[FunctionVerdict]) -> SideSummary {
    let mut side: SideSummary = SideSummary {
        functions: features.len(),
        without_evidence: without_evidence(features),
        ..SideSummary::default()
    };
    for entry in entries {
        match &entry.verdict {
            Verdict::Ambiguous { .. } => side.ambiguous += 1,
            Verdict::Unmatched { cause } => match cause {
                UnmatchedCause::NoAnchor => side.no_anchor += 1,
                UnmatchedCause::NoCandidate => side.no_candidate += 1,
                UnmatchedCause::DuplicateFunctionId => side.duplicate_function_id += 1,
            },
            Verdict::Exact { .. } | Verdict::Structural { .. } | Verdict::Propagated { .. } => {}
        }
    }
    side.refused = side.ambiguous + side.no_anchor + side.no_candidate + side.duplicate_function_id;
    side
}

#[must_use]
pub fn without_evidence(features: &[FunctionFeatures]) -> usize {
    features
        .iter()
        .filter(|entry: &&FunctionFeatures| {
            !entry.has_anchor() && entry.corroborating_key().is_none()
        })
        .count()
}

fn stream_count(entries: &[FunctionVerdict], selector: Selector, side: Side) -> usize {
    let count: usize = entries
        .iter()
        .filter(|entry: &&FunctionVerdict| selector.admits(&entry.verdict, entry.subject.0, side))
        .count();
    if matches!(selector, Selector::Function(_)) {
        count.min(1)
    } else {
        count
    }
}
