use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde::ser::{SerializeSeq, Serializer};

use super::globals;
use super::output::{self, OutputFormat};
use super::progress_ui::StageSpinner;
use disrobe_pass_native::extract_function_features;
use disrobe_similarity::{
    AnchorStrength, CallRelation, DataReference, FunctionFeatures, FunctionId, FunctionVerdict,
    InstructionCategory, InstructionMix, MatchReport, MatchStage, StructuralKey, UnmatchedCause,
    Verdict, match_functions,
};

const SCHEMA: &str = "disrobe.native.match/v2";

const LITERAL_PREVIEW_LIMIT: usize = 64;

const DEFAULT_LISTING_LIMIT: usize = 25;

pub(crate) const LIMIT_HELP: &str = "maximum listing rows to show, 25 by default; 0 shows counts only; a limit given here also bounds the machine report";

pub(crate) const FUNCTION_HELP: &str = "show one function's correspondences from both sides (accepts 0x-prefixed hex); cannot be combined with --stage and is not bounded by --limit";

pub(crate) const STAGE_HELP: &str =
    "show one match stage or refused rows; also filters the machine report";

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum ListingStage {
    DataReference,
    ControlFlow,
    Propagation,
    Refused,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ListingOptions {
    pub(crate) limit: Option<usize>,
    pub(crate) function: Option<u64>,
    pub(crate) stage: Option<ListingStage>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Side {
    A,
    B,
}

impl Side {
    const fn label(self) -> &'static str {
        match self {
            Self::A => "a",
            Self::B => "b",
        }
    }

    const fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Selector {
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

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum ReferenceRow {
    StringLiteral { value: String },
    UnusualConstant { value: u64 },
    ImportedCall { name: String },
}

#[derive(Debug, Serialize)]
struct MixRow {
    category: &'static str,
    count: u32,
}

#[derive(Debug, Serialize)]
#[serde(tag = "verdict", rename_all = "kebab-case")]
enum VerdictBody {
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

#[derive(Debug, Serialize)]
struct VerdictRow {
    side: Side,
    subject: u64,
    #[serde(skip)]
    listed: bool,
    #[serde(flatten)]
    verdict: VerdictBody,
}

#[derive(Debug, Default, Serialize)]
struct StageCounts {
    data_reference: usize,
    control_flow: usize,
    propagation: usize,
}

impl StageCounts {
    const fn total(&self) -> usize {
        self.data_reference + self.control_flow + self.propagation
    }
}

#[derive(Debug, Default, Serialize)]
struct SideSummary {
    functions: usize,
    refused: usize,
    ambiguous: usize,
    no_anchor: usize,
    no_candidate: usize,
    duplicate_function_id: usize,
    without_evidence: usize,
}

#[derive(Debug, Serialize)]
struct ListingWindow {
    limit: Option<usize>,
    stage: Option<&'static str>,
    function: Option<u64>,
    shown: usize,
    withheld: usize,
}

#[derive(Debug, Serialize)]
struct MatchSummary {
    schema: &'static str,
    a: String,
    b: String,
    pairs: usize,
    by_stage: StageCounts,
    a_side: SideSummary,
    b_side: SideSummary,
    listing: ListingWindow,
    a_verdicts: Vec<VerdictRow>,
    b_verdicts: Vec<VerdictRow>,
}

#[derive(Debug)]
struct VerdictStream<'a> {
    entries: &'a [FunctionVerdict],
    selector: Selector,
    side: Side,
}

impl Serialize for VerdictStream<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence: S::SerializeSeq = serializer.serialize_seq(None)?;
        for entry in self.entries {
            let entry: &FunctionVerdict = entry;
            if !self
                .selector
                .admits(&entry.verdict, entry.subject.0, self.side)
            {
                continue;
            }
            let row: VerdictRow = VerdictRow {
                side: self.side,
                subject: entry.subject.0,
                listed: self.selector.lists(&entry.verdict, self.side),
                verdict: body_of(&entry.verdict),
            };
            sequence.serialize_element(&row)?;
            if matches!(self.selector, Selector::Function(_)) {
                break;
            }
        }
        sequence.end()
    }
}

#[derive(Debug, Serialize)]
struct StreamingMatchSummary<'a> {
    schema: &'static str,
    a: String,
    b: String,
    pairs: usize,
    by_stage: StageCounts,
    a_side: SideSummary,
    b_side: SideSummary,
    listing: ListingWindow,
    a_verdicts: VerdictStream<'a>,
    b_verdicts: VerdictStream<'a>,
}

#[derive(Debug)]
enum Written {
    NotRequested,
    Skipped(PathBuf),
    Wrote(PathBuf),
}

#[derive(Debug)]
struct Listing {
    limit: Option<usize>,
    stage: Option<&'static str>,
    function: Option<u64>,
    a: Vec<VerdictRow>,
    b: Vec<VerdictRow>,
    withheld: usize,
}

#[derive(Debug)]
struct Budget {
    ceiling: usize,
    taken: usize,
    withheld: usize,
}

pub(crate) fn run(
    a: PathBuf,
    b: PathBuf,
    out: Option<PathBuf>,
    fmt: OutputFormat,
    options: ListingOptions,
) -> miette::Result<()> {
    let bytes_a: Vec<u8> = std::fs::read(&a)
        .map_err(|e| miette::miette!("DR-NATIVE-0200: cannot read {}: {e}", a.display()))?;
    let bytes_b: Vec<u8> = std::fs::read(&b)
        .map_err(|e| miette::miette!("DR-NATIVE-0201: cannot read {}: {e}", b.display()))?;

    let spinner: StageSpinner = StageSpinner::start("native match", "extracting function features");
    let left: Vec<FunctionFeatures> = extract_function_features(&bytes_a).map_err(|e| {
        miette::miette!(
            "DR-NATIVE-0202: cannot read functions from {}: {e}",
            a.display()
        )
    })?;
    let right: Vec<FunctionFeatures> = extract_function_features(&bytes_b).map_err(|e| {
        miette::miette!(
            "DR-NATIVE-0203: cannot read functions from {}: {e}",
            b.display()
        )
    })?;
    spinner.set_message("matching functions");
    if left.is_empty() || right.is_empty() {
        return Err(miette::miette!(
            "DR-NATIVE-0204: no function to match: {} carries {} function(s), {} carries {}",
            a.display(),
            left.len(),
            b.display(),
            right.len()
        ));
    }
    let report: MatchReport = match_functions(&left, &right);
    let (selector, ceiling): (Selector, Option<usize>) = plan(options, fmt, out.as_deref());
    if ceiling.is_none() && !matches!(selector, Selector::Function(_)) {
        let summary: StreamingMatchSummary<'_> =
            streaming_summary(&a, &b, &left, &right, &report, selector);
        spinner.finish(&format!("{} pair(s)", summary.pairs));
        let written: Written = write_report(&summary, out)?;
        if matches!(fmt, OutputFormat::Text) {
            let text_selector: Selector = match selector {
                Selector::Stage(stage) => Selector::Stage(stage),
                Selector::Function(address) => Selector::Function(address),
                Selector::Listing | Selector::All => Selector::Listing,
            };
            let listing: Listing =
                collect_listing(&report, text_selector, Some(DEFAULT_LISTING_LIMIT));
            let text_summary: MatchSummary = summarize(&a, &b, &left, &right, &report, listing);
            return output::emit(fmt, &summary, || {
                render(
                    &text_summary,
                    &written,
                    options.limit.unwrap_or(DEFAULT_LISTING_LIMIT),
                );
            });
        }
        return output::emit(fmt, &summary, || {});
    }
    let listing: Listing = collect_listing(&report, selector, ceiling);
    let summary: MatchSummary = summarize(&a, &b, &left, &right, &report, listing);
    spinner.finish(&format!("{} pair(s)", summary.pairs));

    if let Some(address) = summary.listing.function
        && summary.a_verdicts.is_empty()
        && summary.b_verdicts.is_empty()
    {
        return Err(miette::miette!(
            "DR-NATIVE-0208: no function at address {address:#x} in either input"
        ));
    }

    let written: Written = write_report(&summary, out)?;
    let display: usize = options.limit.unwrap_or(DEFAULT_LISTING_LIMIT);
    output::emit(fmt, &summary, || render(&summary, &written, display))
}

const fn plan(
    options: ListingOptions,
    fmt: OutputFormat,
    out: Option<&Path>,
) -> (Selector, Option<usize>) {
    if let Some(address) = options.function {
        return (Selector::Function(address), None);
    }
    let complete: bool = fmt.is_machine() || out.is_some();
    match (options.stage, options.limit) {
        (Some(stage), Some(limit)) => (Selector::Stage(stage), Some(limit)),
        (Some(stage), None) if complete => (Selector::Stage(stage), None),
        (Some(stage), None) => (Selector::Stage(stage), Some(DEFAULT_LISTING_LIMIT)),
        (None, Some(limit)) => (Selector::Listing, Some(limit)),
        (None, None) if complete => (Selector::All, None),
        (None, None) => (Selector::Listing, Some(DEFAULT_LISTING_LIMIT)),
    }
}

fn write_report<T: Serialize>(summary: &T, out: Option<PathBuf>) -> miette::Result<Written> {
    let Some(path): Option<PathBuf> = out else {
        return Ok(Written::NotRequested);
    };
    if globals::current().dry_run {
        return Ok(Written::Skipped(path));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-NATIVE-0205: cannot create out dir: {e}"))?;
    }
    let file: std::fs::File = std::fs::File::create(&path).map_err(|error: std::io::Error| {
        miette::miette!("DR-NATIVE-0207: cannot write match report: {error}")
    })?;
    let mut writer: std::io::BufWriter<std::fs::File> = std::io::BufWriter::new(file);
    output::write_json(&mut writer, summary, true).map_err(|error: serde_json::Error| {
        if error.is_io() {
            miette::miette!("DR-NATIVE-0207: cannot write match report: {error}")
        } else {
            miette::miette!("DR-NATIVE-0206: serialize: {error}")
        }
    })?;
    writer.flush().map_err(|error: std::io::Error| {
        miette::miette!("DR-NATIVE-0207: cannot write match report: {error}")
    })?;
    Ok(Written::Wrote(path))
}

fn streaming_summary<'a>(
    a: &Path,
    b: &Path,
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
        schema: SCHEMA,
        a: a.display().to_string(),
        b: b.display().to_string(),
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

fn summarize(
    a: &Path,
    b: &Path,
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
        schema: SCHEMA,
        a: a.display().to_string(),
        b: b.display().to_string(),
        pairs,
        by_stage,
        a_side: side_summary(left, &report.left),
        b_side: side_summary(right, &report.right),
        listing: window,
        a_verdicts: listing.a,
        b_verdicts: listing.b,
    }
}

fn collect_listing(report: &MatchReport, selector: Selector, limit: Option<usize>) -> Listing {
    if let Selector::Function(address) = selector {
        let a: Vec<VerdictRow> = report
            .left
            .iter()
            .find(|entry: &&FunctionVerdict| entry.subject.0 == address)
            .map(|entry: &FunctionVerdict| {
                vec![VerdictRow {
                    side: Side::A,
                    subject: entry.subject.0,
                    listed: true,
                    verdict: body_of(&entry.verdict),
                }]
            })
            .unwrap_or_default();
        let b: Vec<VerdictRow> = report
            .right
            .iter()
            .find(|entry: &&FunctionVerdict| entry.subject.0 == address)
            .map(|entry: &FunctionVerdict| {
                vec![VerdictRow {
                    side: Side::B,
                    subject: entry.subject.0,
                    listed: true,
                    verdict: body_of(&entry.verdict),
                }]
            })
            .unwrap_or_default();
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
        function: match selector {
            Selector::Function(address) => Some(address),
            Selector::Stage(_) | Selector::Listing | Selector::All => None,
        },
        a,
        b,
        withheld: budget.withheld,
    }
}

fn collect_side(
    into: &mut Vec<VerdictRow>,
    budget: &mut Budget,
    side: Side,
    entries: &[FunctionVerdict],
    selector: Selector,
) {
    for entry in entries {
        let entry: &FunctionVerdict = entry;
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

const fn admits_stage(verdict: &Verdict, stage: Option<ListingStage>, side: Side) -> bool {
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
        Some(ListingStage::Refused) => {
            matches!(
                verdict,
                Verdict::Ambiguous { .. } | Verdict::Unmatched { .. }
            )
        }
    }
}

const fn stage_label(stage: ListingStage) -> &'static str {
    match stage {
        ListingStage::DataReference => "data-reference",
        ListingStage::ControlFlow => "control-flow",
        ListingStage::Propagation => "propagation",
        ListingStage::Refused => "refused",
    }
}

fn body_of(verdict: &Verdict) -> VerdictBody {
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
        } => propagation_body(
            *counterpart,
            *anchor,
            *anchor_counterpart,
            *relation,
            *hops,
            *agreement,
        ),
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

fn propagation_body(
    counterpart: FunctionId,
    anchor: FunctionId,
    anchor_counterpart: FunctionId,
    relation: CallRelation,
    hops: u32,
    agreement: StructuralKey,
) -> VerdictBody {
    VerdictBody::Propagation {
        counterpart: counterpart.0,
        anchor: anchor.0,
        anchor_counterpart: anchor_counterpart.0,
        relation: relation_label(relation),
        hops,
        fingerprint: agreement.fingerprint.value(),
        instructions: agreement.instruction_mix.total(),
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

fn without_evidence(features: &[FunctionFeatures]) -> usize {
    features
        .iter()
        .filter(|entry: &&FunctionFeatures| {
            !entry.has_anchor() && entry.corroborating_key().is_none()
        })
        .count()
}

fn render(summary: &MatchSummary, written: &Written, display: usize) {
    println!("native match: OK");
    println!("  a:            {}", summary.a);
    println!("  b:            {}", summary.b);
    println!(
        "  functions:    {} -> {}",
        summary.a_side.functions, summary.b_side.functions
    );
    println!("  pairs:        {}", summary.pairs);
    println!("    data reference: {}", summary.by_stage.data_reference);
    println!("    control flow:   {}", summary.by_stage.control_flow);
    println!("    propagation:    {}", summary.by_stage.propagation);
    render_side("a", &summary.a_side);
    render_side("b", &summary.b_side);
    if summary.listing.function.is_some() {
        render_function(summary);
    } else {
        render_listing(summary, display);
    }
    match written {
        Written::NotRequested => {}
        Written::Skipped(path) => println!("  would write:  {}", path.display()),
        Written::Wrote(path) => println!("  wrote:        {}", path.display()),
    }
}

fn render_side(label: &str, side: &SideSummary) {
    println!(
        "  refused on {label}: {} ({} ambiguous, {} no anchor, {} no candidate, {} duplicate function id)",
        side.refused, side.ambiguous, side.no_anchor, side.no_candidate, side.duplicate_function_id
    );
    println!(
        "  no evidence on {label}: {} of {}",
        side.without_evidence, side.functions
    );
}

fn render_listing(summary: &MatchSummary, display: usize) {
    println!("  listing:");
    let mut shown: usize = 0;
    let mut materialized: usize = 0;
    for row in summary.a_verdicts.iter().chain(&summary.b_verdicts) {
        let row: &VerdictRow = row;
        if !row.listed {
            continue;
        }
        materialized += 1;
        if shown < display {
            render_listing_row(row, false);
            shown += 1;
        }
    }
    if shown == 0 {
        println!("    none");
    }
    let withheld: usize = materialized.saturating_sub(shown) + summary.listing.withheld;
    if withheld > 0 {
        println!("  withheld listing rows: {withheld}");
    }
}

fn render_function(summary: &MatchSummary) {
    for row in summary.a_verdicts.iter().chain(&summary.b_verdicts) {
        let row: &VerdictRow = row;
        println!("  function {:#x} on {}:", row.subject, row.side.label());
        render_listing_row(row, true);
    }
}

fn render_listing_row(row: &VerdictRow, full_evidence: bool) {
    match &row.verdict {
        VerdictBody::DataReference {
            counterpart,
            anchor_strength,
            shared_references,
        } => {
            println!(
                "    {} {:#x} -> {counterpart:#x}  data reference  {anchor_strength} anchor, {} shared reference(s)",
                row.side.label(),
                row.subject,
                shared_references.len()
            );
            for reference in shared_references {
                let reference: &ReferenceRow = reference;
                let text: String = if full_evidence {
                    full_reference_text(reference)
                } else {
                    reference_text(reference)
                };
                println!("        {text}");
            }
        }
        VerdictBody::ControlFlow {
            counterpart,
            fingerprint,
            instructions,
            instruction_mix,
        } => println!(
            "    {} {:#x} -> {counterpart:#x}  control flow    fingerprint {fingerprint:#018x}, {instructions} instruction(s): {}",
            row.side.label(),
            row.subject,
            mix_text(instruction_mix)
        ),
        VerdictBody::Propagation {
            counterpart,
            anchor,
            anchor_counterpart,
            relation,
            hops,
            fingerprint,
            instructions,
        } => println!(
            "    {} {:#x} -> {counterpart:#x}  propagation     {relation} of {anchor:#x} -> {anchor_counterpart:#x}, {hops} hop(s), fingerprint {fingerprint:#018x}, {instructions} instruction(s)",
            row.side.label(),
            row.subject
        ),
        VerdictBody::Ambiguous {
            candidates,
            own_side,
            other_side,
        } => println!(
            "    {} {:#x}  refusal ambiguous: {own_side} on {}, {other_side} on {}; candidates: {}",
            row.side.label(),
            row.subject,
            row.side.label(),
            row.side.other().label(),
            candidate_text(candidates)
        ),
        VerdictBody::Unmatched { cause } => {
            println!(
                "    {} {:#x}  refusal {cause}",
                row.side.label(),
                row.subject
            );
        }
    }
}

fn reference_text(reference: &ReferenceRow) -> String {
    match reference {
        ReferenceRow::StringLiteral { value } => format!("string \"{}\"", preview(value)),
        ReferenceRow::UnusualConstant { value } => format!("constant {value:#x}"),
        ReferenceRow::ImportedCall { name } => format!("import {}", preview(name)),
    }
}

fn full_reference_text(reference: &ReferenceRow) -> String {
    match reference {
        ReferenceRow::StringLiteral { value } => format!("string {value:?}"),
        ReferenceRow::UnusualConstant { value } => format!("constant {value:#x}"),
        ReferenceRow::ImportedCall { name } => format!("import {name}"),
    }
}

fn preview(value: &str) -> String {
    let flattened: String = value
        .chars()
        .map(|character: char| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(LITERAL_PREVIEW_LIMIT)
        .collect();
    if value.chars().count() > LITERAL_PREVIEW_LIMIT {
        return format!("{flattened}...");
    }
    flattened
}

fn mix_text(rows: &[MixRow]) -> String {
    let parts: Vec<String> = rows
        .iter()
        .map(|row: &MixRow| format!("{} {}", row.category, row.count))
        .collect();
    parts.join(", ")
}

fn candidate_text(candidates: &[u64]) -> String {
    let parts: Vec<String> = candidates
        .iter()
        .map(|candidate: &u64| format!("{candidate:#x}"))
        .collect();
    parts.join(", ")
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;

    use disrobe_similarity::{BasicBlock, ControlFlowGraph};

    fn no_references() -> [DataReference; 0] {
        []
    }

    fn graph() -> ControlFlowGraph {
        let exit: [usize; 0] = [];
        ControlFlowGraph::new(
            0,
            [
                BasicBlock::new([1, 2], [InstructionCategory::Compare]),
                BasicBlock::new([2], [InstructionCategory::Move]),
                BasicBlock::new(exit, [InstructionCategory::Return]),
            ],
        )
        .expect("a three block graph is well formed")
    }

    #[test]
    fn every_stage_keeps_its_own_evidence_in_the_row() {
        let exact: VerdictBody = body_of(&Verdict::Exact {
            counterpart: FunctionId(0x2000),
            shared_references: BTreeSet::from([
                DataReference::string_literal("gate"),
                DataReference::imported_call("recv"),
            ]),
            strength: AnchorStrength::Distinctive,
        });
        let VerdictBody::DataReference {
            counterpart,
            anchor_strength,
            shared_references,
        } = exact
        else {
            panic!("an Exact verdict must render as the data reference stage");
        };
        assert_eq!(counterpart, 0x2000);
        assert_eq!(anchor_strength, "distinctive");
        assert_eq!(shared_references.len(), 2);

        let key: StructuralKey = graph()
            .structural_key()
            .expect("a three block graph carries a structural key");
        let structural: VerdictBody = body_of(&Verdict::Structural {
            counterpart: FunctionId(0x3000),
            fingerprint: key.fingerprint,
            instruction_mix: key.instruction_mix,
        });
        let VerdictBody::ControlFlow {
            fingerprint,
            instructions,
            instruction_mix,
            ..
        } = structural
        else {
            panic!("a Structural verdict must render as the control flow stage");
        };
        assert_eq!(fingerprint, key.fingerprint.value());
        assert_eq!(instructions, 3);
        assert_eq!(instruction_mix.len(), 3);

        let propagated: VerdictBody = body_of(&Verdict::Propagated {
            counterpart: FunctionId(0x4000),
            anchor: FunctionId(0x1000),
            anchor_counterpart: FunctionId(0x2000),
            relation: CallRelation::Caller,
            hops: 2,
            agreement: key,
        });
        let VerdictBody::Propagation {
            anchor,
            anchor_counterpart,
            relation,
            hops,
            ..
        } = propagated
        else {
            panic!("a Propagated verdict must render as the propagation stage");
        };
        assert_eq!(anchor, 0x1000);
        assert_eq!(anchor_counterpart, 0x2000);
        assert_eq!(relation, "caller");
        assert_eq!(hops, 2);
    }

    #[test]
    fn a_refusal_keeps_its_candidates_and_its_cause() {
        let ambiguous: VerdictBody = body_of(&Verdict::Ambiguous {
            candidates: BTreeSet::from([FunctionId(0x2000), FunctionId(0x3000)]),
            own_side: 1,
            other_side: 2,
        });
        let VerdictBody::Ambiguous {
            candidates,
            own_side,
            other_side,
        } = ambiguous
        else {
            panic!("an Ambiguous verdict must survive into the report");
        };
        assert_eq!(candidates, vec![0x2000, 0x3000]);
        assert_eq!(own_side, 1);
        assert_eq!(other_side, 2);

        let unmatched: VerdictBody = body_of(&Verdict::Unmatched {
            cause: UnmatchedCause::NoAnchor,
        });
        let VerdictBody::Unmatched { cause } = unmatched else {
            panic!("an Unmatched verdict must survive into the report");
        };
        assert_eq!(cause, "no-anchor");
    }

    #[test]
    fn a_function_with_neither_an_anchor_nor_a_structure_carries_no_evidence() {
        let bare: FunctionFeatures = FunctionFeatures::new(FunctionId(0x1000), no_references());
        let anchored: FunctionFeatures =
            FunctionFeatures::new(FunctionId(0x1100), [DataReference::string_literal("gate")]);
        let structured: FunctionFeatures =
            FunctionFeatures::with_structure(FunctionId(0x1200), no_references(), graph());
        assert_eq!(without_evidence(&[bare, anchored, structured]), 1);
    }

    #[test]
    fn a_long_literal_is_flattened_and_marked_as_cut() {
        let long: String = "a\nb".repeat(64);
        let shown: String = preview(&long);
        assert!(shown.ends_with("..."), "{shown}");
        assert!(!shown.contains('\n'), "{shown}");
        assert_eq!(preview("plain"), "plain");
    }

    #[test]
    fn a_multibyte_literal_is_cut_on_a_character_boundary() {
        let mixed: String = "\u{20ac}\u{7}".repeat(50);
        let shown: String = preview(&mixed);
        assert_eq!(shown.chars().count(), LITERAL_PREVIEW_LIMIT + 3, "{shown}");
        assert!(shown.starts_with("\u{20ac} \u{20ac} "), "{shown}");
        assert!(shown.ends_with("..."), "{shown}");
        assert!(!shown.contains('\u{7}'), "{shown}");
        assert_eq!(
            shown.chars().filter(|c: &char| *c == '\u{20ac}').count(),
            LITERAL_PREVIEW_LIMIT / 2,
            "{shown}"
        );
    }

    fn key() -> StructuralKey {
        graph()
            .structural_key()
            .expect("a three block graph carries a structural key")
    }

    fn every_verdict() -> [Verdict; 5] {
        let agreement: StructuralKey = key();
        [
            Verdict::Exact {
                counterpart: FunctionId(0x2000),
                shared_references: BTreeSet::from([DataReference::string_literal("gate")]),
                strength: AnchorStrength::Distinctive,
            },
            Verdict::Structural {
                counterpart: FunctionId(0x3000),
                fingerprint: agreement.fingerprint,
                instruction_mix: agreement.instruction_mix,
            },
            Verdict::Propagated {
                counterpart: FunctionId(0x4000),
                anchor: FunctionId(0x1000),
                anchor_counterpart: FunctionId(0x2000),
                relation: CallRelation::Callee,
                hops: 1,
                agreement,
            },
            Verdict::Ambiguous {
                candidates: BTreeSet::from([FunctionId(0x2000)]),
                own_side: 1,
                other_side: 2,
            },
            Verdict::Unmatched {
                cause: UnmatchedCause::NoAnchor,
            },
        ]
    }

    fn report_of(left: Vec<FunctionVerdict>, right: Vec<FunctionVerdict>) -> MatchReport {
        MatchReport { left, right }
    }

    fn repeated(verdict: &Verdict, count: usize) -> Vec<FunctionVerdict> {
        (0..count)
            .map(|index: usize| FunctionVerdict {
                subject: FunctionId(0x1000 + index as u64),
                verdict: verdict.clone(),
            })
            .collect()
    }

    #[test]
    fn the_default_listing_keeps_the_asymmetry_between_the_two_sides() {
        const TABLE: [(Option<ListingStage>, [bool; 5], [bool; 5]); 5] = [
            (
                None,
                [true, true, true, true, false],
                [false, false, false, true, false],
            ),
            (
                Some(ListingStage::DataReference),
                [true, false, false, false, false],
                [false; 5],
            ),
            (
                Some(ListingStage::ControlFlow),
                [false, true, false, false, false],
                [false; 5],
            ),
            (
                Some(ListingStage::Propagation),
                [false, false, true, false, false],
                [false; 5],
            ),
            (
                Some(ListingStage::Refused),
                [false, false, false, true, true],
                [false, false, false, true, true],
            ),
        ];
        let verdicts: [Verdict; 5] = every_verdict();
        for (stage, on_a, on_b) in TABLE {
            let stage: Option<ListingStage> = stage;
            for (index, verdict) in verdicts.iter().enumerate() {
                let verdict: &Verdict = verdict;
                assert_eq!(
                    admits_stage(verdict, stage, Side::A),
                    on_a[index],
                    "side a, stage {stage:?}, verdict {verdict:?}"
                );
                assert_eq!(
                    admits_stage(verdict, stage, Side::B),
                    on_b[index],
                    "side b, stage {stage:?}, verdict {verdict:?}"
                );
            }
        }
    }

    #[test]
    fn the_collector_stops_materializing_rows_at_the_limit_and_counts_the_rest() {
        const ENTRIES: usize = 200_000;
        const LIMIT: usize = 8;
        let anchored: Verdict = Verdict::Exact {
            counterpart: FunctionId(0x9000),
            shared_references: BTreeSet::from([DataReference::string_literal(
                "a shared literal the collector must never clone in bulk",
            )]),
            strength: AnchorStrength::Distinctive,
        };
        let report: MatchReport = report_of(repeated(&anchored, ENTRIES), Vec::new());
        let listing: Listing = collect_listing(
            &report,
            Selector::Stage(ListingStage::DataReference),
            Some(LIMIT),
        );
        assert_eq!(listing.a.len(), LIMIT);
        assert!(
            listing.a.capacity() <= LIMIT,
            "the collector reserved {} rows for a limit of {LIMIT}",
            listing.a.capacity()
        );
        assert!(listing.b.is_empty());
        assert_eq!(listing.withheld, ENTRIES - LIMIT);
        assert!(listing.a.iter().all(|row: &VerdictRow| row.side == Side::A));
    }

    #[test]
    fn a_complete_machine_report_streams_from_a_fixed_size_row_view() {
        const ENTRIES: usize = 200_000;
        let anchored: Verdict = Verdict::Exact {
            counterpart: FunctionId(0x9000),
            shared_references: BTreeSet::from([DataReference::string_literal(
                "a shared literal the stream must never clone in bulk",
            )]),
            strength: AnchorStrength::Distinctive,
        };
        let report: MatchReport = report_of(repeated(&anchored, ENTRIES), Vec::new());
        let summary: StreamingMatchSummary<'_> = streaming_summary(
            Path::new("a"),
            Path::new("b"),
            &[],
            &[],
            &report,
            Selector::All,
        );
        assert_eq!(summary.listing.shown, ENTRIES);
        assert_eq!(summary.listing.withheld, 0);
        assert!(
            std::mem::size_of_val(&summary.a_verdicts) <= std::mem::size_of::<[usize; 8]>(),
            "the row view grew beyond eight machine words"
        );
        serde_json::to_writer(std::io::sink(), &summary).expect("stream complete report");
    }

    #[test]
    fn one_limit_is_shared_by_both_sides_and_counts_what_neither_side_collected() {
        const PER_SIDE: usize = 64;
        const LIMIT: usize = 5;
        let refusal: Verdict = Verdict::Ambiguous {
            candidates: BTreeSet::from([FunctionId(0x2000)]),
            own_side: 1,
            other_side: 2,
        };
        let report: MatchReport =
            report_of(repeated(&refusal, PER_SIDE), repeated(&refusal, PER_SIDE));
        let listing: Listing =
            collect_listing(&report, Selector::Stage(ListingStage::Refused), Some(LIMIT));
        assert_eq!(listing.a.len(), LIMIT);
        assert!(listing.b.is_empty());
        assert_eq!(listing.withheld, PER_SIDE * 2 - LIMIT);
        assert!(listing.a.capacity() + listing.b.capacity() <= LIMIT);
    }

    #[test]
    fn a_limit_of_zero_collects_nothing_and_counts_every_matching_row() {
        let verdicts: [Verdict; 5] = every_verdict();
        let refusal: &Verdict = &verdicts[3];
        let report: MatchReport = report_of(repeated(refusal, 12), repeated(refusal, 7));
        let listing: Listing =
            collect_listing(&report, Selector::Stage(ListingStage::Refused), Some(0));
        assert!(listing.a.is_empty());
        assert!(listing.b.is_empty());
        assert_eq!(listing.withheld, 19);
        assert_eq!(listing.limit, Some(0));
        assert_eq!(listing.stage, Some("refused"));
    }

    #[test]
    fn a_selection_that_matches_nothing_withholds_nothing() {
        let verdicts: [Verdict; 5] = every_verdict();
        let unmatched: &Verdict = &verdicts[4];
        let report: MatchReport = report_of(repeated(unmatched, 40), repeated(unmatched, 40));
        let listing: Listing = collect_listing(
            &report,
            Selector::Stage(ListingStage::DataReference),
            Some(25),
        );
        assert!(listing.a.is_empty());
        assert!(listing.b.is_empty());
        assert_eq!(listing.withheld, 0);
    }

    #[test]
    fn a_complete_report_keeps_every_verdict_and_still_marks_the_listing_view() {
        let verdicts: [Verdict; 5] = every_verdict();
        let left: Vec<FunctionVerdict> = verdicts
            .iter()
            .enumerate()
            .map(|(index, verdict): (usize, &Verdict)| FunctionVerdict {
                subject: FunctionId(0x1000 + index as u64),
                verdict: verdict.clone(),
            })
            .collect();
        let right: Vec<FunctionVerdict> = left.clone();
        let report: MatchReport = report_of(left, right);
        let listing: Listing = collect_listing(&report, Selector::All, None);
        assert_eq!(listing.a.len(), 5);
        assert_eq!(listing.b.len(), 5);
        assert_eq!(listing.withheld, 0);
        assert_eq!(
            listing
                .a
                .iter()
                .filter(|row: &&VerdictRow| row.listed)
                .count(),
            4
        );
        assert_eq!(
            listing
                .b
                .iter()
                .filter(|row: &&VerdictRow| row.listed)
                .count(),
            1
        );
    }

    #[test]
    fn a_function_query_returns_both_sides_and_names_the_side_of_every_row() {
        let verdicts: [Verdict; 5] = every_verdict();
        let report: MatchReport = report_of(repeated(&verdicts[0], 6), repeated(&verdicts[3], 6));
        let listing: Listing = collect_listing(&report, Selector::Function(0x1003), None);
        assert_eq!(listing.a.len(), 1);
        assert_eq!(listing.b.len(), 1);
        assert_eq!(listing.withheld, 0);
        assert_eq!(listing.function, Some(0x1003));
        assert_eq!(listing.stage, None);
        assert_eq!(listing.a[0].side, Side::A);
        assert_eq!(listing.b[0].side, Side::B);
        assert_eq!(listing.a[0].subject, 0x1003);
        assert_eq!(listing.b[0].subject, 0x1003);

        let absent: Listing = collect_listing(&report, Selector::Function(u64::MAX), None);
        assert!(absent.a.is_empty() && absent.b.is_empty());
        assert_eq!(absent.withheld, 0);
    }

    #[test]
    fn a_function_query_bounds_duplicate_function_ids_to_one_row_per_side() {
        const DUPLICATES: usize = 10_000;
        let verdicts: [Verdict; 5] = every_verdict();
        let duplicate: FunctionId = FunctionId(0x1000);
        let left: Vec<FunctionVerdict> = (0..DUPLICATES)
            .map(|_: usize| FunctionVerdict {
                subject: duplicate,
                verdict: verdicts[0].clone(),
            })
            .collect();
        let right: Vec<FunctionVerdict> = (0..DUPLICATES)
            .map(|_: usize| FunctionVerdict {
                subject: duplicate,
                verdict: verdicts[3].clone(),
            })
            .collect();
        let report: MatchReport = report_of(left, right);
        let listing: Listing = collect_listing(&report, Selector::Function(duplicate.0), None);
        assert_eq!(listing.a.len(), 1);
        assert_eq!(listing.b.len(), 1);
        assert!(listing.a.capacity() <= 1);
        assert!(listing.b.capacity() <= 1);
        assert_eq!(listing.withheld, 0);
    }

    const fn options(
        limit: Option<usize>,
        function: Option<u64>,
        stage: Option<ListingStage>,
    ) -> ListingOptions {
        ListingOptions {
            limit,
            function,
            stage,
        }
    }

    #[test]
    fn the_report_is_bounded_only_when_the_caller_asks_for_a_bound() {
        let out: PathBuf = PathBuf::from("report.json");
        let file: Option<&Path> = Some(out.as_path());
        assert_eq!(
            plan(options(None, None, None), OutputFormat::Text, None),
            (Selector::Listing, Some(DEFAULT_LISTING_LIMIT))
        );
        for machine in [
            OutputFormat::Json,
            OutputFormat::Ndjson,
            OutputFormat::Sarif,
        ] {
            let machine: OutputFormat = machine;
            assert_eq!(
                plan(options(None, None, None), machine, None),
                (Selector::All, None),
                "{machine:?}"
            );
        }
        assert_eq!(
            plan(options(None, None, None), OutputFormat::Text, file),
            (Selector::All, None)
        );
        assert_eq!(
            plan(options(Some(3), None, None), OutputFormat::Json, None),
            (Selector::Listing, Some(3))
        );
        assert_eq!(
            plan(options(Some(0), None, None), OutputFormat::Text, None),
            (Selector::Listing, Some(0))
        );
        assert_eq!(
            plan(
                options(None, None, Some(ListingStage::Refused)),
                OutputFormat::Json,
                None
            ),
            (Selector::Stage(ListingStage::Refused), None)
        );
        assert_eq!(
            plan(
                options(None, None, Some(ListingStage::Refused)),
                OutputFormat::Text,
                None
            ),
            (
                Selector::Stage(ListingStage::Refused),
                Some(DEFAULT_LISTING_LIMIT)
            )
        );
        assert_eq!(
            plan(
                options(Some(0), Some(0x1000), None),
                OutputFormat::Text,
                None
            ),
            (Selector::Function(0x1000), None),
            "a point query ignores the listing limit"
        );
    }
}
