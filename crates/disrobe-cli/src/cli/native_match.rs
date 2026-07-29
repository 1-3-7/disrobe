use std::path::{Path, PathBuf};

use serde::Serialize;

use super::globals;
use super::output::{self, OutputFormat};
use super::progress_ui::StageSpinner;
use disrobe_pass_native::extract_function_features;
use disrobe_similarity::{
    AnchorStrength, CallRelation, DataReference, FunctionFeatures, FunctionId, FunctionVerdict,
    InstructionCategory, InstructionMix, MatchReport, MatchStage, StructuralKey, UnmatchedCause,
    Verdict, match_functions,
};

const SCHEMA: &str = "disrobe.native.match/v1";

const LITERAL_PREVIEW_LIMIT: usize = 64;

pub(crate) const DEFAULT_LISTING_LIMIT: usize = 25;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum ListingStage {
    DataReference,
    ControlFlow,
    Propagation,
    Refused,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ListingOptions {
    pub(crate) limit: usize,
    pub(crate) function: Option<u64>,
    pub(crate) stage: Option<ListingStage>,
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
    subject: u64,
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
struct MatchSummary {
    schema: &'static str,
    a: String,
    b: String,
    pairs: usize,
    by_stage: StageCounts,
    a_side: SideSummary,
    b_side: SideSummary,
    a_verdicts: Vec<VerdictRow>,
    b_verdicts: Vec<VerdictRow>,
}

#[derive(Debug)]
enum Written {
    NotRequested,
    Skipped(PathBuf),
    Wrote(PathBuf),
}

struct ListingRow<'a> {
    side: &'static str,
    other_side: &'static str,
    row: &'a VerdictRow,
}

pub(crate) fn run(
    a: PathBuf,
    b: PathBuf,
    out: Option<PathBuf>,
    fmt: OutputFormat,
    listing: ListingOptions,
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
    let summary: MatchSummary = summarize(&a, &b, &left, &right, &report);
    spinner.finish(&format!("{} pair(s)", summary.pairs));

    if !fmt.is_machine() {
        let address: Option<u64> = listing.function;
        if let Some(address) = address
            && matching_rows(&summary, address).is_empty()
        {
            return Err(miette::miette!(
                "DR-NATIVE-0208: no function at address {address:#x} in either input"
            ));
        }
    }

    let written: Written = write_report(&summary, out)?;
    output::emit(fmt, &summary, || render(&summary, &written, listing))
}

fn write_report(summary: &MatchSummary, out: Option<PathBuf>) -> miette::Result<Written> {
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
    let buf: Vec<u8> = serde_json::to_vec_pretty(summary)
        .map_err(|e| miette::miette!("DR-NATIVE-0206: serialize: {e}"))?;
    std::fs::write(&path, buf)
        .map_err(|e| miette::miette!("DR-NATIVE-0207: cannot write match report: {e}"))?;
    Ok(Written::Wrote(path))
}

fn summarize(
    a: &Path,
    b: &Path,
    left: &[FunctionFeatures],
    right: &[FunctionFeatures],
    report: &MatchReport,
) -> MatchSummary {
    let by_stage: StageCounts = stage_counts(&report.left);
    let pairs: usize = by_stage.total();
    MatchSummary {
        schema: SCHEMA,
        a: a.display().to_string(),
        b: b.display().to_string(),
        pairs,
        by_stage,
        a_side: side_summary(left, &report.left),
        b_side: side_summary(right, &report.right),
        a_verdicts: rows_of(&report.left),
        b_verdicts: rows_of(&report.right),
    }
}

fn rows_of(entries: &[FunctionVerdict]) -> Vec<VerdictRow> {
    let mut rows: Vec<VerdictRow> = Vec::with_capacity(entries.len());
    for entry in entries {
        rows.push(VerdictRow {
            subject: entry.subject.0,
            verdict: body_of(&entry.verdict),
        });
    }
    rows
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

fn render(summary: &MatchSummary, written: &Written, listing: ListingOptions) {
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
    let address: Option<u64> = listing.function;
    if let Some(address) = address {
        render_function(summary, address);
    } else {
        render_listing(summary, listing);
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

fn render_listing(summary: &MatchSummary, listing: ListingOptions) {
    println!("  listing:");
    let rows: Vec<ListingRow<'_>> = listing_rows(summary, listing.stage);
    let shown: usize = rows.len().min(listing.limit);
    for row in rows.iter().take(shown) {
        let row: &ListingRow<'_> = row;
        render_listing_row(row, false);
    }
    if shown == 0 {
        println!("    none");
    }
    let withheld: usize = rows.len() - shown;
    if withheld > 0 {
        println!("  withheld listing rows: {withheld}");
    }
}

fn render_function(summary: &MatchSummary, address: u64) {
    let rows: Vec<ListingRow<'_>> = matching_rows(summary, address);
    for row in &rows {
        let row: &ListingRow<'_> = row;
        println!("  function {:#x} on {}:", row.row.subject, row.side);
        render_listing_row(row, true);
    }
}

fn listing_rows<'a>(summary: &'a MatchSummary, stage: Option<ListingStage>) -> Vec<ListingRow<'a>> {
    let mut rows: Vec<ListingRow<'a>> =
        Vec::with_capacity(summary.a_verdicts.len() + summary.b_verdicts.len());
    append_listing_rows(&mut rows, "a", "b", &summary.a_verdicts, stage, true);
    append_listing_rows(&mut rows, "b", "a", &summary.b_verdicts, stage, false);
    rows
}

fn append_listing_rows<'a>(
    output: &mut Vec<ListingRow<'a>>,
    side: &'static str,
    other_side: &'static str,
    rows: &'a [VerdictRow],
    stage: Option<ListingStage>,
    left_side: bool,
) {
    for row in rows {
        let row: &'a VerdictRow = row;
        if includes_listing_row(row, stage, left_side) {
            output.push(ListingRow {
                side,
                other_side,
                row,
            });
        }
    }
}

const fn includes_listing_row(
    row: &VerdictRow,
    stage: Option<ListingStage>,
    left_side: bool,
) -> bool {
    match stage {
        None => {
            if left_side {
                !matches!(&row.verdict, VerdictBody::Unmatched { .. })
            } else {
                matches!(&row.verdict, VerdictBody::Ambiguous { .. })
            }
        }
        Some(
            ListingStage::DataReference | ListingStage::ControlFlow | ListingStage::Propagation,
        ) => left_side && matches_stage(row, stage),
        Some(ListingStage::Refused) => is_refusal(row),
    }
}

const fn matches_stage(row: &VerdictRow, stage: Option<ListingStage>) -> bool {
    matches!(
        (&row.verdict, stage),
        (
            VerdictBody::DataReference { .. },
            Some(ListingStage::DataReference)
        ) | (
            VerdictBody::ControlFlow { .. },
            Some(ListingStage::ControlFlow)
        ) | (
            VerdictBody::Propagation { .. },
            Some(ListingStage::Propagation)
        )
    )
}

const fn is_refusal(row: &VerdictRow) -> bool {
    matches!(
        &row.verdict,
        VerdictBody::Ambiguous { .. } | VerdictBody::Unmatched { .. }
    )
}

fn matching_rows<'a>(summary: &'a MatchSummary, address: u64) -> Vec<ListingRow<'a>> {
    let mut rows: Vec<ListingRow<'a>> = Vec::with_capacity(2);
    append_matching_rows(&mut rows, "a", "b", &summary.a_verdicts, address);
    append_matching_rows(&mut rows, "b", "a", &summary.b_verdicts, address);
    rows
}

fn append_matching_rows<'a>(
    output: &mut Vec<ListingRow<'a>>,
    side: &'static str,
    other_side: &'static str,
    rows: &'a [VerdictRow],
    address: u64,
) {
    for row in rows {
        let row: &'a VerdictRow = row;
        if row.subject == address {
            output.push(ListingRow {
                side,
                other_side,
                row,
            });
        }
    }
}

fn render_listing_row(row: &ListingRow<'_>, full_evidence: bool) {
    match &row.row.verdict {
        VerdictBody::DataReference {
            counterpart,
            anchor_strength,
            shared_references,
        } => {
            println!(
                "    {} {:#x} -> {counterpart:#x}  data reference  {anchor_strength} anchor, {} shared reference(s)",
                row.side,
                row.row.subject,
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
            row.side,
            row.row.subject,
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
            row.side, row.row.subject
        ),
        VerdictBody::Ambiguous {
            candidates,
            own_side,
            other_side,
        } => println!(
            "    {} {:#x}  refusal ambiguous: {own_side} on {}, {other_side} on {}; candidates: {}",
            row.side,
            row.row.subject,
            row.side,
            row.other_side,
            candidate_text(candidates)
        ),
        VerdictBody::Unmatched { cause } => {
            println!("    {} {:#x}  refusal {cause}", row.side, row.row.subject);
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
}
