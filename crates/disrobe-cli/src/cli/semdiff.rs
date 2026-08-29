use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use disrobe_nir::{NirFunction, NirModule};
use disrobe_semdiff::{
    ChangeKind, FunctionChange, Indeterminate, LineageMember, LineageReport, LineageVariant,
    MAX_FUNCTIONS_PER_MODULE, MAX_LINEAGE_VARIANTS, MAX_PROPAGATION_ROUNDS, MatchTier,
    SemanticDiff, StructuralMatchReport, StructuralPair, SummaryDecline, VariantFamily,
};
use serde::Serialize;

use crate::cli::nir_source::lift_module_from_bytes;
use crate::cli::output::{self, OutputFormat};

const MAX_SEMDIFF_INPUT_BYTES: u64 = 256 * 1024 * 1024;
const DEFAULT_LISTING_LIMIT: usize = 40;

#[derive(Debug, Clone, Copy, Serialize)]
struct TierCounts {
    leaf_exact: usize,
    symbolic_summary: usize,
    propagated: usize,
}

#[derive(Debug, Serialize)]
struct PairOut {
    base_address: String,
    other_address: String,
    base_name: Option<String>,
    other_name: Option<String>,
    tier: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    round: Option<u32>,
}

#[derive(Debug, Serialize)]
struct UnmatchedOut {
    address: String,
    name: Option<String>,
    reason: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    base_candidates: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    other_candidates: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    base_lang: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    other_lang: Option<&'static str>,
}

#[derive(Debug, Serialize)]
struct DeclineOut {
    address: String,
    name: Option<String>,
    reason: &'static str,
}

#[derive(Debug, Serialize)]
struct SemdiffOutput<'a> {
    base: String,
    other: String,
    base_lang: &'a str,
    other_lang: &'a str,
    base_functions: usize,
    other_functions: usize,
    matched: usize,
    match_rate: f64,
    rounds_run: u32,
    max_propagation_rounds: u32,
    max_functions_per_module: usize,
    tiers: TierCounts,
    listed: usize,
    matches: Vec<PairOut>,
    unmatched_base: Vec<UnmatchedOut>,
    unmatched_other: Vec<UnmatchedOut>,
    summary_declines_base: Vec<DeclineOut>,
    summary_declines_other: Vec<DeclineOut>,
    named_change_count: usize,
    named_changes: Vec<NamedChangeOut<'a>>,
}

#[derive(Debug, Serialize)]
struct NamedChangeOut<'a> {
    function: &'a str,
    kind: &'static str,
}

pub(crate) fn run(
    base: PathBuf,
    others: Vec<PathBuf>,
    lineage: bool,
    limit: Option<usize>,
    fmt: OutputFormat,
) -> miette::Result<()> {
    if lineage {
        return run_lineage(base, others, limit, fmt);
    }
    let [other]: [PathBuf; 1] = <[PathBuf; 1]>::try_from(others).map_err(|got: Vec<PathBuf>| {
        miette::miette!(
            "DR-CLI-0872: semdiff pairs exactly two builds, got {} OTHER argument(s); pass --lineage to track one base across several builds at once",
            got.len()
        )
    })?;
    run_pairwise(base, other, limit, fmt)
}

fn run_pairwise(
    base: PathBuf,
    other: PathBuf,
    limit: Option<usize>,
    fmt: OutputFormat,
) -> miette::Result<()> {
    let base_bytes: Vec<u8> = read_capped(&base)?;
    let other_bytes: Vec<u8> = read_capped(&other)?;
    ensure_same_native_architecture(&base, &base_bytes, &other, &other_bytes)?;
    let base_module: NirModule = lift_module_from_bytes(&base, &base_bytes)?;
    let other_module: NirModule = lift_module_from_bytes(&other, &other_bytes)?;

    let report: StructuralMatchReport =
        disrobe_semdiff::structural_match(&base_module, &other_module);
    let named: SemanticDiff = disrobe_semdiff::diff(&base_module, &other_module);

    let listing_limit: usize = limit.unwrap_or(DEFAULT_LISTING_LIMIT);
    let base_names: BTreeMap<u64, &str> = name_index(&base_module);
    let other_names: BTreeMap<u64, &str> = name_index(&other_module);

    let matched: usize = report.match_count();
    let denominator: usize = base_module
        .functions
        .len()
        .min(other_module.functions.len());
    let payload: SemdiffOutput<'_> = SemdiffOutput {
        base: base.display().to_string(),
        other: other.display().to_string(),
        base_lang: base_module.lang.label(),
        other_lang: other_module.lang.label(),
        base_functions: base_module.functions.len(),
        other_functions: other_module.functions.len(),
        matched,
        match_rate: match_rate(matched, denominator),
        rounds_run: report.rounds_run,
        max_propagation_rounds: MAX_PROPAGATION_ROUNDS,
        max_functions_per_module: MAX_FUNCTIONS_PER_MODULE,
        tiers: tier_counts(&report),
        listed: listing_limit,
        matches: pair_rows(&report, &base_names, &other_names, listing_limit),
        unmatched_base: unmatched_rows(&report.unmatched_base, &base_names, listing_limit),
        unmatched_other: unmatched_rows(&report.unmatched_other, &other_names, listing_limit),
        summary_declines_base: decline_rows(
            &report.summary_declines_base,
            &base_names,
            listing_limit,
        ),
        summary_declines_other: decline_rows(
            &report.summary_declines_other,
            &other_names,
            listing_limit,
        ),
        named_change_count: named.count(),
        named_changes: named_rows(&named, listing_limit),
    };

    output::emit(fmt, &payload, || render_text(&payload))
}

#[derive(Debug, Serialize)]
struct VariantOut {
    label: String,
    lang: &'static str,
    functions: usize,
}

#[derive(Debug, Serialize)]
struct MemberOut {
    variant: usize,
    label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tier: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    possible_outlined: Vec<String>,
}

#[derive(Debug, Serialize)]
struct FamilyOut {
    anchor_address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    anchor_name: Option<String>,
    matched: usize,
    complete: bool,
    members: Vec<MemberOut>,
}

#[derive(Debug, Serialize)]
struct RefusedOut {
    variant: usize,
    label: String,
    reason: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
enum RelationGradeOut {
    Graded {
        expected: usize,
        reported: usize,
        correct: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        precision: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        recall: Option<f64>,
    },
    Unavailable {
        reason: &'static str,
    },
}

const RELATIONS_UNAVAILABLE_REASON: &str = "no-comparable-named-relations-in-the-supplied-images";

fn defined_rate(numerator: usize, denominator: usize) -> Option<f64> {
    if denominator == 0 {
        return None;
    }
    #[expect(
        clippy::cast_precision_loss,
        reason = "relation counts are bounded by MAX_FUNCTIONS_PER_MODULE times MAX_LINEAGE_VARIANTS"
    )]
    let rate: f64 = numerator as f64 / denominator as f64;
    Some(rate)
}

fn relation_grade(graded: Option<(usize, usize, usize)>) -> RelationGradeOut {
    match graded {
        Some((expected, reported, correct)) => RelationGradeOut::Graded {
            expected,
            reported,
            correct,
            precision: defined_rate(correct, reported),
            recall: defined_rate(correct, expected),
        },
        None => RelationGradeOut::Unavailable {
            reason: RELATIONS_UNAVAILABLE_REASON,
        },
    }
}

#[derive(Debug, Serialize)]
struct LineageOutput<'a> {
    anchor: String,
    anchor_lang: &'a str,
    anchor_functions: usize,
    variant_count: usize,
    max_variants: usize,
    variants: Vec<VariantOut>,
    families: usize,
    complete_families: usize,
    matched_members: usize,
    possible_members: usize,
    relation_grade: RelationGradeOut,
    listed: usize,
    family_rows: Vec<FamilyOut>,
    refused: Vec<RefusedOut>,
}

fn run_lineage(
    base: PathBuf,
    others: Vec<PathBuf>,
    limit: Option<usize>,
    fmt: OutputFormat,
) -> miette::Result<()> {
    if others.len() > MAX_LINEAGE_VARIANTS {
        return Err(miette::miette!(
            "DR-CLI-0873: semdiff --lineage tracks at most {MAX_LINEAGE_VARIANTS} variants, got {}; split the run rather than letting variants be dropped",
            others.len()
        ));
    }
    let base_bytes: Vec<u8> = read_capped(&base)?;
    let anchor_module: NirModule = lift_module_from_bytes(&base, &base_bytes)?;

    let mut variant_bytes: Vec<Vec<u8>> = Vec::with_capacity(others.len());
    for path in &others {
        let bytes: Vec<u8> = read_capped(path)?;
        ensure_same_native_architecture(&base, &base_bytes, path, &bytes)?;
        variant_bytes.push(bytes);
    }
    let mut variant_modules: Vec<NirModule> = Vec::with_capacity(others.len());
    for (path, bytes) in others.iter().zip(variant_bytes.iter()) {
        variant_modules.push(lift_module_from_bytes(path, bytes)?);
    }

    let labels: Vec<String> = others
        .iter()
        .map(|path: &PathBuf| path.display().to_string())
        .collect();
    let anchor_label: String = base.display().to_string();
    let anchor: LineageVariant<'_> = LineageVariant {
        label: anchor_label.as_str(),
        module: &anchor_module,
    };
    let variants: Vec<LineageVariant<'_>> = labels
        .iter()
        .zip(variant_modules.iter())
        .map(|(label, module): (&String, &NirModule)| LineageVariant {
            label: label.as_str(),
            module,
        })
        .collect();

    let report: LineageReport = disrobe_semdiff::variant_lineage(&anchor, &variants);
    let anchor_names: BTreeMap<u64, &str> = name_index(&anchor_module);
    let variant_names: Vec<BTreeMap<u64, &str>> = variant_modules.iter().map(name_index).collect();
    let inputs: LineageInputs<'_> = LineageInputs {
        anchor_label: anchor_label.as_str(),
        anchor_lang: anchor_module.lang.label(),
        anchor_functions: anchor_module.functions.len(),
        variants: labels
            .iter()
            .zip(variant_modules.iter())
            .map(|(label, module): (&String, &NirModule)| VariantOut {
                label: label.clone(),
                lang: module.lang.label(),
                functions: module.functions.len(),
            })
            .collect(),
        labels,
        listing_limit: limit.unwrap_or(DEFAULT_LISTING_LIMIT),
    };
    let payload: LineageOutput<'_> =
        lineage_payload(&report, inputs, &anchor_names, &variant_names);

    output::emit(fmt, &payload, || render_lineage(&payload))
}

#[derive(Debug)]
struct LineageInputs<'a> {
    anchor_label: &'a str,
    anchor_lang: &'a str,
    anchor_functions: usize,
    variants: Vec<VariantOut>,
    labels: Vec<String>,
    listing_limit: usize,
}

fn lineage_payload<'a>(
    report: &LineageReport,
    inputs: LineageInputs<'a>,
    anchor_names: &BTreeMap<u64, &str>,
    variant_names: &[BTreeMap<u64, &str>],
) -> LineageOutput<'a> {
    let LineageInputs {
        anchor_label,
        anchor_lang,
        anchor_functions,
        variants,
        labels,
        listing_limit,
    } = inputs;
    let (matched_members, possible_members): (usize, usize) = report.membership();
    LineageOutput {
        anchor: anchor_label.to_owned(),
        anchor_lang,
        anchor_functions,
        variant_count: variants.len(),
        max_variants: MAX_LINEAGE_VARIANTS,
        variants,
        families: report.families.len(),
        complete_families: report.complete_families(),
        matched_members,
        possible_members,
        relation_grade: relation_grade(report.grade_named_relations(anchor_names, variant_names)),
        listed: listing_limit,
        family_rows: family_rows(report, anchor_names, &labels, listing_limit),
        refused: report
            .refused
            .iter()
            .map(|&(variant, reason): &(usize, Indeterminate)| RefusedOut {
                variant,
                label: labels.get(variant).cloned().unwrap_or_default(),
                reason: indeterminate_label(reason),
            })
            .collect(),
    }
}

fn family_rows(
    report: &LineageReport,
    anchor_names: &BTreeMap<u64, &str>,
    labels: &[String],
    limit: usize,
) -> Vec<FamilyOut> {
    report
        .families
        .iter()
        .take(limit)
        .map(|family: &VariantFamily| FamilyOut {
            anchor_address: format!("{:#x}", family.anchor_address),
            anchor_name: anchor_names
                .get(&family.anchor_address)
                .map(|n: &&str| (*n).to_owned()),
            matched: family.matched_count(),
            complete: family.is_complete(),
            members: family
                .members
                .iter()
                .map(|member: &LineageMember| member_row(member, labels))
                .collect(),
        })
        .collect()
}

fn member_row(member: &LineageMember, labels: &[String]) -> MemberOut {
    match member {
        LineageMember::Matched {
            variant,
            address,
            tier,
            possible_outlined,
        } => MemberOut {
            variant: *variant,
            label: labels.get(*variant).cloned().unwrap_or_default(),
            address: Some(format!("{address:#x}")),
            tier: Some(tier_label(*tier)),
            reason: None,
            possible_outlined: possible_outlined
                .iter()
                .map(|address: &u64| format!("{address:#x}"))
                .collect(),
        },
        LineageMember::Absent { variant, reason } => MemberOut {
            variant: *variant,
            label: labels.get(*variant).cloned().unwrap_or_default(),
            address: None,
            tier: None,
            reason: Some(indeterminate_label(*reason)),
            possible_outlined: Vec::new(),
        },
    }
}

fn render_lineage(payload: &LineageOutput<'_>) {
    println!("semdiff lineage: OK");
    println!(
        "  anchor:       {} [{}]",
        payload.anchor, payload.anchor_lang
    );
    println!("  functions:    {}", payload.anchor_functions);
    println!(
        "  variants:     {} of {} allowed",
        payload.variant_count, payload.max_variants
    );
    for variant in &payload.variants {
        println!(
            "    {} [{}] {} function(s)",
            variant.label, variant.lang, variant.functions
        );
    }
    println!(
        "  families:     {} ({} present in every variant)",
        payload.families, payload.complete_families
    );
    println!(
        "  membership:   {} matched of {} possible",
        payload.matched_members, payload.possible_members
    );
    match &payload.relation_grade {
        RelationGradeOut::Graded {
            expected,
            reported,
            correct,
            precision,
            recall,
        } => println!(
            "  relations:    expected {expected} reported {reported} correct {correct} precision {} recall {}",
            percent(*precision),
            percent(*recall)
        ),
        RelationGradeOut::Unavailable { reason } => {
            println!("  relations:    unavailable [{reason}]");
        }
    }
    for family in &payload.family_rows {
        let name: &str = family.anchor_name.as_deref().unwrap_or("<unnamed>");
        println!(
            "    {} @ {} matched {}/{}",
            name,
            family.anchor_address,
            family.matched,
            family.members.len()
        );
        for member in &family.members {
            match (&member.address, member.tier, member.reason) {
                (Some(address), Some(tier), _) => {
                    println!("      [{}] {address} [{tier}]", member.variant);
                    if !member.possible_outlined.is_empty() {
                        println!(
                            "        possible outlined (inferred, unproved): {}",
                            member.possible_outlined.join(", ")
                        );
                    }
                }
                (_, _, Some(reason)) => println!("      [{}] absent [{reason}]", member.variant),
                _ => {}
            }
        }
    }
    print_elision(payload.families, payload.family_rows.len());
    for refused in &payload.refused {
        println!(
            "  refused variant [{}] {}: {}",
            refused.variant, refused.label, refused.reason
        );
    }
}

fn native_architecture(bytes: &[u8]) -> Option<object::Architecture> {
    use object::Object as _;

    object::File::parse(bytes)
        .ok()
        .map(|obj: object::File<'_>| obj.architecture())
}

fn ensure_same_native_architecture(
    base: &Path,
    base_bytes: &[u8],
    other: &Path,
    other_bytes: &[u8],
) -> miette::Result<()> {
    let (Some(left), Some(right)): (Option<object::Architecture>, Option<object::Architecture>) = (
        native_architecture(base_bytes),
        native_architecture(other_bytes),
    ) else {
        return Ok(());
    };
    if left == right {
        return Ok(());
    }
    Err(miette::miette!(
        "DR-CLI-0874: {} is {left:?} and {} is {right:?}; every native image lifts under one source language, so pairing across architectures would compare unrelated code instead of refusing it",
        base.display(),
        other.display()
    ))
}

fn read_capped(path: &Path) -> miette::Result<Vec<u8>> {
    let metadata: std::fs::Metadata = std::fs::metadata(path).map_err(|e: std::io::Error| {
        miette::miette!("DR-CLI-0870: cannot read {}: {e}", path.display())
    })?;
    if metadata.len() > MAX_SEMDIFF_INPUT_BYTES {
        return Err(miette::miette!(
            "DR-CLI-0871: {} is {} bytes, over the {MAX_SEMDIFF_INPUT_BYTES} byte semantic diff input cap",
            path.display(),
            metadata.len()
        ));
    }
    std::fs::read(path).map_err(|e: std::io::Error| {
        miette::miette!("DR-CLI-0870: cannot read {}: {e}", path.display())
    })
}

fn percent(rate: Option<f64>) -> String {
    rate.map_or_else(
        || "undefined".to_owned(),
        |value: f64| format!("{:.1}%", value * 100.0),
    )
}

fn match_rate(matched: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        return 0.0;
    }
    #[expect(
        clippy::cast_precision_loss,
        reason = "function counts are bounded by MAX_FUNCTIONS_PER_MODULE"
    )]
    let rate: f64 = matched as f64 / denominator as f64;
    rate
}

fn name_index(module: &NirModule) -> BTreeMap<u64, &str> {
    module
        .functions
        .iter()
        .filter(|f: &&NirFunction| !f.name.is_empty())
        .map(|f: &NirFunction| (f.address, f.name.as_str()))
        .collect()
}

fn tier_counts(report: &StructuralMatchReport) -> TierCounts {
    let mut counts: TierCounts = TierCounts {
        leaf_exact: 0,
        symbolic_summary: 0,
        propagated: 0,
    };
    for pair in &report.matches {
        match pair.tier {
            MatchTier::LeafExact => counts.leaf_exact += 1,
            MatchTier::SymbolicSummary => counts.symbolic_summary += 1,
            MatchTier::Propagated { .. } => counts.propagated += 1,
        }
    }
    counts
}

const fn tier_label(tier: MatchTier) -> &'static str {
    match tier {
        MatchTier::LeafExact => "leaf-exact",
        MatchTier::SymbolicSummary => "symbolic-summary",
        MatchTier::Propagated { .. } => "propagated",
    }
}

const fn tier_round(tier: MatchTier) -> Option<u32> {
    match tier {
        MatchTier::LeafExact | MatchTier::SymbolicSummary => None,
        MatchTier::Propagated { round } => Some(round),
    }
}

fn pair_rows(
    report: &StructuralMatchReport,
    base_names: &BTreeMap<u64, &str>,
    other_names: &BTreeMap<u64, &str>,
    limit: usize,
) -> Vec<PairOut> {
    report
        .matches
        .iter()
        .take(limit)
        .map(|pair: &StructuralPair| PairOut {
            base_address: format!("{:#x}", pair.base_address),
            other_address: format!("{:#x}", pair.other_address),
            base_name: base_names
                .get(&pair.base_address)
                .map(|n: &&str| (*n).to_owned()),
            other_name: other_names
                .get(&pair.other_address)
                .map(|n: &&str| (*n).to_owned()),
            tier: tier_label(pair.tier),
            round: tier_round(pair.tier),
        })
        .collect()
}

fn unmatched_rows(
    rows: &[(u64, Indeterminate)],
    names: &BTreeMap<u64, &str>,
    limit: usize,
) -> Vec<UnmatchedOut> {
    rows.iter()
        .take(limit)
        .map(|&(address, reason): &(u64, Indeterminate)| {
            let mut row: UnmatchedOut = UnmatchedOut {
                address: format!("{address:#x}"),
                name: names.get(&address).map(|n: &&str| (*n).to_owned()),
                reason: indeterminate_label(reason),
                base_candidates: None,
                other_candidates: None,
                base_lang: None,
                other_lang: None,
            };
            match reason {
                Indeterminate::Ambiguous {
                    base_side,
                    other_side,
                } => {
                    row.base_candidates = Some(base_side);
                    row.other_candidates = Some(other_side);
                }
                Indeterminate::SourceLanguageMismatch { base, other } => {
                    row.base_lang = Some(base.label());
                    row.other_lang = Some(other.label());
                }
                Indeterminate::NoCandidate
                | Indeterminate::RoundBudgetExhausted
                | Indeterminate::FunctionCountCapExceeded
                | Indeterminate::DuplicateAddress => {}
            }
            row
        })
        .collect()
}

const fn indeterminate_label(reason: Indeterminate) -> &'static str {
    match reason {
        Indeterminate::NoCandidate => "no-candidate",
        Indeterminate::Ambiguous { .. } => "ambiguous",
        Indeterminate::RoundBudgetExhausted => "round-budget-exhausted",
        Indeterminate::FunctionCountCapExceeded => "function-count-cap-exceeded",
        Indeterminate::DuplicateAddress => "duplicate-address",
        Indeterminate::SourceLanguageMismatch { .. } => "source-language-mismatch",
    }
}

fn decline_rows(
    rows: &[(u64, SummaryDecline)],
    names: &BTreeMap<u64, &str>,
    limit: usize,
) -> Vec<DeclineOut> {
    rows.iter()
        .take(limit)
        .map(|&(address, reason): &(u64, SummaryDecline)| DeclineOut {
            address: format!("{address:#x}"),
            name: names.get(&address).map(|n: &&str| (*n).to_owned()),
            reason: decline_label(reason),
        })
        .collect()
}

const fn decline_label(reason: SummaryDecline) -> &'static str {
    match reason {
        SummaryDecline::BlockCountExceeded => "block-count-exceeded",
        SummaryDecline::CyclicControlFlow => "cyclic-control-flow",
        SummaryDecline::DepthBudgetExhausted => "depth-budget-exhausted",
        SummaryDecline::InstructionCountExceeded => "instruction-count-exceeded",
        SummaryDecline::MemoryCellBudgetExhausted => "memory-cell-budget-exhausted",
        SummaryDecline::NodeBudgetExhausted => "node-budget-exhausted",
        SummaryDecline::NoObservableOutput => "no-observable-output",
        SummaryDecline::OutputBudgetExhausted => "output-budget-exhausted",
        SummaryDecline::TrivialComputation => "trivial-computation",
        SummaryDecline::UnmodeledEffect => "unmodeled-effect",
        SummaryDecline::UnresolvedCall => "unresolved-call",
    }
}

fn named_rows(named: &SemanticDiff, limit: usize) -> Vec<NamedChangeOut<'_>> {
    named
        .changes()
        .iter()
        .take(limit)
        .map(|change: &FunctionChange| NamedChangeOut {
            function: change.function.as_str(),
            kind: change_label(change.kind),
        })
        .collect()
}

const fn change_label(kind: ChangeKind) -> &'static str {
    match kind {
        ChangeKind::Added => "added",
        ChangeKind::Removed => "removed",
        ChangeKind::Changed => "changed",
    }
}

fn render_text(payload: &SemdiffOutput<'_>) {
    println!("semdiff: OK");
    println!("  base:         {} [{}]", payload.base, payload.base_lang);
    println!("  other:        {} [{}]", payload.other, payload.other_lang);
    println!(
        "  functions:    {} -> {}",
        payload.base_functions, payload.other_functions
    );
    println!(
        "  matched:      {} ({:.1}%)",
        payload.matched,
        payload.match_rate * 100.0
    );
    println!("    leaf-exact:       {}", payload.tiers.leaf_exact);
    println!("    symbolic-summary: {}", payload.tiers.symbolic_summary);
    println!("    propagated:       {}", payload.tiers.propagated);
    println!(
        "  rounds run:   {} of {}",
        payload.rounds_run, payload.max_propagation_rounds
    );
    render_pairs(payload);
    render_unmatched("unmatched base", &payload.unmatched_base);
    render_unmatched("unmatched other", &payload.unmatched_other);
    render_declines("summary declines base", &payload.summary_declines_base);
    render_declines("summary declines other", &payload.summary_declines_other);
    render_named(payload);
}

fn render_pairs(payload: &SemdiffOutput<'_>) {
    if payload.matches.is_empty() {
        return;
    }
    println!("  pairs:");
    for pair in &payload.matches {
        let base: &str = pair.base_name.as_deref().unwrap_or("<unnamed>");
        let other: &str = pair.other_name.as_deref().unwrap_or("<unnamed>");
        let round: String = pair
            .round
            .map_or_else(String::new, |r: u32| format!(" round {r}"));
        println!(
            "    {} @ {} -> {} @ {} [{}{}]",
            base, pair.base_address, other, pair.other_address, pair.tier, round
        );
    }
    print_elision(payload.matched, payload.matches.len());
}

fn render_unmatched(label: &str, rows: &[UnmatchedOut]) {
    if rows.is_empty() {
        return;
    }
    println!("  {label}: {}", rows.len());
    for row in rows {
        let name: &str = row.name.as_deref().unwrap_or("<unnamed>");
        let detail: String = match (row.base_candidates, row.other_candidates) {
            (Some(base), Some(other)) => format!(" ({base} vs {other} candidates)"),
            _ => match (row.base_lang, row.other_lang) {
                (Some(base), Some(other)) => format!(" ({base} vs {other})"),
                _ => String::new(),
            },
        };
        println!("    {} @ {} [{}]{}", name, row.address, row.reason, detail);
    }
}

fn render_declines(label: &str, rows: &[DeclineOut]) {
    if rows.is_empty() {
        return;
    }
    println!("  {label}: {}", rows.len());
    for row in rows {
        let name: &str = row.name.as_deref().unwrap_or("<unnamed>");
        println!("    {} @ {} [{}]", name, row.address, row.reason);
    }
}

fn render_named(payload: &SemdiffOutput<'_>) {
    if payload.named_changes.is_empty() {
        return;
    }
    println!("  name-keyed changes: {}", payload.named_change_count);
    for change in &payload.named_changes {
        println!("    {} [{}]", change.function, change.kind);
    }
    print_elision(payload.named_change_count, payload.named_changes.len());
}

fn print_elision(total: usize, shown: usize) {
    if total > shown {
        println!("    ... {} more, raise --limit to list them", total - shown);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    use serde_json::{Map, Value};

    const ANCHOR_PRIMARY: u64 = 0x1400;
    const VARIANT_PRIMARY: u64 = 0x2400;
    const VARIANT_FRAGMENT: u64 = 0x2500;
    const PRIMARY_NAME: &str = "hot_path";
    const FRAGMENT_NAME: &str = "hot_path.part.0";

    fn inputs() -> LineageInputs<'static> {
        LineageInputs {
            anchor_label: "anchor.exe",
            anchor_lang: "native-x86",
            anchor_functions: 3,
            variants: vec![VariantOut {
                label: "variant.exe".to_owned(),
                lang: "native-x86",
                functions: 4,
            }],
            labels: vec!["variant.exe".to_owned()],
            listing_limit: DEFAULT_LISTING_LIMIT,
        }
    }

    fn report_with(member: LineageMember) -> LineageReport {
        LineageReport {
            anchor_label: "anchor.exe".to_owned(),
            variant_labels: vec!["variant.exe".to_owned()],
            families: vec![VariantFamily {
                anchor_address: ANCHOR_PRIMARY,
                members: vec![member],
            }],
            refused: Vec::new(),
        }
    }

    fn candidate_member() -> LineageMember {
        LineageMember::Matched {
            variant: 0,
            address: VARIANT_PRIMARY,
            tier: MatchTier::LeafExact,
            possible_outlined: vec![VARIANT_FRAGMENT],
        }
    }

    fn anchor_names() -> BTreeMap<u64, &'static str> {
        BTreeMap::from([(ANCHOR_PRIMARY, PRIMARY_NAME)])
    }

    fn variant_names() -> Vec<BTreeMap<u64, &'static str>> {
        vec![BTreeMap::from([
            (VARIANT_PRIMARY, PRIMARY_NAME),
            (VARIANT_FRAGMENT, FRAGMENT_NAME),
        ])]
    }

    fn json_of(payload: &LineageOutput<'_>) -> Value {
        serde_json::to_value(payload).expect("the lineage payload must serialize")
    }

    fn grade_object(value: &Value) -> Map<String, Value> {
        value
            .get("relation_grade")
            .and_then(Value::as_object)
            .cloned()
            .expect("the lineage payload must carry a relation_grade object")
    }

    #[test]
    fn a_graded_lineage_payload_serializes_its_exact_counts_and_possible_outlined_addresses() {
        let report: LineageReport = report_with(candidate_member());
        let payload: LineageOutput<'_> =
            lineage_payload(&report, inputs(), &anchor_names(), &variant_names());
        let json: Value = json_of(&payload);

        assert_eq!(
            json["matched_members"],
            Value::from(1),
            "one structurally matched primary is one matched member: a possible outlined candidate is not a second match"
        );
        assert_eq!(
            json["possible_members"],
            Value::from(2),
            "the possible count carries the matched primary plus its possible outlined candidate"
        );
        assert_eq!(json["families"], Value::from(1));
        assert_eq!(json["complete_families"], Value::from(1));

        let grade: Map<String, Value> = grade_object(&json);
        assert_eq!(grade["state"], Value::from("graded"));
        assert_eq!(grade["expected"], Value::from(2));
        assert_eq!(grade["reported"], Value::from(2));
        assert_eq!(grade["correct"], Value::from(2));
        assert_eq!(grade["precision"], Value::from(1.0));
        assert_eq!(grade["recall"], Value::from(1.0));

        let member: &Value = &json["family_rows"][0]["members"][0];
        assert_eq!(
            json["family_rows"][0]["anchor_name"],
            Value::from(PRIMARY_NAME)
        );
        assert_eq!(
            member["address"],
            Value::from(format!("{VARIANT_PRIMARY:#x}"))
        );
        assert_eq!(member["tier"], Value::from("leaf-exact"));
        assert_eq!(
            member["possible_outlined"],
            Value::from(vec![format!("{VARIANT_FRAGMENT:#x}")]),
            "the candidate fragment address must reach the JSON payload verbatim under its possible label"
        );
        let member_keys: &Map<String, Value> = member
            .as_object()
            .expect("a serialized lineage member must be a JSON object");
        assert!(
            !member_keys.contains_key("outlined"),
            "the ambiguous outlined field must be gone, because a candidate attachment is inferred rather than a definite relation: {:?}",
            member_keys.keys().collect::<Vec<&String>>()
        );
    }

    #[test]
    fn an_ungradable_lineage_payload_carries_a_reason_and_no_metric_fields() {
        let report: LineageReport = report_with(candidate_member());
        let payload: LineageOutput<'_> = lineage_payload(
            &report,
            inputs(),
            &BTreeMap::new(),
            std::slice::from_ref(&BTreeMap::new()),
        );
        let grade: Map<String, Value> = grade_object(&json_of(&payload));

        assert_eq!(grade["state"], Value::from("unavailable"));
        assert_eq!(grade["reason"], Value::from(RELATIONS_UNAVAILABLE_REASON));
        let mut keys: Vec<String> = grade.keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            vec!["reason".to_owned(), "state".to_owned()],
            "an unavailable grade must not publish expected, reported, correct, precision, or recall"
        );
    }

    #[test]
    fn a_grade_with_no_reported_relation_omits_precision_rather_than_publishing_zero() {
        let report: LineageReport = report_with(LineageMember::Absent {
            variant: 0,
            reason: Indeterminate::NoCandidate,
        });
        let payload: LineageOutput<'_> =
            lineage_payload(&report, inputs(), &anchor_names(), &variant_names());
        let grade: Map<String, Value> = grade_object(&json_of(&payload));

        assert_eq!(grade["state"], Value::from("graded"));
        assert_eq!(grade["expected"], Value::from(2));
        assert_eq!(grade["reported"], Value::from(0));
        assert_eq!(grade["correct"], Value::from(0));
        assert!(
            !grade.contains_key("precision"),
            "precision over zero reported relations is undefined and must be absent, not zero"
        );
        assert_eq!(grade["recall"], Value::from(0.0));
    }

    #[test]
    fn a_wrong_possible_outlined_address_is_reported_and_costs_precision() {
        let report: LineageReport = report_with(LineageMember::Matched {
            variant: 0,
            address: VARIANT_PRIMARY,
            tier: MatchTier::LeafExact,
            possible_outlined: vec![VARIANT_FRAGMENT + 0x4000],
        });
        let payload: LineageOutput<'_> =
            lineage_payload(&report, inputs(), &anchor_names(), &variant_names());
        let grade: Map<String, Value> = grade_object(&json_of(&payload));

        assert_eq!(grade["expected"], Value::from(2));
        assert_eq!(grade["reported"], Value::from(2));
        assert_eq!(grade["correct"], Value::from(1));
        assert_eq!(grade["precision"], Value::from(0.5));
        assert_eq!(grade["recall"], Value::from(0.5));
    }

    #[test]
    fn a_rate_is_undefined_only_when_its_denominator_is_zero() {
        assert_eq!(defined_rate(0, 0), None);
        assert_eq!(defined_rate(1, 0), None);
        assert_eq!(defined_rate(0, 4), Some(0.0));
        assert_eq!(defined_rate(1, 4), Some(0.25));
        assert_eq!(percent(None), "undefined");
        assert_eq!(percent(Some(0.25)), "25.0%");
    }
}
