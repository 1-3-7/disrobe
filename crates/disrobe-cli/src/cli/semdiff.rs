use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use disrobe_nir::{NirFunction, NirModule};
use disrobe_semdiff::{
    ChangeKind, FunctionChange, Indeterminate, MAX_FUNCTIONS_PER_MODULE, MAX_PROPAGATION_ROUNDS,
    MatchTier, SemanticDiff, StructuralMatchReport, StructuralPair, SummaryDecline,
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
    other: PathBuf,
    limit: Option<usize>,
    fmt: OutputFormat,
) -> miette::Result<()> {
    let base_bytes: Vec<u8> = read_capped(&base)?;
    let other_bytes: Vec<u8> = read_capped(&other)?;
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
