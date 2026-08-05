use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Arguments;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::doc_region::{self, RegionSyntax};

const KNOWN_ORACLE_KINDS: &[&str] = &[
    "recovery-import",
    "bench-native-unpack",
    "headtohead-import",
    "gate-test-harvest",
];
const KNOWN_STRENGTHS: &[&str] = &["strong", "recompile-only", "coverage-self-reported"];
const MAX_DESCRIPTOR_BYTES: u64 = 1 << 20;
const MAX_EVIDENCE_TEXT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_JAVASCRIPT_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const README_PAIR_SYNTAX: RegionSyntax = RegionSyntax {
    open_prefix: "<!-- evidence-pair:",
    close: "<!-- /evidence-pair -->",
};

macro_rules! push_line {
    ($output:expr, $($arg:tt)*) => {
        push_format_line(&mut $output, format_args!($($arg)*))
    };
}

fn push_format_line(output: &mut String, args: Arguments<'_>) {
    match std::fmt::write(output, args) {
        Ok(()) => output.push('\n'),
        Err(error) => unreachable!("string formatting failed: {error:?}"),
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Mode {
    Render,
    Check,
    List,
}

#[derive(Debug, Deserialize)]
struct Descriptor {
    id: String,
    ecosystem: String,
    title: String,
    claim: String,
    oracle_strength: String,
    #[serde(default)]
    ci: bool,
    oracle: Oracle,
    #[serde(default)]
    source: Option<SourceBinding>,
    #[serde(default)]
    measured: Option<MeasuredBinding>,
}

#[derive(Debug, Deserialize)]
struct MeasuredBinding {
    result_file: String,
    #[serde(default)]
    gate_id: Option<String>,
    #[serde(default)]
    disrobe_floor: Option<f64>,
    #[serde(default)]
    pairs: Vec<MeasuredPair>,
}

#[derive(Debug, Deserialize)]
struct MeasuredPair {
    id: String,
    label: String,
    metric: String,
    disrobe: String,
    competitor: String,
    competitor_label: String,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    kind: String,
    external: String,
    reproduce: String,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    results_md: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SourceBinding {
    recovery_group: String,
    recovery_bar: String,
    #[serde(default)]
    floor: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct RecoveryDoc {
    groups: Vec<RecoveryGroup>,
}

#[derive(Debug, Deserialize)]
struct RecoveryGroup {
    heading: String,
    kind: String,
    bars: Vec<RecoveryBar>,
}

#[derive(Debug, Deserialize)]
struct RecoveryBar {
    label: String,
    #[serde(default)]
    value: Option<f64>,
    #[serde(default)]
    detail: Option<String>,
    #[serde(default)]
    detected: Option<u64>,
    #[serde(default)]
    delivered: Option<u64>,
    #[serde(default)]
    delivered_label: Option<String>,
    #[serde(default)]
    denominator_label: Option<String>,
    source: String,
}

#[derive(Debug)]
struct Resolved {
    id: String,
    ecosystem: String,
    title: String,
    claim: String,
    oracle_strength: String,
    ci: bool,
    oracle_kind: String,
    oracle_external: String,
    reproduce: String,
    oracle_note: Option<String>,
    measured: String,
    floor: Option<f64>,
    floor_holds: Option<bool>,
    gate_source: String,
    detail: Option<String>,
    competitors: Vec<CompetitorRow>,
    disrobe_leads: Option<bool>,
    comparison_basis: Option<String>,
    pairs: Vec<ResolvedPair>,
}

#[derive(Debug, Clone)]
struct CompetitorRow {
    name: String,
    version: String,
    metric: String,
    display: String,
    status: String,
    has_status: bool,
    is_disrobe: bool,
    leg: Option<String>,
    role: Option<String>,
    clean: Option<u64>,
    emitted: Option<u64>,
    value: Option<f64>,
}

#[derive(Debug, Clone)]
struct ResolvedPair {
    id: String,
    label: String,
    metric: String,
    competitor_label: String,
    disrobe: PairScore,
    competitor: PairScore,
}

#[derive(Debug, Clone)]
struct PairScore {
    name: String,
    version: String,
    clean: u64,
    emitted: u64,
    value: f64,
}

#[derive(Debug)]
struct Failures {
    walls: Vec<FailureId>,
    hard_cases: Vec<FailureId>,
}

#[derive(Debug, Deserialize)]
struct FailuresDoc {
    #[serde(default)]
    wall: Vec<FailureId>,
    #[serde(default)]
    hard_case: Vec<FailureId>,
}

#[derive(Debug, Deserialize)]
struct FailureId {
    id: String,
}

pub(crate) fn run(root: &Path, mode: Mode) -> Result<()> {
    let descriptors_dir: PathBuf = root.join("evidence").join("descriptors");
    if !descriptors_dir.is_dir() {
        bail!(
            "evidence descriptors dir missing: {}",
            descriptors_dir.display()
        );
    }
    let recovery_path: PathBuf = root.join("xtask").join("data").join("recovery.json");
    let recovery: RecoveryDoc = load_recovery(&recovery_path)?;
    let failures: Failures = load_failures(&root.join("evidence").join("failures.toml"))?;

    let descriptors: Vec<Descriptor> = discover(&descriptors_dir)?;
    let mut resolved: Vec<Resolved> = Vec::with_capacity(descriptors.len());
    for descriptor in &descriptors {
        validate(descriptor)?;
        resolved.push(resolve(descriptor, &recovery, root)?);
    }
    resolved.sort_by(|a: &Resolved, b: &Resolved| a.id.cmp(&b.id));

    if matches!(mode, Mode::List) {
        print_list(&resolved);
        return Ok(());
    }

    enforce_floors(&resolved)?;

    let results_dir: PathBuf = root.join("evidence").join("results");
    let mut per_descriptor: BTreeMap<String, String> = BTreeMap::new();
    for r in &resolved {
        per_descriptor.insert(format!("{}.json", r.id), render_descriptor_json(r)?);
    }
    let per_descriptor_md: BTreeMap<String, String> = resolved
        .iter()
        .map(|r: &Resolved| (format!("{}.md", r.id), render_descriptor_md(r)))
        .collect();
    let index_json: String = render_index(&resolved, &failures)?;
    let report_md: String = render_report(&resolved);

    let check: bool = matches!(mode, Mode::Check);
    let mut stale: Vec<String> = Vec::new();
    for (name, content) in &per_descriptor {
        sync_file(&results_dir.join(name), content, check, &mut stale)?;
    }
    for (name, content) in &per_descriptor_md {
        sync_file(&results_dir.join(name), content, check, &mut stale)?;
    }
    sync_file(
        &results_dir.join("index.json"),
        &index_json,
        check,
        &mut stale,
    )?;
    sync_file(
        &results_dir.join("EVIDENCE.md"),
        &report_md,
        check,
        &mut stale,
    )?;
    let readme_path: PathBuf = root.join("README.md");
    let readme_source: String = doc_region::read_doc(&readme_path)?;
    let expected_readme_pairs: BTreeMap<String, String> = expected_readme_pair_rows(&resolved)?;
    let rendered_readme: String = rewrite_readme_pairs(&readme_source, &expected_readme_pairs)?;
    sync_file(&readme_path, &rendered_readme, check, &mut stale)?;

    let mut produced: BTreeSet<String> = BTreeSet::new();
    produced.extend(per_descriptor.keys().cloned());
    produced.extend(per_descriptor_md.keys().cloned());
    produced.insert("index.json".to_owned());
    produced.insert("EVIDENCE.md".to_owned());
    report_orphans(&results_dir, &produced, &mut stale)?;

    if check {
        if stale.is_empty() {
            println!(
                "xtask evidence --check: {} descriptor(s) resolved, all results byte-fresh, all floors hold",
                resolved.len()
            );
            Ok(())
        } else {
            bail!(
                "xtask evidence --check: {} artifact(s) stale; run `cargo run -p xtask -- evidence` to regenerate:\n  {}",
                stale.len(),
                stale.join("\n  ")
            )
        }
    } else {
        println!(
            "xtask evidence: rendered {} descriptor(s) into {}",
            resolved.len(),
            results_dir.display()
        );
        Ok(())
    }
}

pub(crate) fn chart_binding_digest(root: &Path) -> Result<String> {
    let descriptors: Vec<Descriptor> = discover(&root.join("evidence").join("descriptors"))?;
    let mut lines: Vec<String> = Vec::with_capacity(descriptors.len());
    for descriptor in &descriptors {
        let Some(binding): Option<&SourceBinding> = descriptor.source.as_ref() else {
            continue;
        };
        lines.push(format!(
            "{} :: {} {} {}\n",
            binding.recovery_group, binding.recovery_bar, descriptor.oracle_strength, descriptor.ci
        ));
    }
    lines.sort();
    let mut hasher: Sha256 = Sha256::new();
    for line in &lines {
        hasher.update(line.as_bytes());
    }
    Ok(format!("{:x}", hasher.finalize())
        .chars()
        .take(32)
        .collect())
}

fn discover(dir: &Path) -> Result<Vec<Descriptor>> {
    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in walkdir::WalkDir::new(dir).sort_by_file_name() {
        let dirent: walkdir::DirEntry = entry?;
        let path: &Path = dirent.path();
        if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("toml") {
            paths.push(path.to_path_buf());
        }
    }
    if paths.is_empty() {
        bail!("no descriptors found under {}", dir.display());
    }
    let mut out: Vec<Descriptor> = Vec::with_capacity(paths.len());
    for path in &paths {
        let raw: String = read_text_bounded(path, MAX_DESCRIPTOR_BYTES)
            .wrap_err_with(|| format!("reading {}", path.display()))?;
        let descriptor: Descriptor = toml::from_str(&raw)
            .wrap_err_with(|| format!("parsing descriptor {}", path.display()))?;
        let stem: Option<&str> = path.file_stem().and_then(|s| s.to_str());
        if stem != Some(descriptor.id.as_str()) {
            bail!(
                "descriptor id `{}` does not match filename `{}`",
                descriptor.id,
                path.display()
            );
        }
        out.push(descriptor);
    }
    Ok(out)
}

fn validate(descriptor: &Descriptor) -> Result<()> {
    if !KNOWN_ORACLE_KINDS.contains(&descriptor.oracle.kind.as_str()) {
        bail!(
            "descriptor `{}`: unknown oracle.kind `{}` (register this kind in evidence.rs first; known: {})",
            descriptor.id,
            descriptor.oracle.kind,
            KNOWN_ORACLE_KINDS.join(", ")
        );
    }
    if !KNOWN_STRENGTHS.contains(&descriptor.oracle_strength.as_str()) {
        bail!(
            "descriptor `{}`: unknown oracle_strength `{}` (known: {})",
            descriptor.id,
            descriptor.oracle_strength,
            KNOWN_STRENGTHS.join(", ")
        );
    }
    match descriptor.oracle.kind.as_str() {
        "recovery-import" if descriptor.source.is_none() => {
            bail!(
                "descriptor `{}`: oracle.kind `recovery-import` requires a [source] table",
                descriptor.id
            );
        }
        "bench-native-unpack" if descriptor.oracle.results_md.is_none() => {
            bail!(
                "descriptor `{}`: oracle.kind `bench-native-unpack` requires oracle.results_md",
                descriptor.id
            );
        }
        "headtohead-import" if descriptor.measured.is_none() => {
            bail!(
                "descriptor `{}`: oracle.kind `headtohead-import` requires a [measured] table",
                descriptor.id
            );
        }
        "gate-test-harvest"
            if descriptor
                .measured
                .as_ref()
                .is_none_or(|m: &MeasuredBinding| m.gate_id.is_none()) =>
        {
            bail!(
                "descriptor `{}`: oracle.kind `gate-test-harvest` requires a [measured] table with gate_id",
                descriptor.id
            );
        }
        _ => {}
    }
    Ok(())
}

struct ResolvedCore {
    measured: String,
    floor: Option<f64>,
    floor_holds: Option<bool>,
    gate_source: String,
    detail: Option<String>,
    competitors: Vec<CompetitorRow>,
    disrobe_leads: Option<bool>,
    comparison_basis: Option<String>,
    pairs: Vec<ResolvedPair>,
}

fn resolve(descriptor: &Descriptor, recovery: &RecoveryDoc, root: &Path) -> Result<Resolved> {
    let core: ResolvedCore = match descriptor.oracle.kind.as_str() {
        "recovery-import" => resolve_recovery_import(descriptor, recovery)?,
        "bench-native-unpack" => {
            let results_md: &str = descriptor
                .oracle
                .results_md
                .as_deref()
                .unwrap_or("benches/native-unpack/results.md");
            ResolvedCore {
                measured: "byte-identity table, see results_md".to_owned(),
                floor: None,
                floor_holds: None,
                gate_source: format!(
                    "{results_md} (regenerated by cargo run -p disrobe-bench-native-unpack)"
                ),
                detail: None,
                competitors: Vec::new(),
                disrobe_leads: None,
                comparison_basis: None,
                pairs: Vec::new(),
            }
        }
        "headtohead-import" => resolve_headtohead(descriptor, root)?,
        "gate-test-harvest" => resolve_gate_harvest(descriptor, root)?,
        other => bail!(
            "descriptor `{}`: unhandled oracle.kind `{other}`",
            descriptor.id
        ),
    };

    Ok(Resolved {
        id: descriptor.id.clone(),
        ecosystem: descriptor.ecosystem.clone(),
        title: descriptor.title.clone(),
        claim: descriptor.claim.clone(),
        oracle_strength: descriptor.oracle_strength.clone(),
        ci: descriptor.ci,
        oracle_kind: descriptor.oracle.kind.clone(),
        oracle_external: descriptor.oracle.external.clone(),
        reproduce: descriptor.oracle.reproduce.clone(),
        oracle_note: descriptor.oracle.note.clone(),
        measured: core.measured,
        floor: core.floor,
        floor_holds: core.floor_holds,
        gate_source: core.gate_source,
        detail: core.detail,
        competitors: core.competitors,
        disrobe_leads: core.disrobe_leads,
        comparison_basis: core.comparison_basis,
        pairs: core.pairs,
    })
}

fn resolve_recovery_import(
    descriptor: &Descriptor,
    recovery: &RecoveryDoc,
) -> Result<ResolvedCore> {
    let binding: &SourceBinding = descriptor
        .source
        .as_ref()
        .ok_or_else(|| eyre::eyre!("descriptor `{}` missing [source]", descriptor.id))?;
    let (group, bar): (&RecoveryGroup, &RecoveryBar) =
        find_bar(recovery, &binding.recovery_group, &binding.recovery_bar).ok_or_else(|| {
            eyre::eyre!(
                "descriptor `{}`: recovery.json has no group `{}` / bar `{}`",
                descriptor.id,
                binding.recovery_group,
                binding.recovery_bar
            )
        })?;
    let measured: String = format_measured(group, bar)?;
    let floor_holds: Option<bool> = match (binding.floor, bar.value) {
        (Some(floor), Some(value)) => Some(value >= floor),
        _ => None,
    };
    Ok(ResolvedCore {
        measured,
        floor: binding.floor,
        floor_holds,
        gate_source: bar.source.clone(),
        detail: bar.detail.clone(),
        competitors: Vec::new(),
        disrobe_leads: None,
        comparison_basis: None,
        pairs: Vec::new(),
    })
}

fn resolve_headtohead(descriptor: &Descriptor, root: &Path) -> Result<ResolvedCore> {
    let binding: &MeasuredBinding = descriptor.measured.as_ref().ok_or_else(|| {
        eyre::eyre!(
            "descriptor `{}`: oracle.kind `headtohead-import` requires a [measured] table",
            descriptor.id
        )
    })?;
    let doc: Value = load_measured(root, &binding.result_file)?;
    let status: &str = doc.get("status").and_then(Value::as_str).unwrap_or("ok");
    let tools: &Vec<Value> = doc.get("tools").and_then(Value::as_array).ok_or_else(|| {
        eyre::eyre!(
            "descriptor `{}`: measured {} has no `tools` array",
            descriptor.id,
            binding.result_file
        )
    })?;
    let competitors: Vec<CompetitorRow> = tools.iter().map(competitor_row).collect();
    let pairs: Vec<ResolvedPair> = if binding.pairs.is_empty() {
        Vec::new()
    } else {
        let declared_status: &str = doc.get("status").and_then(Value::as_str).ok_or_else(|| {
            eyre::eyre!(
                "head-to-head measured result {} has no explicit status",
                binding.result_file
            )
        })?;
        if declared_status != "ok" {
            bail!(
                "head-to-head measured result {} has status `{declared_status}`, but its declared pairs require `ok`",
                binding.result_file
            );
        }
        let measured_reproduce: &str =
            doc.get("reproduce")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    eyre::eyre!(
                        "head-to-head measured result {} has no `reproduce` command",
                        binding.result_file
                    )
                })?;
        if measured_reproduce != descriptor.oracle.reproduce {
            bail!(
                "head-to-head measured result {} has reproduce command `{measured_reproduce}`, expected `{}`",
                binding.result_file,
                descriptor.oracle.reproduce
            );
        }
        resolve_pairs(binding, &competitors)?
    };
    let (measured, floor_holds, disrobe_leads, comparison_basis): (
        String,
        Option<bool>,
        Option<bool>,
        Option<String>,
    ) = if pairs.is_empty() {
        let disrobe_best: Option<f64> = best_value(&competitors, true)?;
        let competitor_best: Option<f64> = best_value(&competitors, false)?;
        let disrobe_leads: Option<bool> = match (disrobe_best, competitor_best) {
            (Some(d), Some(c)) => Some(d >= c - 1e-9),
            (Some(_), None) => Some(true),
            _ => None,
        };
        let measured: String = match status {
            "ok" => disrobe_best.map_or_else(
                || "no disrobe result".to_owned(),
                |d: f64| {
                    competitor_best.map_or_else(
                        || format!("disrobe {d:.1}% (no competitor measured)"),
                        |c: f64| format!("disrobe {d:.1}% vs best competitor {c:.1}%"),
                    )
                },
            ),
            other => format!("skipped ({other})"),
        };
        let floor_holds: Option<bool> = match (binding.disrobe_floor, disrobe_best) {
            (Some(floor), Some(value)) => Some(value >= floor),
            _ => None,
        };
        (
            measured,
            floor_holds,
            disrobe_leads,
            (status == "ok").then(|| "highest reported numeric value".to_owned()),
        )
    } else {
        let floor_holds: Option<bool> = binding.disrobe_floor.map(|floor: f64| {
            pairs
                .iter()
                .all(|pair: &ResolvedPair| pair.disrobe.value >= floor)
        });
        (
            format_pair_summary(&pairs),
            floor_holds,
            Some(
                pairs
                    .iter()
                    .all(|pair: &ResolvedPair| pair.disrobe.clean >= pair.competitor.clean),
            ),
            Some("clean-method count within each declared leg".to_owned()),
        )
    };
    let note: Option<String> = doc
        .get("honest_note")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(ResolvedCore {
        measured,
        floor: binding.disrobe_floor,
        floor_holds,
        gate_source: format!(
            "evidence/results/measured/{} (regenerated by cargo run -p disrobe-bench-head-to-head)",
            binding.result_file
        ),
        detail: note,
        competitors,
        disrobe_leads,
        comparison_basis,
        pairs,
    })
}

fn resolve_pairs(binding: &MeasuredBinding, rows: &[CompetitorRow]) -> Result<Vec<ResolvedPair>> {
    let mut ids: BTreeSet<&str> = BTreeSet::new();
    let mut names: BTreeSet<&str> = BTreeSet::new();
    let mut out: Vec<ResolvedPair> = Vec::with_capacity(binding.pairs.len());
    for pair in &binding.pairs {
        if !ids.insert(&pair.id) {
            bail!("head-to-head measured pair id `{}` is duplicated", pair.id);
        }
        if !names.insert(&pair.disrobe) || !names.insert(&pair.competitor) {
            bail!(
                "head-to-head measured pair `{}` reuses a tool name across declared roles",
                pair.id
            );
        }
        let disrobe: PairScore = pair_score(
            find_unique_row(rows, &pair.disrobe)?,
            &pair.id,
            "disrobe",
            &pair.metric,
        )?;
        let competitor: PairScore = pair_score(
            find_unique_row(rows, &pair.competitor)?,
            &pair.id,
            "competitor",
            &pair.metric,
        )?;
        if disrobe.clean < competitor.clean {
            bail!(
                "head-to-head declared pair `{}` violates its clean-method claim: disrobe {} < {} {}",
                pair.id,
                disrobe.clean,
                pair.competitor_label,
                competitor.clean
            );
        }
        out.push(ResolvedPair {
            id: pair.id.clone(),
            label: pair.label.clone(),
            metric: pair.metric.clone(),
            competitor_label: pair.competitor_label.clone(),
            disrobe,
            competitor,
        });
    }
    for row in rows {
        if !names.contains(row.name.as_str()) {
            bail!(
                "head-to-head measured result has unpaired tool row `{}`",
                row.name
            );
        }
    }
    Ok(out)
}

fn find_unique_row<'a>(rows: &'a [CompetitorRow], name: &str) -> Result<&'a CompetitorRow> {
    let mut matches = rows.iter().filter(|row: &&CompetitorRow| row.name == name);
    let Some(row): Option<&CompetitorRow> = matches.next() else {
        bail!("head-to-head measured result has no row named `{name}`");
    };
    if matches.next().is_some() {
        bail!("head-to-head measured result has multiple rows named `{name}`");
    }
    Ok(row)
}

fn pair_score(row: &CompetitorRow, leg: &str, role: &str, metric: &str) -> Result<PairScore> {
    if row.status != "ok" {
        bail!(
            "head-to-head row `{}` for {leg}/{role} is not publishable: {}",
            row.name,
            row.status
        );
    }
    if !row.has_status {
        bail!("head-to-head row `{}` has no explicit status", row.name);
    }
    if row.leg.as_deref() != Some(leg) {
        bail!(
            "head-to-head row `{}` has leg {:?}, expected `{leg}`",
            row.name,
            row.leg
        );
    }
    if row.role.as_deref() != Some(role) {
        bail!(
            "head-to-head row `{}` has role {:?}, expected `{role}`",
            row.name,
            row.role
        );
    }
    if row.metric != metric {
        bail!(
            "head-to-head row `{}` has metric `{}`, expected `{metric}`",
            row.name,
            row.metric
        );
    }
    let clean: u64 = row
        .clean
        .ok_or_else(|| eyre::eyre!("head-to-head row `{}` has no raw clean count", row.name))?;
    let emitted: u64 = row
        .emitted
        .ok_or_else(|| eyre::eyre!("head-to-head row `{}` has no raw emitted count", row.name))?;
    let value: f64 = row
        .value
        .ok_or_else(|| eyre::eyre!("head-to-head row `{}` has no numeric rate", row.name))?;
    if emitted == 0 || clean > emitted {
        bail!(
            "head-to-head row `{}` has invalid raw counts {clean} / {emitted}",
            row.name
        );
    }
    let calculated: f64 = 100.0 * clean as f64 / emitted as f64;
    if !value.is_finite() || (value - calculated).abs() > 1e-9 {
        bail!(
            "head-to-head row `{}` has rate {value} inconsistent with {clean} / {emitted}",
            row.name
        );
    }
    let expected_display: String = format!("{clean} clean / {emitted} emitted ({calculated:.1}%)");
    if row.display != expected_display {
        bail!(
            "head-to-head row `{}` has display `{}`, expected `{expected_display}`",
            row.name,
            row.display
        );
    }
    Ok(PairScore {
        name: row.name.clone(),
        version: row.version.clone(),
        clean,
        emitted,
        value,
    })
}

fn format_pair_summary(pairs: &[ResolvedPair]) -> String {
    pairs
        .iter()
        .map(|pair: &ResolvedPair| {
            format!(
                "{}: `disrobe` {} / {} ({:.1}%) vs {} {} / {} ({:.1}%)",
                pair.label,
                pair.disrobe.clean,
                pair.disrobe.emitted,
                pair.disrobe.value,
                pair.competitor_label,
                pair.competitor.clean,
                pair.competitor.emitted,
                pair.competitor.value,
            )
        })
        .collect::<Vec<String>>()
        .join("; ")
}

fn expected_readme_pair_rows(resolved: &[Resolved]) -> Result<BTreeMap<String, String>> {
    let mut rows: BTreeMap<String, String> = BTreeMap::new();
    for record in resolved {
        for pair in &record.pairs {
            let slug: String = format!("{}:{}", record.id, pair.id);
            let row: String = render_readme_pair(record, pair);
            if rows.insert(slug.clone(), row).is_some() {
                bail!("README evidence pair marker `{slug}` is declared more than once");
            }
        }
    }
    Ok(rows)
}

fn render_readme_pair(record: &Resolved, pair: &ResolvedPair) -> String {
    format!(
        "{} | {} / {} methods recompile | {}: {} / {} | {} | `{}`",
        pair.label,
        pair.disrobe.clean,
        pair.disrobe.emitted,
        competitor_display(pair),
        pair.competitor.clean,
        pair.competitor.emitted,
        pair_verdict(pair),
        record.reproduce,
    )
}

fn competitor_display(pair: &ResolvedPair) -> String {
    let prefix: String = format!("{} ", pair.competitor_label);
    if pair.competitor.version.starts_with(&prefix) {
        pair.competitor.version.clone()
    } else {
        format!("{} {}", pair.competitor_label, pair.competitor.version)
    }
}

fn pair_verdict(pair: &ResolvedPair) -> String {
    let count: String = match pair.disrobe.clean.cmp(&pair.competitor.clean) {
        std::cmp::Ordering::Greater => format!(
            "`disrobe` recovers {} more clean {}",
            method_count(pair.disrobe.clean - pair.competitor.clean),
            method_noun(pair.disrobe.clean - pair.competitor.clean)
        ),
        std::cmp::Ordering::Less => format!(
            "{} recovers {} more clean {}",
            pair.competitor_label,
            method_count(pair.competitor.clean - pair.disrobe.clean),
            method_noun(pair.competitor.clean - pair.disrobe.clean)
        ),
        std::cmp::Ordering::Equal => "the tools recover the same clean-method count".to_owned(),
    };
    let rate: String = if (pair.disrobe.value - pair.competitor.value).abs() <= 1e-9 {
        "the clean rates are equal".to_owned()
    } else if pair.disrobe.value > pair.competitor.value {
        "`disrobe` has the higher clean rate".to_owned()
    } else {
        format!("{} has the higher clean rate", pair.competitor_label)
    };
    if count.starts_with("`disrobe`") && rate.starts_with("`disrobe`") {
        "`disrobe` leads on clean methods and clean rate".to_owned()
    } else if count.starts_with("`disrobe`") || rate.starts_with("`disrobe`") {
        format!("mixed: {count}; {rate}")
    } else {
        format!("{count}; {rate}")
    }
}

const fn method_noun(amount: u64) -> &'static str {
    if amount == 1 { "method" } else { "methods" }
}

fn method_count(amount: u64) -> String {
    if amount == 1 {
        "one".to_owned()
    } else {
        amount.to_string()
    }
}

fn rewrite_readme_pairs(source: &str, expected: &BTreeMap<String, String>) -> Result<String> {
    let regions: Vec<doc_region::Region> = doc_region::parse(README_PAIR_SYNTAX, source)?;
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for region in &regions {
        if !expected.contains_key(&region.slug) {
            bail!("README has unknown evidence pair marker `{}`", region.slug);
        }
        if !seen.insert(&region.slug) {
            bail!(
                "README has duplicate evidence pair marker `{}`",
                region.slug
            );
        }
    }
    for slug in expected.keys() {
        if !seen.contains(slug.as_str()) {
            bail!("README is missing evidence pair marker `{slug}`");
        }
    }
    doc_region::rewrite(README_PAIR_SYNTAX, source, &|slug: &str| {
        expected
            .get(slug)
            .cloned()
            .ok_or_else(|| eyre::eyre!("README has unknown evidence pair marker `{slug}`"))
    })
}

fn resolve_gate_harvest(descriptor: &Descriptor, root: &Path) -> Result<ResolvedCore> {
    let binding: &MeasuredBinding = descriptor.measured.as_ref().ok_or_else(|| {
        eyre::eyre!(
            "descriptor `{}`: oracle.kind `gate-test-harvest` requires a [measured] table with gate_id",
            descriptor.id
        )
    })?;
    let gate_id: &str = binding.gate_id.as_deref().ok_or_else(|| {
        eyre::eyre!(
            "descriptor `{}`: gate-test-harvest requires measured.gate_id",
            descriptor.id
        )
    })?;
    let doc: Value = load_measured(root, &binding.result_file)?;
    let gates: &Vec<Value> = doc.get("gates").and_then(Value::as_array).ok_or_else(|| {
        eyre::eyre!(
            "descriptor `{}`: measured {} has no `gates` array",
            descriptor.id,
            binding.result_file
        )
    })?;
    let gate: &Value = gates
        .iter()
        .find(|g: &&Value| g.get("id").and_then(Value::as_str) == Some(gate_id))
        .ok_or_else(|| {
            eyre::eyre!(
                "descriptor `{}`: gate id `{gate_id}` not found in {}",
                descriptor.id,
                binding.result_file
            )
        })?;
    let status: &str = gate.get("status").and_then(Value::as_str).unwrap_or("ok");
    let measured: String = match status {
        "ok" => gate
            .get("display")
            .and_then(Value::as_str)
            .unwrap_or("ok")
            .to_owned(),
        other => format!(
            "skipped ({})",
            gate.get("reason").and_then(Value::as_str).unwrap_or(other)
        ),
    };
    let value: Option<f64> = gate.get("value").and_then(Value::as_f64);
    let floor_holds: Option<bool> = match (binding.disrobe_floor, value) {
        (Some(floor), Some(v)) => Some(v >= floor),
        _ => None,
    };
    let detail: Option<String> = gate
        .get("oracle")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(ResolvedCore {
        measured,
        floor: binding.disrobe_floor,
        floor_holds,
        gate_source: format!(
            "{} (gate {gate_id}, harvested by cargo run -p disrobe-bench-head-to-head)",
            gate.get("reproduce").and_then(Value::as_str).unwrap_or("")
        ),
        detail,
        competitors: Vec::new(),
        disrobe_leads: None,
        comparison_basis: None,
        pairs: Vec::new(),
    })
}

fn competitor_row(tool: &Value) -> CompetitorRow {
    let name: String = tool
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("?")
        .to_owned();
    let status: Option<&str> = tool.get("status").and_then(Value::as_str);
    CompetitorRow {
        is_disrobe: name.starts_with("disrobe"),
        name,
        version: tool
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or("n/a")
            .to_owned(),
        metric: tool
            .get("metric")
            .and_then(Value::as_str)
            .unwrap_or("?")
            .to_owned(),
        display: tool
            .get("display")
            .and_then(Value::as_str)
            .unwrap_or("?")
            .to_owned(),
        status: status.unwrap_or("ok").to_owned(),
        has_status: status.is_some(),
        leg: tool.get("leg").and_then(Value::as_str).map(str::to_owned),
        role: tool.get("role").and_then(Value::as_str).map(str::to_owned),
        clean: tool.get("clean").and_then(Value::as_u64),
        emitted: tool.get("emitted").and_then(Value::as_u64),
        value: tool.get("value").and_then(Value::as_f64),
    }
}

fn best_value(rows: &[CompetitorRow], disrobe: bool) -> Result<Option<f64>> {
    let mut best: Option<f64> = None;
    for row in rows
        .iter()
        .filter(|r: &&CompetitorRow| r.is_disrobe == disrobe && r.status == "ok")
    {
        let value: f64 = parse_pct(&row.display).ok_or_else(|| {
            eyre::eyre!(
                "ok head-to-head row for `{}` has no parseable percentage in `{}`",
                row.name,
                row.display
            )
        })?;
        best = Some(best.map_or(value, |current: f64| current.max(value)));
    }
    Ok(best)
}

fn parse_pct(display: &str) -> Option<f64> {
    let open: usize = display.rfind('(')?;
    let pct: usize = display[open..].find('%')?;
    display[open + 1..open + pct].trim().parse::<f64>().ok()
}

fn load_measured(root: &Path, file: &str) -> Result<Value> {
    let path: PathBuf = root
        .join("evidence")
        .join("results")
        .join("measured")
        .join(file);
    let raw: String = read_text_bounded(&path, MAX_EVIDENCE_TEXT_BYTES).wrap_err_with(|| {
        format!(
            "reading measured result {} (run `cargo run -p disrobe-bench-head-to-head` first)",
            path.display()
        )
    })?;
    serde_json::from_str(&raw).wrap_err_with(|| format!("parsing {}", path.display()))
}

fn find_bar<'a>(
    recovery: &'a RecoveryDoc,
    group_heading: &str,
    bar_label: &str,
) -> Option<(&'a RecoveryGroup, &'a RecoveryBar)> {
    for group in &recovery.groups {
        if group.heading != group_heading {
            continue;
        }
        for bar in &group.bars {
            if bar.label == bar_label {
                return Some((group, bar));
            }
        }
    }
    None
}

fn format_measured(group: &RecoveryGroup, bar: &RecoveryBar) -> Result<String> {
    let measured: String = match group.kind.as_str() {
        "percent" => bar
            .value
            .map_or_else(|| "n/a".to_owned(), |v: f64| format!("{v:.2}%")),
        "count" => bar.value.map_or_else(
            || "n/a".to_owned(),
            |v: f64| {
                let amount: i64 = v as i64;
                let unit: &str = if amount == 1 { "family" } else { "families" };
                format!("{amount} {unit}")
            },
        ),
        "scalar" => bar.value.map_or_else(
            || "n/a".to_owned(),
            |v: f64| format!("{} functions", v as i64),
        ),
        "count_pair" => {
            let delivered: u64 = bar.delivered.ok_or_else(|| {
                eyre::eyre!(
                    "recovery.json: `{}` / `{}` has no delivered count for a count_pair",
                    group.heading,
                    bar.label
                )
            })?;
            let detected: u64 = bar.detected.ok_or_else(|| {
                eyre::eyre!(
                    "recovery.json: `{}` / `{}` has no detected count for a count_pair",
                    group.heading,
                    bar.label
                )
            })?;
            let verb: &str = bar.delivered_label.as_deref().unwrap_or("delivered");
            let denominator: &str = bar.denominator_label.as_deref().unwrap_or("detected");
            format!("{delivered} {verb} / {detected} {denominator}")
        }
        other => format!("({other})"),
    };
    Ok(measured)
}

fn enforce_floors(resolved: &[Resolved]) -> Result<()> {
    let mut violations: Vec<String> = Vec::new();
    for r in resolved {
        if r.floor_holds == Some(false) {
            violations.push(format!(
                "{}: measured {} is below floor {}",
                r.id,
                r.measured,
                r.floor
                    .map_or_else(|| "?".to_owned(), |f: f64| format!("{f:.2}"))
            ));
        }
    }
    if violations.is_empty() {
        Ok(())
    } else {
        bail!(
            "xtask evidence: {} floor violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        )
    }
}

fn print_list(resolved: &[Resolved]) {
    println!(
        "xtask evidence --list: {} descriptor(s) discovered\n",
        resolved.len()
    );
    for r in resolved {
        let floor: String = match (r.floor, r.floor_holds) {
            (Some(f), Some(true)) => format!("floor {f:.1} (holds)"),
            (Some(f), Some(false)) => format!("floor {f:.1} (VIOLATED)"),
            (Some(f), None) => format!("floor {f:.1}"),
            (None, _) => "no floor".to_owned(),
        };
        println!(
            "  {id:<28} {eco:<10} {strength:<22} {ci:<10} {measured} | {floor}",
            id = r.id,
            eco = r.ecosystem,
            strength = r.oracle_strength,
            ci = if r.ci { "[CI]" } else { "[local]" },
            measured = r.measured,
        );
    }
}

fn render_descriptor_json(r: &Resolved) -> Result<String> {
    let value: Value = json!({
        "id": r.id,
        "ecosystem": r.ecosystem,
        "title": r.title,
        "claim": r.claim,
        "measured": r.measured,
        "oracle_strength": r.oracle_strength,
        "ci_attested": r.ci,
        "oracle": {
            "kind": r.oracle_kind,
            "external": r.oracle_external,
            "note": r.oracle_note,
        },
        "reproduce": r.reproduce,
        "floor": r.floor,
        "floor_holds": r.floor_holds,
        "gate_source": r.gate_source,
        "detail": r.detail,
        "disrobe_leads": r.disrobe_leads,
        "comparison_basis": r.comparison_basis,
        "pairs": pairs_json(&r.pairs),
        "competitors": competitors_json(&r.competitors),
    });
    to_pretty(&value)
}

fn pairs_json(pairs: &[ResolvedPair]) -> Vec<Value> {
    pairs
        .iter()
        .map(|pair: &ResolvedPair| {
            json!({
                "id": pair.id,
                "label": pair.label,
                "comparison_basis": "clean-method count",
                "metric": pair.metric,
                "disrobe": {
                    "name": pair.disrobe.name,
                    "version": pair.disrobe.version,
                    "clean": pair.disrobe.clean,
                    "emitted": pair.disrobe.emitted,
                    "value": pair.disrobe.value,
                },
                "competitor": {
                    "name": pair.competitor.name,
                    "label": pair.competitor_label,
                    "version": pair.competitor.version,
                    "clean": pair.competitor.clean,
                    "emitted": pair.competitor.emitted,
                    "value": pair.competitor.value,
                },
            })
        })
        .collect()
}

fn competitors_json(rows: &[CompetitorRow]) -> Vec<Value> {
    rows.iter()
        .map(|c: &CompetitorRow| {
            json!({
                "name": c.name,
                "version": c.version,
                "metric": c.metric,
                "result": c.display,
                "status": c.status,
                "is_disrobe": c.is_disrobe,
                "leg": c.leg,
                "role": c.role,
                "clean": c.clean,
                "emitted": c.emitted,
                "value": c.value,
            })
        })
        .collect()
}

fn render_index(resolved: &[Resolved], failures: &Failures) -> Result<String> {
    let descriptors: Vec<Value> = resolved
        .iter()
        .map(|r: &Resolved| {
            json!({
                "id": r.id,
                "ecosystem": r.ecosystem,
                "claim": r.claim,
                "measured": r.measured,
                "oracle_strength": r.oracle_strength,
                "ci_attested": r.ci,
                "external_oracle": r.oracle_external,
                "reproduce": r.reproduce,
                "floor": r.floor,
                "floor_holds": r.floor_holds,
                "disrobe_leads": r.disrobe_leads,
                "comparison_basis": r.comparison_basis,
                "pairs": pairs_json(&r.pairs),
                "competitors": competitors_json(&r.competitors),
            })
        })
        .collect();
    let ecosystems: Vec<String> = {
        let mut set: Vec<String> = resolved
            .iter()
            .map(|r: &Resolved| r.ecosystem.clone())
            .collect();
        set.sort();
        set.dedup();
        set
    };
    let head_to_head: usize = resolved
        .iter()
        .filter(|r: &&Resolved| !r.competitors.is_empty())
        .count();
    let disrobe_losses: usize = resolved
        .iter()
        .filter(|r: &&Resolved| r.disrobe_leads == Some(false))
        .count();
    let value: Value = json!({
        "schema": "disrobe.evidence.index/v1",
        "note": "Generated by `cargo run -p xtask -- evidence`. recovery-import values are read from xtask/data/recovery.json; headtohead-import and gate-test-harvest values are read from evidence/results/measured/*.json (written by `cargo run -p disrobe-bench-head-to-head`). The renderer derives displayed summaries from those records and validates declared paired counts, rates, and display text. `cargo xtask evidence --check` is the CI drift gate.",
        "descriptor_count": resolved.len(),
        "head_to_head_count": head_to_head,
        "disrobe_loss_count": disrobe_losses,
        "ecosystems": ecosystems,
        "failure_count": failures.walls.len() + failures.hard_cases.len(),
        "wall_count": failures.walls.len(),
        "hard_case_count": failures.hard_cases.len(),
        "descriptors": descriptors,
    });
    to_pretty(&value)
}

fn render_descriptor_md(r: &Resolved) -> String {
    let mut md: String = String::with_capacity(1024);
    push_line!(md, "# {}", r.title);
    md.push('\n');
    push_line!(md, "- id: `{}`", r.id);
    push_line!(md, "- ecosystem: {}", r.ecosystem);
    push_line!(md, "- claim: {}", r.claim);
    push_line!(md, "- measured: {}", r.measured);
    push_line!(md, "- oracle strength: {}", r.oracle_strength);
    push_line!(
        md,
        "- CI-attested: {}",
        if r.ci { "yes [CI]" } else { "no [local]" }
    );
    push_line!(md, "- evidence basis: {}", r.oracle_external);
    push_line!(md, "- reproduce: `{}`", r.reproduce);
    if let Some(floor) = r.floor {
        let holds: &str = match r.floor_holds {
            Some(true) => "holds",
            Some(false) => "VIOLATED",
            None => "not comparable",
        };
        push_line!(md, "- floor: {floor:.2} ({holds})");
    }
    push_line!(md, "- gate source: {}", r.gate_source);
    if let Some(note) = &r.oracle_note {
        push_line!(md, "- note: {note}");
    }
    if !r.competitors.is_empty() {
        md.push('\n');
        md.push_str("| tool | version | metric | result | status |\n");
        md.push_str("|---|---|---|---|---|\n");
        for c in &r.competitors {
            let marker: &str = if c.is_disrobe { "**" } else { "" };
            push_line!(
                md,
                "| {marker}{}{marker} | {} | {} | {} | {} |",
                esc(&c.name),
                esc(&c.version),
                esc(&c.metric),
                esc(&c.display),
                esc(&c.status),
            );
        }
    }
    md
}

fn render_report(resolved: &[Resolved]) -> String {
    let mut md: String = String::with_capacity(16384);
    md.push_str("# Evidence report\n\n");
    md.push_str(
        "Generated by `cargo run -p xtask -- evidence`. Every measured value below is read \
         from its source: recovery-import rows from `xtask/data/recovery.json`, \
         head-to-head and gate-harvest rows from `evidence/results/measured/*.json` (written by \
         `cargo run -p disrobe-bench-head-to-head`). The report derives summaries from those \
         records and validates declared paired counts, rates, and display text. Each row states \
         the claim, the measured number, its evidence strength, the \
         source or external oracle it relies on, and the exact command a stranger runs to \
         reproduce it. \
         `cargo run -p xtask -- evidence --check` is the CI drift gate that fails if any rendered \
         number drifts from its source or any floor is violated.\n\n",
    );
    let ci_count: usize = resolved.iter().filter(|r: &&Resolved| r.ci).count();
    let h2h_count: usize = resolved
        .iter()
        .filter(|r: &&Resolved| !r.competitors.is_empty())
        .count();
    let loss_count: usize = resolved
        .iter()
        .filter(|r: &&Resolved| r.disrobe_leads == Some(false))
        .count();
    push_line!(
        md,
        "{} evidence record(s) surfaced ({ci_count} CI-attested, {} local), {h2h_count} head-to-head comparison(s) (`disrobe` trails on {loss_count}).\n",
        resolved.len(),
        resolved.len() - ci_count,
    );

    md.push_str("## Benchmarks\n\n");
    md.push_str(
        "Oracle strength: `strong` = external-equivalence, execution, or byte-identity; \
         `recompile-only` = the recovered source compiles but byte-equivalence is not asserted; \
         `coverage-self-reported` = a coverage count graded against nothing external.\n\n",
    );
    md.push_str("| ecosystem | claim | measured | strength | CI | evidence basis | reproduce |\n");
    md.push_str("|---|---|---|---|---|---|---|\n");
    for r in resolved {
        push_line!(
            md,
            "| {} | {} | {} | {} | {} | {} | `{}` |",
            esc(&r.ecosystem),
            esc(&r.claim),
            esc(&r.measured),
            esc(&r.oracle_strength),
            if r.ci { "[CI]" } else { "[local]" },
            esc(&r.oracle_external),
            esc(&r.reproduce),
        );
    }
    md.push('\n');

    render_head_to_head(&mut md, resolved);

    md.push_str("## Floors\n\n");
    md.push_str(
        "Floors sit a declared margin below the measured value so a regression masked by an \
         offsetting improvement is still caught; the harness records both.\n\n",
    );
    md.push_str("| id | measured | floor | holds |\n");
    md.push_str("|---|---|---|---|\n");
    for r in resolved {
        let floor: String = r
            .floor
            .map_or_else(|| "n/a".to_owned(), |f: f64| format!("{f:.2}"));
        let holds: &str = match r.floor_holds {
            Some(true) => "yes",
            Some(false) => "NO",
            None => "n/a",
        };
        push_line!(
            md,
            "| {} | {} | {} | {} |",
            esc(&r.id),
            esc(&r.measured),
            floor,
            holds
        );
    }
    md.push('\n');

    finish_markdown(md)
}

fn finish_markdown(mut md: String) -> String {
    while md.ends_with("\n\n") {
        md.pop();
    }
    if !md.ends_with('\n') {
        md.push('\n');
    }
    md
}

fn render_head_to_head(mut md: &mut String, resolved: &[Resolved]) {
    let h2h: Vec<&Resolved> = resolved
        .iter()
        .filter(|r: &&Resolved| !r.competitors.is_empty())
        .collect();
    if h2h.is_empty() {
        return;
    }
    md.push_str("## Head-to-head comparisons\n\n");
    md.push_str(
        "Within each declared leg, `disrobe` and the competing tool receive byte-identical input and \
         the same external oracle. The `disrobe` row is bold. Losses are rendered in the same table \
         as wins, never filtered. A declared comparison with a skipped or errored tool fails closed, \
         never dropping the tool from its claim.\n\n",
    );
    for r in &h2h {
        push_line!(md, "### {}\n", r.title);
        push_line!(md, "{}\n", r.claim);
        let lead: &str = match (r.disrobe_leads, r.pairs.is_empty()) {
            (Some(true), false) => {
                "`disrobe` meets the declared clean-count comparison on every required leg."
            }
            (Some(true), true) => "`disrobe` leads or ties on this dataset.",
            (Some(false), _) => "`disrobe` trails a competitor on this dataset (published as-is).",
            (None, _) => "comparison incomplete on this run (see tool statuses).",
        };
        push_line!(
            md,
            "{lead} CI-attested: {}\n",
            if r.ci { "[CI]" } else { "[local]" }
        );
        md.push_str("| tool | version | metric | result | status |\n");
        md.push_str("|---|---|---|---|---|\n");
        for c in &r.competitors {
            let marker: &str = if c.is_disrobe { "**" } else { "" };
            push_line!(
                md,
                "| {marker}{}{marker} | {} | {} | {} | {} |",
                esc(&c.name),
                esc(&c.version),
                esc(&c.metric),
                esc(&c.display),
                esc(&c.status),
            );
        }
        md.push('\n');
        push_line!(md, "Reproduce: `{}`\n", r.reproduce);
    }
}

fn load_recovery(path: &Path) -> Result<RecoveryDoc> {
    let raw: String = read_text_bounded(path, MAX_EVIDENCE_TEXT_BYTES)
        .wrap_err_with(|| format!("reading {}", path.display()))?;
    let recovery: RecoveryDoc =
        serde_json::from_str(&raw).wrap_err_with(|| format!("parsing {}", path.display()))?;
    validate_recovery(&recovery)?;
    Ok(recovery)
}

fn validate_recovery(recovery: &RecoveryDoc) -> Result<()> {
    for group in &recovery.groups {
        for bar in &group.bars {
            if group.kind == "count_pair" {
                let Some(delivered): Option<u64> = bar.delivered else {
                    bail!(
                        "recovery.json: `{}` / `{}` must carry delivered and detected counts for a count_pair",
                        group.heading,
                        bar.label
                    );
                };
                let Some(detected): Option<u64> = bar.detected else {
                    bail!(
                        "recovery.json: `{}` / `{}` must carry delivered and detected counts for a count_pair",
                        group.heading,
                        bar.label
                    );
                };
                if delivered > MAX_JAVASCRIPT_SAFE_INTEGER || detected > MAX_JAVASCRIPT_SAFE_INTEGER
                {
                    bail!(
                        "recovery.json: `{}` / `{}` exceeds the JavaScript safe-integer ceiling",
                        group.heading,
                        bar.label
                    );
                }
                if detected == 0 || delivered > detected {
                    bail!(
                        "recovery.json: `{}` / `{}` must carry a positive detected count no smaller than delivered",
                        group.heading,
                        bar.label
                    );
                }
            }
            validate_count_pair_label(
                group,
                bar,
                "delivered_label",
                bar.delivered_label.as_deref(),
            )?;
            validate_count_pair_label(
                group,
                bar,
                "denominator_label",
                bar.denominator_label.as_deref(),
            )?;
        }
    }
    Ok(())
}

fn validate_count_pair_label(
    group: &RecoveryGroup,
    bar: &RecoveryBar,
    field: &str,
    value: Option<&str>,
) -> Result<()> {
    let Some(label): Option<&str> = value else {
        return Ok(());
    };
    if group.kind != "count_pair" {
        bail!(
            "recovery.json: `{}` / `{}` has {field} outside a count_pair group",
            group.heading,
            bar.label
        );
    }
    let unsafe_cell: bool = label
        .chars()
        .any(|character: char| character.is_control() || character == '|');
    if label.is_empty() || label.trim() != label || unsafe_cell {
        bail!(
            "recovery.json: `{}` / `{}` has an invalid {field}",
            group.heading,
            bar.label
        );
    }
    Ok(())
}

fn load_failures(path: &Path) -> Result<Failures> {
    let raw: String = read_text_bounded(path, MAX_DESCRIPTOR_BYTES)
        .wrap_err_with(|| format!("reading {}", path.display()))?;
    let doc: FailuresDoc =
        toml::from_str(&raw).wrap_err_with(|| format!("parsing {}", path.display()))?;
    if doc.wall.is_empty() && doc.hard_case.is_empty() {
        bail!("evidence/failures.toml is empty; the failure catalog must never be empty");
    }
    let mut seen: Vec<&str> = Vec::new();
    for entry in doc.wall.iter().chain(doc.hard_case.iter()) {
        if seen.contains(&entry.id.as_str()) {
            bail!(
                "evidence/failures.toml: duplicate failure id `{}`",
                entry.id
            );
        }
        seen.push(&entry.id);
    }
    Ok(Failures {
        walls: doc.wall,
        hard_cases: doc.hard_case,
    })
}

fn report_orphans(
    results_dir: &Path,
    produced: &BTreeSet<String>,
    stale: &mut Vec<String>,
) -> Result<()> {
    if !results_dir.is_dir() {
        return Ok(());
    }
    let entries: std::fs::ReadDir = std::fs::read_dir(results_dir)
        .wrap_err_with(|| format!("listing {}", results_dir.display()))?;
    for entry in entries {
        let entry: std::fs::DirEntry =
            entry.wrap_err_with(|| format!("reading an entry of {}", results_dir.display()))?;
        if entry.path().is_dir() {
            continue;
        }
        let name: String = entry.file_name().to_string_lossy().into_owned();
        if !produced.contains(&name) {
            stale.push(format!(
                "{} is not produced by any descriptor in evidence/descriptors, so it is published with numbers nothing backs; delete it or restore its descriptor",
                entry.path().display()
            ));
        }
    }
    Ok(())
}

fn sync_file(path: &Path, content: &str, check: bool, stale: &mut Vec<String>) -> Result<()> {
    if check {
        match read_text_bounded(path, MAX_EVIDENCE_TEXT_BYTES) {
            Ok(on_disk) if on_disk == content => {}
            Ok(_) => stale.push(path.display().to_string()),
            Err(_) => stale.push(format!("{} (missing)", path.display())),
        }
        Ok(())
    } else {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .wrap_err_with(|| format!("creating {}", parent.display()))?;
        }
        fs::write(path, content).wrap_err_with(|| format!("writing {}", path.display()))
    }
}

fn read_text_bounded(path: &Path, max: u64) -> Result<String> {
    let metadata: fs::Metadata =
        fs::metadata(path).wrap_err_with(|| format!("stat {}", path.display()))?;
    if metadata.len() > max {
        bail!("{} exceeds {max} byte cap", path.display());
    }
    let file: fs::File =
        fs::File::open(path).wrap_err_with(|| format!("open {}", path.display()))?;
    let mut limited: std::io::Take<fs::File> = file.take(max.saturating_add(1));
    let mut bytes: Vec<u8> = Vec::new();
    let read_len: usize = limited
        .read_to_end(&mut bytes)
        .wrap_err_with(|| format!("read {}", path.display()))?;
    let read_len_u64: u64 = u64::try_from(read_len).unwrap_or(u64::MAX);
    if read_len_u64 > max {
        bail!("{} grew past {max} byte cap while reading", path.display());
    }
    String::from_utf8(bytes).wrap_err_with(|| format!("{} is not UTF-8", path.display()))
}

fn to_pretty(value: &Value) -> Result<String> {
    let mut out: String =
        serde_json::to_string_pretty(value).wrap_err("serializing evidence JSON")?;
    out.push('\n');
    Ok(out)
}

fn esc(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(kind: &str, strength: &str, with_source: bool) -> Descriptor {
        Descriptor {
            id: "t".to_owned(),
            ecosystem: "python".to_owned(),
            title: "t".to_owned(),
            claim: "c".to_owned(),
            oracle_strength: strength.to_owned(),
            ci: true,
            oracle: Oracle {
                kind: kind.to_owned(),
                external: "e".to_owned(),
                reproduce: "r".to_owned(),
                note: None,
                results_md: None,
            },
            source: with_source.then(|| SourceBinding {
                recovery_group: "g".to_owned(),
                recovery_bar: "b".to_owned(),
                floor: None,
            }),
            measured: None,
        }
    }

    fn bar(value: Option<f64>) -> RecoveryBar {
        RecoveryBar {
            label: "b".to_owned(),
            value,
            detail: None,
            detected: None,
            delivered: None,
            delivered_label: None,
            denominator_label: None,
            source: "s".to_owned(),
        }
    }

    fn recovery_validation_error(doc: &RecoveryDoc) -> Result<String> {
        match validate_recovery(doc) {
            Ok(()) => bail!("expected recovery validation to fail"),
            Err(error) => Ok(error.to_string()),
        }
    }

    fn resolved(floor: Option<f64>, holds: Option<bool>) -> Resolved {
        Resolved {
            id: "t".to_owned(),
            ecosystem: "python".to_owned(),
            title: "t".to_owned(),
            claim: "c".to_owned(),
            oracle_strength: "strong".to_owned(),
            ci: true,
            oracle_kind: "recovery-import".to_owned(),
            oracle_external: "e".to_owned(),
            reproduce: "r".to_owned(),
            oracle_note: None,
            measured: "90.00%".to_owned(),
            floor,
            floor_holds: holds,
            gate_source: "s".to_owned(),
            detail: None,
            competitors: Vec::new(),
            disrobe_leads: None,
            comparison_basis: None,
            pairs: Vec::new(),
        }
    }

    fn pair_score(name: &str, version: &str, clean: u64, emitted: u64) -> PairScore {
        PairScore {
            name: name.to_owned(),
            version: version.to_owned(),
            clean,
            emitted,
            value: 100.0 * clean as f64 / emitted as f64,
        }
    }

    fn apk_record() -> Resolved {
        let mut record: Resolved = resolved(Some(95.0), Some(true));
        record.id = "apk-jadx-cfr".to_owned();
        record.reproduce =
            "cargo run --locked -p disrobe-bench-head-to-head -- --check --only apk-jadx-cfr"
                .to_owned();
        record.comparison_basis = Some("clean-method count within each declared leg".to_owned());
        record.pairs = vec![
            ResolvedPair {
                id: "dex".to_owned(),
                label: "Android DEX".to_owned(),
                metric: "recompile-clean main-class methods (clean / emitted)".to_owned(),
                competitor_label: "JADX".to_owned(),
                disrobe: pair_score(
                    "disrobe (in-house Dalvik, DEX input)",
                    "n/a (in-process)",
                    129,
                    132,
                ),
                competitor: pair_score("jadx (DEX input)", "1.5.5", 128, 130),
            },
            ResolvedPair {
                id: "jar".to_owned(),
                label: "JVM classfile".to_owned(),
                metric: "recompile-clean main-class methods (clean / emitted)".to_owned(),
                competitor_label: "CFR".to_owned(),
                disrobe: pair_score(
                    "disrobe (in-house JVM, JAR input)",
                    "n/a (in-process)",
                    131,
                    131,
                ),
                competitor: pair_score("cfr (JAR input)", "CFR 0.152", 105, 106),
            },
        ];
        record
    }

    fn paired_rows() -> Vec<CompetitorRow> {
        vec![
            CompetitorRow {
                name: "disrobe (in-house Dalvik, DEX input)".to_owned(),
                version: "n/a (in-process)".to_owned(),
                metric: "recompile-clean main-class methods (clean / emitted)".to_owned(),
                display: "129 clean / 132 emitted (97.7%)".to_owned(),
                status: "ok".to_owned(),
                has_status: true,
                is_disrobe: true,
                leg: Some("dex".to_owned()),
                role: Some("disrobe".to_owned()),
                clean: Some(129),
                emitted: Some(132),
                value: Some(100.0 * 129.0 / 132.0),
            },
            CompetitorRow {
                name: "jadx (DEX input)".to_owned(),
                version: "1.5.5".to_owned(),
                metric: "recompile-clean main-class methods (clean / emitted)".to_owned(),
                display: "128 clean / 130 emitted (98.5%)".to_owned(),
                status: "ok".to_owned(),
                has_status: true,
                is_disrobe: false,
                leg: Some("dex".to_owned()),
                role: Some("competitor".to_owned()),
                clean: Some(128),
                emitted: Some(130),
                value: Some(100.0 * 128.0 / 130.0),
            },
            CompetitorRow {
                name: "disrobe (in-house JVM, JAR input)".to_owned(),
                version: "n/a (in-process)".to_owned(),
                metric: "recompile-clean main-class methods (clean / emitted)".to_owned(),
                display: "131 clean / 131 emitted (100.0%)".to_owned(),
                status: "ok".to_owned(),
                has_status: true,
                is_disrobe: true,
                leg: Some("jar".to_owned()),
                role: Some("disrobe".to_owned()),
                clean: Some(131),
                emitted: Some(131),
                value: Some(100.0),
            },
            CompetitorRow {
                name: "cfr (JAR input)".to_owned(),
                version: "CFR 0.152".to_owned(),
                metric: "recompile-clean main-class methods (clean / emitted)".to_owned(),
                display: "105 clean / 106 emitted (99.1%)".to_owned(),
                status: "ok".to_owned(),
                has_status: true,
                is_disrobe: false,
                leg: Some("jar".to_owned()),
                role: Some("competitor".to_owned()),
                clean: Some(105),
                emitted: Some(106),
                value: Some(100.0 * 105.0 / 106.0),
            },
        ]
    }

    fn apk_binding() -> MeasuredBinding {
        MeasuredBinding {
            result_file: "apk-jadx-cfr.json".to_owned(),
            gate_id: None,
            disrobe_floor: Some(95.0),
            pairs: vec![
                MeasuredPair {
                    id: "dex".to_owned(),
                    label: "Android DEX".to_owned(),
                    metric: "recompile-clean main-class methods (clean / emitted)".to_owned(),
                    disrobe: "disrobe (in-house Dalvik, DEX input)".to_owned(),
                    competitor: "jadx (DEX input)".to_owned(),
                    competitor_label: "JADX".to_owned(),
                },
                MeasuredPair {
                    id: "jar".to_owned(),
                    label: "JVM classfile".to_owned(),
                    metric: "recompile-clean main-class methods (clean / emitted)".to_owned(),
                    disrobe: "disrobe (in-house JVM, JAR input)".to_owned(),
                    competitor: "cfr (JAR input)".to_owned(),
                    competitor_label: "CFR".to_owned(),
                },
            ],
        }
    }

    #[test]
    fn declared_pairs_use_raw_counts_and_require_every_leg() -> Result<()> {
        let binding: MeasuredBinding = apk_binding();
        let pairs: Vec<ResolvedPair> = resolve_pairs(&binding, &paired_rows())?;
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].id, "dex");
        assert_eq!(pairs[0].disrobe.clean, 129);
        assert!(
            pairs
                .iter()
                .all(|pair: &ResolvedPair| { pair.disrobe.clean >= pair.competitor.clean })
        );

        let mut trailing: Vec<CompetitorRow> = paired_rows();
        trailing.push(CompetitorRow {
            name: "unpaired".to_owned(),
            version: "test".to_owned(),
            metric: "recompile-clean main-class methods (clean / emitted)".to_owned(),
            display: "0 clean / 1 emitted (0.0%)".to_owned(),
            status: "ok".to_owned(),
            has_status: true,
            is_disrobe: false,
            leg: Some("dex".to_owned()),
            role: Some("competitor".to_owned()),
            clean: Some(0),
            emitted: Some(1),
            value: Some(0.0),
        });
        let error: eyre::Report = match resolve_pairs(&binding, &trailing) {
            Ok(_) => bail!("an unpaired row must fail"),
            Err(error) => error,
        };
        let error: String = error.to_string();
        assert!(error.contains("unpaired tool row"), "{error}");

        let mut trailing: Vec<CompetitorRow> = paired_rows();
        trailing[0].clean = Some(127);
        trailing[0].value = Some(100.0 * 127.0 / 132.0);
        trailing[0].display = "127 clean / 132 emitted (96.2%)".to_owned();
        let error: eyre::Report = match resolve_pairs(&binding, &trailing) {
            Ok(_) => bail!("a clean-count loss must fail"),
            Err(error) => error,
        };
        let error: String = error.to_string();
        assert!(error.contains("violates its clean-method claim"), "{error}");

        let mut missing_status: Vec<CompetitorRow> = paired_rows();
        missing_status[0].has_status = false;
        let error: eyre::Report = match resolve_pairs(&binding, &missing_status) {
            Ok(_) => bail!("a paired row without status must fail"),
            Err(error) => error,
        };
        let error: String = error.to_string();
        assert!(error.contains("has no explicit status"), "{error}");

        let mut bad_display: Vec<CompetitorRow> = paired_rows();
        bad_display[0].display = "130 clean / 132 emitted (98.5%)".to_owned();
        let error: eyre::Report = match resolve_pairs(&binding, &bad_display) {
            Ok(_) => bail!("a raw/display mismatch must fail"),
            Err(error) => error,
        };
        let error: String = error.to_string();
        assert!(error.contains("has display"), "{error}");
        Ok(())
    }

    #[test]
    fn declared_pairs_reject_a_skipped_measurement() -> Result<()> {
        let dir: tempfile::TempDir = tempfile::tempdir()?;
        let measured: PathBuf = dir.path().join("evidence").join("results").join("measured");
        fs::create_dir_all(&measured)?;
        fs::write(
            measured.join("apk-jadx-cfr.json"),
            r#"{"status":"skipped","tools":[]}"#,
        )?;
        let mut item: Descriptor = descriptor("headtohead-import", "recompile-only", false);
        item.measured = Some(apk_binding());
        let error: String = match resolve_headtohead(&item, dir.path()) {
            Ok(_) => bail!("declared pairs must not fall back from a skipped result"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("declared pairs require `ok`"), "{error}");
        fs::write(measured.join("apk-jadx-cfr.json"), r#"{"tools":[]}"#)?;
        let error: String = match resolve_headtohead(&item, dir.path()) {
            Ok(_) => bail!("declared pairs must require an explicit status"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("has no explicit status"), "{error}");
        fs::write(
            measured.join("apk-jadx-cfr.json"),
            r#"{"status":"ok","reproduce":"other","tools":[]}"#,
        )?;
        let error: String = match resolve_headtohead(&item, dir.path()) {
            Ok(_) => bail!("declared pairs must reject a mismatched reproduce command"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("has reproduce command `other`"), "{error}");
        Ok(())
    }

    #[test]
    fn readme_pair_rows_render_from_resolved_measurements() -> Result<()> {
        let record: Resolved = apk_record();
        let expected: BTreeMap<String, String> = expected_readme_pair_rows(&[record])?;
        let source: &str = concat!(
            "| <!-- evidence-pair:apk-jadx-cfr:jar -->stale<!-- /evidence-pair --> |\n",
            "| <!-- evidence-pair:apk-jadx-cfr:dex -->stale<!-- /evidence-pair --> |\n",
            "| APK secrets | 8 / 8 | apkleaks | win | command |\n",
        );
        let once: String = rewrite_readme_pairs(source, &expected)?;
        assert_eq!(
            once,
            concat!(
                "| <!-- evidence-pair:apk-jadx-cfr:jar -->JVM classfile | 131 / 131 methods recompile | CFR 0.152: 105 / 106 | `disrobe` leads on clean methods and clean rate | `cargo run --locked -p disrobe-bench-head-to-head -- --check --only apk-jadx-cfr`<!-- /evidence-pair --> |\n",
                "| <!-- evidence-pair:apk-jadx-cfr:dex -->Android DEX | 129 / 132 methods recompile | JADX 1.5.5: 128 / 130 | mixed: `disrobe` recovers one more clean method; JADX has the higher clean rate | `cargo run --locked -p disrobe-bench-head-to-head -- --check --only apk-jadx-cfr`<!-- /evidence-pair --> |\n",
                "| APK secrets | 8 / 8 | apkleaks | win | command |\n",
            )
        );
        let twice: String = rewrite_readme_pairs(&once, &expected)?;
        assert_eq!(once, twice);
        Ok(())
    }

    #[test]
    fn readme_pair_markers_require_the_exact_declared_set() -> Result<()> {
        let expected: BTreeMap<String, String> = expected_readme_pair_rows(&[apk_record()])?;
        let cases: [(&str, &str); 3] = [
            (
                "| <!-- evidence-pair:apk-jadx-cfr:dex -->stale<!-- /evidence-pair --> |\n",
                "missing evidence pair marker `apk-jadx-cfr:jar`",
            ),
            (
                "| <!-- evidence-pair:apk-jadx-cfr:dex -->stale<!-- /evidence-pair --> |\n| <!-- evidence-pair:apk-jadx-cfr:dex -->stale<!-- /evidence-pair --> |\n| <!-- evidence-pair:apk-jadx-cfr:jar -->stale<!-- /evidence-pair --> |\n",
                "duplicate evidence pair marker `apk-jadx-cfr:dex`",
            ),
            (
                "| <!-- evidence-pair:apk-jadx-cfr:dex -->stale<!-- /evidence-pair --> |\n| <!-- evidence-pair:apk-jadx-cfr:other -->stale<!-- /evidence-pair --> |\n| <!-- evidence-pair:apk-jadx-cfr:jar -->stale<!-- /evidence-pair --> |\n",
                "unknown evidence pair marker `apk-jadx-cfr:other`",
            ),
        ];
        for (source, needle) in cases {
            let error: eyre::Report = match rewrite_readme_pairs(source, &expected) {
                Ok(_) => bail!("invalid README marker set must fail"),
                Err(error) => error,
            };
            let error: String = error.to_string();
            assert!(error.contains(needle), "{error}");
        }
        Ok(())
    }

    #[test]
    fn readme_pair_numeric_mutation_is_stale() -> Result<()> {
        let expected: BTreeMap<String, String> = expected_readme_pair_rows(&[apk_record()])?;
        let source: &str = concat!(
            "| <!-- evidence-pair:apk-jadx-cfr:jar -->JVM classfile | 131 / 131 methods recompile | CFR 0.152: 105 / 106 | `disrobe` leads on clean methods and clean rate | `cargo run --locked -p disrobe-bench-head-to-head -- --check --only apk-jadx-cfr`<!-- /evidence-pair --> |\n",
            "| <!-- evidence-pair:apk-jadx-cfr:dex -->Android DEX | 130 / 132 methods recompile | JADX 1.5.5: 128 / 130 | mixed: `disrobe` recovers two more clean methods; JADX has the higher clean rate | `cargo run --locked -p disrobe-bench-head-to-head -- --check --only apk-jadx-cfr`<!-- /evidence-pair --> |\n",
        );
        let rendered: String = rewrite_readme_pairs(source, &expected)?;
        let dir: tempfile::TempDir = tempfile::tempdir()?;
        let path: PathBuf = dir.path().join("README.md");
        fs::write(&path, source)?;
        let mut stale: Vec<String> = Vec::new();
        sync_file(&path, &rendered, true, &mut stale)?;
        assert_eq!(stale, vec![path.display().to_string()]);
        Ok(())
    }

    #[test]
    fn paired_serialization_declares_its_clean_count_basis() -> Result<()> {
        let rendered: String = render_descriptor_json(&apk_record())?;
        let value: Value = serde_json::from_str(&rendered)?;
        assert_eq!(
            value["comparison_basis"],
            "clean-method count within each declared leg"
        );
        let pairs: &Vec<Value> = value["pairs"]
            .as_array()
            .ok_or_else(|| eyre::eyre!("paired serialization has no pairs array"))?;
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0]["id"], "dex");
        assert_eq!(pairs[0]["disrobe"]["clean"], 129);
        assert_eq!(pairs[0]["competitor"]["name"], "jadx (DEX input)");
        assert_eq!(pairs[1]["id"], "jar");
        assert_eq!(pairs[1]["competitor"]["emitted"], 106);
        Ok(())
    }

    fn validate_error(descriptor: Descriptor) -> core::result::Result<String, String> {
        match validate(&descriptor) {
            Ok(()) => Err("expected descriptor validation to fail".to_owned()),
            Err(err) => Ok(err.to_string()),
        }
    }

    #[test]
    fn validate_rejects_unknown_oracle_kind() -> core::result::Result<(), String> {
        let err: String = validate_error(descriptor("made-up-kind", "strong", true))?;
        assert!(err.contains("unknown oracle.kind"), "{err}");
        Ok(())
    }

    #[test]
    fn validate_rejects_unknown_strength() -> core::result::Result<(), String> {
        let err: String = validate_error(descriptor("recovery-import", "kinda-strong", true))?;
        assert!(err.contains("unknown oracle_strength"), "{err}");
        Ok(())
    }

    #[test]
    fn validate_requires_source_for_recovery_import() -> core::result::Result<(), String> {
        let err: String = validate_error(descriptor("recovery-import", "strong", false))?;
        assert!(err.contains("requires a [source]"), "{err}");
        Ok(())
    }

    #[test]
    fn validate_requires_measured_for_headtohead() -> core::result::Result<(), String> {
        let err: String = validate_error(descriptor("headtohead-import", "recompile-only", false))?;
        assert!(err.contains("requires a [measured]"), "{err}");
        Ok(())
    }

    #[test]
    fn validate_requires_gate_id_for_gate_harvest() -> core::result::Result<(), String> {
        let err: String = validate_error(descriptor("gate-test-harvest", "strong", false))?;
        assert!(err.contains("gate_id"), "{err}");
        Ok(())
    }

    #[test]
    fn parse_pct_reads_the_trailing_percentage() {
        assert_eq!(parse_pct("131 clean / 131 emitted (100.0%)"), Some(100.0));
        assert_eq!(parse_pct("5/8 (62.5%)"), Some(62.5));
        assert_eq!(parse_pct("128/130 (98.5%)"), Some(98.5));
        assert_eq!(parse_pct("skipped"), None);
    }

    #[test]
    fn headtohead_ok_disrobe_row_with_bad_display_fails_floor_gate()
    -> core::result::Result<(), String> {
        let dir: tempfile::TempDir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let measured_dir: PathBuf = dir.path().join("evidence").join("results").join("measured");
        fs::create_dir_all(&measured_dir).map_err(|e| e.to_string())?;
        let path: PathBuf = measured_dir.join("bad.json");
        let doc: Value = json!({
            "status": "ok",
            "tools": [
                {
                    "name": "disrobe",
                    "version": "test",
                    "metric": "recompile",
                    "display": "bad display",
                    "status": "ok"
                }
            ]
        });
        fs::write(&path, doc.to_string()).map_err(|e| e.to_string())?;

        let mut item: Descriptor = descriptor("headtohead-import", "recompile-only", false);
        item.measured = Some(MeasuredBinding {
            result_file: "bad.json".to_owned(),
            gate_id: None,
            disrobe_floor: Some(90.0),
            pairs: Vec::new(),
        });
        let err: String = match resolve_headtohead(&item, dir.path()) {
            Ok(_) => return Err("malformed ok row must fail".to_owned()),
            Err(err) => err.to_string(),
        };
        assert!(
            err.contains("no parseable percentage"),
            "unexpected error: {err}"
        );
        Ok(())
    }

    #[test]
    fn validate_accepts_a_well_formed_descriptor() {
        assert!(validate(&descriptor("recovery-import", "strong", true)).is_ok());
    }

    #[test]
    fn enforce_floors_catches_a_violation_and_passes_a_holder() {
        assert!(enforce_floors(&[resolved(Some(90.0), Some(false))]).is_err());
        assert!(enforce_floors(&[resolved(Some(90.0), Some(true))]).is_ok());
        assert!(enforce_floors(&[resolved(None, None)]).is_ok());
    }

    #[test]
    fn format_measured_renders_each_recovery_kind() -> Result<()> {
        let percent: RecoveryGroup = RecoveryGroup {
            heading: "h".to_owned(),
            kind: "percent".to_owned(),
            bars: Vec::new(),
        };
        assert_eq!(format_measured(&percent, &bar(Some(94.18)))?, "94.18%");

        let count: RecoveryGroup = RecoveryGroup {
            heading: "h".to_owned(),
            kind: "count".to_owned(),
            bars: Vec::new(),
        };
        assert_eq!(format_measured(&count, &bar(Some(1.0)))?, "1 family");
        assert_eq!(format_measured(&count, &bar(Some(2.0)))?, "2 families");

        let pair: RecoveryGroup = RecoveryGroup {
            heading: "h".to_owned(),
            kind: "count_pair".to_owned(),
            bars: Vec::new(),
        };
        let mut pair_bar: RecoveryBar = bar(None);
        pair_bar.detected = Some(98);
        pair_bar.delivered = Some(98);
        pair_bar.delivered_label = Some("extracted".to_owned());
        assert_eq!(
            format_measured(&pair, &pair_bar)?,
            "98 extracted / 98 detected"
        );

        pair_bar.denominator_label = Some("manifest-named trial wrappers".to_owned());
        assert_eq!(
            format_measured(&pair, &pair_bar)?,
            "98 extracted / 98 manifest-named trial wrappers"
        );
        Ok(())
    }

    #[test]
    fn recovery_rejects_blank_count_pair_denominator_label() -> Result<()> {
        let mut pair_bar: RecoveryBar = bar(None);
        pair_bar.detected = Some(1);
        pair_bar.delivered = Some(1);
        pair_bar.denominator_label = Some("   ".to_owned());
        let doc: RecoveryDoc = RecoveryDoc {
            groups: vec![RecoveryGroup {
                heading: "h".to_owned(),
                kind: "count_pair".to_owned(),
                bars: vec![pair_bar],
            }],
        };
        let error: String = recovery_validation_error(&doc)?;
        assert!(error.contains("denominator_label"), "{error}");
        Ok(())
    }

    #[test]
    fn recovery_rejects_denominator_label_outside_count_pair() -> Result<()> {
        let mut percent_bar: RecoveryBar = bar(Some(1.0));
        percent_bar.denominator_label = Some("trial wrappers".to_owned());
        let doc: RecoveryDoc = RecoveryDoc {
            groups: vec![RecoveryGroup {
                heading: "h".to_owned(),
                kind: "percent".to_owned(),
                bars: vec![percent_bar],
            }],
        };
        let error: String = recovery_validation_error(&doc)?;
        assert!(error.contains("count_pair"), "{error}");
        Ok(())
    }

    #[test]
    fn recovery_rejects_unsafe_denominator_label() -> Result<()> {
        for label in ["named\nwrappers", "named\twrappers", "named|wrappers"] {
            let mut pair_bar: RecoveryBar = bar(None);
            pair_bar.detected = Some(1);
            pair_bar.delivered = Some(1);
            pair_bar.denominator_label = Some(label.to_owned());
            let doc: RecoveryDoc = RecoveryDoc {
                groups: vec![RecoveryGroup {
                    heading: "h".to_owned(),
                    kind: "count_pair".to_owned(),
                    bars: vec![pair_bar],
                }],
            };
            let error: String = recovery_validation_error(&doc)?;
            assert!(error.contains("denominator_label"), "{error}");
        }
        Ok(())
    }

    #[test]
    fn recovery_rejects_unsafe_delivered_label() -> Result<()> {
        let mut pair_bar: RecoveryBar = bar(None);
        pair_bar.detected = Some(1);
        pair_bar.delivered = Some(1);
        pair_bar.delivered_label = Some("decoded\tobjects".to_owned());
        let doc: RecoveryDoc = RecoveryDoc {
            groups: vec![RecoveryGroup {
                heading: "h".to_owned(),
                kind: "count_pair".to_owned(),
                bars: vec![pair_bar],
            }],
        };
        let error: String = recovery_validation_error(&doc)?;
        assert!(error.contains("delivered_label"), "{error}");
        Ok(())
    }

    #[test]
    fn recovery_rejects_count_pair_without_both_counts() -> Result<()> {
        let mut missing_delivered: RecoveryBar = bar(None);
        missing_delivered.detected = Some(1);
        let missing_delivered_doc: RecoveryDoc = RecoveryDoc {
            groups: vec![RecoveryGroup {
                heading: "h".to_owned(),
                kind: "count_pair".to_owned(),
                bars: vec![missing_delivered],
            }],
        };
        let missing_delivered_error: String = recovery_validation_error(&missing_delivered_doc)?;
        assert!(
            missing_delivered_error.contains("delivered and detected counts"),
            "{missing_delivered_error}"
        );

        let mut missing_detected: RecoveryBar = bar(None);
        missing_detected.delivered = Some(1);
        let missing_detected_doc: RecoveryDoc = RecoveryDoc {
            groups: vec![RecoveryGroup {
                heading: "h".to_owned(),
                kind: "count_pair".to_owned(),
                bars: vec![missing_detected],
            }],
        };
        let missing_detected_error: String = recovery_validation_error(&missing_detected_doc)?;
        assert!(
            missing_detected_error.contains("delivered and detected counts"),
            "{missing_detected_error}"
        );
        Ok(())
    }

    #[test]
    fn recovery_rejects_invalid_count_pair_values() -> Result<()> {
        for (delivered, detected, expected) in [
            (Some(0), Some(0), "positive detected count"),
            (Some(2), Some(1), "no smaller than delivered"),
            (
                Some(1),
                Some(MAX_JAVASCRIPT_SAFE_INTEGER + 1),
                "safe-integer ceiling",
            ),
        ] {
            let mut pair_bar: RecoveryBar = bar(None);
            pair_bar.delivered = delivered;
            pair_bar.detected = detected;
            let doc: RecoveryDoc = RecoveryDoc {
                groups: vec![RecoveryGroup {
                    heading: "h".to_owned(),
                    kind: "count_pair".to_owned(),
                    bars: vec![pair_bar],
                }],
            };
            let error: String = recovery_validation_error(&doc)?;
            assert!(error.contains(expected), "{error}");
        }
        Ok(())
    }

    #[test]
    fn find_bar_matches_group_and_label_exactly() {
        let doc: RecoveryDoc = RecoveryDoc {
            groups: vec![RecoveryGroup {
                heading: "Group A".to_owned(),
                kind: "percent".to_owned(),
                bars: vec![bar(Some(50.0))],
            }],
        };
        assert!(find_bar(&doc, "Group A", "b").is_some());
        assert!(find_bar(&doc, "Group A", "missing").is_none());
        assert!(find_bar(&doc, "Missing", "b").is_none());
    }

    #[test]
    fn esc_escapes_pipes_and_newlines() {
        assert_eq!(esc("a|b\nc"), "a\\|b c");
    }

    #[test]
    fn read_text_bounded_rejects_oversized_input() -> core::result::Result<(), String> {
        let dir: tempfile::TempDir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let path: PathBuf = dir.path().join("oversized.txt");
        fs::write(&path, "abcdef").map_err(|e| e.to_string())?;
        let result: Result<String> = read_text_bounded(&path, 5);
        assert!(result.is_err(), "six bytes must exceed a five-byte cap");
        Ok(())
    }
}
