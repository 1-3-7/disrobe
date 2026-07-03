use std::collections::BTreeMap;
use std::fmt::Arguments;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};
use serde::Deserialize;
use serde_json::{Value, json};

const KNOWN_ORACLE_KINDS: &[&str] = &[
    "recovery-import",
    "bench-native-unpack",
    "headtohead-import",
    "gate-test-harvest",
];
const KNOWN_STRENGTHS: &[&str] = &["strong", "recompile-only", "coverage-self-reported"];
const MAX_DESCRIPTOR_BYTES: u64 = 1 << 20;
const MAX_EVIDENCE_TEXT_BYTES: u64 = 16 * 1024 * 1024;

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
}

#[derive(Debug, Clone)]
struct CompetitorRow {
    name: String,
    version: String,
    metric: String,
    display: String,
    status: String,
    is_disrobe: bool,
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

    if check {
        if stale.is_empty() {
            println!(
                "xtask evidence --check: {} descriptor(s) resolved, all results byte-fresh, all floors hold",
                resolved.len()
            );
            Ok(())
        } else {
            bail!(
                "xtask evidence --check: {} result file(s) stale; run `cargo run -p xtask -- evidence` to regenerate:\n  {}",
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
    let measured: String = format_measured(group, bar);
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
    })
}

fn competitor_row(tool: &Value) -> CompetitorRow {
    let name: String = tool
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("?")
        .to_owned();
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
        status: tool
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("ok")
            .to_owned(),
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

fn format_measured(group: &RecoveryGroup, bar: &RecoveryBar) -> String {
    match group.kind.as_str() {
        "percent" => bar
            .value
            .map_or_else(|| "n/a".to_owned(), |v: f64| format!("{v:.2}%")),
        "count" => bar.value.map_or_else(
            || "n/a".to_owned(),
            |v: f64| format!("{} families", v as i64),
        ),
        "scalar" => bar.value.map_or_else(
            || "n/a".to_owned(),
            |v: f64| format!("{} functions", v as i64),
        ),
        "count_pair" => {
            let verb: &str = bar.delivered_label.as_deref().unwrap_or("delivered");
            format!(
                "{} {verb} / {} detected",
                bar.delivered.unwrap_or(0),
                bar.detected.unwrap_or(0)
            )
        }
        other => format!("({other})"),
    }
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
        "competitors": competitors_json(&r.competitors),
    });
    to_pretty(&value)
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
        "note": "Generated by `cargo run -p xtask -- evidence`. recovery-import values are read VERBATIM from xtask/data/recovery.json; headtohead-import and gate-test-harvest values are read VERBATIM from evidence/results/measured/*.json (written by `cargo run -p disrobe-bench-head-to-head`). This harness never recomputes or rounds a number. `cargo xtask evidence --check` is the CI drift gate.",
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
    push_line!(md, "- external oracle: {}", r.oracle_external);
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
         `cargo run -p disrobe-bench-head-to-head`). This report does not recompute or round any \
         number. Each row states the claim, the measured number, the external oracle that can \
         reject a wrong answer, and the exact command a stranger runs to reproduce it. \
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
        "{} oracle(s) surfaced ({ci_count} CI-attested, {} local), {h2h_count} head-to-head comparison(s) (`disrobe` trails on {loss_count}).\n",
        resolved.len(),
        resolved.len() - ci_count,
    );

    md.push_str("## Benchmarks\n\n");
    md.push_str(
        "Oracle strength: `strong` = external-equivalence, execution, or byte-identity; \
         `recompile-only` = the recovered source compiles but byte-equivalence is not asserted; \
         `coverage-self-reported` = a coverage count graded against nothing external.\n\n",
    );
    md.push_str("| ecosystem | claim | measured | strength | CI | external oracle | reproduce |\n");
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
        "`disrobe` and the leading competing tool both receive the byte-identical input and are \
         graded by the same external oracle. The `disrobe` row is bold. Losses are rendered in the \
         same table as wins, never filtered. A skipped or errored tool counts its samples as misses, \
         never a dropped sample.\n\n",
    );
    for r in &h2h {
        push_line!(md, "### {}\n", r.title);
        push_line!(md, "{}\n", r.claim);
        let lead: &str = match r.disrobe_leads {
            Some(true) => "`disrobe` leads or ties on this dataset.",
            Some(false) => "`disrobe` trails a competitor on this dataset (published as-is).",
            None => "comparison incomplete on this run (see tool statuses).",
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
    serde_json::from_str(&raw).wrap_err_with(|| format!("parsing {}", path.display()))
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
            source: "s".to_owned(),
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
        }
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
    fn format_measured_renders_each_recovery_kind() {
        let percent: RecoveryGroup = RecoveryGroup {
            heading: "h".to_owned(),
            kind: "percent".to_owned(),
            bars: Vec::new(),
        };
        assert_eq!(format_measured(&percent, &bar(Some(94.18))), "94.18%");

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
            format_measured(&pair, &pair_bar),
            "98 extracted / 98 detected"
        );
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
