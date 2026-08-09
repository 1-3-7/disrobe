use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::capability_reachability::strip_cfg_test;
use crate::doc_region::{self, Mode, RegionSyntax};
use crate::fileio::read_text_bounded;

const MAX_SOURCE_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_DECLARATION_BYTES: u64 = 256 * 1024;
const INVENTORY_RELATIVE: &str = "xtask/data/fuzz_surface.json";
const DECLARATION_RELATIVE: &str = "fuzz/coverage.toml";
const SEED_REACH_CONTRACT_RELATIVE: &str = "fuzz/seed_reach.toml";
const SEED_REACH_REPORT_RELATIVE: &str = "xtask/data/fuzz_seed_reach.json";
const SEED_REACH_GENERATOR: &str = "cargo run --manifest-path fuzz/Cargo.toml --bin seed_replay";
const SYNTAX: RegionSyntax = RegionSyntax {
    open_prefix: "<!-- parse-surface:",
    close: "<!-- /parse-surface -->",
};

const SLUG_ENTRY_POINTS: &str = "entry-points";
const SLUG_PARSE_SHAPED: &str = "parse-shaped";
const SLUG_WITH_TARGET: &str = "with-target";
const SLUG_REPLAY_PROVEN: &str = "replay-proven";
const SLUG_REACH_RECORDED: &str = "reach-recorded";
const SLUG_SEED_OBLIGATIONS_SATISFIED: &str = "seed-obligations-satisfied";
const SLUG_SEED_OBLIGATIONS_DECLARED: &str = "seed-obligations-declared";
const SLUG_SEED_POSITIVE_WITNESSES: &str = "seed-positive-witnesses";
const SLUG_SEED_REJECTION_WITNESSES: &str = "seed-rejection-witnesses";
const MAX_SIGNATURE_LINES: usize = 24;

const PARSE_SHAPED_PREFIXES: &[&str] = &[
    "carve",
    "decode",
    "detect",
    "disassemble",
    "extract",
    "load",
    "open",
    "parse",
    "read",
    "unpack",
    "validate",
    "walk",
];

const REACH_RECORDER_MARKERS: &[&str] = &["SeedReach", "ReachTally"];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct EntryPoint {
    package: String,
    function: String,
    module_path: String,
}

impl EntryPoint {
    fn qualified(&self) -> String {
        format!("{}::{}", self.module_path, self.function)
    }

    fn parse_shaped(&self) -> bool {
        PARSE_SHAPED_PREFIXES
            .iter()
            .any(|prefix: &&str| self.function.starts_with(prefix))
    }
}

#[derive(Debug, Default)]
struct CrateRow {
    entry_points: usize,
    parse_shaped: usize,
    declared_fuzzed: usize,
    replay_proven: usize,
    in_resilience_suite: usize,
    in_reach_recording_suite: usize,
    unreached: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SeedReachReport {
    schema: u32,
    generator: String,
    contract_sha256: String,
    obligations: SeedReachTotals,
    targets: Vec<SeedReachTarget>,
}

#[derive(Debug, Default, Clone, Copy, Deserialize)]
struct SeedReachTotals {
    #[serde(rename = "satisfied")]
    satisfied_obligations: usize,
    #[serde(rename = "declared")]
    declared_obligations: usize,
    positive_witnesses: usize,
    expected_rejection_witnesses: usize,
}

#[derive(Debug)]
struct SemanticWitnessReport {
    by_target: BTreeMap<String, BTreeSet<String>>,
    totals: SeedReachTotals,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
enum SeedReplayTarget {
    #[serde(rename = "python_bytecode")]
    PythonBytecode,
    #[serde(rename = "dex_jvm_classfile")]
    DexJvmClassfile,
}

impl SeedReplayTarget {
    const fn declaration_name(self) -> &'static str {
        match self {
            Self::PythonBytecode => "python_bytecode.rs",
            Self::DexJvmClassfile => "dex_jvm_classfile.rs",
        }
    }
}

impl std::fmt::Display for SeedReplayTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::PythonBytecode => "python_bytecode",
            Self::DexJvmClassfile => "dex_jvm_classfile",
        })
    }
}

#[derive(Debug, Deserialize)]
struct SeedReachTarget {
    name: SeedReplayTarget,
    satisfied_obligations: usize,
    declared_obligations: usize,
    positive_witnesses: Vec<SeedReachWitness>,
    expected_rejection_witnesses: Vec<SeedReachWitness>,
    #[serde(default)]
    seeds: Vec<SeedReachTrace>,
}

#[derive(Debug, Deserialize)]
struct SeedReachWitness {
    seed: String,
    entry_point: SeedSemanticEntryPoint,
    surface: SeedSemanticSurface,
}

#[derive(Debug, Deserialize)]
struct SeedReachTrace {
    sha256: String,
    trace: Vec<SeedObservation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
enum SeedSemanticSurface {
    #[serde(rename = "python.pyc.header")]
    PycHeader,
    #[serde(rename = "python.marshal.root")]
    MarshalRoot,
    #[serde(rename = "python.reference-table")]
    ReferenceTable,
    #[serde(rename = "jvm.class-file")]
    JvmClassFile,
    #[serde(rename = "jvm.code-attribute")]
    JvmCodeAttribute,
    #[serde(rename = "jvm.bytecode")]
    JvmBytecode,
    #[serde(rename = "android.dex.header")]
    DexHeader,
    #[serde(rename = "android.dex.file")]
    DexFile,
    #[serde(rename = "android.dex.code-items")]
    DexCodeItems,
}

impl SeedSemanticSurface {
    const fn target(self) -> SeedReplayTarget {
        match self {
            Self::PycHeader | Self::MarshalRoot | Self::ReferenceTable => {
                SeedReplayTarget::PythonBytecode
            }
            Self::JvmClassFile
            | Self::JvmCodeAttribute
            | Self::JvmBytecode
            | Self::DexHeader
            | Self::DexFile
            | Self::DexCodeItems => SeedReplayTarget::DexJvmClassfile,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
enum SeedSemanticEntryPoint {
    #[serde(rename = "disrobe-py-marshal/src/pyc.rs::read_pyc")]
    ReadPyc,
    #[serde(rename = "disrobe-py-marshal/src/reader.rs::load")]
    Load,
    #[serde(rename = "disrobe-py-marshal/src/reader.rs::load_with_reftable")]
    LoadWithRefTable,
    #[serde(rename = "disrobe-py-marshal/src/reftable.rs::dump_reftable")]
    DumpRefTable,
    #[serde(rename = "disrobe-pass-jvm/src/classfile.rs::parse")]
    ParseClassFile,
    #[serde(rename = "disrobe-pass-jvm/src/bytecode.rs::parse_code_attribute")]
    ParseCodeAttribute,
    #[serde(rename = "disrobe-pass-jvm/src/bytecode.rs::disassemble")]
    Disassemble,
    #[serde(rename = "disrobe-pass-jvm/src/dex.rs::parse_header")]
    ParseDexHeader,
    #[serde(rename = "disrobe-pass-jvm/src/dex.rs::parse")]
    ParseDex,
    #[serde(rename = "disrobe-pass-jvm/src/dex.rs::parse_code_items")]
    ParseDexCodeItems,
}

impl SeedSemanticEntryPoint {
    const fn qualified(self) -> &'static str {
        match self {
            Self::ReadPyc => "disrobe-py-marshal/src/pyc.rs::read_pyc",
            Self::Load => "disrobe-py-marshal/src/reader.rs::load",
            Self::LoadWithRefTable => "disrobe-py-marshal/src/reader.rs::load_with_reftable",
            Self::DumpRefTable => "disrobe-py-marshal/src/reftable.rs::dump_reftable",
            Self::ParseClassFile => "disrobe-pass-jvm/src/classfile.rs::parse",
            Self::ParseCodeAttribute => "disrobe-pass-jvm/src/bytecode.rs::parse_code_attribute",
            Self::Disassemble => "disrobe-pass-jvm/src/bytecode.rs::disassemble",
            Self::ParseDexHeader => "disrobe-pass-jvm/src/dex.rs::parse_header",
            Self::ParseDex => "disrobe-pass-jvm/src/dex.rs::parse",
            Self::ParseDexCodeItems => "disrobe-pass-jvm/src/dex.rs::parse_code_items",
        }
    }

    const fn target(self) -> SeedReplayTarget {
        match self {
            Self::ReadPyc | Self::Load | Self::LoadWithRefTable | Self::DumpRefTable => {
                SeedReplayTarget::PythonBytecode
            }
            Self::ParseClassFile
            | Self::ParseCodeAttribute
            | Self::Disassemble
            | Self::ParseDexHeader
            | Self::ParseDex
            | Self::ParseDexCodeItems => SeedReplayTarget::DexJvmClassfile,
        }
    }

    const fn surface(self) -> SeedSemanticSurface {
        match self {
            Self::ReadPyc => SeedSemanticSurface::PycHeader,
            Self::Load => SeedSemanticSurface::MarshalRoot,
            Self::LoadWithRefTable | Self::DumpRefTable => SeedSemanticSurface::ReferenceTable,
            Self::ParseClassFile => SeedSemanticSurface::JvmClassFile,
            Self::ParseCodeAttribute => SeedSemanticSurface::JvmCodeAttribute,
            Self::Disassemble => SeedSemanticSurface::JvmBytecode,
            Self::ParseDexHeader => SeedSemanticSurface::DexHeader,
            Self::ParseDex => SeedSemanticSurface::DexFile,
            Self::ParseDexCodeItems => SeedSemanticSurface::DexCodeItems,
        }
    }
}

type SemanticRoute = (SeedSemanticEntryPoint, SeedSemanticSurface);
type SemanticTraceOutcomes = (BTreeSet<SemanticRoute>, BTreeSet<SemanticRoute>);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum SeedObservationPhase {
    Entered,
    Accepted,
    Rejected,
}

#[derive(Debug, Deserialize)]
struct SeedObservation {
    span: u64,
    surface: SeedSemanticSurface,
    entry_point: SeedSemanticEntryPoint,
    phase: SeedObservationPhase,
    bytes_consumed: usize,
    items: usize,
}

pub(crate) fn run(root: &Path, check: bool) -> Result<()> {
    let entries: Vec<EntryPoint> = collect_entry_points(root)?;
    if entries.is_empty() {
        bail!("the parse-surface derivation found no entry points, which means its pattern broke");
    }
    let declared: BTreeMap<String, BTreeSet<String>> = read_declarations(root)?;
    validate_declarations(root, &entries, &declared)?;
    let semantic_report: Option<SemanticWitnessReport> = read_semantic_witnesses(root)?;
    let replay_proven_all: BTreeSet<String> = semantic_report
        .as_ref()
        .into_iter()
        .flat_map(|report: &SemanticWitnessReport| report.by_target.values())
        .flat_map(|entry_points: &BTreeSet<String>| entry_points.iter().cloned())
        .collect();
    let declared_all: BTreeSet<String> = declared
        .values()
        .flat_map(|set: &BTreeSet<String>| set.iter().cloned())
        .collect();
    let suites: Vec<(String, bool)> = collect_suites(root);

    let mut rows: BTreeMap<String, CrateRow> = BTreeMap::new();
    for entry in &entries {
        let row: &mut CrateRow = rows.entry(entry.package.clone()).or_default();
        row.entry_points = row.entry_points.saturating_add(1);
        if entry.parse_shaped() {
            row.parse_shaped = row.parse_shaped.saturating_add(1);
        }
        let is_declared: bool = declared_all.contains(&entry.qualified());
        if is_declared {
            row.declared_fuzzed = row.declared_fuzzed.saturating_add(1);
        }
        let is_replay_proven: bool = replay_proven_all.contains(&entry.qualified());
        if is_replay_proven {
            row.replay_proven = row.replay_proven.saturating_add(1);
        }
        let mut named: bool = false;
        let mut named_with_reach: bool = false;
        for (body, records) in &suites {
            if !mentions(body, &entry.function) {
                continue;
            }
            named = true;
            if *records {
                named_with_reach = true;
            }
        }
        if named {
            row.in_resilience_suite = row.in_resilience_suite.saturating_add(1);
        }
        if named_with_reach {
            row.in_reach_recording_suite = row.in_reach_recording_suite.saturating_add(1);
        }
        if !is_declared && !named {
            row.unreached.push(entry.qualified());
        }
    }
    for row in rows.values_mut() {
        row.unreached.sort_unstable();
    }

    let targets_in_tree: usize = count_targets(root);
    let seed_reach: SeedReachTotals = semantic_report.as_ref().map_or_else(
        SeedReachTotals::default,
        |report: &SemanticWitnessReport| report.totals,
    );
    let rendered: String = render(&rows, declared.len(), targets_in_tree, &seed_reach);
    let inventory_path: PathBuf = root.join(INVENTORY_RELATIVE);
    if check {
        let committed: String = read_text_bounded(&inventory_path, MAX_DECLARATION_BYTES)
            .wrap_err_with(|| format!("reading {}", inventory_path.display()))?;
        if committed.replace("\r\n", "\n") != rendered {
            bail!(
                "{INVENTORY_RELATIVE} drifted from the tree; rerun the generator so the parse-surface ratio matches what the code now exposes"
            );
        }
    } else {
        fs::write(&inventory_path, rendered.as_bytes())
            .wrap_err_with(|| format!("writing {}", inventory_path.display()))?;
    }

    let totals: CrateRow =
        rows.values()
            .fold(CrateRow::default(), |mut acc: CrateRow, row: &CrateRow| {
                acc.entry_points = acc.entry_points.saturating_add(row.entry_points);
                acc.parse_shaped = acc.parse_shaped.saturating_add(row.parse_shaped);
                acc.declared_fuzzed = acc.declared_fuzzed.saturating_add(row.declared_fuzzed);
                acc.replay_proven = acc.replay_proven.saturating_add(row.replay_proven);
                acc.in_reach_recording_suite = acc
                    .in_reach_recording_suite
                    .saturating_add(row.in_reach_recording_suite);
                acc
            });
    let mode: Mode = if check { Mode::Check } else { Mode::Write };
    let spans: usize = publish_ratio(root, &totals, &seed_reach, mode)?;
    println!(
        "xtask regen: parse-surface inventory ok ({} entry point(s) over {} crate(s), {} parse-shaped, {} with a declared coverage-guided target, {} with replay-proven semantic reach, {} named by a suite that records seed reach, published through {spans} marker span(s))",
        totals.entry_points,
        rows.len(),
        totals.parse_shaped,
        totals.declared_fuzzed,
        totals.replay_proven,
        totals.in_reach_recording_suite
    );
    Ok(())
}

fn collect_entry_points(root: &Path) -> Result<Vec<EntryPoint>> {
    let crates_dir: PathBuf = root.join("crates");
    let mut sources: Vec<PathBuf> = Vec::new();
    collect_sources(&crates_dir, &mut sources)?;
    let mut entries: Vec<EntryPoint> = Vec::new();
    for source in sources {
        let Ok(text): Result<String> = read_text_bounded(&source, MAX_SOURCE_FILE_BYTES) else {
            continue;
        };
        let production: String = strip_cfg_test(&text)
            .wrap_err_with(|| format!("stripping test modules from {}", source.display()))?;
        let body: &str = &production;
        let Some(package): Option<String> = package_of(&crates_dir, &source) else {
            continue;
        };
        let module_path: String = module_path_of(&crates_dir, &source, &package);
        let lines: Vec<&str> = body.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            let trimmed: &str = line.trim_start();
            let Some(rest): Option<&str> = trimmed.strip_prefix("pub fn ") else {
                continue;
            };
            let Some(name_end): Option<usize> = rest.find(['(', '<']) else {
                continue;
            };
            let function: &str = rest.get(..name_end).unwrap_or("").trim();
            if function.is_empty()
                || !function
                    .chars()
                    .all(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            {
                continue;
            }
            let signature: String = join_signature(&lines, index);
            if !takes_untrusted_bytes(&signature) {
                continue;
            }
            entries.push(EntryPoint {
                package: package.clone(),
                function: function.to_owned(),
                module_path: module_path.clone(),
            });
        }
    }
    entries.sort_unstable();
    entries.dedup();
    Ok(entries)
}

fn join_signature(lines: &[&str], start: usize) -> String {
    let mut joined: String = String::new();
    let mut depth: i32 = 0;
    let mut opened: bool = false;
    for line in lines.iter().skip(start).take(MAX_SIGNATURE_LINES) {
        joined.push_str(line);
        joined.push(' ');
        for character in line.chars() {
            match character {
                '(' => {
                    depth += 1;
                    opened = true;
                }
                ')' => depth -= 1,
                _ => {}
            }
        }
        if opened && depth <= 0 {
            break;
        }
    }
    joined
}

fn takes_untrusted_bytes(signature: &str) -> bool {
    let Some(open): Option<usize> = signature.find('(') else {
        return false;
    };
    let params: &str = signature.get(open..).unwrap_or("");
    let normalized: String = params
        .chars()
        .filter(|c: &char| !c.is_whitespace())
        .collect();
    normalized.contains("&[u8]") || normalized.contains("&mut[u8]")
}

fn collect_sources(directory: &Path, into: &mut Vec<PathBuf>) -> Result<()> {
    let Ok(entries): std::io::Result<fs::ReadDir> = fs::read_dir(directory) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        let path: PathBuf = entry.path();
        if path.is_dir() {
            collect_sources(&path, into)?;
        } else if path
            .extension()
            .is_some_and(|kind: &std::ffi::OsStr| kind == "rs")
            && path.components().any(|part: std::path::Component<'_>| {
                part.as_os_str() == std::ffi::OsStr::new("src")
            })
        {
            into.push(path);
        }
    }
    Ok(())
}

fn package_of(crates_dir: &Path, source: &Path) -> Option<String> {
    let relative: &Path = source.strip_prefix(crates_dir).ok()?;
    relative
        .components()
        .next()
        .map(|part: std::path::Component<'_>| part.as_os_str().to_string_lossy().into_owned())
}

fn module_path_of(crates_dir: &Path, source: &Path, package: &str) -> String {
    let Ok(relative): Result<&Path, _> = source.strip_prefix(crates_dir) else {
        return package.to_owned();
    };
    let mut parts: Vec<String> = Vec::new();
    let mut seen_src: bool = false;
    for component in relative.components() {
        let text: String = component.as_os_str().to_string_lossy().into_owned();
        if !seen_src {
            seen_src = text == "src";
            continue;
        }
        parts.push(text);
    }
    let joined: String = parts.join("/");
    let trimmed: &str = joined.strip_suffix(".rs").unwrap_or(&joined);
    format!("{package}/src/{trimmed}.rs")
}

fn collect_suites(root: &Path) -> Vec<(String, bool)> {
    let crates_dir: PathBuf = root.join("crates");
    let mut suites: Vec<(String, bool)> = Vec::new();
    let Ok(packages): std::io::Result<fs::ReadDir> = fs::read_dir(&crates_dir) else {
        return suites;
    };
    for package in packages.flatten() {
        let tests_dir: PathBuf = package.path().join("tests");
        let Ok(files): std::io::Result<fs::ReadDir> = fs::read_dir(&tests_dir) else {
            continue;
        };
        for file in files.flatten() {
            let path: PathBuf = file.path();
            let Some(name): Option<&str> = path
                .file_name()
                .and_then(|raw: &std::ffi::OsStr| raw.to_str())
            else {
                continue;
            };
            if !(name.contains("fuzz")
                || name.contains("resilience")
                || name.contains("never_panic")
                || name.contains("adversarial")
                || name.contains("malformed"))
            {
                continue;
            }
            let Ok(text): Result<String> = read_text_bounded(&path, MAX_SOURCE_FILE_BYTES) else {
                continue;
            };
            let records: bool = REACH_RECORDER_MARKERS
                .iter()
                .any(|marker: &&str| text.contains(marker));
            suites.push((text, records));
        }
    }
    suites
}

fn mentions(body: &str, function: &str) -> bool {
    let bytes: &[u8] = body.as_bytes();
    let needle: &[u8] = function.as_bytes();
    let mut index: usize = 0;
    while let Some(found) = body.get(index..).and_then(|rest: &str| rest.find(function)) {
        let start: usize = index + found;
        let end: usize = start + needle.len();
        let before_ok: bool = start == 0
            || bytes
                .get(start.wrapping_sub(1))
                .is_none_or(|byte: &u8| !byte.is_ascii_alphanumeric() && *byte != b'_');
        let after_ok: bool = bytes
            .get(end)
            .is_none_or(|byte: &u8| !byte.is_ascii_alphanumeric() && *byte != b'_');
        if before_ok && after_ok {
            return true;
        }
        index = end;
    }
    false
}

fn read_declarations(root: &Path) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let path: PathBuf = root.join(DECLARATION_RELATIVE);
    let raw: String = read_text_bounded(&path, MAX_DECLARATION_BYTES)
        .wrap_err_with(|| format!("reading {}", path.display()))?;
    let parsed: toml::Table = raw
        .parse::<toml::Table>()
        .wrap_err_with(|| format!("parsing {}", path.display()))?;
    let mut declarations: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let Some(targets): Option<&Vec<toml::Value>> =
        parsed.get("target").and_then(toml::Value::as_array)
    else {
        return Ok(declarations);
    };
    for target in targets {
        let Some(name): Option<&str> = target.get("name").and_then(toml::Value::as_str) else {
            bail!("{DECLARATION_RELATIVE} has a [[target]] with no name");
        };
        let Some(list): Option<&Vec<toml::Value>> =
            target.get("entry_points").and_then(toml::Value::as_array)
        else {
            bail!("{DECLARATION_RELATIVE} target {name} declares no entry_points");
        };
        let mut set: BTreeSet<String> = BTreeSet::new();
        for item in list {
            let Some(text): Option<&str> = item.as_str() else {
                bail!("{DECLARATION_RELATIVE} target {name} has a non-string entry point");
            };
            set.insert(text.to_owned());
        }
        declarations.insert(name.to_owned(), set);
    }
    Ok(declarations)
}

fn validate_declarations(
    root: &Path,
    entries: &[EntryPoint],
    declared: &BTreeMap<String, BTreeSet<String>>,
) -> Result<()> {
    let known: BTreeSet<String> = entries
        .iter()
        .map(EntryPoint::qualified)
        .collect::<BTreeSet<String>>();
    let semantic_report: Option<SemanticWitnessReport> = read_semantic_witnesses(root)?;
    let mut problems: Vec<String> = Vec::new();
    for (target, points) in declared {
        let body: String = read_target_route(root, target);
        if body.is_empty() {
            problems.push(format!(
                "{target} is declared but its source is missing or empty"
            ));
            continue;
        }
        for point in points {
            if !known.contains(point) {
                problems.push(format!(
                    "{target} claims {point}, which the tree does not expose"
                ));
                continue;
            }
            let Some(function): Option<&str> = point.rsplit("::").next() else {
                continue;
            };
            if !mentions(&body, function) {
                problems.push(format!(
                    "{target} claims {point} but never names {function}, so the claim is unbacked"
                ));
            }
        }
        if let Some(witnessed) = semantic_report
            .as_ref()
            .and_then(|report: &SemanticWitnessReport| report.by_target.get(target))
        {
            for entry_point in witnessed.difference(points) {
                problems.push(format!(
                    "{target} has a semantic witness for undeclared entry point {entry_point}"
                ));
            }
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        bail!(
            "{DECLARATION_RELATIVE} claims coverage it cannot back:\n  {}",
            problems.join("\n  ")
        )
    }
}

fn read_target_route(root: &Path, target: &str) -> String {
    let source: PathBuf = root.join("fuzz").join("fuzz_targets").join(target);
    let Ok(mut body): Result<String> = read_text_bounded(&source, MAX_SOURCE_FILE_BYTES) else {
        return String::new();
    };
    let Some(stem): Option<&str> = target.strip_suffix(".rs") else {
        return body;
    };
    if !mentions(&body, stem) {
        return body;
    }
    let exercise: PathBuf = root.join("fuzz").join("src").join(target);
    let Ok(exercise_body): Result<String> = read_text_bounded(&exercise, MAX_SOURCE_FILE_BYTES)
    else {
        return body;
    };
    body.push('\n');
    body.push_str(&exercise_body);
    body
}

fn read_semantic_witnesses(root: &Path) -> Result<Option<SemanticWitnessReport>> {
    let path: PathBuf = root.join(SEED_REACH_REPORT_RELATIVE);
    if !path.is_file() {
        return Ok(None);
    }
    let raw: String = read_text_bounded(&path, MAX_DECLARATION_BYTES)
        .wrap_err_with(|| format!("reading {}", path.display()))?;
    let report: SeedReachReport =
        serde_json::from_str(&raw).wrap_err_with(|| format!("parsing {}", path.display()))?;
    if report.schema != 3 {
        bail!(
            "{SEED_REACH_REPORT_RELATIVE} has unsupported schema {}",
            report.schema
        );
    }
    if report.generator != SEED_REACH_GENERATOR {
        bail!(
            "{SEED_REACH_REPORT_RELATIVE} names unsupported generator {}",
            report.generator
        );
    }
    let contract_path: PathBuf = root.join(SEED_REACH_CONTRACT_RELATIVE);
    let contract: String = read_text_bounded(&contract_path, MAX_DECLARATION_BYTES)
        .wrap_err_with(|| format!("reading {}", contract_path.display()))?;
    let contract_sha256: String = format!("{:x}", Sha256::digest(contract.as_bytes()));
    if report.contract_sha256 != contract_sha256 {
        bail!(
            "{SEED_REACH_REPORT_RELATIVE} was generated from contract {} instead of {}",
            report.contract_sha256,
            contract_sha256
        );
    }
    if report.obligations.declared_obligations == 0
        || report.obligations.satisfied_obligations != report.obligations.declared_obligations
        || report
            .obligations
            .positive_witnesses
            .saturating_add(report.obligations.expected_rejection_witnesses)
            != report.obligations.satisfied_obligations
    {
        bail!("{SEED_REACH_REPORT_RELATIVE} has inconsistent or vacuous obligation totals");
    }
    let mut witnessed_by_target: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut derived_totals: SeedReachTotals = SeedReachTotals::default();
    for target in report.targets {
        let declaration_name: String = target.name.declaration_name().to_owned();
        if witnessed_by_target.contains_key(&declaration_name) {
            bail!(
                "{SEED_REACH_REPORT_RELATIVE} repeats target {}",
                declaration_name
            );
        }
        if target.declared_obligations == 0
            || target.satisfied_obligations != target.declared_obligations
            || target
                .positive_witnesses
                .len()
                .saturating_add(target.expected_rejection_witnesses.len())
                != target.satisfied_obligations
        {
            bail!(
                "{SEED_REACH_REPORT_RELATIVE} target {} has inconsistent or vacuous obligation totals",
                target.name
            );
        }
        let witnessed: BTreeSet<String> = verify_target_witnesses(&target)?;
        derived_totals.satisfied_obligations = derived_totals
            .satisfied_obligations
            .saturating_add(target.satisfied_obligations);
        derived_totals.declared_obligations = derived_totals
            .declared_obligations
            .saturating_add(target.declared_obligations);
        derived_totals.positive_witnesses = derived_totals
            .positive_witnesses
            .saturating_add(target.positive_witnesses.len());
        derived_totals.expected_rejection_witnesses = derived_totals
            .expected_rejection_witnesses
            .saturating_add(target.expected_rejection_witnesses.len());
        witnessed_by_target.insert(declaration_name, witnessed);
    }
    if derived_totals.satisfied_obligations != report.obligations.satisfied_obligations
        || derived_totals.declared_obligations != report.obligations.declared_obligations
        || derived_totals.positive_witnesses != report.obligations.positive_witnesses
        || derived_totals.expected_rejection_witnesses
            != report.obligations.expected_rejection_witnesses
    {
        bail!("{SEED_REACH_REPORT_RELATIVE} target totals do not match its summary");
    }
    Ok(Some(SemanticWitnessReport {
        by_target: witnessed_by_target,
        totals: report.obligations,
    }))
}

fn verify_target_witnesses(target: &SeedReachTarget) -> Result<BTreeSet<String>> {
    let mut accepted: BTreeSet<(String, SeedSemanticEntryPoint, SeedSemanticSurface)> =
        BTreeSet::new();
    let mut rejected: BTreeSet<(String, SeedSemanticEntryPoint, SeedSemanticSurface)> =
        BTreeSet::new();
    let mut seed_digests: BTreeSet<String> = BTreeSet::new();
    for seed in &target.seeds {
        if seed.sha256.is_empty() {
            bail!(
                "{SEED_REACH_REPORT_RELATIVE} target {} has an empty seed digest",
                target.name
            );
        }
        if !seed_digests.insert(seed.sha256.clone()) {
            bail!(
                "{SEED_REACH_REPORT_RELATIVE} target {} repeats seed {}",
                target.name,
                seed.sha256
            );
        }
        let (seed_accepted, seed_rejected): SemanticTraceOutcomes =
            verify_seed_trace(target.name, seed)?;
        accepted.extend(seed_accepted.into_iter().map(
            |(entry_point, surface): (SeedSemanticEntryPoint, SeedSemanticSurface)| {
                (seed.sha256.clone(), entry_point, surface)
            },
        ));
        rejected.extend(seed_rejected.into_iter().map(
            |(entry_point, surface): (SeedSemanticEntryPoint, SeedSemanticSurface)| {
                (seed.sha256.clone(), entry_point, surface)
            },
        ));
    }

    let mut witnessed_entry_points: BTreeSet<String> = BTreeSet::new();
    for witness in &target.positive_witnesses {
        if witness.seed.is_empty() {
            bail!(
                "{SEED_REACH_REPORT_RELATIVE} target {} has an incomplete positive witness",
                target.name
            );
        }
        if !accepted.contains(&(witness.seed.clone(), witness.entry_point, witness.surface)) {
            bail!(
                "{SEED_REACH_REPORT_RELATIVE} target {} claims a positive witness absent from seed {} trace",
                target.name,
                witness.seed
            );
        }
        witnessed_entry_points.insert(witness.entry_point.qualified().to_owned());
    }
    for witness in &target.expected_rejection_witnesses {
        if witness.seed.is_empty() {
            bail!(
                "{SEED_REACH_REPORT_RELATIVE} target {} has an incomplete expected-rejection witness",
                target.name
            );
        }
        if !rejected.contains(&(witness.seed.clone(), witness.entry_point, witness.surface)) {
            bail!(
                "{SEED_REACH_REPORT_RELATIVE} target {} claims an expected rejection absent from seed {} trace",
                target.name,
                witness.seed
            );
        }
    }
    Ok(witnessed_entry_points)
}

fn verify_seed_trace(
    target_name: SeedReplayTarget,
    seed: &SeedReachTrace,
) -> Result<SemanticTraceOutcomes> {
    let mut spans: BTreeMap<u64, (SeedSemanticEntryPoint, SeedSemanticSurface, bool)> =
        BTreeMap::new();
    let mut accepted: BTreeSet<SemanticRoute> = BTreeSet::new();
    let mut rejected: BTreeSet<SemanticRoute> = BTreeSet::new();
    for observation in &seed.trace {
        validate_semantic_route(target_name, observation.entry_point, observation.surface)?;
        match observation.phase {
            SeedObservationPhase::Entered => {
                if observation.bytes_consumed != 0 || observation.items != 0 {
                    bail!(
                        "{SEED_REACH_REPORT_RELATIVE} target {target_name} seed {} has evidence on an entered observation",
                        seed.sha256
                    );
                }
                if spans
                    .insert(
                        observation.span,
                        (observation.entry_point, observation.surface, false),
                    )
                    .is_some()
                {
                    bail!(
                        "{SEED_REACH_REPORT_RELATIVE} target {target_name} seed {} repeats span {}",
                        seed.sha256,
                        observation.span
                    );
                }
            }
            SeedObservationPhase::Accepted | SeedObservationPhase::Rejected => {
                let Some((entry_point, surface, completed)): Option<&mut (
                    SeedSemanticEntryPoint,
                    SeedSemanticSurface,
                    bool,
                )> = spans.get_mut(&observation.span) else {
                    bail!(
                        "{SEED_REACH_REPORT_RELATIVE} target {target_name} seed {} terminates unknown span {}",
                        seed.sha256,
                        observation.span
                    );
                };
                if *entry_point != observation.entry_point
                    || *surface != observation.surface
                    || *completed
                {
                    bail!(
                        "{SEED_REACH_REPORT_RELATIVE} target {target_name} seed {} has an invalid terminal observation for span {}",
                        seed.sha256,
                        observation.span
                    );
                }
                *completed = true;
                match observation.phase {
                    SeedObservationPhase::Accepted => {
                        if observation.bytes_consumed == 0 || observation.items == 0 {
                            bail!(
                                "{SEED_REACH_REPORT_RELATIVE} target {target_name} seed {} has a vacuous accepted observation",
                                seed.sha256
                            );
                        }
                        accepted.insert((observation.entry_point, observation.surface));
                    }
                    SeedObservationPhase::Rejected => {
                        if observation.bytes_consumed != 0 || observation.items != 0 {
                            bail!(
                                "{SEED_REACH_REPORT_RELATIVE} target {target_name} seed {} has evidence on a rejected observation",
                                seed.sha256
                            );
                        }
                        rejected.insert((observation.entry_point, observation.surface));
                    }
                    SeedObservationPhase::Entered => {}
                }
            }
        }
    }
    if spans.is_empty() {
        bail!(
            "{SEED_REACH_REPORT_RELATIVE} target {target_name} seed {} has no observations",
            seed.sha256
        );
    }
    if spans
        .values()
        .any(|(_, _, completed): &(SeedSemanticEntryPoint, SeedSemanticSurface, bool)| !completed)
    {
        bail!(
            "{SEED_REACH_REPORT_RELATIVE} target {target_name} seed {} has an incomplete observation",
            seed.sha256
        );
    }
    Ok((accepted, rejected))
}

fn validate_semantic_route(
    target: SeedReplayTarget,
    entry_point: SeedSemanticEntryPoint,
    surface: SeedSemanticSurface,
) -> Result<()> {
    if entry_point.target() != target || surface.target() != target {
        bail!(
            "{SEED_REACH_REPORT_RELATIVE} entry point {} does not belong to target {target}",
            entry_point.qualified()
        );
    }
    if entry_point.surface() != surface {
        bail!(
            "{SEED_REACH_REPORT_RELATIVE} entry point {} does not match its semantic surface",
            entry_point.qualified()
        );
    }
    Ok(())
}

fn count_targets(root: &Path) -> usize {
    let directory: PathBuf = root.join("fuzz").join("fuzz_targets");
    let Ok(entries): std::io::Result<fs::ReadDir> = fs::read_dir(&directory) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|entry: &fs::DirEntry| {
            entry
                .path()
                .extension()
                .is_some_and(|kind: &std::ffi::OsStr| kind == "rs")
        })
        .count()
}

fn render_slug(totals: &CrateRow, seed_reach: &SeedReachTotals, slug: &str) -> Result<String> {
    match slug {
        SLUG_ENTRY_POINTS => Ok(totals.entry_points.to_string()),
        SLUG_PARSE_SHAPED => Ok(totals.parse_shaped.to_string()),
        SLUG_WITH_TARGET => Ok(totals.declared_fuzzed.to_string()),
        SLUG_REPLAY_PROVEN => Ok(totals.replay_proven.to_string()),
        SLUG_REACH_RECORDED => Ok(totals.in_reach_recording_suite.to_string()),
        SLUG_SEED_OBLIGATIONS_SATISFIED => Ok(seed_reach.satisfied_obligations.to_string()),
        SLUG_SEED_OBLIGATIONS_DECLARED => Ok(seed_reach.declared_obligations.to_string()),
        SLUG_SEED_POSITIVE_WITNESSES => Ok(seed_reach.positive_witnesses.to_string()),
        SLUG_SEED_REJECTION_WITNESSES => Ok(seed_reach.expected_rejection_witnesses.to_string()),
        other => bail!("unknown parse-surface marker `{other}`"),
    }
}

fn publish_ratio(
    root: &Path,
    totals: &CrateRow,
    seed_reach: &SeedReachTotals,
    mode: Mode,
) -> Result<usize> {
    let mut files: Vec<PathBuf> = doc_region::manifest(root)?;
    files.push(root.join("SECURITY.md"));
    let mut spans: usize = 0;
    for path in &files {
        let body: String = doc_region::read_doc(path)?;
        let regions: Vec<doc_region::Region> = doc_region::parse(SYNTAX, &body)?;
        spans = spans.saturating_add(regions.len());
        if regions.is_empty() {
            continue;
        }
        let updated: String = doc_region::rewrite(SYNTAX, &body, &|slug: &str| {
            render_slug(totals, seed_reach, slug)
        })
        .wrap_err_with(|| format!("rewriting the parse-surface ratio in {}", path.display()))?;
        match mode {
            Mode::Write => {
                if updated != body {
                    fs::write(path, &updated)
                        .wrap_err_with(|| format!("writing {}", path.display()))?;
                }
            }
            Mode::Check => {
                if updated != body {
                    bail!(
                        "{} states a parse-surface figure the tree no longer produces",
                        doc_region::label(root, path)
                    );
                }
            }
        }
    }
    if spans == 0 {
        bail!(
            "no document carries a `{}` span, so the derived parse-surface ratio is published nowhere",
            SYNTAX.open_prefix
        );
    }
    Ok(spans)
}

fn render(
    rows: &BTreeMap<String, CrateRow>,
    target_count: usize,
    targets_in_tree: usize,
    seed_reach: &SeedReachTotals,
) -> String {
    let entry_points: usize = rows.values().map(|row: &CrateRow| row.entry_points).sum();
    let parse_shaped: usize = rows.values().map(|row: &CrateRow| row.parse_shaped).sum();
    let declared_fuzzed: usize = rows
        .values()
        .map(|row: &CrateRow| row.declared_fuzzed)
        .sum();
    let replay_proven: usize = rows.values().map(|row: &CrateRow| row.replay_proven).sum();
    let in_suite: usize = rows
        .values()
        .map(|row: &CrateRow| row.in_resilience_suite)
        .sum();
    let with_reach: usize = rows
        .values()
        .map(|row: &CrateRow| row.in_reach_recording_suite)
        .sum();
    let unreached: usize = rows
        .values()
        .map(|row: &CrateRow| row.unreached.len())
        .sum();

    let mut out: String = String::new();
    out.push_str("{\n");
    out.push_str("  \"title\": \"Untrusted parse surface and its fuzz coverage\",\n");
    out.push_str("  \"generator\": \"xtask regen, parse-surface inventory\",\n");
    out.push_str("  \"note\": \"Derived from the tree. An entry point is a public function taking a byte slice, outside test modules. Declared coverage means fuzz/coverage.toml names the entry point and the target route names its function. Replay-proven semantic reach is narrower: a committed content-addressed seed must produce a complete parser-owned accepted trace for the entry point. The resilience columns count dedicated resilience-shaped test files only; malformed-input assertions in other tests are real coverage this inventory does not see.\",\n");
    let _ = std::fmt::Write::write_fmt(
        &mut out,
        format_args!(
            "  \"totals\": {{\n    \"entry_points\": {entry_points},\n    \"parse_shaped\": {parse_shaped},\n    \"coverage_guided_targets_in_tree\": {targets_in_tree},\n    \"targets_declaring_entry_points\": {target_count},\n    \"with_declared_coverage_guided_target\": {declared_fuzzed},\n    \"with_replay_proven_semantic_reach\": {replay_proven},\n    \"named_by_a_resilience_suite\": {in_suite},\n    \"named_by_a_suite_recording_seed_reach\": {with_reach},\n    \"named_by_neither\": {unreached}\n  }},\n"
        ),
    );
    let _ = std::fmt::Write::write_fmt(
        &mut out,
        format_args!(
            "  \"seed_reach\": {{\n    \"satisfied_obligations\": {},\n    \"declared_obligations\": {},\n    \"positive_witnesses\": {},\n    \"expected_rejection_witnesses\": {}\n  }},\n",
            seed_reach.satisfied_obligations,
            seed_reach.declared_obligations,
            seed_reach.positive_witnesses,
            seed_reach.expected_rejection_witnesses
        ),
    );
    out.push_str("  \"crates\": [\n");
    let mut first: bool = true;
    for (package, row) in rows {
        if !first {
            out.push_str(",\n");
        }
        first = false;
        let _ = std::fmt::Write::write_fmt(
            &mut out,
            format_args!(
                "    {{\n      \"crate\": \"{package}\",\n      \"entry_points\": {},\n      \"parse_shaped\": {},\n      \"with_declared_coverage_guided_target\": {},\n      \"with_replay_proven_semantic_reach\": {},\n      \"named_by_a_resilience_suite\": {},\n      \"named_by_a_suite_recording_seed_reach\": {},\n      \"named_by_neither\": [",
                row.entry_points,
                row.parse_shaped,
                row.declared_fuzzed,
                row.replay_proven,
                row.in_resilience_suite,
                row.in_reach_recording_suite
            ),
        );
        for (index, name) in row.unreached.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str("\n        \"");
            out.push_str(name);
            out.push('"');
        }
        if row.unreached.is_empty() {
            out.push(']');
        } else {
            out.push_str("\n      ]");
        }
        out.push_str("\n    }");
    }
    out.push_str("\n  ]\n}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_entry_after_test_only_item_keeps_its_canonical_identifier() -> Result<()> {
        let temporary: tempfile::TempDir = tempfile::tempdir()?;
        let root: &Path = temporary.path();
        let source_directory: PathBuf = root.join("crates").join("disrobe-py-marshal").join("src");
        fs::create_dir_all(&source_directory)?;
        fs::write(
            source_directory.join("reader.rs"),
            concat!(
                "#[cfg(test)]\n",
                "const TEST_LIMIT: usize = 1;\n",
                "pub fn load(data: &[u8]) { let _ = data; }\n",
                "#[cfg(test)]\n",
                "mod tests { pub fn load(data: &[u8]) { let _ = r#\"}\"#; let _ = data; } }\n",
                "pub fn load_after_tests(data: &[u8]) { let _ = data; }\n",
            ),
        )?;

        let identifiers: BTreeSet<String> = collect_entry_points(root)?
            .into_iter()
            .map(|entry: EntryPoint| entry.qualified())
            .collect();
        assert_eq!(
            identifiers,
            BTreeSet::from([
                "disrobe-py-marshal/src/reader.rs::load".to_owned(),
                "disrobe-py-marshal/src/reader.rs::load_after_tests".to_owned(),
            ])
        );
        Ok(())
    }

    #[test]
    fn target_name_does_not_prove_semantic_seed_reach() -> Result<()> {
        let temporary: tempfile::TempDir = tempfile::tempdir()?;
        let root: &Path = temporary.path();
        let target_directory: PathBuf = root.join("fuzz").join("fuzz_targets");
        fs::create_dir_all(&target_directory)?;
        fs::create_dir_all(root.join("xtask").join("data"))?;
        fs::write(
            target_directory.join("python_bytecode.rs"),
            "fn exercise(data: &[u8]) { let _ = read_pyc(data); }\n",
        )?;
        let contract: &str = "schema = 3\n";
        fs::write(root.join("fuzz").join("seed_reach.toml"), contract)?;
        let contract_sha256: String = format!("{:x}", Sha256::digest(contract.as_bytes()));
        fs::write(
            root.join("xtask").join("data").join("fuzz_seed_reach.json"),
            format!(
                concat!(
                    "{{\n",
                    "  \"schema\": 3,\n",
                    "  \"generator\": \"{}\",\n",
                    "  \"contract_sha256\": \"{}\",\n",
                    "  \"obligations\": {{\"satisfied\": 1, \"declared\": 1, \"positive_witnesses\": 1, \"expected_rejection_witnesses\": 0}},\n",
                    "  \"targets\": [{{\n",
                    "    \"name\": \"python_bytecode\",\n",
                    "    \"satisfied_obligations\": 1,\n",
                    "    \"declared_obligations\": 1,\n",
                    "    \"positive_witnesses\": [{{\n",
                    "      \"seed\": \"0123456789abcdef\",\n",
                    "      \"entry_point\": \"disrobe-py-marshal/src/reader.rs::load\",\n",
                    "      \"surface\": \"python.marshal.root\"\n",
                    "    }}],\n",
                    "    \"expected_rejection_witnesses\": [],\n",
                    "    \"seeds\": [{{\n",
                    "      \"sha256\": \"0123456789abcdef\",\n",
                    "      \"trace\": [\n",
                    "        {{\"span\": 0, \"surface\": \"python.marshal.root\", \"entry_point\": \"disrobe-py-marshal/src/reader.rs::load\", \"phase\": \"entered\", \"bytes_consumed\": 0, \"items\": 0}},\n",
                    "        {{\"span\": 0, \"surface\": \"python.marshal.root\", \"entry_point\": \"disrobe-py-marshal/src/reader.rs::load\", \"phase\": \"accepted\", \"bytes_consumed\": 1, \"items\": 1}}\n",
                    "      ]\n",
                    "    }}]\n",
                    "  }}]\n",
                    "}}\n",
                ),
                SEED_REACH_GENERATOR, contract_sha256
            ),
        )?;

        let entries: Vec<EntryPoint> = vec![EntryPoint {
            package: "disrobe-py-marshal".to_owned(),
            function: "read_pyc".to_owned(),
            module_path: "disrobe-py-marshal/src/pyc.rs".to_owned(),
        }];
        let declared: BTreeMap<String, BTreeSet<String>> = BTreeMap::from([(
            "python_bytecode.rs".to_owned(),
            BTreeSet::from(["disrobe-py-marshal/src/pyc.rs::read_pyc".to_owned()]),
        )]);

        let result: Result<()> = validate_declarations(root, &entries, &declared);

        let error: String = result
            .err()
            .map_or_else(String::new, |source| source.to_string());
        assert!(error.contains("semantic witness for undeclared entry point"));
        Ok(())
    }

    #[test]
    fn jvm_entry_point_cannot_witness_a_python_target() -> Result<()> {
        let temporary: tempfile::TempDir = tempfile::tempdir()?;
        let root: &Path = temporary.path();
        fs::create_dir_all(root.join("fuzz"))?;
        fs::create_dir_all(root.join("xtask").join("data"))?;
        let contract: &str = "schema = 3\n";
        fs::write(root.join("fuzz").join("seed_reach.toml"), contract)?;
        let contract_sha256: String = format!("{:x}", Sha256::digest(contract.as_bytes()));
        fs::write(
            root.join("xtask").join("data").join("fuzz_seed_reach.json"),
            format!(
                concat!(
                    "{{\n",
                    "  \"schema\": 3,\n",
                    "  \"generator\": \"{}\",\n",
                    "  \"contract_sha256\": \"{}\",\n",
                    "  \"obligations\": {{\"satisfied\": 1, \"declared\": 1, \"positive_witnesses\": 1, \"expected_rejection_witnesses\": 0}},\n",
                    "  \"targets\": [{{\n",
                    "    \"name\": \"python_bytecode\",\n",
                    "    \"satisfied_obligations\": 1,\n",
                    "    \"declared_obligations\": 1,\n",
                    "    \"positive_witnesses\": [{{\"seed\": \"0123456789abcdef\", \"entry_point\": \"disrobe-pass-jvm/src/classfile.rs::parse\", \"surface\": \"jvm.class-file\"}}],\n",
                    "    \"expected_rejection_witnesses\": [],\n",
                    "    \"seeds\": [{{\n",
                    "      \"sha256\": \"0123456789abcdef\",\n",
                    "      \"trace\": [\n",
                    "        {{\"span\": 0, \"surface\": \"jvm.class-file\", \"entry_point\": \"disrobe-pass-jvm/src/classfile.rs::parse\", \"phase\": \"entered\", \"bytes_consumed\": 0, \"items\": 0}},\n",
                    "        {{\"span\": 0, \"surface\": \"jvm.class-file\", \"entry_point\": \"disrobe-pass-jvm/src/classfile.rs::parse\", \"phase\": \"accepted\", \"bytes_consumed\": 1, \"items\": 1}}\n",
                    "      ]\n",
                    "    }}]\n",
                    "  }}]\n",
                    "}}\n",
                ),
                SEED_REACH_GENERATOR, contract_sha256
            ),
        )?;

        let result: Result<Option<SemanticWitnessReport>> = read_semantic_witnesses(root);
        let error: String = result
            .err()
            .map_or_else(String::new, |source| format!("{source:?}"));
        assert!(error.contains("does not belong to target"));
        Ok(())
    }

    #[test]
    fn forged_witnesses_cannot_replace_parser_owned_trace() -> Result<()> {
        let temporary: tempfile::TempDir = tempfile::tempdir()?;
        let root: &Path = temporary.path();
        let target_directory: PathBuf = root.join("fuzz").join("fuzz_targets");
        let seed_directory: PathBuf = root
            .join("corpus")
            .join("python")
            .join("freezers")
            .join("pyc_zipper");
        fs::create_dir_all(&target_directory)?;
        fs::create_dir_all(&seed_directory)?;
        fs::create_dir_all(root.join("xtask").join("data"))?;
        fs::write(
            target_directory.join("python_bytecode.rs"),
            "fn exercise(data: &[u8]) { let _ = read_pyc(data); let _ = dump_reftable(data); }\n",
        )?;
        let seed: &[u8] =
            include_bytes!("../../corpus/python/freezers/pyc_zipper/original.pyc.bin");
        fs::write(seed_directory.join("original.pyc.bin"), seed)?;
        fs::write(
            root.join("fuzz").join("seed_reach.toml"),
            concat!(
                "schema = 3\n",
                "\n",
                "[[seed]]\n",
                "target = \"python_bytecode\"\n",
                "path = \"corpus/python/freezers/pyc_zipper/original.pyc.bin\"\n",
                "sha256 = \"94a93aad7c1c0a0551cb1e84549d3ab9d6570dfa492ddaa4789857e13d322feb\"\n",
            ),
        )?;
        let contract: String = fs::read_to_string(root.join("fuzz").join("seed_reach.toml"))?;
        let contract_sha256: String = format!("{:x}", Sha256::digest(contract.as_bytes()));
        fs::write(
            root.join("xtask").join("data").join("fuzz_seed_reach.json"),
            format!(
                concat!(
                    "{{\n",
                    "  \"schema\": 3,\n",
                    "  \"generator\": \"{}\",\n",
                    "  \"contract_sha256\": \"{}\",\n",
                    "  \"obligations\": {{\"satisfied\": 3, \"declared\": 3, \"positive_witnesses\": 3, \"expected_rejection_witnesses\": 0}},\n",
                    "  \"targets\": [{{\n",
                    "    \"name\": \"python_bytecode\",\n",
                    "    \"satisfied_obligations\": 3,\n",
                    "    \"declared_obligations\": 3,\n",
                    "    \"positive_witnesses\": [\n",
                    "      {{\"seed\": \"94a93aad7c1c0a0551cb1e84549d3ab9d6570dfa492ddaa4789857e13d322feb\", \"entry_point\": \"disrobe-py-marshal/src/pyc.rs::read_pyc\", \"surface\": \"python.pyc.header\"}},\n",
                    "      {{\"seed\": \"94a93aad7c1c0a0551cb1e84549d3ab9d6570dfa492ddaa4789857e13d322feb\", \"entry_point\": \"disrobe-py-marshal/src/reader.rs::load\", \"surface\": \"python.marshal.root\"}},\n",
                    "      {{\"seed\": \"94a93aad7c1c0a0551cb1e84549d3ab9d6570dfa492ddaa4789857e13d322feb\", \"entry_point\": \"disrobe-py-marshal/src/reftable.rs::dump_reftable\", \"surface\": \"python.reference-table\"}}\n",
                    "    ],\n",
                    "    \"expected_rejection_witnesses\": [],\n",
                    "    \"seeds\": [{{\n",
                    "      \"sha256\": \"94a93aad7c1c0a0551cb1e84549d3ab9d6570dfa492ddaa4789857e13d322feb\",\n",
                    "      \"trace\": [\n",
                    "        {{\"span\": 0, \"surface\": \"python.pyc.header\", \"entry_point\": \"disrobe-py-marshal/src/pyc.rs::read_pyc\", \"phase\": \"entered\", \"bytes_consumed\": 0, \"items\": 0}},\n",
                    "        {{\"span\": 0, \"surface\": \"python.pyc.header\", \"entry_point\": \"disrobe-py-marshal/src/pyc.rs::read_pyc\", \"phase\": \"accepted\", \"bytes_consumed\": 16, \"items\": 1}},\n",
                    "        {{\"span\": 1, \"surface\": \"python.marshal.root\", \"entry_point\": \"disrobe-py-marshal/src/pyc.rs::read_pyc\", \"phase\": \"entered\", \"bytes_consumed\": 0, \"items\": 0}},\n",
                    "        {{\"span\": 1, \"surface\": \"python.marshal.root\", \"entry_point\": \"disrobe-py-marshal/src/pyc.rs::read_pyc\", \"phase\": \"accepted\", \"bytes_consumed\": 962, \"items\": 1}},\n",
                    "        {{\"span\": 2, \"surface\": \"python.reference-table\", \"entry_point\": \"disrobe-py-marshal/src/reftable.rs::dump_reftable\", \"phase\": \"entered\", \"bytes_consumed\": 0, \"items\": 0}},\n",
                    "        {{\"span\": 2, \"surface\": \"python.reference-table\", \"entry_point\": \"disrobe-py-marshal/src/reftable.rs::dump_reftable\", \"phase\": \"accepted\", \"bytes_consumed\": 962, \"items\": 1}}\n",
                    "      ]\n",
                    "    }}]\n",
                    "  }}]\n",
                    "}}\n",
                ),
                SEED_REACH_GENERATOR, contract_sha256
            ),
        )?;

        let entries: Vec<EntryPoint> = vec![
            EntryPoint {
                package: "disrobe-py-marshal".to_owned(),
                function: "read_pyc".to_owned(),
                module_path: "disrobe-py-marshal/src/pyc.rs".to_owned(),
            },
            EntryPoint {
                package: "disrobe-py-marshal".to_owned(),
                function: "dump_reftable".to_owned(),
                module_path: "disrobe-py-marshal/src/reftable.rs".to_owned(),
            },
        ];
        let declared: BTreeMap<String, BTreeSet<String>> = BTreeMap::from([(
            "python_bytecode.rs".to_owned(),
            BTreeSet::from([
                "disrobe-py-marshal/src/pyc.rs::read_pyc".to_owned(),
                "disrobe-py-marshal/src/reftable.rs::dump_reftable".to_owned(),
            ]),
        )]);

        let result: Result<()> = validate_declarations(root, &entries, &declared);

        let error: String = result
            .err()
            .map_or_else(String::new, |source| source.to_string());
        assert!(error.contains("does not match its semantic surface"));
        Ok(())
    }

    #[test]
    fn generated_inventory_separates_declared_and_replay_proven_coverage() -> Result<()> {
        let rows: BTreeMap<String, CrateRow> = BTreeMap::from([(
            "disrobe-py-marshal".to_owned(),
            CrateRow {
                entry_points: 2,
                parse_shaped: 2,
                declared_fuzzed: 2,
                replay_proven: 1,
                in_resilience_suite: 0,
                in_reach_recording_suite: 0,
                unreached: Vec::new(),
            },
        )]);
        let seed_reach: SeedReachTotals = SeedReachTotals {
            satisfied_obligations: 4,
            declared_obligations: 4,
            positive_witnesses: 3,
            expected_rejection_witnesses: 1,
        };

        let rendered: String = render(&rows, 1, 1, &seed_reach);
        let parsed: serde_json::Value = serde_json::from_str(&rendered)?;

        assert_eq!(parsed["totals"]["with_declared_coverage_guided_target"], 2);
        assert_eq!(parsed["totals"]["with_replay_proven_semantic_reach"], 1);
        assert_eq!(parsed["seed_reach"]["satisfied_obligations"], 4);
        assert_eq!(parsed["seed_reach"]["declared_obligations"], 4);
        Ok(())
    }
}
