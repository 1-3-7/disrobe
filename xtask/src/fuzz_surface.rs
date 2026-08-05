use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};

use crate::doc_region::{self, Mode, RegionSyntax};
use crate::fileio::read_text_bounded;

const MAX_SOURCE_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_DECLARATION_BYTES: u64 = 256 * 1024;
const INVENTORY_RELATIVE: &str = "xtask/data/fuzz_surface.json";
const DECLARATION_RELATIVE: &str = "fuzz/coverage.toml";
const SYNTAX: RegionSyntax = RegionSyntax {
    open_prefix: "<!-- parse-surface:",
    close: "<!-- /parse-surface -->",
};

const SLUG_ENTRY_POINTS: &str = "entry-points";
const SLUG_PARSE_SHAPED: &str = "parse-shaped";
const SLUG_WITH_TARGET: &str = "with-target";
const SLUG_REACH_RECORDED: &str = "reach-recorded";
const CFG_TEST_ATTR: &str = "#[cfg(test)]";
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
    in_resilience_suite: usize,
    in_reach_recording_suite: usize,
    unreached: Vec<String>,
}

pub(crate) fn run(root: &Path, check: bool) -> Result<()> {
    let entries: Vec<EntryPoint> = collect_entry_points(root)?;
    if entries.is_empty() {
        bail!("the parse-surface derivation found no entry points, which means its pattern broke");
    }
    let declared: BTreeMap<String, BTreeSet<String>> = read_declarations(root)?;
    validate_declarations(root, &entries, &declared)?;
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
    let rendered: String = render(&rows, declared.len(), targets_in_tree);
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
                acc.in_reach_recording_suite = acc
                    .in_reach_recording_suite
                    .saturating_add(row.in_reach_recording_suite);
                acc
            });
    let mode: Mode = if check { Mode::Check } else { Mode::Write };
    let spans: usize = publish_ratio(root, &totals, mode)?;
    println!(
        "xtask regen: parse-surface inventory ok ({} entry point(s) over {} crate(s), {} parse-shaped, {} with a declared coverage-guided target, {} named by a suite that records seed reach, published through {spans} marker span(s))",
        totals.entry_points,
        rows.len(),
        totals.parse_shaped,
        totals.declared_fuzzed,
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
        let body: &str = text.split(CFG_TEST_ATTR).next().unwrap_or("");
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
    let mut problems: Vec<String> = Vec::new();
    for (target, points) in declared {
        let source: PathBuf = root.join("fuzz").join("fuzz_targets").join(target);
        let body: String = read_text_bounded(&source, MAX_SOURCE_FILE_BYTES).unwrap_or_default();
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

fn render_slug(totals: &CrateRow, slug: &str) -> Result<String> {
    match slug {
        SLUG_ENTRY_POINTS => Ok(totals.entry_points.to_string()),
        SLUG_PARSE_SHAPED => Ok(totals.parse_shaped.to_string()),
        SLUG_WITH_TARGET => Ok(totals.declared_fuzzed.to_string()),
        SLUG_REACH_RECORDED => Ok(totals.in_reach_recording_suite.to_string()),
        other => bail!("unknown parse-surface marker `{other}`"),
    }
}

fn publish_ratio(root: &Path, totals: &CrateRow, mode: Mode) -> Result<usize> {
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
        let updated: String =
            doc_region::rewrite(SYNTAX, &body, &|slug: &str| render_slug(totals, slug))
                .wrap_err_with(|| {
                    format!("rewriting the parse-surface ratio in {}", path.display())
                })?;
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
) -> String {
    let entry_points: usize = rows.values().map(|row: &CrateRow| row.entry_points).sum();
    let parse_shaped: usize = rows.values().map(|row: &CrateRow| row.parse_shaped).sum();
    let declared_fuzzed: usize = rows
        .values()
        .map(|row: &CrateRow| row.declared_fuzzed)
        .sum();
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
    out.push_str("  \"note\": \"Derived from the tree. An entry point is a public function taking a byte slice, outside test modules. A coverage-guided target counts only when fuzz/coverage.toml declares it and the target source names the function, so a name collision cannot be read as coverage. The resilience columns count dedicated resilience-shaped test files only; ad-hoc malformed-input assertions inside functional tests are real coverage this inventory does not see.\",\n");
    let _ = std::fmt::Write::write_fmt(
        &mut out,
        format_args!(
            "  \"totals\": {{\n    \"entry_points\": {entry_points},\n    \"parse_shaped\": {parse_shaped},\n    \"coverage_guided_targets_in_tree\": {targets_in_tree},\n    \"targets_declaring_entry_points\": {target_count},\n    \"with_declared_coverage_guided_target\": {declared_fuzzed},\n    \"named_by_a_resilience_suite\": {in_suite},\n    \"named_by_a_suite_recording_seed_reach\": {with_reach},\n    \"named_by_neither\": {unreached}\n  }},\n"
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
                "    {{\n      \"crate\": \"{package}\",\n      \"entry_points\": {},\n      \"parse_shaped\": {},\n      \"with_declared_coverage_guided_target\": {},\n      \"named_by_a_resilience_suite\": {},\n      \"named_by_a_suite_recording_seed_reach\": {},\n      \"named_by_neither\": [",
                row.entry_points,
                row.parse_shaped,
                row.declared_fuzzed,
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
