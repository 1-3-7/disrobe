use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail, eyre};

use crate::facts::attribute_spans;
use crate::fileio::read_text_bounded;
use crate::health::workspace_members;

const MAX_SOURCE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
const MAX_DOC_BYTES: u64 = 8 * 1024 * 1024;

const CHAIN_DETECTOR_FILE: &str = "chain_detector.rs";
const CHAIN_FEATURE: &str = "chain";

const MIN_CHAIN_DETECTORS: usize = 25;
const MIN_HIDDEN_CRATES: usize = 28;
const MIN_SCANNED_COMMANDS: usize = 20;

const UNDECLARED: &str = "hidden-test-surface-undeclared";
const STALE: &str = "hidden-test-surface-stale";
const EMPTY_CHAIN_DETECTOR: &str = "chain-detector-without-tests";
const SKIPPING_COMMAND: &str = "verification-command-skips-tests";
const UNKNOWN_PACKAGE: &str = "verification-command-unknown-package";

const HIDDEN_TEST_SURFACE: &[(&str, &[&str])] = &[
    ("disrobe-binfmt", &["chain"]),
    ("disrobe-capabilities", &["yaml_rules"]),
    (
        "disrobe-cli",
        &["!(prowl & net-fetch & server)", "!jvm", "!wasm"],
    ),
    ("disrobe-core", &["chain"]),
    ("disrobe-irsummary", &["llm-metadata"]),
    ("disrobe-mba", &["smt-solver"]),
    ("disrobe-pass-as3", &["chain"]),
    ("disrobe-pass-beam", &["chain"]),
    ("disrobe-pass-dotnet", &["chain"]),
    ("disrobe-pass-go", &["chain"]),
    ("disrobe-pass-js-deob", &["chain"]),
    ("disrobe-pass-jvm", &["chain", "lifter-diag"]),
    ("disrobe-pass-lua", &["chain"]),
    ("disrobe-pass-mobile", &["chain"]),
    ("disrobe-pass-native", &["chain", "smt-solver"]),
    ("disrobe-pass-nativelang", &["chain"]),
    ("disrobe-pass-nuitka", &["chain"]),
    ("disrobe-pass-php", &["chain"]),
    ("disrobe-pass-pickle", &["chain"]),
    ("disrobe-pass-py-decompile", &["chain"]),
    ("disrobe-pass-py-deob", &["chain"]),
    ("disrobe-pass-py-disasm", &["chain"]),
    ("disrobe-pass-pyarmor", &["chain"]),
    ("disrobe-pass-pyfreeze", &["chain"]),
    ("disrobe-pass-pyinstaller", &["chain"]),
    ("disrobe-pass-ruby", &["chain"]),
    ("disrobe-pass-scriptlang", &["chain"]),
    ("disrobe-pass-shell", &["chain"]),
    ("disrobe-pass-sourcedefender", &["chain"]),
    ("disrobe-pass-swift-objc", &["chain"]),
    ("disrobe-pass-wasm-deob", &["chain", "sandbox"]),
    ("disrobe-pass-webview", &["chain"]),
];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Requirement {
    Enabled(String),
    Disabled(String),
    NotAll(Vec<String>),
}

impl Requirement {
    fn label(&self) -> String {
        match self {
            Self::Enabled(feature) => feature.clone(),
            Self::Disabled(feature) => format!("!{feature}"),
            Self::NotAll(features) => format!("!({})", features.join(" & ")),
        }
    }

    fn holds(&self, selection: &Selection) -> bool {
        match self {
            Self::Enabled(feature) => selection.enables(feature),
            Self::Disabled(feature) => !selection.enables(feature),
            Self::NotAll(features) => !features
                .iter()
                .all(|feature: &String| selection.enables(feature)),
        }
    }
}

#[derive(Debug, Clone)]
enum Selection {
    Named(BTreeSet<String>),
    All,
}

impl Selection {
    fn enables(&self, feature: &str) -> bool {
        match self {
            Self::Named(named) => named.contains(feature),
            Self::All => true,
        }
    }

    fn satisfies(&self, requirements: &[Requirement]) -> bool {
        requirements
            .iter()
            .all(|requirement: &Requirement| requirement.holds(self))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TestTarget {
    Unit,
    Integration(String),
}

#[derive(Debug)]
struct GatedFile {
    relative: String,
    target: TestTarget,
    requirements: Vec<Requirement>,
    tests: usize,
}

#[derive(Debug)]
struct CrateFacts {
    package: String,
    dir: String,
    features: BTreeMap<String, Vec<String>>,
    default_selection: Selection,
    gated: Vec<GatedFile>,
    chain_detector_tests: Option<usize>,
}

impl CrateFacts {
    fn hidden_labels(&self) -> BTreeSet<String> {
        let mut out: BTreeSet<String> = BTreeSet::new();
        for file in &self.gated {
            if file.tests == 0 || self.default_selection.satisfies(&file.requirements) {
                continue;
            }
            for requirement in &file.requirements {
                if !requirement.holds(&self.default_selection) {
                    out.insert(requirement.label());
                }
            }
        }
        out
    }

    fn hidden_tests(&self, selection: &Selection) -> Vec<&GatedFile> {
        self.gated
            .iter()
            .filter(|file: &&GatedFile| file.tests > 0 && !selection.satisfies(&file.requirements))
            .collect()
    }
}

#[derive(Debug)]
pub(crate) struct Finding {
    pub(crate) check: &'static str,
    pub(crate) detail: String,
}

#[derive(Debug, Default)]
pub(crate) struct Audit {
    pub(crate) findings: Vec<Finding>,
    pub(crate) hidden_crates: usize,
    pub(crate) chain_detectors: usize,
    pub(crate) chain_tests_hidden_by_default: usize,
    pub(crate) commands_scanned: usize,
}

impl Audit {
    fn fail(&mut self, check: &'static str, detail: String) {
        self.findings.push(Finding { check, detail });
    }
}

pub(crate) fn audit(root: &Path) -> Result<Audit> {
    let crates: Vec<CrateFacts> = load_crates(root)?;
    let mut report: Audit = Audit::default();

    let mut declared: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for (package, labels) in HIDDEN_TEST_SURFACE {
        let entry: BTreeSet<String> = labels.iter().map(|l: &&str| (*l).to_owned()).collect();
        if declared.insert(package, entry).is_some() {
            bail!("HIDDEN_TEST_SURFACE names {package} twice");
        }
    }

    let mut hidden_crates: usize = 0;
    for facts in &crates {
        if let Some(tests) = facts.chain_detector_tests {
            report.chain_detectors += 1;
            if tests == 0 {
                report.fail(
                    EMPTY_CHAIN_DETECTOR,
                    format!(
                        "{}/src/{CHAIN_DETECTOR_FILE} declares no test, so no wrong chain-routing \
                         answer can turn a suite red for {}",
                        facts.dir, facts.package
                    ),
                );
            }
            if !facts.default_selection.enables(CHAIN_FEATURE) {
                report.chain_tests_hidden_by_default += tests;
            }
        }

        let actual: BTreeSet<String> = facts.hidden_labels();
        if !actual.is_empty() {
            hidden_crates += 1;
        }
        let expected: Option<&BTreeSet<String>> = declared.get(facts.package.as_str());
        match (actual.is_empty(), expected) {
            (false, None) => report.fail(
                UNDECLARED,
                format!(
                    "{} hides test-bearing code behind [{}], which its default feature set does \
                     not enable, so `cargo test -p {}` compiles those tests away and still prints \
                     a passing result; run `{}` and add the entry to HIDDEN_TEST_SURFACE in \
                     xtask/src/feature_gated_tests.rs",
                    facts.package,
                    render_labels(&actual),
                    facts.package,
                    render_command(&facts.package, &actual)
                ),
            ),
            (true, Some(_)) => report.fail(
                STALE,
                format!(
                    "HIDDEN_TEST_SURFACE lists {} but it now hides no test behind a non-default \
                     feature; either a gate was lifted or the tests behind it were deleted, so \
                     drop the entry in xtask/src/feature_gated_tests.rs and confirm the tests \
                     still exist",
                    facts.package
                ),
            ),
            (false, Some(want)) if want != &actual => report.fail(
                UNDECLARED,
                format!(
                    "{} hides test-bearing code behind [{}] but HIDDEN_TEST_SURFACE declares [{}]; \
                     update the entry in xtask/src/feature_gated_tests.rs and state the flag in \
                     docs/src/contributing.md",
                    facts.package,
                    render_labels(&actual),
                    render_labels(want)
                ),
            ),
            (true, None) | (false, Some(_)) => {}
        }
    }
    report.hidden_crates = hidden_crates;

    for (package, _) in HIDDEN_TEST_SURFACE {
        if !crates
            .iter()
            .any(|facts: &CrateFacts| facts.package == *package)
        {
            report.fail(
                STALE,
                format!(
                    "HIDDEN_TEST_SURFACE names {package}, which is no longer a workspace member; \
                     drop the entry"
                ),
            );
        }
    }

    if report.chain_detectors < MIN_CHAIN_DETECTORS {
        bail!(
            "this sweep resolved {} src/{CHAIN_DETECTOR_FILE} file(s) across the workspace, fewer \
             than the {MIN_CHAIN_DETECTORS} it requires; a walk that finds almost nothing would \
             grade almost nothing",
            report.chain_detectors
        );
    }
    if hidden_crates < MIN_HIDDEN_CRATES {
        bail!(
            "this sweep resolved {hidden_crates} crate(s) hiding test-bearing code behind a \
             non-default feature, fewer than the {MIN_HIDDEN_CRATES} it requires; the inner \
             attribute reader or the feature-closure walk broke, and an empty population would \
             report every command safe"
        );
    }

    let by_package: BTreeMap<&str, &CrateFacts> = crates
        .iter()
        .map(|facts: &CrateFacts| (facts.package.as_str(), facts))
        .collect();
    report.commands_scanned = scan_commands(root, &by_package, &mut report.findings)?;
    if report.commands_scanned < MIN_SCANNED_COMMANDS {
        bail!(
            "this sweep read {} per-crate `cargo test -p` invocation(s) out of the repository's \
             documentation and workflows, fewer than the {MIN_SCANNED_COMMANDS} it requires; the \
             command reader broke and no written command is being checked",
            report.commands_scanned
        );
    }

    report
        .findings
        .sort_by(|a: &Finding, b: &Finding| (a.check, &a.detail).cmp(&(b.check, &b.detail)));
    Ok(report)
}

fn render_labels(labels: &BTreeSet<String>) -> String {
    labels.iter().cloned().collect::<Vec<String>>().join(", ")
}

fn render_command(package: &str, labels: &BTreeSet<String>) -> String {
    let enable: Vec<String> = labels
        .iter()
        .filter(|label: &&String| !label.starts_with('!'))
        .cloned()
        .collect();
    if enable.is_empty() {
        format!("cargo test -p {package} --no-default-features")
    } else {
        format!("cargo test -p {package} --features {}", enable.join(","))
    }
}

fn load_crates(root: &Path) -> Result<Vec<CrateFacts>> {
    let root_manifest: String = read_text_bounded(&root.join("Cargo.toml"), MAX_MANIFEST_BYTES)
        .wrap_err("reading the workspace manifest")?;
    let root_doc: toml::Value =
        toml::from_str(&root_manifest).wrap_err("parsing the workspace manifest")?;
    let members: BTreeSet<String> = workspace_members(&root_doc);
    if members.is_empty() {
        bail!("the workspace manifest lists no members, so this sweep would grade nothing");
    }

    let mut out: Vec<CrateFacts> = Vec::with_capacity(members.len());
    for member in &members {
        let manifest_path: PathBuf = root.join(member).join("Cargo.toml");
        if !manifest_path.is_file() {
            continue;
        }
        let text: String = read_text_bounded(&manifest_path, MAX_MANIFEST_BYTES)
            .wrap_err_with(|| format!("reading {member}/Cargo.toml"))?;
        let doc: toml::Value =
            toml::from_str(&text).wrap_err_with(|| format!("parsing {member}/Cargo.toml"))?;
        let Some(package) = doc
            .get("package")
            .and_then(|p: &toml::Value| p.get("name"))
            .and_then(toml::Value::as_str)
        else {
            continue;
        };
        let features: BTreeMap<String, Vec<String>> = parse_features(&doc, member)?;
        let default_selection: Selection =
            Selection::Named(feature_closure(&features, ["default".to_owned()]));
        let (gated, chain_detector_tests): (Vec<GatedFile>, Option<usize>) =
            scan_crate_sources(root, member)?;
        out.push(CrateFacts {
            package: package.to_owned(),
            dir: member.clone(),
            features,
            default_selection,
            gated,
            chain_detector_tests,
        });
    }
    Ok(out)
}

fn parse_features(doc: &toml::Value, member: &str) -> Result<BTreeMap<String, Vec<String>>> {
    let Some(table) = doc.get("features").and_then(toml::Value::as_table) else {
        return Ok(BTreeMap::new());
    };
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, value) in table {
        let Some(entries) = value.as_array() else {
            bail!("{member}/Cargo.toml [features] {name} is not an array");
        };
        let edges: Vec<String> = entries
            .iter()
            .filter_map(|entry: &toml::Value| entry.as_str().map(str::to_owned))
            .collect();
        out.insert(name.clone(), edges);
    }
    Ok(out)
}

fn feature_closure(
    features: &BTreeMap<String, Vec<String>>,
    seeds: impl IntoIterator<Item = String>,
) -> BTreeSet<String> {
    let mut enabled: BTreeSet<String> = BTreeSet::new();
    let mut pending: Vec<String> = seeds.into_iter().collect();
    while let Some(name) = pending.pop() {
        if name.starts_with("dep:") || name.contains('/') {
            continue;
        }
        if !enabled.insert(name.clone()) {
            continue;
        }
        if let Some(edges) = features.get(&name) {
            pending.extend(edges.iter().cloned());
        }
    }
    enabled
}

fn scan_crate_sources(root: &Path, member: &str) -> Result<(Vec<GatedFile>, Option<usize>)> {
    let crate_root: PathBuf = root.join(member);
    let mut gated: Vec<GatedFile> = Vec::new();
    let mut chain_detector_tests: Option<usize> = None;

    let src_dir: PathBuf = crate_root.join("src");
    if src_dir.is_dir() {
        for path in rust_files_recursive(&src_dir)? {
            let relative: String = relative_label(&crate_root, &path);
            let text: String = read_text_bounded(&path, MAX_SOURCE_BYTES)
                .wrap_err_with(|| format!("reading {member}/{relative}"))?;
            let tests: usize = count_tests(&text);
            if path.file_name().and_then(|n: &std::ffi::OsStr| n.to_str())
                == Some(CHAIN_DETECTOR_FILE)
            {
                chain_detector_tests = Some(tests);
            }
            if let Some(requirements) = file_requirements(&text, &format!("{member}/{relative}"))? {
                gated.push(GatedFile {
                    relative,
                    target: TestTarget::Unit,
                    requirements,
                    tests,
                });
            }
        }
    }

    let tests_dir: PathBuf = crate_root.join("tests");
    if tests_dir.is_dir() {
        for path in rust_files_shallow(&tests_dir)? {
            let relative: String = relative_label(&crate_root, &path);
            let Some(stem) = path
                .file_stem()
                .and_then(|n: &std::ffi::OsStr| n.to_str())
                .map(str::to_owned)
            else {
                continue;
            };
            let text: String = read_text_bounded(&path, MAX_SOURCE_BYTES)
                .wrap_err_with(|| format!("reading {member}/{relative}"))?;
            if let Some(requirements) = file_requirements(&text, &format!("{member}/{relative}"))? {
                gated.push(GatedFile {
                    relative,
                    target: TestTarget::Integration(stem),
                    requirements,
                    tests: count_tests(&text),
                });
            }
        }
    }

    Ok((gated, chain_detector_tests))
}

fn relative_label(crate_root: &Path, path: &Path) -> String {
    path.strip_prefix(crate_root).map_or_else(
        |_| path.to_string_lossy().into_owned(),
        |rest: &Path| rest.to_string_lossy().replace('\\', "/"),
    )
}

fn rust_files_recursive(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out: Vec<PathBuf> = Vec::new();
    for entry in walkdir::WalkDir::new(dir).sort_by_file_name() {
        let entry: walkdir::DirEntry =
            entry.wrap_err_with(|| format!("walking {}", dir.display()))?;
        if entry.file_type().is_file()
            && entry
                .path()
                .extension()
                .and_then(|e: &std::ffi::OsStr| e.to_str())
                == Some("rs")
        {
            out.push(entry.into_path());
        }
    }
    Ok(out)
}

fn rust_files_shallow(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out: Vec<PathBuf> = Vec::new();
    for entry in walkdir::WalkDir::new(dir)
        .min_depth(1)
        .max_depth(1)
        .sort_by_file_name()
    {
        let entry: walkdir::DirEntry =
            entry.wrap_err_with(|| format!("walking {}", dir.display()))?;
        if entry.file_type().is_file()
            && entry
                .path()
                .extension()
                .and_then(|e: &std::ffi::OsStr| e.to_str())
                == Some("rs")
        {
            out.push(entry.into_path());
        }
    }
    Ok(out)
}

fn count_tests(text: &str) -> usize {
    attribute_spans(text)
        .into_iter()
        .filter(|&(start, end): &(usize, usize)| {
            text.get(start..end)
                .is_some_and(|attribute: &str| attribute.trim() == "#[test]")
        })
        .count()
}

fn leading_inner_attributes(text: &str) -> Vec<&str> {
    let mut out: Vec<&str> = Vec::new();
    let mut cursor: usize = 0;
    for (start, end) in attribute_spans(text) {
        let Some(between) = text.get(cursor..start) else {
            break;
        };
        if !between.trim().is_empty() {
            break;
        }
        let Some(attribute) = text.get(start..end) else {
            break;
        };
        if !attribute.starts_with("#![") {
            break;
        }
        out.push(attribute);
        cursor = end;
    }
    out
}

fn file_requirements(text: &str, whence: &str) -> Result<Option<Vec<Requirement>>> {
    let mut out: Vec<Requirement> = Vec::new();
    for attribute in leading_inner_attributes(text) {
        let Some(body) = attribute
            .strip_prefix("#![cfg(")
            .and_then(|rest: &str| rest.strip_suffix(")]"))
        else {
            continue;
        };
        if !body.contains("feature") {
            continue;
        }
        out.extend(parse_cfg_predicate(body.trim(), whence)?);
    }
    if out.is_empty() {
        return Ok(None);
    }
    out.sort();
    out.dedup();
    Ok(Some(out))
}

fn parse_cfg_predicate(body: &str, whence: &str) -> Result<Vec<Requirement>> {
    if let Some(inner) = body
        .strip_prefix("not(")
        .and_then(|rest: &str| rest.strip_suffix(')'))
    {
        let trimmed: &str = inner.trim();
        if let Some(features) = parse_feature_group(trimmed, "all(") {
            return Ok(vec![Requirement::NotAll(features?)]);
        }
        if let Some(features) = parse_feature_group(trimmed, "any(") {
            return Ok(features?.into_iter().map(Requirement::Disabled).collect());
        }
        let feature: String = parse_feature_equality(trimmed).ok_or_else(|| {
            eyre!(
                "{whence} carries `#![cfg(not({inner}))]`, which is not one of the \
                 `not(feature = \"...\")`, `not(all(feature = ..., ...))` or \
                 `not(any(feature = ..., ...))` shapes this sweep parses"
            )
        })?;
        return Ok(vec![Requirement::Disabled(feature)]);
    }
    if let Some(inner) = body
        .strip_prefix("all(")
        .and_then(|rest: &str| rest.strip_suffix(')'))
    {
        let mut out: Vec<Requirement> = Vec::new();
        for item in inner.split(',') {
            let trimmed: &str = item.trim();
            if trimmed.is_empty() {
                continue;
            }
            if !trimmed.contains("feature") {
                continue;
            }
            let feature: String = parse_feature_equality(trimmed).ok_or_else(|| {
                eyre!(
                    "{whence} carries `all(...)` term `{trimmed}`, which is not the plain \
                     `feature = \"...\"` shape this sweep parses"
                )
            })?;
            out.push(Requirement::Enabled(feature));
        }
        return Ok(out);
    }
    let feature: String = parse_feature_equality(body).ok_or_else(|| {
        eyre!(
            "{whence} carries `#![cfg({body})]`, which mentions a feature but is not one of the \
             `feature = \"...\"`, `all(feature = ..., ...)`, `not(feature = \"...\")`, \
             `not(all(...))` or `not(any(...))` shapes this sweep parses; teach the parser the \
             new shape rather than leaving the file unaudited"
        )
    })?;
    Ok(vec![Requirement::Enabled(feature)])
}

fn parse_feature_group(body: &str, opener: &str) -> Option<Result<Vec<String>>> {
    let inner: &str = body.strip_prefix(opener)?.strip_suffix(')')?;
    let mut features: Vec<String> = Vec::new();
    for item in inner.split(',') {
        let trimmed: &str = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some(feature) = parse_feature_equality(trimmed) else {
            return Some(Err(eyre!(
                "`{opener}...)` term `{trimmed}` is not the plain `feature = \"...\"` shape this \
                 sweep parses"
            )));
        };
        features.push(feature);
    }
    if features.is_empty() {
        return None;
    }
    Some(Ok(features))
}

fn parse_feature_equality(term: &str) -> Option<String> {
    let rest: &str = term.trim().strip_prefix("feature")?.trim_start();
    let value: &str = rest.strip_prefix('=')?.trim();
    let unquoted: &str = value.strip_prefix('"')?.strip_suffix('"')?;
    (!unquoted.is_empty()).then(|| unquoted.to_owned())
}

#[derive(Debug, Default)]
struct Invocation {
    package: Option<String>,
    tests: Vec<String>,
    features: Vec<String>,
    all_features: bool,
    no_default_features: bool,
    narrowed: bool,
    all_targets: bool,
    placeholder: bool,
}

fn trim_delimiters(token: &str, extra: &[char]) -> String {
    token
        .trim_matches(|c: char| {
            !(c.is_ascii_alphanumeric() || c == '_' || c == '-' || extra.contains(&c))
        })
        .to_owned()
}

fn name_token(token: &str) -> String {
    trim_delimiters(token, &[])
}

fn feature_token(token: &str) -> String {
    trim_delimiters(token, &[','])
}

fn flag_value<'a>(flag: &str, token: &'a str) -> Option<&'a str> {
    token
        .strip_prefix(flag)
        .and_then(|rest: &'a str| rest.strip_prefix('='))
}

fn parse_invocation(line: &str) -> Invocation {
    let mut out: Invocation = Invocation::default();
    let mut raw_package: Option<String> = None;
    let mut tokens: std::str::SplitWhitespace<'_> = line.split_whitespace();
    while let Some(token) = tokens.next() {
        let token: &str = token.trim_end_matches('`');
        if token == "--" {
            break;
        }
        match token {
            "-p" | "--package" => raw_package = tokens.next().map(str::to_owned),
            "--test" => out.tests.extend(tokens.next().map(name_token)),
            "--features" | "-F" => out.features.extend(tokens.next().map(feature_token)),
            "--all-features" => out.all_features = true,
            "--no-default-features" => out.no_default_features = true,
            "--lib" | "--bins" | "--bin" | "--example" | "--examples" | "--bench" | "--benches"
            | "--doc" => out.narrowed = true,
            "--all-targets" => out.all_targets = true,
            _ => {
                if let Some(value) = flag_value("--package", token) {
                    raw_package = Some(value.to_owned());
                } else if let Some(value) = flag_value("--test", token) {
                    out.tests.push(name_token(value));
                } else if let Some(value) = flag_value("--features", token) {
                    out.features.push(feature_token(value));
                }
            }
        }
    }
    if let Some(raw) = raw_package.as_deref() {
        out.placeholder = raw.contains(['<', '$', '%', '{']);
        out.package = Some(name_token(raw));
    }
    out
}

fn invocation_selection(facts: &CrateFacts, invocation: &Invocation) -> Selection {
    if invocation.all_features {
        return Selection::All;
    }
    let mut seeds: Vec<String> = Vec::new();
    if !invocation.no_default_features {
        seeds.push("default".to_owned());
    }
    for group in &invocation.features {
        for name in group.split([',', ' ']) {
            let trimmed: &str = name.trim();
            if !trimmed.is_empty() {
                seeds.push(trimmed.to_owned());
            }
        }
    }
    Selection::Named(feature_closure(&facts.features, seeds))
}

fn command_sources(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out: Vec<PathBuf> = Vec::new();
    for named in ["README.md", ".github/CONTRIBUTING.md"] {
        let path: PathBuf = root.join(named);
        if path.is_file() {
            out.push(path);
        }
    }
    let docs: PathBuf = root.join("docs").join("src");
    if docs.is_dir() {
        for entry in walkdir::WalkDir::new(&docs).sort_by_file_name() {
            let entry: walkdir::DirEntry =
                entry.wrap_err_with(|| format!("walking {}", docs.display()))?;
            if entry.file_type().is_file()
                && entry
                    .path()
                    .extension()
                    .and_then(|e: &std::ffi::OsStr| e.to_str())
                    == Some("md")
            {
                out.push(entry.into_path());
            }
        }
    }
    let workflows: PathBuf = root.join(".github").join("workflows");
    if workflows.is_dir() {
        for entry in walkdir::WalkDir::new(&workflows)
            .min_depth(1)
            .max_depth(1)
            .sort_by_file_name()
        {
            let entry: walkdir::DirEntry =
                entry.wrap_err_with(|| format!("walking {}", workflows.display()))?;
            let is_yaml: bool = entry
                .path()
                .extension()
                .and_then(|e: &std::ffi::OsStr| e.to_str())
                .is_some_and(|ext: &str| ext == "yml" || ext == "yaml");
            if entry.file_type().is_file() && is_yaml {
                out.push(entry.into_path());
            }
        }
    }
    Ok(out)
}

fn scan_commands(
    root: &Path,
    by_package: &BTreeMap<&str, &CrateFacts>,
    findings: &mut Vec<Finding>,
) -> Result<usize> {
    let mut scanned: usize = 0;
    for path in command_sources(root)? {
        let label: String = relative_label(root, &path);
        let text: String =
            read_text_bounded(&path, MAX_DOC_BYTES).wrap_err_with(|| format!("reading {label}"))?;
        for (number, line) in text.lines().enumerate() {
            let Some(at) = line.find("cargo test ") else {
                continue;
            };
            let Some(command) = line.get(at..) else {
                continue;
            };
            let invocation: Invocation = parse_invocation(command);
            let Some(package) = invocation.package.clone() else {
                continue;
            };
            if invocation.placeholder {
                continue;
            }
            scanned += 1;
            let whence: String = format!("{label}:{}", number + 1);
            let Some(facts) = by_package.get(package.as_str()) else {
                findings.push(Finding {
                    check: UNKNOWN_PACKAGE,
                    detail: format!(
                        "{whence} runs `cargo test -p {package}`, which is not a workspace \
                         package; a mistyped package name makes the command grade nothing"
                    ),
                });
                continue;
            };
            let selection: Selection = invocation_selection(facts, &invocation);
            report_skipped_tests(facts, &invocation, &selection, &whence, findings);
        }
    }
    Ok(scanned)
}

fn report_skipped_tests(
    facts: &CrateFacts,
    invocation: &Invocation,
    selection: &Selection,
    whence: &str,
    findings: &mut Vec<Finding>,
) {
    if !invocation.tests.is_empty() {
        for wanted in &invocation.tests {
            let Some(file) = facts
                .gated
                .iter()
                .find(|file: &&GatedFile| file.target == TestTarget::Integration(wanted.clone()))
            else {
                continue;
            };
            if selection.satisfies(&file.requirements) {
                continue;
            }
            findings.push(Finding {
                check: SKIPPING_COMMAND,
                detail: format!(
                    "{whence} names `--test {wanted}`, but {}/{} is behind [{}] and this command \
                     does not enable it, so the step compiles zero tests and still reports ok",
                    facts.dir,
                    file.relative,
                    file.requirements
                        .iter()
                        .map(Requirement::label)
                        .collect::<Vec<String>>()
                        .join(", ")
                ),
            });
        }
        return;
    }
    if invocation.narrowed
        || invocation.all_features
        || invocation.no_default_features
        || !invocation.features.is_empty()
    {
        return;
    }
    let hidden: Vec<&GatedFile> = facts.hidden_tests(selection);
    if hidden.is_empty() {
        return;
    }
    let labels: BTreeSet<String> = facts.hidden_labels();
    let shape: &str = if invocation.all_targets {
        "the per-crate command with `--all-targets`, which selects every target but no extra \
         feature, for"
    } else {
        "the bare per-crate command for"
    };
    findings.push(Finding {
        check: SKIPPING_COMMAND,
        detail: format!(
            "{whence} runs {shape} {}, which compiles away {} test-bearing file(s) held behind \
             [{}]; write `{}` instead",
            facts.package,
            hidden.len(),
            render_labels(&labels),
            render_command(&facts.package, &labels)
        ),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_features(pairs: &[(&str, &[&str])]) -> BTreeMap<String, Vec<String>> {
        pairs
            .iter()
            .map(|(name, edges): &(&str, &[&str])| {
                (
                    (*name).to_owned(),
                    edges.iter().map(|e: &&str| (*e).to_owned()).collect(),
                )
            })
            .collect()
    }

    fn crate_facts(defaults: &[(&str, &[&str])], gated: Vec<GatedFile>) -> CrateFacts {
        let features: BTreeMap<String, Vec<String>> = manifest_features(defaults);
        let default_selection: Selection =
            Selection::Named(feature_closure(&features, ["default".to_owned()]));
        CrateFacts {
            package: "disrobe-pass-example".to_owned(),
            dir: "crates/disrobe-pass-example".to_owned(),
            features,
            default_selection,
            gated,
            chain_detector_tests: Some(3),
        }
    }

    fn chain_detector(tests: usize) -> GatedFile {
        GatedFile {
            relative: "src/chain_detector.rs".to_owned(),
            target: TestTarget::Unit,
            requirements: vec![Requirement::Enabled("chain".to_owned())],
            tests,
        }
    }

    #[test]
    fn a_chain_detector_behind_a_non_default_feature_is_hidden() {
        let facts: CrateFacts = crate_facts(
            &[("default", &[]), ("chain", &["disrobe-core/chain"])],
            vec![chain_detector(19)],
        );
        assert_eq!(
            facts.hidden_labels(),
            BTreeSet::from(["chain".to_owned()]),
            "a chain detector the default feature set removes must be reported hidden"
        );
    }

    #[test]
    fn the_same_crate_with_chain_in_default_hides_nothing() {
        let facts: CrateFacts = crate_facts(
            &[("default", &["chain"]), ("chain", &["disrobe-core/chain"])],
            vec![chain_detector(19)],
        );
        assert!(
            facts.hidden_labels().is_empty(),
            "a chain detector the default feature set keeps must not be reported hidden"
        );
    }

    #[test]
    fn a_transitive_default_feature_counts_as_enabled() {
        let facts: CrateFacts = crate_facts(
            &[
                ("default", &["full"]),
                ("full", &["chain", "js"]),
                ("chain", &[]),
                ("js", &[]),
            ],
            vec![chain_detector(4)],
        );
        assert!(facts.hidden_labels().is_empty());
    }

    #[test]
    fn a_gated_file_carrying_no_test_is_not_counted_as_hidden_tests() {
        let facts: CrateFacts = crate_facts(&[("default", &[])], vec![chain_detector(0)]);
        assert!(facts.hidden_labels().is_empty());
    }

    #[test]
    fn the_bare_per_crate_command_is_reported_as_skipping_tests() {
        let facts: CrateFacts = crate_facts(
            &[("default", &[]), ("chain", &[])],
            vec![chain_detector(19)],
        );
        let invocation: Invocation = parse_invocation("cargo test -p disrobe-pass-example");
        let selection: Selection = invocation_selection(&facts, &invocation);
        let mut findings: Vec<Finding> = Vec::new();
        report_skipped_tests(
            &facts,
            &invocation,
            &selection,
            "docs/x.md:1",
            &mut findings,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check, SKIPPING_COMMAND);
        assert!(findings[0].detail.contains("--features chain"));
    }

    #[test]
    fn all_targets_does_not_excuse_a_command_from_the_hidden_test_check() {
        let facts: CrateFacts = crate_facts(
            &[("default", &[]), ("chain", &[])],
            vec![chain_detector(19)],
        );
        let invocation: Invocation =
            parse_invocation("cargo test -p disrobe-pass-example --all-targets");
        let selection: Selection = invocation_selection(&facts, &invocation);
        let mut findings: Vec<Finding> = Vec::new();
        report_skipped_tests(
            &facts,
            &invocation,
            &selection,
            "docs/x.md:1",
            &mut findings,
        );
        assert_eq!(
            findings.len(),
            1,
            "`--all-targets` selects every target but enables no feature, so it compiles a gated \
             test away exactly as the bare command does and must be reported"
        );
        assert_eq!(findings[0].check, SKIPPING_COMMAND);
        assert!(findings[0].detail.contains("--all-targets"));
        assert!(findings[0].detail.contains("--features chain"));
    }

    #[test]
    fn a_doc_test_run_is_still_excused_because_it_genuinely_narrows() {
        let facts: CrateFacts = crate_facts(
            &[("default", &[]), ("chain", &[])],
            vec![chain_detector(19)],
        );
        let invocation: Invocation = parse_invocation("cargo test -p disrobe-pass-example --doc");
        let selection: Selection = invocation_selection(&facts, &invocation);
        let mut findings: Vec<Finding> = Vec::new();
        report_skipped_tests(
            &facts,
            &invocation,
            &selection,
            "docs/x.md:1",
            &mut findings,
        );
        assert!(
            findings.is_empty(),
            "`--doc` runs only doctests, so a gated integration test not running is the flag \
             working rather than a missed surface"
        );
    }

    #[test]
    fn the_same_command_with_the_feature_is_accepted() {
        let facts: CrateFacts = crate_facts(
            &[("default", &[]), ("chain", &[])],
            vec![chain_detector(19)],
        );
        let invocation: Invocation =
            parse_invocation("cargo test -p disrobe-pass-example --features chain");
        let selection: Selection = invocation_selection(&facts, &invocation);
        let mut findings: Vec<Finding> = Vec::new();
        report_skipped_tests(
            &facts,
            &invocation,
            &selection,
            "docs/x.md:1",
            &mut findings,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn a_named_gated_target_without_its_feature_is_reported() {
        let gated: GatedFile = GatedFile {
            relative: "tests/chain_recovery_real.rs".to_owned(),
            target: TestTarget::Integration("chain_recovery_real".to_owned()),
            requirements: vec![Requirement::Enabled("chain".to_owned())],
            tests: 5,
        };
        let facts: CrateFacts = crate_facts(&[("default", &[]), ("chain", &[])], vec![gated]);
        let invocation: Invocation =
            parse_invocation("cargo test -p disrobe-pass-example --test chain_recovery_real");
        let selection: Selection = invocation_selection(&facts, &invocation);
        let mut findings: Vec<Finding> = Vec::new();
        report_skipped_tests(&facts, &invocation, &selection, "ci.yml:1", &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check, SKIPPING_COMMAND);
    }

    #[test]
    fn a_negated_feature_gate_is_satisfied_only_without_that_feature() {
        let gated: GatedFile = GatedFile {
            relative: "tests/slim_bail.rs".to_owned(),
            target: TestTarget::Integration("slim_bail".to_owned()),
            requirements: vec![Requirement::Disabled("wasm".to_owned())],
            tests: 2,
        };
        let facts: CrateFacts = crate_facts(&[("default", &["wasm"]), ("wasm", &[])], vec![gated]);
        let with_defaults: Invocation =
            parse_invocation("cargo test -p disrobe-pass-example --test slim_bail");
        let mut findings: Vec<Finding> = Vec::new();
        report_skipped_tests(
            &facts,
            &with_defaults,
            &invocation_selection(&facts, &with_defaults),
            "ci.yml:1",
            &mut findings,
        );
        assert_eq!(findings.len(), 1);

        let slim: Invocation = parse_invocation(
            "cargo test -p disrobe-pass-example --no-default-features --test slim_bail",
        );
        let mut accepted: Vec<Finding> = Vec::new();
        report_skipped_tests(
            &facts,
            &slim,
            &invocation_selection(&facts, &slim),
            "ci.yml:2",
            &mut accepted,
        );
        assert!(accepted.is_empty());
    }

    #[test]
    fn the_inner_attribute_reader_finds_a_gate_below_an_allow() -> Result<()> {
        let text: &str = "#![allow(clippy::panic)]\n#![cfg(feature = \"chain\")]\n\nfn a() {}\n";
        let requirements: Vec<Requirement> =
            file_requirements(text, "probe.rs")?.ok_or_else(|| eyre!("expected a feature gate"))?;
        assert_eq!(requirements, vec![Requirement::Enabled("chain".to_owned())]);
        Ok(())
    }

    #[test]
    fn a_negated_conjunction_is_read_as_one_requirement_rather_than_three() -> Result<()> {
        let text: &str = "#![cfg(not(all(feature = \"prowl\", feature = \"net-fetch\", \
                          feature = \"server\")))]\nfn a() {}\n";
        let requirements: Vec<Requirement> =
            file_requirements(text, "probe.rs")?.ok_or_else(|| eyre!("expected a feature gate"))?;
        assert_eq!(
            requirements,
            vec![Requirement::NotAll(vec![
                "prowl".to_owned(),
                "net-fetch".to_owned(),
                "server".to_owned(),
            ])]
        );
        Ok(())
    }

    #[test]
    fn a_negated_conjunction_holds_unless_every_named_feature_is_enabled() {
        let requirement: Requirement = Requirement::NotAll(vec![
            "prowl".to_owned(),
            "net-fetch".to_owned(),
            "server".to_owned(),
        ]);
        let named = |features: &[&str]| -> Selection {
            Selection::Named(features.iter().map(|f: &&str| (*f).to_owned()).collect())
        };
        assert!(
            !requirement.holds(&named(&["prowl", "net-fetch", "server"])),
            "all three enabled compiles the file away"
        );
        assert!(
            requirement.holds(&named(&["prowl", "net-fetch"])),
            "one missing feature is enough for the file to compile"
        );
        assert!(requirement.holds(&named(&[])), "the slim build compiles it");
        assert!(
            !requirement.holds(&Selection::All),
            "--all-features compiles the file away"
        );
        assert_eq!(requirement.label(), "!(prowl & net-fetch & server)");
    }

    #[test]
    fn a_negated_disjunction_becomes_one_disabled_requirement_per_feature() -> Result<()> {
        let text: &str = "#![cfg(not(any(feature = \"a\", feature = \"b\")))]\nfn a() {}\n";
        let requirements: Vec<Requirement> =
            file_requirements(text, "probe.rs")?.ok_or_else(|| eyre!("expected a feature gate"))?;
        assert_eq!(
            requirements,
            vec![
                Requirement::Disabled("a".to_owned()),
                Requirement::Disabled("b".to_owned()),
            ]
        );
        Ok(())
    }

    #[test]
    fn a_platform_gate_is_not_a_feature_gate() -> Result<()> {
        let text: &str = "#![cfg(target_os = \"linux\")]\nfn a() {}\n";
        assert!(file_requirements(text, "probe.rs")?.is_none());
        Ok(())
    }

    #[test]
    fn an_all_of_two_features_requires_both() -> Result<()> {
        let text: &str = "#![cfg(all(feature = \"chain\", feature = \"mobile\"))]\n";
        let requirements: Vec<Requirement> =
            file_requirements(text, "probe.rs")?.ok_or_else(|| eyre!("expected a feature gate"))?;
        assert_eq!(requirements.len(), 2);
        assert!(!Selection::Named(BTreeSet::from(["chain".to_owned()])).satisfies(&requirements));
        assert!(
            Selection::Named(BTreeSet::from(["chain".to_owned(), "mobile".to_owned()]))
                .satisfies(&requirements)
        );
        Ok(())
    }

    #[test]
    fn an_unparsed_feature_shape_is_refused_rather_than_ignored() {
        let text: &str = "#![cfg(any(feature = \"chain\", feature = \"js\"))]\n";
        assert!(file_requirements(text, "probe.rs").is_err());
    }

    #[test]
    fn a_gate_inside_an_inline_module_is_not_read_as_a_whole_file_gate() -> Result<()> {
        let text: &str = "pub mod inner {\n    #![cfg(feature = \"chain\")]\n}\n";
        assert!(file_requirements(text, "probe.rs")?.is_none());
        Ok(())
    }

    #[test]
    fn tests_are_counted_from_attributes_not_from_string_literals() {
        let text: &str = "const SAMPLE: &str = \"#[test]\";\n#[test]\nfn probe() {}\n";
        assert_eq!(count_tests(text), 1);
    }

    #[test]
    fn a_placeholder_package_is_skipped() {
        let invocation: Invocation = parse_invocation("cargo test -p <crate>          # comment");
        assert!(invocation.placeholder);
    }

    #[test]
    fn a_package_name_wrapped_in_markdown_delimiters_is_normalized() {
        let invocation: Invocation = parse_invocation("cargo test -p disrobe-pass-lua`.");
        assert_eq!(invocation.package.as_deref(), Some("disrobe-pass-lua"));
        assert!(!invocation.placeholder);
    }

    #[test]
    fn an_equals_form_flag_is_parsed() {
        let invocation: Invocation =
            parse_invocation("cargo test --package=disrobe-cli --features=chain,js");
        assert_eq!(invocation.package.as_deref(), Some("disrobe-cli"));
        assert_eq!(invocation.features, vec!["chain,js".to_owned()]);
    }

    #[test]
    fn libtest_arguments_after_the_separator_are_not_read_as_cargo_flags() {
        let invocation: Invocation = parse_invocation(
            "cargo test -p disrobe-pass-beam --test x -- --nocapture --features nonsense",
        );
        assert!(invocation.features.is_empty());
        assert_eq!(invocation.tests, vec!["x".to_owned()]);
    }
}
