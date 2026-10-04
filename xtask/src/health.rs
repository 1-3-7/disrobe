use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use eyre::{Result, WrapErr, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::fileio::{
    read_bytes_bounded, read_text_bounded, tracked_files, tracked_or_nonignored_files,
};

const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
const MAX_AUTHORED_SOURCE_BYTES: u64 = 8 * 1024 * 1024;

const NON_MEMBER_CRATE_ALLOWLIST: &[(&str, &str)] = &[(
    "fuzz",
    "cargo-fuzz requires its own workspace, so it is built by `cargo fuzz`, never by the root workspace",
)];

const KNOWN_UNWIRED_CRATES: &[(&str, &str)] = &[];

const KNOWN_STANDALONE_BINARIES: &[(&str, &str)] = &[
    (
        "disrobe-cli",
        "the product's own top-level CLI binary; users invoke it directly and no workspace member depends on it as a library",
    ),
    (
        "disrobe-transcode",
        "a standalone tool that rewrites a .dr envelope's hot segment in place; invoked directly, not linked by another crate",
    ),
    (
        "disrobe-validator",
        "the corpus-wide end-to-end validation and benchmark harness; run directly against the sample corpus, not linked by another crate",
    ),
    (
        "xtask",
        "the workspace's own dev-tooling binary (health, regen, release helpers); cargo invokes it directly via `cargo run -p xtask`",
    ),
    (
        "disrobe-bench-head-to-head",
        "a reproducible benchmark binary that runs disrobe against a competing tool and emits committed measured results; run directly, not linked by another crate",
    ),
    (
        "disrobe-bench-native-unpack",
        "a reproducible benchmark binary over the native packer corpus; run directly, not linked by another crate",
    ),
    (
        "disrobe-evidence-mba",
        "a ground-truth corpus generator for mixed-boolean-arithmetic recovery, deliberately linking no recovery crate so it cannot grade its own output; run directly, not linked by another crate",
    ),
];

#[derive(Debug, Default)]
pub(crate) struct Report {
    findings: Vec<Finding>,
    facts: BTreeMap<String, Value>,
}

#[derive(Debug)]
struct Finding {
    check: &'static str,
    detail: String,
}

impl Report {
    fn fail(&mut self, check: &'static str, detail: String) {
        self.findings.push(Finding { check, detail });
    }

    fn fact(&mut self, key: &str, value: Value) {
        self.facts.insert(key.to_string(), value);
    }

    fn to_json(&self) -> Value {
        json!({
            "healthy": self.findings.is_empty(),
            "findings": self.findings.iter().map(|f: &Finding| json!({
                "check": f.check,
                "detail": f.detail,
            })).collect::<Vec<Value>>(),
            "facts": self.facts.iter().map(|(k, v)| (k.clone(), v.clone())).collect::<serde_json::Map<String, Value>>(),
        })
    }
}

pub(crate) fn run(root: &Path, as_json: bool) -> Result<()> {
    let mut report: Report = Report::default();

    let root_manifest: String = read_text_bounded(&root.join("Cargo.toml"), MAX_MANIFEST_BYTES)
        .wrap_err("reading the workspace manifest")?;
    let root_doc: toml::Value =
        toml::from_str(&root_manifest).wrap_err("parsing the workspace manifest")?;

    let members: BTreeSet<String> = workspace_members(&root_doc);
    let crate_dirs: BTreeSet<String> = discover_crate_dirs(root)?;

    check_membership(&members, &crate_dirs, &mut report);
    check_members_exist(root, &members, &mut report);

    let member_manifests: BTreeMap<String, toml::Value> = load_member_manifests(root, &members)?;
    let workspace_version: String = workspace_package_version(&root_doc);

    check_internal_versions(
        &root_doc,
        &member_manifests,
        &workspace_version,
        root,
        &mut report,
    );
    check_unused_workspace_deps(root, &root_doc, &member_manifests, &mut report);
    check_unwired_members(root, &member_manifests, &mut report);
    check_layering(&member_manifests, &mut report);
    match crate::unused_deps::find(root) {
        Ok(findings) => {
            for finding in &findings {
                report.fail("unused-dependency", finding.render());
            }
        }
        Err(error) => report.fail(
            "unused-dependency",
            format!("the unused-dependency scan could not run: {error:#}"),
        ),
    }
    check_generator_disjointness(root, &mut report);
    check_feature_hidden_tests(root, &mut report);
    check_wasm_build_records(root, &mut report);
    check_private_references(root, &mut report);
    check_host_paths(root, &mut report);
    check_as_char_casts(root, &mut report);
    check_shell_catalog(root, &mut report);
    check_tracked_paths(root, &mut report);
    check_pyarmor_serial_footprint(root, &mut report);
    check_pycdc_blobs(root, &mut report);
    check_prose_tells(root, &mut report);
    check_readme_family_evidence(root, &mut report);
    check_authored_sources(root, &mut report);

    report.fact("workspace_members", json!(members.len()));
    report.fact("crate_directories", json!(crate_dirs.len()));
    report.fact("workspace_version", json!(workspace_version));

    if !as_json
        && let Some(edges) = report
            .facts
            .get("layering_violations")
            .and_then(Value::as_array)
    {
        println!(
            "xtask health: layering, report only: {} dependency edge(s) point at the same or a higher level",
            edges.len()
        );
        for edge in edges.iter().filter_map(Value::as_str) {
            println!("  {edge}");
        }
    }

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report.to_json())
                .wrap_err("rendering the health report")?
        );
    }

    if report.findings.is_empty() {
        if !as_json {
            println!(
                "xtask health: workspace coherent ({} member(s), {} crate directory(ies), every internal version at {}, no unused workspace dependency)",
                members.len(),
                crate_dirs.len(),
                workspace_version
            );
        }
        return Ok(());
    }

    let rendered: String = report
        .findings
        .iter()
        .map(|f: &Finding| format!("[{}] {}", f.check, f.detail))
        .collect::<Vec<String>>()
        .join("\n  ");
    bail!(
        "xtask health: {} coherence failure(s):\n  {rendered}",
        report.findings.len()
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoredSources {
    source: Vec<AuthoredSource>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoredSource {
    path: String,
    sha256: String,
}

fn check_authored_sources(root: &Path, report: &mut Report) {
    const CHECK: &str = "authored-sources";
    let manifest: PathBuf = root.join("crates/disrobe-testkit/data/authored_sources.toml");
    let text: String = match read_text_bounded(&manifest, MAX_MANIFEST_BYTES) {
        Ok(text) => text,
        Err(error) => {
            report.fail(
                CHECK,
                format!("cannot read authored-source manifest: {error:#}"),
            );
            return;
        }
    };
    let entries: AuthoredSources = match toml::from_str(&text) {
        Ok(entries) => entries,
        Err(error) => {
            report.fail(
                CHECK,
                format!("cannot parse authored-source manifest: {error}"),
            );
            return;
        }
    };
    let tracked: BTreeSet<String> = match tracked_files(root) {
        Ok(files) => files,
        Err(error) => {
            report.fail(CHECK, format!("cannot list tracked files: {error:#}"));
            return;
        }
    };
    let (count, problems): (usize, Vec<String>) =
        audit_authored_sources(root, entries.source, &tracked);
    for problem in problems {
        report.fail(CHECK, problem);
    }
    report.fact("authored_sources", json!(count));
}

fn audit_authored_sources(
    root: &Path,
    entries: Vec<AuthoredSource>,
    tracked: &BTreeSet<String>,
) -> (usize, Vec<String>) {
    let canonical_root: Option<PathBuf> = root.canonicalize().ok();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut problems: Vec<String> = Vec::new();
    for entry in entries {
        let path: &str = &entry.path;
        let invalid: bool = path.is_empty()
            || path.contains(':')
            || Path::new(path).is_absolute()
            || path.contains('\\')
            || path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..");
        if invalid || !seen.insert(path.to_owned()) {
            problems.push(format!("invalid or duplicate authored source path: {path}"));
            continue;
        }
        if !is_sha256_hex(&entry.sha256) {
            problems.push(format!("{path} has invalid sha256"));
            continue;
        }
        if !tracked.contains(path) {
            problems.push(format!("{path} is not tracked"));
            continue;
        }
        let candidate: PathBuf = root.join(path);
        if !candidate.is_file() {
            problems.push(format!("{path} is missing or not a file"));
            continue;
        }
        let resolved: PathBuf = match candidate.canonicalize() {
            Ok(resolved) => resolved,
            Err(error) => {
                problems.push(format!("cannot resolve {path}: {error}"));
                continue;
            }
        };
        if canonical_root
            .as_ref()
            .is_none_or(|canonical_root| !resolved.starts_with(canonical_root))
        {
            problems.push(format!("{path} resolves outside the workspace"));
            continue;
        }
        match read_bytes_bounded(&resolved, MAX_AUTHORED_SOURCE_BYTES) {
            Ok(bytes) => {
                let digest: String = format!("{:x}", Sha256::digest(&bytes));
                if digest != entry.sha256 {
                    problems.push(format!("{path} sha256 drift"));
                }
            }
            Err(error) => problems.push(format!("cannot read {path}: {error:#}")),
        }
    }
    (seen.len(), problems)
}

fn check_feature_hidden_tests(root: &Path, report: &mut Report) {
    const CHECK: &str = "feature-hidden-test-surface";
    let audit: crate::feature_gated_tests::Audit = match crate::feature_gated_tests::audit(root) {
        Ok(found) => found,
        Err(error) => {
            report.fail(
                CHECK,
                format!("could not audit the feature-gated test surface: {error}"),
            );
            return;
        }
    };
    for finding in &audit.findings {
        report.fail(finding.check, finding.detail.clone());
    }
    report.fact(
        "feature_hidden_test_surface_crates",
        json!(audit.hidden_crates),
    );
    report.fact("chain_detectors", json!(audit.chain_detectors));
    report.fact(
        "chain_tests_hidden_by_default",
        json!(audit.chain_tests_hidden_by_default),
    );
    report.fact(
        "verification_commands_scanned",
        json!(audit.commands_scanned),
    );
}

fn check_generator_disjointness(root: &Path, report: &mut Report) {
    const CHECK: &str = "corpus-generator-disjointness";
    let verdicts: Vec<crate::graph_disjointness::Verdict> =
        match crate::graph_disjointness::audit(root) {
            Ok(found) => found,
            Err(error) => {
                report.fail(
                    CHECK,
                    format!("could not resolve the dependency graph: {error}"),
                );
                return;
            }
        };
    let mut audited: Vec<Value> = Vec::with_capacity(verdicts.len());
    for verdict in &verdicts {
        let linked: Vec<String> = verdict
            .linked_recovery_packages
            .iter()
            .cloned()
            .collect::<Vec<String>>();
        if !linked.is_empty() {
            report.fail(
                CHECK,
                format!(
                    "{} resolves to the recovery package(s) it grades: {}",
                    verdict.generator,
                    linked.join(", ")
                ),
            );
        }
        audited.push(json!({
            "generator": verdict.generator,
            "resolved_dependencies": verdict.resolved_dependencies,
            "linked_recovery_packages": linked,
        }));
    }
    report.fact("corpus_generators", json!(audited));
}

const PRIVATE_REFERENCE_EXEMPT: [&str; 1] = [".gitignore"];
const PRIVATE_DIR: &str = concat!(".develop", "er/");
const MAX_SCANNED_TEXT_BYTES: u64 = 8 * 1024 * 1024;
const FINDING_ID_PREFIXES: [&str; 9] = [
    "SEC-", "HYG-", "BUG-", "FEAT-", "CPF-", "NAT-", "WIRE-", "TEST-", "BLN-",
];

fn check_pyarmor_serial_footprint(root: &Path, report: &mut Report) {
    const CHECK: &str = "pyarmor-serial-footprint";
    use crate::licence_footprint::{
        Footprint, PINNED_FILE_COUNT, PINNED_SET_SHA256, PYARMOR_SERIAL_SHA256, footprint,
    };
    let found: Footprint = match tracked_or_nonignored_files(root)
        .and_then(|files: BTreeSet<String>| footprint(root, &files, PYARMOR_SERIAL_SHA256))
    {
        Ok(found) => found,
        Err(error) => {
            report.fail(
                CHECK,
                format!("could not scan tracked files for the PyArmor Pro serial: {error:#}"),
            );
            return;
        }
    };
    report.fact("pyarmor_serial_files", json!(found.files.len()));
    if found.files.len() == PINNED_FILE_COUNT && found.set_sha256 == PINNED_SET_SHA256 {
        return;
    }
    let files: String = found.masked_files(PYARMOR_SERIAL_SHA256).join("; ");
    if found.files.len() > PINNED_FILE_COUNT {
        report.fail(
            CHECK,
            format!(
                "{} files carry the PyArmor Pro serial, {PINNED_FILE_COUNT} are allowed; build no new fixture under that licence and keep the serial out of new files: {files}",
                found.files.len()
            ),
        );
    } else {
        report.fail(
            CHECK,
            format!(
                "the files carrying the PyArmor Pro serial changed ({} now, {PINNED_FILE_COUNT} pinned); if one was removed, pin the count {} and set digest {} in xtask/src/licence_footprint.rs: {files}",
                found.files.len(),
                found.files.len(),
                found.set_sha256
            ),
        );
    }
}

fn check_pycdc_blobs(root: &Path, report: &mut Report) {
    const CHECK: &str = "pycdc-blobs";
    let scanned: Result<(BTreeSet<String>, BTreeMap<String, String>)> =
        crate::pycdc_blobs::load_list(root).and_then(|listed: BTreeSet<String>| {
            Ok((listed, crate::pycdc_blobs::working_tree_blob_ids(root)?))
        });
    match scanned {
        Ok((listed, blobs)) => report_pycdc_blobs(&blobs, &listed, report),
        Err(error) => report.fail(
            CHECK,
            format!("could not compare tracked files with the pycdc blob list: {error:#}"),
        ),
    }
}

fn report_pycdc_blobs(
    blobs: &BTreeMap<String, String>,
    listed: &BTreeSet<String>,
    report: &mut Report,
) {
    let found: Vec<String> = crate::pycdc_blobs::listed_files(blobs, listed);
    report.fact("pycdc_blob_files", json!(found.len()));
    if !found.is_empty() {
        report.fail(
            "pycdc-blobs",
            format!(
                "{} file(s) are byte-identical to files in pycdc's GPL-3.0 tree ({}); remove them and author a replacement: {}",
                found.len(),
                crate::pycdc_blobs::LIST_PATH,
                found.join("; ")
            ),
        );
    }
}

fn check_prose_tells(root: &Path, report: &mut Report) {
    const CHECK: &str = "prose-tells";
    let scan: crate::prose_tells::TellScan = match tracked_or_nonignored_files(root)
        .and_then(|files: BTreeSet<String>| crate::prose_tells::scan(root, &files))
    {
        Ok(scan) => scan,
        Err(error) => {
            report.fail(
                CHECK,
                format!("could not scan public text for AI tells: {error:#}"),
            );
            return;
        }
    };
    report.fact("prose_tells", json!(scan.prose_hits.len()));
    report.fact("rust_source_tells", json!(scan.rust_hits));
    if !scan.prose_hits.is_empty() {
        report.fail(
            CHECK,
            format!(
                "{} AI tell(s) or attribution line(s) in public prose; rewrite each in plain technical voice: {}",
                scan.prose_hits.len(),
                scan.prose_hits.join("; ")
            ),
        );
    }
    let ceiling: usize = crate::prose_tells::RUST_SOURCE_CEILING;
    if scan.rust_hits > ceiling {
        report.fail(
            CHECK,
            format!(
                "{} AI-tell words in crate Rust sources, the ceiling is {ceiling}; rewrite the new ones, the ceiling in xtask/src/prose_tells.rs only goes down",
                scan.rust_hits
            ),
        );
    }
}

const README_FAMILY_SECTION: &str = "## What it recovers";
const README_EVIDENCE_COLUMN: &str = "Evidence";
const REAL_LABEL: &str = "`real`";
const SYNTHETIC_LABEL: &str = "`synthetic`";
const MAX_README_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Default, PartialEq, Eq)]
struct FamilyEvidenceAudit {
    rows: usize,
    problems: Vec<String>,
}

fn check_readme_family_evidence(root: &Path, report: &mut Report) {
    const CHECK: &str = "readme-family-evidence";
    let readme: String = match read_text_bounded(&root.join("README.md"), MAX_README_BYTES) {
        Ok(text) => text,
        Err(error) => {
            report.fail(CHECK, format!("could not read README.md: {error:#}"));
            return;
        }
    };
    match audit_family_evidence(&readme, |target: &str| root.join(target).is_file()) {
        Ok(audit) => {
            report.fact("readme_family_rows", json!(audit.rows));
            for problem in audit.problems {
                report.fail(CHECK, problem);
            }
        }
        Err(problem) => report.fail(CHECK, problem),
    }
}

fn audit_family_evidence(
    readme: &str,
    exists: impl Fn(&str) -> bool,
) -> std::result::Result<FamilyEvidenceAudit, String> {
    let mut section = readme
        .lines()
        .skip_while(|line: &&str| line.trim_end() != README_FAMILY_SECTION);
    if section.next().is_none() {
        return Err(format!(
            "README.md has no `{README_FAMILY_SECTION}` section, so no family row can be checked for evidence"
        ));
    }
    let table: Vec<&str> = section
        .take_while(|line: &&str| !line.starts_with("## "))
        .skip_while(|line: &&str| !line.starts_with('|'))
        .take_while(|line: &&str| line.starts_with('|'))
        .collect();
    let [header, _separator, rows @ ..] = table.as_slice() else {
        return Err(format!(
            "README.md has no family table under `{README_FAMILY_SECTION}`"
        ));
    };
    let columns: Vec<&str> = table_cells(header);
    let Some(evidence_at): Option<usize> = columns
        .iter()
        .position(|column: &&str| *column == README_EVIDENCE_COLUMN)
    else {
        return Err(format!(
            "the family table under `{README_FAMILY_SECTION}` has no `{README_EVIDENCE_COLUMN}` column, so no row states whether a real fixture grades it"
        ));
    };
    let mut problems: Vec<String> = Vec::new();
    for row in rows {
        let cells: Vec<&str> = table_cells(row);
        let family: &str = cells.first().copied().unwrap_or_default();
        let Some(evidence): Option<&str> = cells
            .get(evidence_at)
            .copied()
            .filter(|_: &&str| cells.len() == columns.len())
        else {
            problems.push(format!(
                "README.md family row `{family}` has {} cells and the header has {}",
                cells.len(),
                columns.len()
            ));
            continue;
        };
        problems.extend(row_evidence_problems(family, evidence, &exists));
    }
    Ok(FamilyEvidenceAudit {
        rows: rows.len(),
        problems,
    })
}

fn table_cells(line: &str) -> Vec<&str> {
    let trimmed: &str = line.trim();
    let inner: &str = trimmed.strip_prefix('|').unwrap_or(trimmed);
    let inner: &str = inner.strip_suffix('|').unwrap_or(inner);
    inner.split('|').map(str::trim).collect()
}

fn link_targets(cell: &str) -> Vec<&str> {
    let mut targets: Vec<&str> = Vec::new();
    let mut rest: &str = cell;
    while let Some(open) = rest.find("](") {
        let after: &str = &rest[open + 2..];
        let Some(close) = after.find(')') else {
            break;
        };
        targets.push(&after[..close]);
        rest = &after[close + 1..];
    }
    targets
}

fn is_graded_evidence(path: &str) -> bool {
    let extension: Option<&std::ffi::OsStr> = Path::new(path).extension();
    let has = |wanted: &str| extension.is_some_and(|found: &std::ffi::OsStr| found == wanted);
    (path.starts_with("evidence/results/") && has("md"))
        || (path.starts_with("crates/") && path.contains("/tests/") && has("rs"))
}

fn row_evidence_problems(
    family: &str,
    evidence: &str,
    exists: &impl Fn(&str) -> bool,
) -> Vec<String> {
    let mut problems: Vec<String> = Vec::new();
    let mut graded: usize = 0;
    for target in link_targets(evidence) {
        if target.contains("://") {
            continue;
        }
        let path: &str = target.split('#').next().unwrap_or_default();
        if !exists(path) {
            problems.push(format!(
                "README.md family row `{family}` links `{path}` as evidence, which does not exist"
            ));
        } else if is_graded_evidence(path) {
            graded += 1;
        }
    }
    let real: bool = evidence.contains(REAL_LABEL);
    if real && graded == 0 {
        problems.push(format!(
            "README.md family row `{family}` is labelled {REAL_LABEL} but links no existing evidence/results/*.md descriptor or crates/*/tests/*.rs test that grades a real fixture"
        ));
    } else if !real && !evidence.contains(SYNTHETIC_LABEL) {
        problems.push(format!(
            "README.md family row `{family}` has neither a {REAL_LABEL} label with a linked graded fixture nor a {SYNTHETIC_LABEL} label"
        ));
    }
    problems
}

fn check_tracked_paths(root: &Path, report: &mut Report) {
    const CHECK: &str = "tracked-paths";
    match crate::tracked_paths::inventory(root) {
        Ok(inventory) => {
            report.fact("tracked_paths", json!(inventory.kinds.len()));
            if !inventory.unclassified.is_empty() {
                report.fail(
                    CHECK,
                    format!(
                        "{} tracked path(s) match no rule in xtask/src/tracked_paths.rs; add a rule or move the file: {}",
                        inventory.unclassified.len(),
                        inventory.unclassified.join(", ")
                    ),
                );
            }
            if !inventory.ignored_but_tracked.is_empty() {
                report.fail(
                    CHECK,
                    format!(
                        "{} tracked path(s) are also matched by an ignore rule; narrow the rule or add a negation in .gitignore: {}",
                        inventory.ignored_but_tracked.len(),
                        inventory.ignored_but_tracked.join(", ")
                    ),
                );
            }
        }
        Err(error) => report.fail(
            CHECK,
            format!("could not classify tracked paths: {error:#}"),
        ),
    }
}

fn check_host_paths(root: &Path, report: &mut Report) {
    const CHECK: &str = "host-path";
    let scan: crate::host_paths::HomeScan = match tracked_or_nonignored_files(root)
        .and_then(|files: BTreeSet<String>| crate::host_paths::scan_homes(root, &files))
    {
        Ok(scan) => scan,
        Err(error) => {
            report.fail(
                CHECK,
                format!("could not scan tracked files for home directories: {error:#}"),
            );
            return;
        }
    };
    report.fact("host_home_paths", json!(scan.unexpected.len()));
    report.fact(
        "host_install_directory_paths",
        json!(scan.unexpected_install_directories.len()),
    );
    if !scan.unexpected.is_empty() {
        report.fail(
            CHECK,
            format!(
                "{} home directory path(s) in tracked files; rebuild the artifact with a prefix map or replace the path with a same-length neutral one and record it: {}",
                scan.unexpected.len(),
                scan.unexpected.join("; ")
            ),
        );
    }
    if !scan.stale_allowances.is_empty() {
        report.fail(
            CHECK,
            format!(
                "{} allowed home path(s) no longer occur; remove them from the allow-list: {}",
                scan.stale_allowances.len(),
                scan.stale_allowances.join("; ")
            ),
        );
    }
    if !scan.unexpected_install_directories.is_empty() {
        report.fail(
            CHECK,
            format!(
                "{} drive-rooted install-directory path(s) in Rust sources; use PATH or an explicit environment override, or record an exact synthetic fixture allowance: {}",
                scan.unexpected_install_directories.len(),
                scan.unexpected_install_directories.join("; ")
            ),
        );
    }
    if !scan.stale_install_directory_allowances.is_empty() {
        report.fail(
            CHECK,
            format!(
                "{} allowed drive-rooted install-directory path(s) no longer occur; remove them from the allow-list: {}",
                scan.stale_install_directory_allowances.len(),
                scan.stale_install_directory_allowances.join("; ")
            ),
        );
    }
}

fn check_as_char_casts(root: &Path, report: &mut Report) {
    const CHECK: &str = "as-char-cast";
    let scan: crate::as_char::AsCharScan = match crate::as_char::scan(root) {
        Ok(scan) => scan,
        Err(error) => {
            report.fail(
                CHECK,
                format!("could not scan pass sources for `as char` casts: {error:#}"),
            );
            return;
        }
    };
    report.fact("as_char_sites", json!(scan.sites));
    report.fact("as_char_latin1_allowances", json!(scan.latin1_allowances));
    if !scan.unlisted.is_empty() {
        report.fail(
            CHECK,
            format!(
                "{} `as char` cast(s) on byte data are not in {}; decode the bytes with an explicit encoding, or list the site there with a one-line reason: {}",
                scan.unlisted.len(),
                crate::as_char::ALLOW_LIST,
                scan.unlisted.join("; ")
            ),
        );
    }
    if !scan.stale.is_empty() {
        report.fail(
            CHECK,
            format!(
                "{} allowed `as char` site(s) no longer occur; remove or re-anchor them in {}: {}",
                scan.stale.len(),
                crate::as_char::ALLOW_LIST,
                scan.stale.join("; ")
            ),
        );
    }
    if !scan.invalid.is_empty() {
        report.fail(
            CHECK,
            format!(
                "{} malformed `as char` allowance(s) in {}: {}",
                scan.invalid.len(),
                crate::as_char::ALLOW_LIST,
                scan.invalid.join("; ")
            ),
        );
    }
}

fn check_shell_catalog(root: &Path, report: &mut Report) {
    const CHECK: &str = "shell-catalog-evidence";
    let scan: crate::shell_catalog::ShellCatalogScan = match crate::shell_catalog::scan(root) {
        Ok(scan) => scan,
        Err(error) => {
            report.fail(
                CHECK,
                format!(
                    "could not compare {} with {}: {error:#}",
                    crate::shell_catalog::MANIFEST,
                    crate::shell_catalog::CATALOG_DOC
                ),
            );
            return;
        }
    };
    report.fact("shell_catalog_families", json!(scan.families));
    if !scan.problems.is_empty() {
        report.fail(
            CHECK,
            format!(
                "{} shell family grading claim(s) disagree with their evidence; list each family under the grading its manifest status records: {}",
                scan.problems.len(),
                scan.problems.join("; ")
            ),
        );
    }
}

fn check_private_references(root: &Path, report: &mut Report) {
    const CHECK: &str = "private-reference";
    let files: BTreeSet<String> = match tracked_or_nonignored_files(root) {
        Ok(files) => files,
        Err(error) => {
            report.fail(CHECK, format!("could not list tracked files: {error:#}"));
            return;
        }
    };
    check_private_references_with_files(root, &files, report);
}

fn check_private_references_with_files(root: &Path, files: &BTreeSet<String>, report: &mut Report) {
    const CHECK: &str = "private-reference";
    let mut hits: Vec<String> = Vec::new();
    for file in files {
        if PRIVATE_REFERENCE_EXEMPT.contains(&file.as_str()) {
            continue;
        }
        let Ok(bytes) = read_bytes_bounded(&root.join(file), MAX_SCANNED_TEXT_BYTES) else {
            continue;
        };
        if bytes.iter().take(8192).any(|byte: &u8| *byte == 0) {
            continue;
        }
        let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&bytes);
        for found in private_references(&text) {
            hits.push(format!("{file}: {found}"));
        }
    }
    report.fact("private_references", json!(hits.len()));
    if !hits.is_empty() {
        report.fail(
            CHECK,
            format!(
                "{} private path or internal work-item reference(s) in tracked files; describe the fact instead of citing a private file or an internal id: {}",
                hits.len(),
                hits.join("; ")
            ),
        );
    }
}

fn private_references(text: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    if text.contains(PRIVATE_DIR) {
        found.push(format!("{PRIVATE_DIR} path"));
    }
    let bytes: &[u8] = text.as_bytes();
    for (start, _) in text.char_indices() {
        if start > 0 && bytes[start - 1].is_ascii_alphanumeric() {
            continue;
        }
        let rest: &str = &text[start..];
        if let Some(id) = internal_id(rest) {
            found.push(id);
        }
    }
    found
}

fn internal_id(rest: &str) -> Option<String> {
    let digits_then_boundary = |tail: &str, min: usize, max: usize| -> Option<usize> {
        let count: usize = tail.bytes().take_while(u8::is_ascii_digit).count();
        let boundary: bool = tail
            .as_bytes()
            .get(count)
            .is_none_or(|byte: &u8| !byte.is_ascii_alphanumeric());
        (count >= min && count <= max && boundary).then_some(count)
    };
    if let Some(tail) = rest.strip_prefix("T-P")
        && let Some(phase) = tail.bytes().next().filter(u8::is_ascii_digit)
        && tail.as_bytes().get(1) == Some(&b'-')
        && let Some(count) = digits_then_boundary(&tail[2..], 1, 3)
    {
        return Some(format!("T-P{}-{}", char::from(phase), &tail[2..2 + count]));
    }
    if let Some(tail) = rest.strip_prefix("D-0")
        && let Some(count) = digits_then_boundary(tail, 2, 2)
    {
        return Some(format!("D-0{}", &tail[..count]));
    }
    for prefix in FINDING_ID_PREFIXES {
        if let Some(tail) = rest.strip_prefix(prefix)
            && let Some(count) = digits_then_boundary(tail, 3, 3)
        {
            return Some(format!("{prefix}{}", &tail[..count]));
        }
    }
    None
}

const WASM_BUILD_RECORDS_SCHEMA: &str = "disrobe.wasm.build-records/v2";
const MAX_WASM_RECORDS_BYTES: u64 = 256 * 1024;
const MAX_WASM_ARTIFACT_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
struct WasmRecordSet {
    directory: &'static str,
    artifact_dir: Option<&'static str>,
    name_prefix: &'static str,
}

const WASM_RECORD_SETS: [WasmRecordSet; 2] = [
    WasmRecordSet {
        directory: "corpus/wasm/obf",
        artifact_dir: Some("real"),
        name_prefix: "",
    },
    WasmRecordSet {
        directory: "crates/disrobe-pass-wasm-deob/tests/fixtures",
        artifact_dir: None,
        name_prefix: "cff_",
    },
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WasmBuildRecords {
    schema: String,
    artifact: Vec<WasmBuildRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WasmBuildRecord {
    path: String,
    sha256: String,
    origin: WasmOrigin,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WasmOrigin {
    Built(WasmBuilt),
    Authored(WasmAuthored),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WasmBuilt {
    source: String,
    toolchain: String,
    command: String,
    rebuilt_sha256: String,
    difference: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WasmAuthored {
    note: String,
}

#[derive(Debug, Default)]
struct WasmRecordAudit {
    rebuilt_identical: usize,
    rebuild_differences: usize,
    authored: usize,
    unrecorded: Vec<String>,
    problems: Vec<String>,
}

fn check_wasm_build_records(root: &Path, report: &mut Report) {
    const INTEGRITY: &str = "wasm-build-record";
    let public_files: BTreeSet<String> = match tracked_or_nonignored_files(root) {
        Ok(files) => files,
        Err(error) => {
            report.fail(
                INTEGRITY,
                format!("could not list tracked wasm artifacts: {error:#}"),
            );
            return;
        }
    };
    check_wasm_build_records_with_files(root, &public_files, report);
}

fn check_wasm_build_records_with_files(
    root: &Path,
    public_files: &BTreeSet<String>,
    report: &mut Report,
) {
    const INTEGRITY: &str = "wasm-build-record";
    const RATCHET: &str = "wasm-unrecorded-artifact";
    let mut totals: WasmRecordAudit = WasmRecordAudit::default();
    for set in WASM_RECORD_SETS {
        match audit_wasm_record_set(root, set, Some(public_files)) {
            Ok(audit) => {
                totals.rebuilt_identical += audit.rebuilt_identical;
                totals.rebuild_differences += audit.rebuild_differences;
                totals.authored += audit.authored;
                totals.unrecorded.extend(audit.unrecorded);
                totals.problems.extend(audit.problems);
            }
            Err(error) => report.fail(
                INTEGRITY,
                format!("could not audit {}/records.toml: {error:#}", set.directory),
            ),
        }
    }
    for problem in totals.problems {
        report.fail(INTEGRITY, problem);
    }
    if !totals.unrecorded.is_empty() {
        report.fail(
            RATCHET,
            format!(
                "{} tracked or nonignored wasm artifact(s) in the wasm corpus and cff fixture scan have no build record: {}; the unrecorded count stays at zero, so record each one in its records.toml with the source, toolchain, command and rebuilt sha256 that produce it, or as hand-written WAT with a note",
                totals.unrecorded.len(),
                totals.unrecorded.join(", ")
            ),
        );
    }
    report.fact(
        "wasm_build_records",
        json!({
            "rebuilt_identical": totals.rebuilt_identical,
            "rebuild_differences": totals.rebuild_differences,
            "authored": totals.authored,
            "unrecorded": totals.unrecorded.len(),
            "scanned_sets": WASM_RECORD_SETS.iter().map(|set: &WasmRecordSet| set.directory).collect::<Vec<&str>>(),
        }),
    );
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte: u8| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_relative_inside(path: &str) -> bool {
    !path.is_empty()
        && Path::new(path)
            .components()
            .all(|component: Component<'_>| matches!(component, Component::Normal(_)))
}

fn audit_wasm_record_set(
    root: &Path,
    set: WasmRecordSet,
    public_files: Option<&BTreeSet<String>>,
) -> Result<WasmRecordAudit> {
    let directory: PathBuf = root.join(set.directory);
    let records_path: PathBuf = directory.join("records.toml");
    let text: String = read_text_bounded(&records_path, MAX_WASM_RECORDS_BYTES)?;
    let records: WasmBuildRecords =
        toml::from_str(&text).wrap_err_with(|| format!("parsing {}", records_path.display()))?;
    let label: String = format!("{}/records.toml", set.directory);
    let mut audit: WasmRecordAudit = WasmRecordAudit::default();
    if records.schema != WASM_BUILD_RECORDS_SCHEMA {
        audit.problems.push(format!(
            "{label} declares schema {}, not {WASM_BUILD_RECORDS_SCHEMA}",
            records.schema
        ));
    }
    let mut recorded: BTreeSet<&str> = BTreeSet::new();
    for record in &records.artifact {
        let path: &str = record.path.as_str();
        if !recorded.insert(path) {
            audit.problems.push(format!("{label} records {path} twice"));
            continue;
        }
        if !is_relative_inside(path) {
            audit.problems.push(format!(
                "{label} records {path}, which is not a relative path inside {}",
                set.directory
            ));
            continue;
        }
        match read_bytes_bounded(&directory.join(path), MAX_WASM_ARTIFACT_BYTES) {
            Ok(bytes) => {
                let digest: String = format!("{:x}", Sha256::digest(&bytes));
                if digest != record.sha256 {
                    audit.problems.push(format!(
                        "{label}: {path} hashes to {digest}, not the recorded {}; a test refuses to run it until the record names the build that produced these bytes",
                        record.sha256
                    ));
                }
            }
            Err(error) => audit
                .problems
                .push(format!("{label}: {path} cannot be read: {error:#}")),
        }
        match &record.origin {
            WasmOrigin::Built(built) => {
                let source_path: String =
                    format!("{}/{source}", set.directory, source = built.source);
                if !is_relative_inside(&built.source)
                    || !directory.join(&built.source).is_file()
                    || public_files
                        .is_some_and(|files: &BTreeSet<String>| !files.contains(&source_path))
                {
                    audit.problems.push(format!(
                        "{label}: {path} names the source {}, which is not committed beside it",
                        built.source
                    ));
                }
                if built.toolchain.trim().is_empty() || !built.command.contains(&built.source) {
                    audit.problems.push(format!(
                        "{label}: {path} must record its toolchain and a command that compiles {}",
                        built.source
                    ));
                }
                if !is_sha256_hex(&built.rebuilt_sha256) {
                    audit.problems.push(format!(
                        "{label}: {path} records rebuilt_sha256 {:?}, which is not a lowercase sha256 digest",
                        built.rebuilt_sha256
                    ));
                }
                let identical: bool = built.rebuilt_sha256 == record.sha256;
                let difference: Option<&str> = built
                    .difference
                    .as_deref()
                    .map(str::trim)
                    .filter(|note: &&str| !note.is_empty());
                match (identical, difference) {
                    (true, None) => audit.rebuilt_identical += 1,
                    (false, Some(_)) => audit.rebuild_differences += 1,
                    (true, Some(_)) => audit.problems.push(format!(
                        "{label}: {path} rebuilds to its committed bytes but still records a difference"
                    )),
                    (false, None) => audit.problems.push(format!(
                        "{label}: {path} rebuilds to {}, not its committed {}, and records no difference; describe it, or regenerate the file from the recorded command",
                        built.rebuilt_sha256, record.sha256
                    )),
                }
            }
            WasmOrigin::Authored(authored) => {
                if authored.note.trim().is_empty() {
                    audit.problems.push(format!(
                        "{label}: {path} is recorded as hand-written without a note"
                    ));
                } else {
                    audit.authored += 1;
                }
            }
        }
    }
    let artifact_directory: PathBuf = match set.artifact_dir {
        Some(name) => directory.join(name),
        None => directory,
    };
    let mut committed: BTreeSet<String> = BTreeSet::new();
    for entry in std::fs::read_dir(&artifact_directory)
        .wrap_err_with(|| format!("listing {}", artifact_directory.display()))?
    {
        let entry: std::fs::DirEntry =
            entry.wrap_err_with(|| format!("listing {}", artifact_directory.display()))?;
        let Ok(name) = entry.file_name().into_string() else {
            audit.problems.push(format!(
                "{} holds a file whose name is not UTF-8",
                artifact_directory.display()
            ));
            continue;
        };
        let loaded_by_graders: bool =
            Path::new(&name)
                .extension()
                .is_some_and(|extension: &std::ffi::OsStr| {
                    extension.eq_ignore_ascii_case("wat") || extension.eq_ignore_ascii_case("wasm")
                });
        if loaded_by_graders && name.starts_with(set.name_prefix) {
            let path: String = match set.artifact_dir {
                Some(dir) => format!("{dir}/{name}"),
                None => name,
            };
            let workspace_path: String = format!("{}/{path}", set.directory);
            if public_files.is_none_or(|files: &BTreeSet<String>| files.contains(&workspace_path)) {
                committed.insert(path);
            }
        }
    }
    if committed.is_empty() {
        audit.problems.push(format!(
            "{} holds no wasm artifact, so the record audit compared nothing",
            artifact_directory.display()
        ));
    }
    audit.unrecorded = committed
        .into_iter()
        .filter(|path: &String| !recorded.contains(path.as_str()))
        .map(|path: String| format!("{}/{path}", set.directory))
        .collect();
    Ok(audit)
}

pub(crate) fn workspace_members(root_doc: &toml::Value) -> BTreeSet<String> {
    root_doc
        .get("workspace")
        .and_then(|w: &toml::Value| w.get("members"))
        .and_then(toml::Value::as_array)
        .map(|a: &Vec<toml::Value>| {
            a.iter()
                .filter_map(|v: &toml::Value| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn workspace_package_version(root_doc: &toml::Value) -> String {
    root_doc
        .get("workspace")
        .and_then(|w: &toml::Value| w.get("package"))
        .and_then(|p: &toml::Value| p.get("version"))
        .and_then(toml::Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn discover_crate_dirs(root: &Path) -> Result<BTreeSet<String>> {
    let mut found: BTreeSet<String> = BTreeSet::new();
    for entry in walkdir::WalkDir::new(root)
        .max_depth(3)
        .into_iter()
        .filter_entry(|e: &walkdir::DirEntry| {
            let name: &str = e.file_name().to_str().unwrap_or_default();
            !name.starts_with('.') && !matches!(name, "target" | "node_modules")
        })
    {
        let entry: walkdir::DirEntry = entry.wrap_err("walking the repository for crate dirs")?;
        if entry.file_name() != "Cargo.toml" {
            continue;
        }
        let Some(dir) = entry.path().parent() else {
            continue;
        };
        if dir == root {
            continue;
        }
        let Ok(rel) = dir.strip_prefix(root) else {
            continue;
        };
        found.insert(rel.to_string_lossy().replace('\\', "/"));
    }
    Ok(found)
}

fn check_membership(
    members: &BTreeSet<String>,
    crate_dirs: &BTreeSet<String>,
    report: &mut Report,
) {
    for dir in crate_dirs.difference(members) {
        let allowed: Option<&(&str, &str)> = NON_MEMBER_CRATE_ALLOWLIST
            .iter()
            .find(|(name, _)| name == dir);
        if allowed.is_none() {
            report.fail(
                "workspace-membership",
                format!(
                    "{dir}/Cargo.toml exists but {dir} is not a workspace member and is not on the allowlist; add it to members in Cargo.toml, or add it to NON_MEMBER_CRATE_ALLOWLIST in xtask/src/health.rs with the reason it stays out"
                ),
            );
        }
    }
}

fn check_members_exist(root: &Path, members: &BTreeSet<String>, report: &mut Report) {
    for member in members {
        let manifest: PathBuf = root.join(member).join("Cargo.toml");
        if !manifest.is_file() {
            report.fail(
                "member-missing",
                format!("Cargo.toml lists {member} as a workspace member but {member}/Cargo.toml does not exist"),
            );
        }
    }
}

fn load_member_manifests(
    root: &Path,
    members: &BTreeSet<String>,
) -> Result<BTreeMap<String, toml::Value>> {
    let mut out: BTreeMap<String, toml::Value> = BTreeMap::new();
    for member in members {
        let path: PathBuf = root.join(member).join("Cargo.toml");
        if !path.is_file() {
            continue;
        }
        let text: String = read_text_bounded(&path, MAX_MANIFEST_BYTES)
            .wrap_err_with(|| format!("reading {}", path.display()))?;
        let doc: toml::Value =
            toml::from_str(&text).wrap_err_with(|| format!("parsing {}", path.display()))?;
        out.insert(member.clone(), doc);
    }
    Ok(out)
}

fn package_version(doc: &toml::Value, workspace_version: &str) -> Option<String> {
    let package: &toml::Value = doc.get("package")?;
    let version: &toml::Value = package.get("version")?;
    if let Some(literal) = version.as_str() {
        return Some(literal.to_string());
    }
    if version
        .get("workspace")
        .and_then(toml::Value::as_bool)
        .unwrap_or(false)
    {
        return Some(workspace_version.to_string());
    }
    None
}

fn check_internal_versions(
    root_doc: &toml::Value,
    member_manifests: &BTreeMap<String, toml::Value>,
    workspace_version: &str,
    root: &Path,
    report: &mut Report,
) {
    let Some(deps) = root_doc
        .get("workspace")
        .and_then(|w: &toml::Value| w.get("dependencies"))
        .and_then(toml::Value::as_table)
    else {
        return;
    };

    let mut by_dir: BTreeMap<String, String> = BTreeMap::new();
    for (dir, doc) in member_manifests {
        if let Some(v) = package_version(doc, workspace_version) {
            by_dir.insert(dir.clone(), v);
        }
    }

    let workspace_default_enabled_dirs: BTreeSet<String> = deps
        .values()
        .filter_map(|specification: &toml::Value| {
            let table: &toml::map::Map<String, toml::Value> = specification.as_table()?;
            let path: &str = table.get("path")?.as_str()?;
            let default_features_enabled: bool = table
                .get("default-features")
                .and_then(toml::Value::as_bool)
                .unwrap_or(true);
            default_features_enabled.then(|| path.replace('\\', "/"))
        })
        .collect();

    for (name, spec) in deps {
        let Some(table) = spec.as_table() else {
            continue;
        };
        let Some(path) = table.get("path").and_then(toml::Value::as_str) else {
            continue;
        };
        let Some(declared) = table.get("version").and_then(toml::Value::as_str) else {
            continue;
        };
        let normalized: String = path.replace('\\', "/");
        let Some(actual) = by_dir.get(&normalized) else {
            if !root.join(path).join("Cargo.toml").is_file() {
                report.fail(
                    "path-dependency-missing",
                    format!(
                        "[workspace.dependencies] {name} points at {path}, which has no Cargo.toml"
                    ),
                );
            }
            continue;
        };
        if declared != actual {
            report.fail(
                "internal-version-drift",
                format!(
                    "[workspace.dependencies] {name} declares version {declared} but {path} is actually at {actual}"
                ),
            );
        }
    }

    for (member_dir, doc) in member_manifests {
        check_member_internal_version_pins(
            member_dir,
            doc,
            &by_dir,
            &workspace_default_enabled_dirs,
            report,
        );
    }
}

fn normalized_dependency_dir(member_dir: &str, dependency_path: &str) -> Option<String> {
    let joined: PathBuf = Path::new(member_dir).join(dependency_path);
    let mut components: Vec<String> = Vec::new();
    for component in joined.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(value) => components.push(value.to_string_lossy().into_owned()),
            Component::ParentDir => {
                components.pop()?;
            }
            Component::Prefix(_) | Component::RootDir => return None,
        }
    }
    Some(components.join("/"))
}

fn check_member_internal_version_pins(
    member_dir: &str,
    doc: &toml::Value,
    internal_dirs: &BTreeMap<String, String>,
    workspace_default_enabled_dirs: &BTreeSet<String>,
    report: &mut Report,
) {
    for section_name in ["dependencies", "dev-dependencies", "build-dependencies"] {
        check_dependency_table_for_internal_version_pins(
            member_dir,
            section_name,
            doc.get(section_name),
            internal_dirs,
            workspace_default_enabled_dirs,
            report,
        );
    }
    let Some(targets) = doc.get("target").and_then(toml::Value::as_table) else {
        return;
    };
    for (target_name, target_doc) in targets {
        for section_name in ["dependencies", "dev-dependencies", "build-dependencies"] {
            let location: String = format!("target.{target_name}.{section_name}");
            check_dependency_table_for_internal_version_pins(
                member_dir,
                &location,
                target_doc.get(section_name),
                internal_dirs,
                workspace_default_enabled_dirs,
                report,
            );
        }
    }
}

fn check_dependency_table_for_internal_version_pins(
    member_dir: &str,
    location: &str,
    section: Option<&toml::Value>,
    internal_dirs: &BTreeMap<String, String>,
    workspace_default_enabled_dirs: &BTreeSet<String>,
    report: &mut Report,
) {
    let Some(dependencies) = section.and_then(toml::Value::as_table) else {
        return;
    };
    for (dependency_name, specification) in dependencies {
        let Some(table) = specification.as_table() else {
            continue;
        };
        let Some(path) = table.get("path").and_then(toml::Value::as_str) else {
            continue;
        };
        let Some(dependency_dir) = normalized_dependency_dir(member_dir, path) else {
            continue;
        };
        let Some(internal_version): Option<&String> = internal_dirs.get(&dependency_dir) else {
            continue;
        };
        let disables_workspace_defaults: bool = table
            .get("default-features")
            .and_then(toml::Value::as_bool)
            .is_some_and(|enabled: bool| !enabled)
            && workspace_default_enabled_dirs.contains(&dependency_dir);
        if disables_workspace_defaults
            && table.get("version").and_then(toml::Value::as_str) == Some(internal_version.as_str())
        {
            continue;
        }
        let check: &'static str = if table.get("version").and_then(toml::Value::as_str).is_some() {
            "internal-version-pin"
        } else {
            "internal-workspace-bypass"
        };
        report.fail(
            check,
            format!(
                "{member_dir}/Cargo.toml [{location}] {dependency_name} declares an internal path dependency outside [workspace.dependencies]; use `workspace = true`, except when a local path is required to disable workspace defaults"
            ),
        );
    }
}

fn check_unused_workspace_deps(
    root: &Path,
    root_doc: &toml::Value,
    member_manifests: &BTreeMap<String, toml::Value>,
    report: &mut Report,
) {
    let Some(deps) = root_doc
        .get("workspace")
        .and_then(|w: &toml::Value| w.get("dependencies"))
        .and_then(toml::Value::as_table)
    else {
        return;
    };

    let mut referenced: BTreeSet<String> = BTreeSet::new();
    for doc in member_manifests.values() {
        for section in [
            "dependencies",
            "dev-dependencies",
            "build-dependencies",
            "target",
        ] {
            collect_workspace_refs(doc.get(section), &mut referenced);
        }
    }

    for (name, spec) in deps {
        if referenced.contains(name) {
            continue;
        }
        let is_internal: bool = spec
            .as_table()
            .and_then(|t: &toml::map::Map<String, toml::Value>| t.get("path"))
            .is_some();
        if !is_internal {
            report.fail(
                "unused-workspace-dependency",
                format!(
                    "[workspace.dependencies] declares {name} but no workspace member takes it with `workspace = true`; remove the declaration or wire it to the crate that needs it"
                ),
            );
        }
    }

    let _ = root;
}

fn crate_name(doc: &toml::Value) -> Option<String> {
    doc.get("package")?
        .get("name")?
        .as_str()
        .map(str::to_string)
}

fn has_bin_target(root: &Path, dir: &str, doc: &toml::Value) -> bool {
    if doc.get("bin").and_then(toml::Value::as_array).is_some() {
        return true;
    }
    root.join(dir).join("src").join("main.rs").is_file()
        || root.join(dir).join("src").join("bin").is_dir()
}

fn is_consumed_outside_rust(doc: &toml::Value) -> bool {
    doc.get("lib")
        .and_then(|l: &toml::Value| l.get("crate-type"))
        .and_then(toml::Value::as_array)
        .is_some_and(|kinds: &Vec<toml::Value>| {
            kinds
                .iter()
                .any(|k: &toml::Value| matches!(k.as_str(), Some("cdylib" | "staticlib" | "dylib")))
        })
}

fn declared_dependency_names(doc: &toml::Value) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    let visit = |section: Option<&toml::Value>, out: &mut BTreeSet<String>| {
        if let Some(table) = section.and_then(toml::Value::as_table) {
            for name in table.keys() {
                out.insert(name.clone());
            }
        }
    };
    visit(doc.get("dependencies"), &mut out);
    visit(doc.get("dev-dependencies"), &mut out);
    visit(doc.get("build-dependencies"), &mut out);
    if let Some(targets) = doc.get("target").and_then(toml::Value::as_table) {
        for spec in targets.values() {
            visit(spec.get("dependencies"), &mut out);
            visit(spec.get("dev-dependencies"), &mut out);
            visit(spec.get("build-dependencies"), &mut out);
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CrateLevel {
    Rank(i64),
    Dev,
}

fn crate_level(doc: &toml::Value) -> Option<CrateLevel> {
    let level: &toml::Value = doc
        .get("package")?
        .get("metadata")?
        .get("disrobe")?
        .get("level")?;
    match level {
        toml::Value::Integer(rank) => Some(CrateLevel::Rank(*rank)),
        toml::Value::String(text) if text == "dev" => Some(CrateLevel::Dev),
        _ => None,
    }
}

fn crate_group(doc: &toml::Value) -> Option<String> {
    doc.get("package")?
        .get("metadata")?
        .get("disrobe")?
        .get("group")?
        .as_str()
        .map(str::to_owned)
}

fn normal_dependency_names(doc: &toml::Value) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    let visit = |section: Option<&toml::Value>, out: &mut BTreeSet<String>| {
        if let Some(table) = section.and_then(toml::Value::as_table) {
            out.extend(table.keys().cloned());
        }
    };
    visit(doc.get("dependencies"), &mut out);
    visit(doc.get("build-dependencies"), &mut out);
    if let Some(targets) = doc.get("target").and_then(toml::Value::as_table) {
        for spec in targets.values() {
            visit(spec.get("dependencies"), &mut out);
            visit(spec.get("build-dependencies"), &mut out);
        }
    }
    out
}

fn check_layering(member_manifests: &BTreeMap<String, toml::Value>, report: &mut Report) {
    const CHECK: &str = "layering";
    let mut crates: BTreeMap<String, (Option<CrateLevel>, Option<String>, &toml::Value)> =
        BTreeMap::new();
    for (dir, doc) in member_manifests {
        if !dir.starts_with("crates/") {
            continue;
        }
        if let Some(name) = crate_name(doc) {
            crates.insert(name, (crate_level(doc), crate_group(doc), doc));
        }
    }
    let unlevelled: Vec<&str> = crates
        .iter()
        .filter(|(_, (level, _, _))| level.is_none())
        .map(|(name, _)| name.as_str())
        .collect();
    if !unlevelled.is_empty() {
        report.fail(
            CHECK,
            format!(
                "{} crate(s) declare no `[package.metadata.disrobe] level`: {}",
                unlevelled.len(),
                unlevelled.join(", ")
            ),
        );
    }
    let mut violations: Vec<String> = Vec::new();
    for (name, (level, group, doc)) in &crates {
        let Some(level) = level else {
            continue;
        };
        for dependency in normal_dependency_names(doc) {
            let Some((Some(target), target_group, _)) = crates.get(&dependency) else {
                continue;
            };
            if group.is_some() && group == target_group {
                continue;
            }
            let violates: bool = match (level, target) {
                (_, CrateLevel::Dev) => true,
                (CrateLevel::Rank(own), CrateLevel::Rank(theirs)) => theirs >= own,
                (CrateLevel::Dev, CrateLevel::Rank(_)) => false,
            };
            if violates {
                violations.push(format!(
                    "{name} ({}) -> {dependency} ({})",
                    level_label(level),
                    level_label(target)
                ));
            }
        }
    }
    report.fact("layering_violations", json!(violations));
}

fn level_label(level: &CrateLevel) -> String {
    match level {
        CrateLevel::Rank(rank) => rank.to_string(),
        CrateLevel::Dev => "dev".to_owned(),
    }
}

fn check_unwired_members(
    root: &Path,
    member_manifests: &BTreeMap<String, toml::Value>,
    report: &mut Report,
) {
    let mut names: BTreeMap<String, String> = BTreeMap::new();
    for (dir, doc) in member_manifests {
        if let Some(name) = crate_name(doc) {
            names.insert(name, dir.clone());
        }
    }

    let mut known_unwired: usize = 0;
    let mut known_standalone_binaries: usize = 0;
    let mut depended_on: BTreeSet<String> = BTreeSet::new();
    for (dir, doc) in member_manifests {
        let self_name: Option<String> = crate_name(doc);
        for dep in declared_dependency_names(doc) {
            if names.contains_key(&dep) && Some(&dep) != self_name.as_ref() {
                depended_on.insert(dep);
            }
        }
        let _ = dir;
    }

    for (name, dir) in &names {
        if depended_on.contains(name) {
            continue;
        }
        let Some(doc) = member_manifests.get(dir) else {
            continue;
        };
        if is_consumed_outside_rust(doc) {
            continue;
        }
        if has_bin_target(root, dir, doc) {
            if KNOWN_STANDALONE_BINARIES
                .iter()
                .any(|(known, _)| known == name)
            {
                known_standalone_binaries += 1;
                continue;
            }
            report.fail(
                "unwired-crate",
                format!(
                    "{name} ({dir}) has a binary target but no other workspace crate depends on it and it is not in KNOWN_STANDALONE_BINARIES in xtask/src/health.rs, so a bin-only crate can rot unnoticed. Add it there with the reason it stands alone, or wire it to a consumer"
                ),
            );
            continue;
        }
        if KNOWN_UNWIRED_CRATES.iter().any(|(known, _)| known == name) {
            known_unwired += 1;
            continue;
        }
        report.fail(
            "unwired-crate",
            format!(
                "{name} ({dir}) has no binary target and no other workspace crate depends on it, so it compiles only because nothing exercises it. Wire it to a consumer, merge it, or move it out of the workspace, or add it to KNOWN_UNWIRED_CRATES in xtask/src/health.rs with the reason and the item tracking it"
            ),
        );
    }

    for (known, _) in KNOWN_UNWIRED_CRATES {
        if !names.contains_key(*known) {
            report.fail(
                "stale-unwired-allowlist",
                format!(
                    "KNOWN_UNWIRED_CRATES names {known}, which is no longer a workspace crate; drop the entry"
                ),
            );
        } else if depended_on.contains(*known) {
            report.fail(
                "stale-unwired-allowlist",
                format!(
                    "KNOWN_UNWIRED_CRATES still lists {known} but something now depends on it; drop the entry so the gate keeps ratcheting"
                ),
            );
        }
    }

    for (known, _) in KNOWN_STANDALONE_BINARIES {
        let Some(dir) = names.get(*known) else {
            report.fail(
                "stale-unwired-allowlist",
                format!(
                    "KNOWN_STANDALONE_BINARIES names {known}, which is no longer a workspace crate; drop the entry"
                ),
            );
            continue;
        };
        if depended_on.contains(*known) {
            report.fail(
                "stale-unwired-allowlist",
                format!(
                    "KNOWN_STANDALONE_BINARIES still lists {known} but something now depends on it; drop the entry so the gate keeps ratcheting"
                ),
            );
        } else if let Some(doc) = member_manifests.get(dir)
            && !has_bin_target(root, dir, doc)
        {
            report.fail(
                "stale-unwired-allowlist",
                format!(
                    "KNOWN_STANDALONE_BINARIES still lists {known} but it no longer has a binary target; drop the entry"
                ),
            );
        }
    }

    report.fact("known_unwired_crates", json!(known_unwired));
    report.fact(
        "known_standalone_binaries",
        json!(known_standalone_binaries),
    );
}

fn collect_workspace_refs(section: Option<&toml::Value>, out: &mut BTreeSet<String>) {
    let Some(value) = section else {
        return;
    };
    let Some(table) = value.as_table() else {
        return;
    };
    for (name, spec) in table {
        let takes_workspace: bool = spec
            .as_table()
            .and_then(|t: &toml::map::Map<String, toml::Value>| t.get("workspace"))
            .and_then(toml::Value::as_bool)
            .unwrap_or(false);
        if takes_workspace {
            out.insert(name.clone());
            continue;
        }
        if spec.as_table().is_some() && spec.get("workspace").is_none() {
            collect_workspace_refs(spec.get("dependencies"), out);
            collect_workspace_refs(spec.get("dev-dependencies"), out);
            collect_workspace_refs(spec.get("build-dependencies"), out);
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn authored_source(path: &str, bytes: &[u8]) -> AuthoredSource {
        AuthoredSource {
            path: path.to_owned(),
            sha256: format!("{:x}", Sha256::digest(bytes)),
        }
    }

    #[test]
    fn authored_source_audit_rejects_duplicate_missing_untracked_and_drifted_entries() -> Result<()>
    {
        let root: tempfile::TempDir = tempfile::tempdir()?;
        std::fs::create_dir(root.path().join("scripts"))?;
        std::fs::write(root.path().join("scripts/ok.py"), b"print('ok')\n")?;
        std::fs::write(root.path().join("scripts/drift.py"), b"print('changed')\n")?;
        let tracked: BTreeSet<String> = BTreeSet::from([
            "scripts/ok.py".to_owned(),
            "scripts/drift.py".to_owned(),
            "scripts/missing.py".to_owned(),
        ]);
        let entries: Vec<AuthoredSource> = vec![
            authored_source("scripts/ok.py", b"print('ok')\n"),
            authored_source("scripts/ok.py", b"print('ok')\n"),
            authored_source("scripts/missing.py", b"print('missing')\n"),
            authored_source("scripts/untracked.py", b"print('untracked')\n"),
            authored_source("scripts/drift.py", b"print('original')\n"),
            authored_source("C:/outside.py", b"print('outside')\n"),
        ];
        let (count, problems): (usize, Vec<String>) =
            audit_authored_sources(root.path(), entries, &tracked);
        assert_eq!(count, 4);
        assert!(problems.iter().any(|problem| problem.contains("duplicate")));
        assert!(problems.iter().any(|problem| problem.contains("invalid")));
        assert!(problems.iter().any(|problem| problem.contains("missing")));
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("not tracked"))
        );
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("sha256 drift")),
            "{problems:#?}"
        );
        Ok(())
    }

    #[test]
    fn a_file_with_a_listed_pycdc_blob_fails_health() {
        let id: &str = "24cc0f2f81a267dfc0a819000ef4f8d51af39dcd";
        let listed: BTreeSet<String> = BTreeSet::from([id.to_owned()]);
        let mut blobs: BTreeMap<String, String> = BTreeMap::new();
        blobs.insert("probe/readded.pyc".to_owned(), id.to_owned());
        let mut report: Report = Report::default();
        report_pycdc_blobs(&blobs, &listed, &mut report);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].check, "pycdc-blobs");
        assert!(report.findings[0].detail.contains("probe/readded.pyc"));

        blobs.insert("probe/readded.pyc".to_owned(), "0".repeat(40));
        let mut clean: Report = Report::default();
        report_pycdc_blobs(&blobs, &listed, &mut clean);
        assert!(clean.findings.is_empty());
    }

    fn internal_version_report(member_manifest: &str) -> Result<Report, toml::de::Error> {
        let root_doc: toml::Value = toml::from_str(
            r#"
                [workspace.dependencies]
                disrobe-a = { path = "crates/disrobe-a", version = "0.10.5" }
                disrobe-b = { path = "crates/disrobe-b", version = "0.10.5" }
            "#,
        )?;
        let mut member_manifests: BTreeMap<String, toml::Value> = BTreeMap::new();
        member_manifests.insert(
            "crates/disrobe-a".to_owned(),
            toml::from_str(
                r#"
                    [package]
                    name = "disrobe-a"
                    version = "0.10.5"
                "#,
            )?,
        );
        member_manifests.insert(
            "crates/disrobe-b".to_owned(),
            toml::from_str(member_manifest)?,
        );
        let mut report: Report = Report::default();
        check_internal_versions(
            &root_doc,
            &member_manifests,
            "0.10.5",
            Path::new("."),
            &mut report,
        );
        Ok(report)
    }

    #[test]
    fn internal_literal_path_dependency_fails_health() -> Result<(), toml::de::Error> {
        let report: Report = internal_version_report(
            r#"
                [package]
                name = "disrobe-b"
                version = "0.10.5"

                [dev-dependencies.disrobe-a]
                path = "../disrobe-a"
                version = "0.10.4"
            "#,
        )?;
        assert!(
            report
                .findings
                .iter()
                .any(|finding: &Finding| finding.check == "internal-version-pin")
        );
        Ok(())
    }

    #[test]
    fn target_specific_internal_literal_path_dependency_fails_health() -> Result<(), toml::de::Error>
    {
        let report: Report = internal_version_report(
            r#"
                [package]
                name = "disrobe-b"
                version = "0.10.5"

                [target.'cfg(windows)'.build-dependencies]
                disrobe-a = { path = "../disrobe-a", version = "0.10.4" }
            "#,
        )?;
        assert!(
            report
                .findings
                .iter()
                .any(|finding: &Finding| finding.check == "internal-version-pin")
        );
        Ok(())
    }

    #[test]
    fn workspace_internal_dependency_passes_health() -> Result<(), toml::de::Error> {
        let report: Report = internal_version_report(
            r#"
                [package]
                name = "disrobe-b"
                version = "0.10.5"

                [dependencies]
                disrobe-a = { workspace = true }
            "#,
        )?;
        assert!(report.findings.is_empty());
        Ok(())
    }

    #[test]
    fn internal_path_without_a_version_still_fails_health() -> Result<(), toml::de::Error> {
        let report: Report = internal_version_report(
            r#"
                [package]
                name = "disrobe-b"
                version = "0.10.5"

                [dependencies]
                disrobe-a = { path = "../disrobe-a" }
            "#,
        )?;
        assert!(
            report
                .findings
                .iter()
                .any(|finding: &Finding| finding.check == "internal-workspace-bypass")
        );
        Ok(())
    }

    #[test]
    fn versioned_local_path_can_disable_workspace_defaults() -> Result<(), toml::de::Error> {
        let report: Report = internal_version_report(
            r#"
                [package]
                name = "disrobe-b"
                version = "0.10.5"

                [dependencies]
                disrobe-a = { path = "../disrobe-a", version = "0.10.5", default-features = false }
            "#,
        )?;
        assert!(report.findings.is_empty());
        Ok(())
    }

    #[test]
    fn local_path_disabling_defaults_rejects_a_wrong_version() -> Result<(), toml::de::Error> {
        let report: Report = internal_version_report(
            r#"
                [package]
                name = "disrobe-b"
                version = "0.10.5"

                [dependencies]
                disrobe-a = { path = "../disrobe-a", version = "0.10.4", default-features = false }
            "#,
        )?;
        assert!(
            report
                .findings
                .iter()
                .any(|finding: &Finding| finding.check == "internal-version-pin")
        );
        Ok(())
    }

    const TEST_WASM_SET: WasmRecordSet = WasmRecordSet {
        directory: "set",
        artifact_dir: Some("real"),
        name_prefix: "",
    };

    const AUTHORED_MODULE: &[u8] = b"(module)\n";

    fn sha256_hex(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn wasm_record_set(records: &str, files: &[(&str, &[u8])]) -> Result<tempfile::TempDir> {
        let root: tempfile::TempDir = tempfile::tempdir()?;
        let directory: PathBuf = root.path().join(TEST_WASM_SET.directory);
        std::fs::create_dir_all(directory.join("real"))?;
        std::fs::write(directory.join("records.toml"), records)?;
        for (path, bytes) in files {
            std::fs::write(directory.join(path), bytes)?;
        }
        Ok(root)
    }

    fn authored_record(path: &str, sha256: &str) -> String {
        format!(
            r#"schema = "{WASM_BUILD_RECORDS_SCHEMA}"

[[artifact]]
path = "{path}"
sha256 = "{sha256}"
origin.authored.note = "hand-written for this test"
"#
        )
    }

    fn built_record(sha256: &str, rebuilt_sha256: &str, difference: Option<&str>) -> String {
        let difference_line: String = difference.map_or_else(String::new, |note: &str| {
            format!("origin.built.difference = \"{note}\"\n")
        });
        format!(
            r#"schema = "{WASM_BUILD_RECORDS_SCHEMA}"

[[artifact]]
path = "real/a.wat"
sha256 = "{sha256}"
origin.built.source = "a.c"
origin.built.toolchain = "clang 22.1.6"
origin.built.command = "clang --target=wasm32 -o real/a.wasm a.c && wasm-tools print real/a.wasm > real/a.wat"
origin.built.rebuilt_sha256 = "{rebuilt_sha256}"
{difference_line}"#
        )
    }

    fn wasm_record_sets(
        corpus_records: &str,
        corpus_files: &[(&str, &[u8])],
        fixture_records: &str,
        fixture_files: &[(&str, &[u8])],
    ) -> Result<(tempfile::TempDir, BTreeSet<String>)> {
        let root: tempfile::TempDir = tempfile::tempdir()?;
        let corpus: PathBuf = root.path().join(WASM_RECORD_SETS[0].directory);
        let fixtures: PathBuf = root.path().join(WASM_RECORD_SETS[1].directory);
        std::fs::create_dir_all(corpus.join("real"))?;
        std::fs::create_dir_all(&fixtures)?;
        std::fs::write(corpus.join("records.toml"), corpus_records)?;
        std::fs::write(fixtures.join("records.toml"), fixture_records)?;
        let mut public_files: BTreeSet<String> = BTreeSet::new();
        for (path, bytes) in corpus_files {
            std::fs::write(corpus.join(path), bytes)?;
            public_files.insert(format!("{}/{path}", WASM_RECORD_SETS[0].directory));
        }
        for (path, bytes) in fixture_files {
            std::fs::write(fixtures.join(path), bytes)?;
            public_files.insert(format!("{}/{path}", WASM_RECORD_SETS[1].directory));
        }
        Ok((root, public_files))
    }

    #[test]
    fn a_fully_recorded_wasm_set_passes_the_record_audit() -> Result<()> {
        let root: tempfile::TempDir = wasm_record_set(
            &authored_record("real/a.wat", &sha256_hex(AUTHORED_MODULE)),
            &[("real/a.wat", AUTHORED_MODULE)],
        )?;
        let audit: WasmRecordAudit = audit_wasm_record_set(root.path(), TEST_WASM_SET, None)?;
        assert_eq!(audit.problems, Vec::<String>::new());
        assert_eq!(audit.unrecorded, Vec::<String>::new());
        assert_eq!(audit.authored, 1);
        Ok(())
    }

    #[test]
    fn a_wasm_artifact_without_a_record_breaks_the_zero_ratchet() -> Result<()> {
        let root: tempfile::TempDir = wasm_record_set(
            &authored_record("real/a.wat", &sha256_hex(AUTHORED_MODULE)),
            &[
                ("real/a.wat", AUTHORED_MODULE),
                ("real/b.obf.wat", AUTHORED_MODULE),
                ("real/notes.txt", b"not a module"),
            ],
        )?;
        let audit: WasmRecordAudit = audit_wasm_record_set(root.path(), TEST_WASM_SET, None)?;
        assert_eq!(audit.unrecorded, vec!["set/real/b.obf.wat".to_owned()]);
        Ok(())
    }

    #[test]
    fn a_wasm_artifact_whose_bytes_drift_from_its_record_fails_the_audit() -> Result<()> {
        let root: tempfile::TempDir = wasm_record_set(
            &authored_record("real/a.wat", &sha256_hex(b"(module (memory 1))\n")),
            &[("real/a.wat", AUTHORED_MODULE)],
        )?;
        let audit: WasmRecordAudit = audit_wasm_record_set(root.path(), TEST_WASM_SET, None)?;
        assert_eq!(audit.problems.len(), 1, "{:?}", audit.problems);
        assert!(
            audit.problems[0].starts_with(&format!(
                "set/records.toml: real/a.wat hashes to {}",
                sha256_hex(AUTHORED_MODULE)
            )),
            "{:?}",
            audit.problems
        );
        Ok(())
    }

    #[test]
    fn layering_reports_upward_edges_skips_groups_and_fails_unlevelled_crates() -> Result<()> {
        let manifest = |name: &str, meta: &str, deps: &str| -> Result<toml::Value> {
            Ok(toml::from_str(&format!(
                "[package]\nname = \"{name}\"\n{meta}\n[dependencies]\n{deps}\n"
            ))?)
        };
        let mut manifests: BTreeMap<String, toml::Value> = BTreeMap::new();
        manifests.insert(
            "crates/disrobe-low".to_owned(),
            manifest(
                "disrobe-low",
                "[package.metadata.disrobe]\nlevel = 1\ngroup = \"g\"",
                "disrobe-peer = { workspace = true }",
            )?,
        );
        manifests.insert(
            "crates/disrobe-peer".to_owned(),
            manifest(
                "disrobe-peer",
                "[package.metadata.disrobe]\nlevel = 1\ngroup = \"g\"",
                "",
            )?,
        );
        manifests.insert(
            "crates/disrobe-high".to_owned(),
            manifest("disrobe-high", "[package.metadata.disrobe]\nlevel = 3", "")?,
        );
        manifests.insert(
            "crates/disrobe-leaf".to_owned(),
            manifest(
                "disrobe-leaf",
                "[package.metadata.disrobe]\nlevel = 2",
                "disrobe-high = { workspace = true }\ndisrobe-low = { workspace = true }",
            )?,
        );
        manifests.insert(
            "crates/disrobe-bare".to_owned(),
            manifest("disrobe-bare", "", "")?,
        );
        let mut report: Report = Report::default();
        check_layering(&manifests, &mut report);
        assert_eq!(
            report.facts.get("layering_violations"),
            Some(&json!(["disrobe-leaf (2) -> disrobe-high (3)"]))
        );
        assert_eq!(report.findings.len(), 1);
        assert!(report.findings[0].detail.contains("disrobe-bare"));
        Ok(())
    }

    #[test]
    fn private_references_find_paths_and_internal_ids_but_not_lookalikes() {
        let probe: String = format!(
            "see {PRIVATE_DIR}scratch/x.md and {}, {}, {}, {}.",
            concat!("T-", "P1-48"),
            concat!("D-", "041"),
            concat!("SEC-", "05X"),
            concat!("BUG-", "072")
        );
        assert_eq!(
            private_references(&probe),
            vec![
                format!("{PRIVATE_DIR} path"),
                concat!("T-", "P1-48").to_owned(),
                concat!("D-", "041").to_owned(),
                concat!("BUG-", "072").to_owned()
            ]
        );
        assert!(
            private_references("DR-CLI-0110, UTF-8, x86-64, ADD-0123, HD-0123, TEST-1234")
                .is_empty()
        );
    }

    #[test]
    fn a_tracked_file_citing_a_private_path_fails_health() -> Result<()> {
        let root: tempfile::TempDir = tempfile::tempdir()?;
        std::fs::write(
            root.path().join("notes.md"),
            format!(
                "built from {PRIVATE_DIR}tools/x
"
            ),
        )?;
        std::fs::write(
            root.path().join(".gitignore"),
            format!(
                "{PRIVATE_DIR}
"
            ),
        )?;
        let files: BTreeSet<String> =
            BTreeSet::from(["notes.md".to_owned(), ".gitignore".to_owned()]);
        let mut report: Report = Report::default();
        check_private_references_with_files(root.path(), &files, &mut report);
        assert!(
            report
                .findings
                .iter()
                .any(|finding: &Finding| finding.check == "private-reference"
                    && finding
                        .detail
                        .contains(&format!("notes.md: {PRIVATE_DIR} path"))),
            "{:?}",
            report
                .findings
                .iter()
                .map(|f: &Finding| &f.detail)
                .collect::<Vec<&String>>()
        );
        assert!(
            report
                .findings
                .iter()
                .all(|finding: &Finding| !finding.detail.contains(".gitignore")),
            "the ignore rule itself is exempt"
        );
        Ok(())
    }

    #[test]
    fn wasm_build_record_health_reports_unrecorded_and_drifted_artifacts() -> Result<()> {
        let correct: String = sha256_hex(AUTHORED_MODULE);
        let drifted: String = sha256_hex(b"(module (memory 1))\n");
        let (root, public_files): (tempfile::TempDir, BTreeSet<String>) = wasm_record_sets(
            &authored_record("real/a.wat", &drifted),
            &[
                ("real/a.wat", AUTHORED_MODULE),
                ("real/b.wat", AUTHORED_MODULE),
            ],
            &authored_record("cff_fixture.wat", &correct),
            &[("cff_fixture.wat", AUTHORED_MODULE)],
        )?;
        let mut report: Report = Report::default();
        check_wasm_build_records_with_files(root.path(), &public_files, &mut report);
        let json: Value = report.to_json();
        let findings: &[Value] = json["findings"]
            .as_array()
            .expect("health findings are an array");
        assert!(findings.iter().any(|finding: &Value| {
            finding["check"] == "wasm-unrecorded-artifact"
                && finding["detail"]
                    .as_str()
                    .is_some_and(|detail: &str| detail.contains("corpus/wasm/obf/real/b.wat"))
        }));
        assert!(
            findings
                .iter()
                .any(|finding: &Value| finding["check"] == "wasm-build-record")
        );
        assert_eq!(json["facts"]["wasm_build_records"]["unrecorded"], 1);
        Ok(())
    }

    #[test]
    fn a_differing_rebuild_must_record_its_difference() -> Result<()> {
        let committed: String = sha256_hex(AUTHORED_MODULE);
        let rebuilt: String = sha256_hex(b"(module (func))\n");
        let files: [(&str, &[u8]); 2] = [("real/a.wat", AUTHORED_MODULE), ("a.c", b"int a;\n")];

        let silent: tempfile::TempDir =
            wasm_record_set(&built_record(&committed, &rebuilt, None), &files)?;
        let audit: WasmRecordAudit = audit_wasm_record_set(silent.path(), TEST_WASM_SET, None)?;
        assert_eq!(
            audit.problems,
            vec![format!(
                "set/records.toml: real/a.wat rebuilds to {rebuilt}, not its committed {committed}, and records no difference; describe it, or regenerate the file from the recorded command"
            )]
        );

        let described: tempfile::TempDir = wasm_record_set(
            &built_record(
                &committed,
                &rebuilt,
                Some("the rebuild orders one loop differently"),
            ),
            &files,
        )?;
        let audit: WasmRecordAudit = audit_wasm_record_set(described.path(), TEST_WASM_SET, None)?;
        assert_eq!(audit.problems, Vec::<String>::new());
        assert_eq!(audit.rebuild_differences, 1);

        let identical: tempfile::TempDir = wasm_record_set(
            &built_record(&committed, &committed, Some("nothing differs")),
            &files,
        )?;
        let audit: WasmRecordAudit = audit_wasm_record_set(identical.path(), TEST_WASM_SET, None)?;
        assert_eq!(
            audit.problems,
            vec![
                "set/records.toml: real/a.wat rebuilds to its committed bytes but still records a difference"
                    .to_owned()
            ]
        );
        Ok(())
    }

    const FAMILY_TABLE_HEAD: &str = "# Disrobe\n\n## What it recovers\n\nEach row names a family.\n\n| Ecosystem | Formats | Evidence |\n|---|---|---|\n";

    fn family_audit(rows: &str) -> FamilyEvidenceAudit {
        audit_family_evidence(
            &format!("{FAMILY_TABLE_HEAD}{rows}\n## Measured results\n\n| A | b |\n"),
            |path: &str| path == "evidence/results/a.md" || path == "crates/c/tests/t.rs",
        )
        .expect("the probe README carries a family table with an Evidence column")
    }

    #[test]
    fn a_family_row_without_a_graded_real_fixture_or_a_synthetic_label_fails_health() {
        let audit: FamilyEvidenceAudit = family_audit(
            "| A | x | `real`: [a](evidence/results/a.md) |\n\
             | B | x | `synthetic` |\n\
             | C | x | `real`: [t](crates/c/tests/t.rs); `synthetic` for the rest |\n\
             | D | x | `claimed` |\n\
             | E | x | `real`: [gone](evidence/results/gone.md) |\n\
             | F | x | `real` |\n\
             | G | x | [a](evidence/results/a.md) |\n\
             | H | x |\n",
        );
        assert_eq!(audit.rows, 8);
        assert_eq!(
            audit.problems,
            vec![
                "README.md family row `D` has neither a `real` label with a linked graded fixture nor a `synthetic` label".to_owned(),
                "README.md family row `E` links `evidence/results/gone.md` as evidence, which does not exist".to_owned(),
                "README.md family row `E` is labelled `real` but links no existing evidence/results/*.md descriptor or crates/*/tests/*.rs test that grades a real fixture".to_owned(),
                "README.md family row `F` is labelled `real` but links no existing evidence/results/*.md descriptor or crates/*/tests/*.rs test that grades a real fixture".to_owned(),
                "README.md family row `G` has neither a `real` label with a linked graded fixture nor a `synthetic` label".to_owned(),
                "README.md family row `H` has 2 cells and the header has 3".to_owned(),
            ]
        );
    }

    #[test]
    fn a_family_table_without_an_evidence_column_fails_health() {
        let missing: std::result::Result<FamilyEvidenceAudit, String> = audit_family_evidence(
            "## What it recovers\n\n| Ecosystem | Formats |\n|---|---|\n| A | x |\n",
            |_: &str| true,
        );
        assert!(
            missing
                .as_ref()
                .is_err_and(|problem: &String| problem.contains("no `Evidence` column")),
            "{missing:?}"
        );
        let absent: std::result::Result<FamilyEvidenceAudit, String> =
            audit_family_evidence("# Disrobe\n\n| A | b |\n|---|---|\n", |_: &str| true);
        assert!(absent.is_err(), "{absent:?}");
    }

    #[test]
    fn the_committed_readme_labels_every_family_row() -> Result<()> {
        let root: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let readme: String = read_text_bounded(&root.join("README.md"), MAX_README_BYTES)?;
        let audit: FamilyEvidenceAudit =
            audit_family_evidence(&readme, |target: &str| root.join(target).is_file())
                .map_err(|problem: String| eyre::eyre!(problem))?;
        assert_eq!(audit.problems, Vec::<String>::new());
        assert!(audit.rows > 0, "the family table has no rows");
        Ok(())
    }

    #[test]
    fn the_committed_wasm_build_records_pass_the_audit() -> Result<()> {
        let root: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let public_files: BTreeSet<String> = tracked_or_nonignored_files(&root)?;
        for set in WASM_RECORD_SETS {
            let audit: WasmRecordAudit = audit_wasm_record_set(&root, set, Some(&public_files))?;
            assert_eq!(audit.problems, Vec::<String>::new(), "{}", set.directory);
            assert_eq!(audit.unrecorded, Vec::<String>::new(), "{}", set.directory);
        }
        Ok(())
    }
}
