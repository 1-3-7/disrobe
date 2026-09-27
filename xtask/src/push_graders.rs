use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::ExitStatus;
use std::time::{Duration, Instant};

use disrobe_tool_process::{CaptureOutcome, CommandSpec, Completion, Execution};
use eyre::{Result, WrapErr, bail};
use serde::Deserialize;
use serde::de::{Deserializer, Error as DeError};
use serde_json::Value;

use disrobe_core::chain::Ecosystem;

const MANIFEST: &str = include_str!("../data/push_graders.toml");
const JUNIT_FILENAME: &str = "junit.xml";
const GRADER_TIMEOUT: Duration = Duration::from_mins(30);
const GRADER_CAPTURE_LIMIT: usize = 8 * 1024 * 1024;
const MAX_JUNIT_REPORT_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Deserialize)]
struct Manifest {
    version: u32,
    grader: Vec<Grader>,
    uncovered: Vec<Uncovered>,
}

#[derive(Debug, Deserialize)]
struct Grader {
    ecosystem: EcosystemName,
    package: String,
    target: String,
    features: Vec<String>,
    reference: TestCitation,
    mutation: TestCitation,
}

#[derive(Debug, Deserialize)]
struct TestCitation {
    path: String,
    test: String,
}

#[derive(Debug, Deserialize)]
struct Uncovered {
    ecosystem: EcosystemName,
    reason: String,
}

#[derive(Debug, Eq, PartialEq)]
struct RunCounts {
    run: usize,
    passed: usize,
}

#[derive(Debug, Eq, PartialEq)]
struct ListedTests {
    count: usize,
    identities: BTreeSet<String>,
}

#[derive(Debug, Eq, PartialEq)]
struct JunitReceipt {
    counts: RunCounts,
    passed: BTreeSet<String>,
}

#[derive(Debug)]
struct CapturedOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct EcosystemName(Ecosystem);

impl<'de> Deserialize<'de> for EcosystemName {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw: String = String::deserialize(deserializer)?;
        let Some(ecosystem): Option<Ecosystem> = Ecosystem::parse(&raw) else {
            return Err(D::Error::custom(format!("unknown ecosystem {raw:?}")));
        };
        if raw != ecosystem.slug() {
            return Err(D::Error::custom(format!(
                "ecosystem {raw:?} must use canonical slug {:?}",
                ecosystem.slug()
            )));
        }
        Ok(Self(ecosystem))
    }
}

pub(crate) fn check(root: &Path) -> Result<()> {
    let manifest: Manifest = load()?;
    verify_links(root, &manifest)?;
    println!(
        "push-graders: {} grader target(s), {} uncovered ecosystem(s)",
        manifest.grader.len(),
        manifest.uncovered.len()
    );
    Ok(())
}

pub(crate) fn run(root: &Path) -> Result<()> {
    let manifest: Manifest = load()?;
    verify_links(root, &manifest)?;
    let started: Instant = Instant::now();
    let mut listed: usize = 0;
    let mut run: usize = 0;
    let mut passed: usize = 0;
    for grader in &manifest.grader {
        let listed_tests: ListedTests = listed_tests(root, grader)?;
        require_citations(grader, &listed_tests.identities, "listed")?;
        let count: usize = listed_tests.count;
        listed = listed
            .checked_add(count)
            .ok_or_else(|| eyre::eyre!("push grader count overflow"))?;
        let counts: RunCounts = run_grader(root, grader, count)?;
        run = run
            .checked_add(counts.run)
            .ok_or_else(|| eyre::eyre!("push grader count overflow"))?;
        passed = passed
            .checked_add(counts.passed)
            .ok_or_else(|| eyre::eyre!("push grader count overflow"))?;
    }
    let elapsed = started.elapsed();
    if listed != run || run != passed {
        bail!("push graders disagree: listed={listed} run={run} passed={passed}");
    }
    println!("push-graders: listed={listed} run={run} passed={passed}");
    println!("push-graders: Finished in {:.3}s", elapsed.as_secs_f64());
    Ok(())
}

fn load() -> Result<Manifest> {
    let manifest: Manifest =
        toml::from_str(MANIFEST).wrap_err("parsing xtask/data/push_graders.toml")?;
    validate(&manifest)?;
    Ok(manifest)
}

fn validate(manifest: &Manifest) -> Result<()> {
    if manifest.version != 1 {
        bail!(
            "push grader manifest version must be 1, found {}",
            manifest.version
        );
    }
    let mut coverage: BTreeMap<Ecosystem, &'static str> = BTreeMap::new();
    let mut targets: BTreeSet<(String, String, Vec<String>)> = BTreeSet::new();
    for grader in &manifest.grader {
        validate_grader(grader)?;
        let mut features: Vec<String> = grader.features.clone();
        features.sort();
        if !targets.insert((grader.package.clone(), grader.target.clone(), features)) {
            bail!(
                "{}:{} with these features is listed by more than one ecosystem",
                grader.package,
                grader.target
            );
        }
        if let Some(previous) = coverage.insert(grader.ecosystem.0, "grader") {
            bail!(
                "{} is declared as both {previous} and grader",
                grader.ecosystem.0.label()
            );
        }
    }
    for uncovered in &manifest.uncovered {
        require_text("uncovered reason", &uncovered.reason)?;
        if let Some(previous) = coverage.insert(uncovered.ecosystem.0, "uncovered") {
            bail!(
                "{} is declared as both {previous} and uncovered",
                uncovered.ecosystem.0.label()
            );
        }
    }
    for &ecosystem in Ecosystem::all() {
        if !coverage.contains_key(&ecosystem) {
            bail!(
                "{} is neither graded nor explicitly uncovered",
                ecosystem.label()
            );
        }
    }
    Ok(())
}

fn validate_grader(grader: &Grader) -> Result<()> {
    validate_selector("package", &grader.package)?;
    validate_selector("test target", &grader.target)?;
    validate_citation("reference", &grader.reference)?;
    validate_citation("mutation control", &grader.mutation)?;
    if grader.reference.path == grader.mutation.path
        && grader.reference.test == grader.mutation.test
    {
        bail!(
            "{} must cite distinct reference and mutation-control tests",
            grader.ecosystem.0.label()
        );
    }
    let mut features: BTreeSet<&str> = BTreeSet::new();
    for feature in &grader.features {
        validate_selector("feature", feature)?;
        if !features.insert(feature) {
            bail!("{} repeats feature {feature}", grader.ecosystem.0.label());
        }
    }
    Ok(())
}

fn validate_citation(kind: &str, citation: &TestCitation) -> Result<()> {
    validate_relative_path(kind, &citation.path)?;
    validate_selector(&format!("{kind} test"), &citation.test)
}

fn validate_relative_path(label: &str, value: &str) -> Result<()> {
    let path: &Path = Path::new(value);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir
                    | std::path::Component::ParentDir
                    | std::path::Component::Prefix(_)
                    | std::path::Component::RootDir
            )
        })
    {
        bail!("push grader {label} path must be a repository-relative file: {value:?}");
    }
    Ok(())
}

fn validate_selector(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.starts_with('-')
        || !value
            .bytes()
            .all(|byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        bail!("push grader {label} must be a non-option Cargo identifier: {value:?}");
    }
    Ok(())
}

fn require_text(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("push grader {label} must not be empty");
    }
    Ok(())
}

fn verify_links(root: &Path, manifest: &Manifest) -> Result<()> {
    for grader in &manifest.grader {
        for (kind, citation) in [
            ("reference", &grader.reference),
            ("mutation control", &grader.mutation),
        ] {
            let path = root.join(&citation.path);
            let text: String = fs::read_to_string(&path)
                .wrap_err_with(|| format!("reading push grader {kind} {}", citation.path))?;
            if !has_test_function(&text, &citation.test) {
                bail!(
                    "{}:{} names {kind} test {:?}, which is not in {}",
                    grader.package,
                    grader.target,
                    citation.test,
                    citation.path,
                );
            }
        }
    }
    Ok(())
}

fn has_test_function(source: &str, test: &str) -> bool {
    let signature: String = format!("fn {test}(");
    let mut test_attribute: bool = false;
    for line in source.lines() {
        let line: &str = line.trim();
        if line == "#[test]" {
            test_attribute = true;
            continue;
        }
        if line.starts_with("#[") {
            continue;
        }
        if line.contains(&signature) {
            if test_attribute {
                return true;
            }
        } else if !line.is_empty() {
            test_attribute = false;
        }
    }
    false
}

fn listed_tests(root: &Path, grader: &Grader) -> Result<ListedTests> {
    let output: CapturedOutput = nextest(root, grader, "list", true)?;
    let value: Value = serde_json::from_slice(&output.stdout).wrap_err_with(|| {
        format!(
            "parsing cargo nextest list JSON for {}:{}",
            grader.package, grader.target
        )
    })?;
    let listed: ListedTests = listed_count(&value, grader)?;
    if listed.count == 0 {
        bail!(
            "{}:{} listed zero tests; every push grader must exercise at least one test",
            grader.package,
            grader.target
        );
    }
    Ok(listed)
}

fn listed_count(value: &Value, grader: &Grader) -> Result<ListedTests> {
    let count: usize = value
        .get("test-count")
        .and_then(Value::as_u64)
        .and_then(|count: u64| usize::try_from(count).ok())
        .ok_or_else(|| eyre::eyre!("nextest list has no valid test-count"))?;
    let suites: &serde_json::Map<String, Value> = value
        .get("rust-suites")
        .and_then(Value::as_object)
        .ok_or_else(|| eyre::eyre!("nextest list has no rust-suites"))?;
    let mut observed: usize = 0;
    let mut identities: BTreeSet<String> = BTreeSet::new();
    for suite in suites.values() {
        if suite.get("status").and_then(Value::as_str) != Some("listed") {
            bail!(
                "{}:{} has a suite omitted from the push grader list",
                grader.package,
                grader.target
            );
        }
        let testcases: &serde_json::Map<String, Value> = suite
            .get("testcases")
            .and_then(Value::as_object)
            .ok_or_else(|| eyre::eyre!("listed suite has no testcases"))?;
        for (identity, testcase) in testcases {
            if testcase.get("ignored").and_then(Value::as_bool) != Some(false)
                || testcase
                    .get("filter-match")
                    .and_then(|filter: &Value| filter.get("status"))
                    .and_then(Value::as_str)
                    != Some("matches")
            {
                bail!(
                    "{}:{} has an ignored, filtered, or malformed listed test",
                    grader.package,
                    grader.target
                );
            }
            observed = observed
                .checked_add(1)
                .ok_or_else(|| eyre::eyre!("push grader count overflow"))?;
            identities.insert(identity.clone());
        }
    }
    if observed != count {
        bail!(
            "{}:{} reports {count} listed tests but exposes {observed} runnable testcases",
            grader.package,
            grader.target
        );
    }
    Ok(ListedTests { count, identities })
}

fn run_grader(root: &Path, grader: &Grader, expected: usize) -> Result<RunCounts> {
    let report: std::path::PathBuf = junit_path(root);
    match fs::remove_file(&report) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).wrap_err_with(|| format!("removing {}", report.display())),
    }
    let output: CapturedOutput = nextest(root, grader, "run", false)?;
    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    let receipt: JunitReceipt = junit_counts(&report, expected)?;
    require_citations(grader, &receipt.passed, "passed")?;
    Ok(receipt.counts)
}

fn junit_path(root: &Path) -> std::path::PathBuf {
    root.join("target")
        .join("nextest")
        .join("push-graders")
        .join(JUNIT_FILENAME)
}

fn junit_counts(path: &Path, expected: usize) -> Result<JunitReceipt> {
    let text: String = crate::fileio::read_text_bounded(path, MAX_JUNIT_REPORT_BYTES)
        .wrap_err_with(|| format!("reading nextest JUnit report {}", path.display()))?;
    let document: roxmltree::Document<'_> = roxmltree::Document::parse(&text)
        .wrap_err_with(|| format!("parsing nextest JUnit report {}", path.display()))?;
    let mut run: usize = 0;
    let mut passed: usize = 0;
    let mut passed_tests: BTreeSet<String> = BTreeSet::new();
    for testcase in document
        .descendants()
        .filter(|node| node.has_tag_name("testcase"))
    {
        let identity: &str = testcase
            .attribute("name")
            .ok_or_else(|| eyre::eyre!("nextest JUnit testcase has no name"))?;
        run = run
            .checked_add(1)
            .ok_or_else(|| eyre::eyre!("push grader count overflow"))?;
        if testcase.children().any(|node| {
            node.has_tag_name("failure")
                || node.has_tag_name("error")
                || node.has_tag_name("skipped")
        }) {
            bail!("nextest JUnit report contains a failed, errored, or skipped testcase");
        }
        passed = passed
            .checked_add(1)
            .ok_or_else(|| eyre::eyre!("push grader count overflow"))?;
        passed_tests.insert(identity.to_owned());
    }
    if run != expected || passed != expected {
        bail!("nextest JUnit result mismatch: listed={expected} run={run} passed={passed}");
    }
    Ok(JunitReceipt {
        counts: RunCounts { run, passed },
        passed: passed_tests,
    })
}

fn require_citations(grader: &Grader, identities: &BTreeSet<String>, phase: &str) -> Result<()> {
    for (kind, citation) in [
        ("reference", &grader.reference),
        ("mutation control", &grader.mutation),
    ] {
        if !identities.contains(&citation.test) {
            bail!(
                "{}:{} cited {kind} test {:?} was not {phase}",
                grader.package,
                grader.target,
                citation.test
            );
        }
    }
    Ok(())
}

fn nextest(root: &Path, grader: &Grader, mode: &str, json: bool) -> Result<CapturedOutput> {
    let manifest_path: std::path::PathBuf = root.join("Cargo.toml");
    let manifest: &str = manifest_path
        .to_str()
        .ok_or_else(|| eyre::eyre!("push grader workspace path is not UTF-8"))?;
    let mut arguments: Vec<String> = vec![
        "nextest".to_owned(),
        mode.to_owned(),
        "--locked".to_owned(),
        "--profile".to_owned(),
        "push-graders".to_owned(),
        "--manifest-path".to_owned(),
        manifest.to_owned(),
    ];
    if mode == "run" {
        arguments.push("--no-tests=fail".to_owned());
    }
    if json {
        arguments.extend(["--message-format".to_owned(), "json".to_owned()]);
    }
    arguments.extend([
        "-p".to_owned(),
        grader.package.clone(),
        "--test".to_owned(),
        grader.target.clone(),
    ]);
    if !grader.features.is_empty() {
        arguments.extend(["--features".to_owned(), grader.features.join(",")]);
    }
    let execution: Execution = CommandSpec::new("cargo-nextest", GRADER_TIMEOUT)
        .args(arguments)
        .capture_limits(GRADER_CAPTURE_LIMIT, GRADER_CAPTURE_LIMIT)
        .run()
        .wrap_err_with(|| {
            format!(
                "starting cargo nextest {mode} for {}:{}",
                grader.package, grader.target
            )
        })?;
    let output: CapturedOutput = captured_output(execution, mode, grader)?;
    if !output.status.success() {
        bail!(
            "cargo nextest {mode} failed for {}:{} ({})\nstdout:\n{}\nstderr:\n{}",
            grader.package,
            grader.target,
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    Ok(output)
}

fn captured_output(execution: Execution, mode: &str, grader: &Grader) -> Result<CapturedOutput> {
    let status: ExitStatus = match execution.completion {
        Completion::Exited(status) => status,
        Completion::TimedOut(status) => bail!(
            "cargo nextest {mode} timed out after {} seconds for {}:{} ({status})",
            GRADER_TIMEOUT.as_secs(),
            grader.package,
            grader.target
        ),
    };
    let stdout: Vec<u8> = complete_capture(execution.stdout, "stdout", mode, grader)?;
    let stderr: Vec<u8> = complete_capture(execution.stderr, "stderr", mode, grader)?;
    Ok(CapturedOutput {
        status,
        stdout,
        stderr,
    })
}

fn complete_capture(
    capture: CaptureOutcome,
    stream: &str,
    mode: &str,
    grader: &Grader,
) -> Result<Vec<u8>> {
    let CaptureOutcome::Complete(captured) = capture else {
        bail!(
            "cargo nextest {mode} did not capture {stream} for {}:{}",
            grader.package,
            grader.target
        );
    };
    if captured.truncated {
        bail!(
            "cargo nextest {mode} exceeded the {stream} capture limit of {GRADER_CAPTURE_LIMIT} bytes for {}:{}",
            grader.package,
            grader.target
        );
    }
    Ok(captured.bytes)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn committed_manifest_covers_every_ecosystem_once() {
        let manifest: Manifest = load().expect("committed push grader manifest");
        assert_eq!(manifest.grader.len(), 11);
        assert_eq!(manifest.uncovered.len(), 6);
    }

    #[test]
    fn duplicate_ecosystem_is_rejected() {
        let manifest: Manifest = Manifest {
            version: 1,
            grader: vec![grader(Ecosystem::Python)],
            uncovered: vec![Uncovered {
                ecosystem: EcosystemName(Ecosystem::Python),
                reason: "covered twice".to_owned(),
            }],
        };
        let error: eyre::Report = validate(&manifest).expect_err("duplicate ecosystem must fail");
        assert!(error.to_string().contains("both grader and uncovered"));
    }

    #[test]
    fn selector_option_is_rejected() {
        let mut grader: Grader = grader(Ecosystem::Python);
        grader.package = "--workspace".to_owned();
        let error: eyre::Report = validate_grader(&grader).expect_err("option must fail");
        assert!(error.to_string().contains("non-option Cargo identifier"));
    }

    #[test]
    fn ignored_or_filtered_test_is_rejected() {
        let value: Value = serde_json::json!({
            "test-count": 1,
            "rust-suites": {
                "example": {
                    "status": "listed",
                    "testcases": {
                        "example::test": {
                            "ignored": true,
                            "filter-match": {"status": "matches"}
                        }
                    }
                }
            }
        });
        let error: eyre::Report =
            listed_count(&value, &grader(Ecosystem::Python)).expect_err("ignored test must fail");
        assert!(
            error
                .to_string()
                .contains("ignored, filtered, or malformed")
        );
    }

    #[test]
    fn list_without_a_count_is_rejected() {
        let value: Value = serde_json::json!({"rust-suites": {}});
        let error: eyre::Report = listed_count(&value, &grader(Ecosystem::Python))
            .expect_err("missing list count must fail");
        assert!(error.to_string().contains("no valid test-count"));
    }

    #[test]
    fn citation_missing_from_the_list_is_rejected() {
        let identities: BTreeSet<String> = BTreeSet::from(["reference".to_owned()]);
        let error: eyre::Report =
            require_citations(&grader(Ecosystem::Python), &identities, "listed")
                .expect_err("missing mutation citation must fail");
        assert!(
            error
                .to_string()
                .contains("mutation control test \"mutation\" was not listed")
        );
    }

    #[test]
    fn skipped_junit_test_is_rejected() {
        let temp: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
        let report = temp.path().join(JUNIT_FILENAME);
        fs::write(
            &report,
            "<testsuites><testsuite><testcase name=\"reference\"><skipped /></testcase></testsuite></testsuites>",
        )
        .expect("write JUnit fixture");
        let error: eyre::Report = junit_counts(&report, 1).expect_err("skipped test must fail");
        assert!(error.to_string().contains("failed, errored, or skipped"));
    }

    #[test]
    fn failed_junit_test_is_rejected() {
        let temp: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
        let report = temp.path().join(JUNIT_FILENAME);
        fs::write(
            &report,
            "<testsuites><testsuite><testcase name=\"reference\"><failure /></testcase></testsuite></testsuites>",
        )
        .expect("write JUnit fixture");
        let error: eyre::Report = junit_counts(&report, 1).expect_err("failed test must fail");
        assert!(error.to_string().contains("failed, errored, or skipped"));
    }

    #[test]
    fn oversized_junit_report_is_rejected_before_parsing() {
        let temp: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
        let report = temp.path().join(JUNIT_FILENAME);
        let oversized: Vec<u8> = vec![b'x'; MAX_JUNIT_REPORT_BYTES as usize + 1];
        fs::write(&report, oversized).expect("write oversized JUnit fixture");
        let error: eyre::Report = junit_counts(&report, 1).expect_err("oversized report must fail");
        assert!(format!("{error:#}").contains("exceeds 8388608 byte cap"));
    }

    #[test]
    fn complete_junit_result_reports_exact_counts() {
        let temp: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
        let report = temp.path().join(JUNIT_FILENAME);
        fs::write(
            &report,
            "<testsuites><testsuite><testcase name=\"reference\" /></testsuite></testsuites>",
        )
        .expect("write JUnit fixture");
        assert_eq!(
            junit_counts(&report, 1).expect("complete report"),
            JunitReceipt {
                counts: RunCounts { run: 1, passed: 1 },
                passed: BTreeSet::from(["reference".to_owned()]),
            }
        );
    }

    #[test]
    fn citation_missing_from_passed_junit_result_is_rejected() {
        let temp: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
        let report = temp.path().join(JUNIT_FILENAME);
        fs::write(
            &report,
            "<testsuites><testsuite><testcase name=\"reference\" /></testsuite></testsuites>",
        )
        .expect("write JUnit fixture");
        let receipt: JunitReceipt = junit_counts(&report, 1).expect("complete report");
        let error: eyre::Report =
            require_citations(&grader(Ecosystem::Python), &receipt.passed, "passed")
                .expect_err("missing mutation citation must fail");
        assert!(
            error
                .to_string()
                .contains("mutation control test \"mutation\" was not passed")
        );
    }

    #[test]
    fn citation_source_must_be_a_test_function() {
        assert!(!has_test_function("fn reference() {}", "reference"));
        assert!(has_test_function("#[test]\nfn reference() {}", "reference"));
    }

    #[test]
    fn missing_or_mismatched_junit_result_is_rejected() {
        let temp: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
        let report = temp.path().join(JUNIT_FILENAME);
        let missing: eyre::Report = junit_counts(&report, 1).expect_err("missing report must fail");
        assert!(missing.to_string().contains("reading nextest JUnit report"));
        fs::write(&report, "<testsuites><testsuite /></testsuites>").expect("write JUnit fixture");
        let mismatch: eyre::Report =
            junit_counts(&report, 1).expect_err("count mismatch must fail");
        assert!(mismatch.to_string().contains("result mismatch"));
    }

    fn grader(ecosystem: Ecosystem) -> Grader {
        Grader {
            ecosystem: EcosystemName(ecosystem),
            package: "disrobe-pass-example".to_owned(),
            target: "example".to_owned(),
            features: Vec::new(),
            reference: citation("reference"),
            mutation: citation("mutation"),
        }
    }

    fn citation(test: &str) -> TestCitation {
        TestCitation {
            path: "crates/disrobe-pass-example/tests/example.rs".to_owned(),
            test: test.to_owned(),
        }
    }
}
