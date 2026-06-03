#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::unnecessary_debug_formatting
)]

use std::collections::BTreeSet;
use std::path::Path;
use std::path::PathBuf;

use serde_yaml_ng::Value;

fn workspace_root() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn github_dir() -> PathBuf {
    workspace_root().join(".github")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", path.display()))
}

fn parse_yaml(path: &Path) -> Value {
    let text: String = read(path);
    serde_yaml_ng::from_str::<Value>(&text)
        .unwrap_or_else(|e: serde_yaml_ng::Error| panic!("parse {}: {e}", path.display()))
}

fn yaml_files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut stack: Vec<PathBuf> = vec![dir.to_path_buf()];
    while let Some(cur) = stack.pop() {
        let entries = std::fs::read_dir(&cur)
            .unwrap_or_else(|e: std::io::Error| panic!("read_dir {}: {e}", cur.display()));
        for entry in entries {
            let entry = entry.expect("dir entry");
            let path: PathBuf = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if matches!(
                path.extension().and_then(|s| s.to_str()),
                Some("yml" | "yaml")
            ) {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

#[test]
fn every_github_yaml_parses() {
    let files: Vec<PathBuf> = yaml_files_under(&github_dir());
    assert!(
        files.len() >= 10,
        "expected the full .github yaml surface, found {}",
        files.len()
    );
    for path in &files {
        let _: Value = parse_yaml(path);
    }
}

#[test]
fn issue_template_set_is_exact() {
    let dir: PathBuf = github_dir().join("ISSUE_TEMPLATE");
    let mut stems: BTreeSet<String> = BTreeSet::new();
    for path in yaml_files_under(&dir) {
        stems.insert(
            path.file_stem()
                .and_then(|s| s.to_str())
                .expect("utf-8 stem")
                .to_string(),
        );
    }
    let expected: BTreeSet<String> = [
        "bug",
        "feature",
        "perf",
        "pass-request",
        "sample-doesnt-work",
        "security",
        "config",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(stems, expected, "ISSUE_TEMPLATE set drifted");
}

#[test]
fn security_issue_template_is_labeled_security_and_steers_to_advisory() {
    let path: PathBuf = github_dir().join("ISSUE_TEMPLATE").join("security.yml");
    let doc: Value = parse_yaml(&path);
    let labels: &Vec<Value> = doc
        .get("labels")
        .and_then(Value::as_sequence)
        .expect("security.yml labels sequence");
    assert!(
        labels
            .iter()
            .any(|v: &Value| v.as_str() == Some("security")),
        "security.yml must carry the `security` label"
    );
    let raw: String = read(&path);
    assert!(
        raw.contains("security/advisories/new"),
        "security.yml must point at the private advisory channel"
    );
}

#[test]
fn labeler_maps_python_passes_to_lang_python() {
    let path: PathBuf = github_dir().join("labeler.yml");
    let doc: Value = parse_yaml(&path);
    assert!(
        doc.get("lang:python").is_some(),
        "labeler.yml must define lang:python"
    );
    let raw: String = read(&path);
    assert!(
        raw.contains("crates/disrobe-pass-py-*/**"),
        "lang:python must glob the python pass crates"
    );
}

#[test]
fn release_notes_config_has_security_and_catchall_categories() {
    let path: PathBuf = github_dir().join("release.yml");
    let doc: Value = parse_yaml(&path);
    let categories: &Vec<Value> = doc
        .get("changelog")
        .and_then(|c: &Value| c.get("categories"))
        .and_then(Value::as_sequence)
        .expect("release.yml changelog.categories");
    let titles: Vec<&str> = categories
        .iter()
        .filter_map(|c: &Value| c.get("title").and_then(Value::as_str))
        .collect();
    assert!(
        titles.iter().any(|t: &&str| t.contains("Security")),
        "release.yml needs a Security category"
    );
    let has_catchall: bool = categories.iter().any(|c: &Value| {
        c.get("labels")
            .and_then(Value::as_sequence)
            .is_some_and(|ls: &Vec<Value>| ls.iter().any(|l: &Value| l.as_str() == Some("*")))
    });
    assert!(has_catchall, "release.yml needs a `*` catch-all category");
}

#[test]
fn stale_config_exempts_security_and_pass_request() {
    let path: PathBuf = github_dir().join("stale.yml");
    let doc: Value = parse_yaml(&path);
    let exempt: &Vec<Value> = doc
        .get("exemptLabels")
        .and_then(Value::as_sequence)
        .expect("stale.yml exemptLabels");
    let set: BTreeSet<&str> = exempt.iter().filter_map(Value::as_str).collect();
    assert!(set.contains("security"), "stale must exempt security");
    assert!(
        set.contains("pass-request"),
        "stale must exempt pass-request"
    );
}

#[test]
fn labeler_config_is_consumed_by_a_labeler_workflow() {
    let path: PathBuf = github_dir().join("workflows").join("labeler.yml");
    assert!(
        path.is_file(),
        "missing .github/workflows/labeler.yml to consume labeler.yml"
    );
    let _: Value = parse_yaml(&path);
    let raw: String = read(&path);
    assert!(
        raw.contains("actions/labeler@"),
        "labeler workflow must run actions/labeler"
    );
}

#[test]
fn stale_workflow_exempts_every_label_in_the_policy_file() {
    let policy: Value = parse_yaml(&github_dir().join("stale.yml"));
    let exempt: BTreeSet<String> = policy
        .get("exemptLabels")
        .and_then(Value::as_sequence)
        .expect("stale.yml exemptLabels")
        .iter()
        .filter_map(|v: &Value| v.as_str().map(str::to_owned))
        .collect();

    let path: PathBuf = github_dir().join("workflows").join("stale.yml");
    assert!(
        path.is_file(),
        "missing .github/workflows/stale.yml to consume the stale policy"
    );
    let _: Value = parse_yaml(&path);
    let raw: String = read(&path);
    assert!(
        raw.contains("actions/stale@"),
        "stale workflow must run actions/stale"
    );
    let exempt_line: &str = raw
        .lines()
        .find(|l: &&str| l.contains("exempt-issue-labels"))
        .expect("stale workflow must set exempt-issue-labels");
    for label in &exempt {
        assert!(
            exempt_line.contains(label.as_str()),
            "stale workflow exempt-issue-labels missing `{label}` from .github/stale.yml policy"
        );
    }
}

fn cron_workflow(name: &str) -> Value {
    parse_yaml(&github_dir().join("workflows").join(name))
}

fn crons(doc: &Value) -> Vec<String> {
    doc.get("on")
        .or_else(|| doc.get(Value::Bool(true)))
        .and_then(|on: &Value| on.get("schedule"))
        .and_then(Value::as_sequence)
        .map(|s: &Vec<Value>| {
            s.iter()
                .filter_map(|e: &Value| e.get("cron").and_then(Value::as_str).map(String::from))
                .collect::<Vec<String>>()
        })
        .unwrap_or_default()
}

#[test]
fn pyarmor_catchup_is_monthly_idempotent_issue_opener() {
    let path: PathBuf = github_dir().join("workflows").join("pyarmor-catchup.yml");
    let doc: Value = cron_workflow("pyarmor-catchup.yml");
    assert_eq!(
        crons(&doc),
        vec!["0 6 1 * *".to_string()],
        "pyarmor-catchup must run on the first of every month at 06:00 UTC"
    );
    let raw: String = read(&path);
    assert!(
        raw.contains("gh issue create"),
        "pyarmor-catchup must create an issue"
    );
    assert!(
        raw.contains("gh issue list --state open --label"),
        "pyarmor-catchup must guard against an already-open issue"
    );
    assert!(
        raw.contains("pyarmor-catchup"),
        "pyarmor-catchup must reference its tracking label"
    );
}

#[test]
fn competitive_intel_refresh_is_quarterly_idempotent_issue_opener() {
    let path: PathBuf = github_dir()
        .join("workflows")
        .join("competitive-intel-refresh.yml");
    let doc: Value = cron_workflow("competitive-intel-refresh.yml");
    assert_eq!(
        crons(&doc),
        vec!["0 6 1 1,4,7,10 *".to_string()],
        "competitive-intel-refresh must run quarterly on the first at 06:00 UTC"
    );
    let raw: String = read(&path);
    assert!(
        raw.contains("gh issue create"),
        "competitive-intel-refresh must create an issue"
    );
    assert!(
        raw.contains("gh issue list --state open --label"),
        "competitive-intel-refresh must guard against an already-open issue"
    );
    assert!(
        raw.contains("competitive-intel"),
        "competitive-intel-refresh must reference its tracking label"
    );
}

#[test]
fn ci_mirrors_the_weekly_cron_pattern() {
    let doc: Value = cron_workflow("ci.yml");
    assert!(
        !crons(&doc).is_empty(),
        "ci.yml must keep its scheduled cron trigger"
    );
}
