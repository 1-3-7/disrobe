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
        files.len() >= 6,
        "expected the trimmed .github yaml surface, found {}",
        files.len()
    );
    for path in &files {
        let _: Value = parse_yaml(path);
    }
}

#[test]
fn github_yaml_set_is_exact() {
    let mut names: BTreeSet<String> = BTreeSet::new();
    for path in yaml_files_under(&github_dir()) {
        let rel: String = path
            .strip_prefix(github_dir())
            .expect("under .github")
            .to_string_lossy()
            .replace('\\', "/");
        names.insert(rel);
    }
    let expected: BTreeSet<String> = [
        "FUNDING.yml",
        "ISSUE_TEMPLATE/bug_report.yml",
        "ISSUE_TEMPLATE/config.yml",
        "ISSUE_TEMPLATE/feature_request.yml",
        "workflows/benchmark.yml",
        "workflows/ci.yml",
        "workflows/docs.yml",
        "workflows/evidence.yml",
        "workflows/fuzz.yml",
        "workflows/native-gcc-oracle.yml",
        "workflows/native-ms-x64-fp-oracle.yml",
        "workflows/release.yml",
        "workflows/verify-release.yml",
        "workflows/wiki-sync.yml",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(names, expected, ".github yaml set drifted");
}

#[test]
fn no_pr_or_bot_automation_remains() {
    let gone: [PathBuf; 7] = [
        github_dir().join("PULL_REQUEST_TEMPLATE.md"),
        github_dir().join("CODEOWNERS"),
        github_dir().join("labeler.yml"),
        github_dir().join("stale.yml"),
        github_dir().join("dependabot.yml"),
        github_dir().join("workflows").join("labeler.yml"),
        github_dir().join("workflows").join("stale.yml"),
    ];
    for path in &gone {
        assert!(
            !path.exists(),
            "{} must stay deleted: this repo takes direct pushes only, never PRs or bot automation",
            path.display()
        );
    }
}

#[test]
fn workflows_have_no_pull_request_trigger() {
    let dir: PathBuf = github_dir().join("workflows");
    for path in yaml_files_under(&dir) {
        let doc: Value = parse_yaml(&path);
        let on: &Value = doc
            .get("on")
            .or_else(|| doc.get(Value::Bool(true)))
            .unwrap_or_else(|| panic!("{} has no `on` block", path.display()));
        assert!(
            on.get("pull_request").is_none() && on.get("pull_request_target").is_none(),
            "{} must not carry a pull_request trigger: PRs are never opened on this repo",
            path.display()
        );
    }
}

#[test]
fn security_md_steers_to_private_advisory() {
    let raw: String = read(&workspace_root().join("SECURITY.md"));
    assert!(
        raw.contains("security/advisories/new"),
        "SECURITY.md must point at the private advisory channel"
    );
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
fn ci_mirrors_the_weekly_cron_pattern() {
    let doc: Value = cron_workflow("ci.yml");
    assert!(
        !crons(&doc).is_empty(),
        "ci.yml must keep its scheduled cron trigger"
    );
}
