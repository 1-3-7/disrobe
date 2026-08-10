#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::unnecessary_debug_formatting
)]

use std::collections::BTreeSet;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use disrobe_core::chain::{VerdictDoc, VerdictGrade, VerdictThreshold};
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

fn tracked_yaml_under_github() -> BTreeSet<String> {
    let root: PathBuf = workspace_root();
    let output: std::process::Output = Command::new("git")
        .args(["ls-files", "-z", "--", ".github"])
        .current_dir(&root)
        .output()
        .unwrap_or_else(|e: std::io::Error| {
            panic!("running git ls-files in {}: {e}", root.display())
        });
    assert!(
        output.status.success(),
        "git ls-files exited with {} in {}",
        output.status,
        root.display()
    );
    let raw: String = String::from_utf8(output.stdout).expect("git ls-files output is utf-8");
    let tracked: BTreeSet<String> = raw
        .split('\0')
        .filter(|entry: &&str| {
            matches!(
                Path::new(entry)
                    .extension()
                    .and_then(|s: &std::ffi::OsStr| s.to_str()),
                Some("yml" | "yaml")
            )
        })
        .filter_map(|entry: &str| entry.strip_prefix(".github/"))
        .map(String::from)
        .collect();
    assert!(
        tracked.contains("workflows/ci.yml"),
        "git ls-files returned no workflows/ci.yml under .github, so the tracked set is not \
         trustworthy: {tracked:?}"
    );
    tracked
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
    let expected: BTreeSet<String> = tracked_yaml_under_github();
    assert_eq!(
        names, expected,
        ".github yaml set on disk drifted from the git index: a yaml file under .github is \
         untracked, or a tracked one is missing from the checkout"
    );
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

fn action_yaml() -> Value {
    parse_yaml(&workspace_root().join("action.yml"))
}

fn action_run_script() -> String {
    let doc: Value = action_yaml();
    let steps: &Vec<Value> = doc
        .get("runs")
        .and_then(|runs: &Value| runs.get("steps"))
        .and_then(Value::as_sequence)
        .expect("action.yml runs.steps");
    steps
        .iter()
        .filter_map(|step: &Value| step.get("run").and_then(Value::as_str))
        .collect::<Vec<&str>>()
        .join("\n")
}

fn disrobe_output(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_disrobe"))
        .args(args)
        .output()
        .unwrap_or_else(|error: std::io::Error| panic!("run disrobe {args:?}: {error}"))
}

fn top_level_commands() -> BTreeSet<String> {
    let output: std::process::Output = disrobe_output(&["subcommand-tree"]);
    assert!(
        output.status.success(),
        "subcommand-tree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("subcommand tree is utf-8")
        .lines()
        .filter_map(|path: &str| path.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

fn commands_accepting_out() -> BTreeSet<String> {
    top_level_commands()
        .into_iter()
        .filter(|command: &String| {
            let output: std::process::Output = disrobe_output(&[command, "--help"]);
            assert!(
                output.status.success(),
                "{command} --help failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout)
                .expect("command help is utf-8")
                .lines()
                .any(|line: &str| {
                    let trimmed: &str = line.trim_start();
                    trimmed.starts_with("-o, --out ") || trimmed.starts_with("--out ")
                })
        })
        .collect()
}

fn out_commands_without_positional_path() -> BTreeSet<String> {
    commands_accepting_out()
        .into_iter()
        .filter(|command: &String| {
            let output: std::process::Output = disrobe_output(&[command, "--help"]);
            assert!(output.status.success(), "{command} --help failed");
            String::from_utf8(output.stdout)
                .expect("command help is utf-8")
                .lines()
                .find(|line: &&str| line.starts_with("Usage:"))
                .is_some_and(|usage: &str| !usage.contains('<'))
        })
        .collect()
}

#[test]
fn action_out_and_path_pairing_matches_the_built_cli() {
    let script: String = action_run_script();
    let out_commands: BTreeSet<String> = commands_accepting_out();
    let out_pattern: String = out_commands.into_iter().collect::<Vec<String>>().join("|");
    assert!(
        script.contains(&format!(
            "{out_pattern})\n    outflag=(--out \"${{DR_OUT}}\")"
        )),
        "action.yml must pass --out to exactly the subcommands whose clap help declares it"
    );
    assert!(
        script.contains(&format!(
            "{})\n    patharg=()",
            out_commands_without_positional_path()
                .into_iter()
                .collect::<Vec<String>>()
                .join("|")
        )),
        "--out commands with no positional path must not receive inputs.path"
    );
    assert!(
        script.contains("\"${DR_BIN}\" \"${DR_COMMAND}\"")
            && script.contains("\"${extra[@]}\" \"${patharg[@]}\""),
        "the invocation must use the command-specific positional array"
    );
    assert!(
        script.contains("extra arguments must not repeat the action-managed --out flag"),
        "a user-supplied --out must be rejected before clap sees a duplicate"
    );
    assert!(
        script.contains("--out|--out=*|-o|-o?*)"),
        "both long and short user-supplied out forms must be rejected"
    );
    let rejection: usize = script
        .find("extra arguments must not repeat the action-managed --out flag")
        .expect("duplicate-out rejection");
    let invocation: usize = script
        .find("\"${DR_BIN}\" \"${DR_COMMAND}\"")
        .expect("disrobe invocation");
    let runtime_rejection: usize = script
        .find("if grep -qiE '^error: (unexpected argument")
        .expect("runtime argument-rejection guard");
    let fallback: usize = script
        .find("if [ ! -s \"${DR_SARIF}\" ]")
        .expect("SARIF fallback");
    assert!(
        rejection < invocation && invocation < runtime_rejection && runtime_rejection < fallback,
        "argument rejection must precede invocation, and the runtime rejection guard must precede the SARIF fallback"
    );
}

#[test]
fn every_chain_verdict_grades_to_a_fail_on_rung() {
    let cases: [(VerdictDoc, VerdictGrade); 10] = [
        (VerdictDoc::Ok, VerdictGrade::Ok),
        (VerdictDoc::Complete, VerdictGrade::Ok),
        (VerdictDoc::FanOut, VerdictGrade::Ok),
        (VerdictDoc::Extracted, VerdictGrade::Ok),
        (VerdictDoc::FanOutPartial, VerdictGrade::Incomplete),
        (VerdictDoc::Stalled, VerdictGrade::Incomplete),
        (VerdictDoc::Cycle, VerdictGrade::Incomplete),
        (VerdictDoc::CapReached, VerdictGrade::Incomplete),
        (VerdictDoc::DryRun, VerdictGrade::Incomplete),
        (VerdictDoc::Error, VerdictGrade::Failed),
    ];
    for (verdict, expected) in &cases {
        assert_eq!(
            verdict.grade(),
            *expected,
            "{verdict:?} must grade to {expected:?}; a new chain verdict needs a stated rung here \
             before the action can present it to a reader"
        );
    }
    let named: BTreeSet<String> = cases
        .iter()
        .map(|(verdict, _): &(VerdictDoc, VerdictGrade)| format!("{verdict:?}"))
        .collect();
    let declared: BTreeSet<String> = read(
        &workspace_root()
            .join("crates")
            .join("disrobe-core")
            .join("src")
            .join("chain")
            .join("chain_json.rs"),
    )
    .lines()
    .skip_while(|line: &&str| !line.contains("pub enum VerdictDoc {"))
    .skip(1)
    .take_while(|line: &&str| !line.contains('}'))
    .filter_map(|line: &str| {
        let trimmed: &str = line.trim().trim_end_matches(',');
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    })
    .collect();
    assert_eq!(
        named, declared,
        "the graded cases above and the VerdictDoc variants have drifted, so some verdict reaches \
         the action with no rung"
    );
}

#[test]
fn every_threshold_decides_every_grade() {
    let cases: [(VerdictThreshold, VerdictGrade, bool); 12] = [
        (VerdictThreshold::Never, VerdictGrade::Ok, false),
        (VerdictThreshold::Never, VerdictGrade::Incomplete, false),
        (VerdictThreshold::Never, VerdictGrade::Failed, false),
        (VerdictThreshold::Incomplete, VerdictGrade::Ok, false),
        (VerdictThreshold::Incomplete, VerdictGrade::Incomplete, true),
        (VerdictThreshold::Incomplete, VerdictGrade::Failed, true),
        (VerdictThreshold::Failed, VerdictGrade::Ok, false),
        (VerdictThreshold::Failed, VerdictGrade::Incomplete, false),
        (VerdictThreshold::Failed, VerdictGrade::Failed, true),
        (VerdictThreshold::Any, VerdictGrade::Ok, false),
        (VerdictThreshold::Any, VerdictGrade::Incomplete, true),
        (VerdictThreshold::Any, VerdictGrade::Failed, true),
    ];
    for (threshold, grade, expected) in cases {
        assert_eq!(
            grade.meets(threshold),
            expected,
            "grade {grade:?} against fail-on {threshold:?}"
        );
    }
    for raw in ["never", "incomplete", "failed", "any"] {
        assert!(
            VerdictThreshold::parse(raw).is_some(),
            "the action documents fail-on {raw}, which the parser must accept"
        );
    }
    assert!(VerdictThreshold::parse("sometimes").is_none());
}

#[test]
fn the_action_reads_its_verdict_from_the_recovery_report() {
    let script: String = action_run_script();
    assert!(
        script.contains("context --out") && script.contains("--fail-on"),
        "action.yml must ask the disrobe binary for the chain verdict rather than deciding it in shell"
    );
    assert!(
        script.contains("disrobe-verdict:"),
        "action.yml must read the verdict marker the context command prints"
    );
    let sarif_drives_verdict: bool = script
        .lines()
        .any(|line: &str| line.contains("verdict=\"incomplete\"") && line.contains("results"));
    assert!(
        !sarif_drives_verdict,
        "the SARIF finding count must not decide the verdict; a clean chain that reported a secret \
         is a complete run"
    );
    let doc: Value = action_yaml();
    let outputs: &Value = doc.get("outputs").expect("action.yml outputs");
    for name in ["verdict", "chain-verdict", "summary", "sarif"] {
        assert!(
            outputs.get(name).is_some(),
            "action.yml must declare the {name} output it writes"
        );
    }
}
