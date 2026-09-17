use std::io::{IsTerminal, Read};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use camino::Utf8PathBuf;
use eyre::{Result, WrapErr, bail};
use serde::Deserialize;

const REGEN_TRIGGER_PREFIXES: &[&str] = &[
    "xtask/",
    "schemas/",
    "bindings/",
    "evidence/",
    "docs/assets/",
    "docs/errors/",
    "docs/demo/",
    "docs/src/",
    "crates/disrobe-cli/src/cli/explain/codes/",
];

const SELF_CRATE: &str = "xtask";

const REGEN_TRIGGER_FILES: &[&str] = &["README.md"];

#[derive(Debug)]
enum Scope {
    All,
    Skip,
    Changed(Vec<Utf8PathBuf>),
}

#[derive(Debug)]
enum GateOutcome {
    Ran,
    Skipped(String),
}

#[derive(Debug, PartialEq, Eq)]
struct ScopedTestCommands {
    nextest: Vec<String>,
    doctest: Vec<String>,
    self_excluded: bool,
    selected_crates: usize,
}

pub(crate) fn run(root: &Path, full: bool) -> Result<()> {
    let scope: Scope = compute_scope(root, full)?;
    match &scope {
        Scope::Skip => {
            println!("xtask prepush: tag/delete-only push, nothing to gate");
            return Ok(());
        }
        Scope::All => {
            println!("xtask prepush: full scope (every workspace crate, every gate)");
        }
        Scope::Changed(paths) => {
            println!("xtask prepush: {} changed path(s) in scope", paths.len());
        }
    }

    let mut total: Duration = Duration::ZERO;
    total += gate("fmt", || gate_fmt(root, &scope))?;
    total += gate("regen", || gate_regen(root, &scope))?;
    total += gate("clippy", || gate_clippy(root))?;
    total += gate("test", || gate_test(root, &scope))?;
    println!(
        "xtask prepush: all gates passed in {:.1}s",
        total.as_secs_f64()
    );
    Ok(())
}

pub(crate) fn setup_hooks(root: &Path) -> Result<()> {
    let result: std::io::Result<std::process::ExitStatus> = Command::new("lefthook")
        .arg("install")
        .current_dir(root)
        .status();
    match result {
        Ok(status) if status.success() => {
            println!(
                "xtask setup-hooks: lefthook hooks installed (pre-commit, commit-msg, pre-push)"
            );
            Ok(())
        }
        Ok(status) => bail!("`lefthook install` exited with {status}"),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => bail!(
            "lefthook is not on PATH; install it and re-run `cargo xtask setup-hooks`:\n  \
             go install github.com/evilmartians/lefthook@latest\n  \
             npm install --global lefthook\n  \
             brew install lefthook\n  \
             winget install evilmartians.lefthook"
        ),
        Err(err) => Err(err).wrap_err("spawning lefthook install"),
    }
}

fn gate<F: FnOnce() -> Result<GateOutcome>>(name: &str, run_gate: F) -> Result<Duration> {
    let start: Instant = Instant::now();
    let outcome: GateOutcome = run_gate().wrap_err_with(|| format!("prepush gate `{name}`"))?;
    let elapsed: Duration = start.elapsed();
    match outcome {
        GateOutcome::Ran => println!("  [{name}] ok ({:.1}s)", elapsed.as_secs_f64()),
        GateOutcome::Skipped(reason) => {
            println!(
                "  [{name}] skipped ({reason}) ({:.1}s)",
                elapsed.as_secs_f64()
            );
        }
    }
    Ok(elapsed)
}

fn gate_fmt(root: &Path, scope: &Scope) -> Result<GateOutcome> {
    let crates: Vec<String> = match scope {
        Scope::All => workspace_crates(root)?,
        Scope::Changed(paths) => owning_crates(root, paths)?,
        Scope::Skip => return Ok(GateOutcome::Skipped("no push content".to_owned())),
    };
    if crates.is_empty() {
        return Ok(GateOutcome::Skipped("no changed rust crates".to_owned()));
    }
    for name in &crates {
        run_checked(
            root,
            cargo_bin().as_str(),
            &["fmt", "-p", name, "--", "--check"],
            || format!("cargo fmt -p {name} && git add -u && git commit --amend --no-edit"),
        )?;
    }
    Ok(GateOutcome::Ran)
}

fn gate_regen(root: &Path, scope: &Scope) -> Result<GateOutcome> {
    let triggered: bool = match scope {
        Scope::All => true,
        Scope::Changed(paths) => paths.iter().any(|path: &Utf8PathBuf| touches_regen(path)),
        Scope::Skip => false,
    };
    if !triggered {
        return Ok(GateOutcome::Skipped("no relevant changes".to_owned()));
    }
    crate::regen::run(root, true).wrap_err("generated artifacts are stale")?;
    Ok(GateOutcome::Ran)
}

fn gate_clippy(root: &Path) -> Result<GateOutcome> {
    run_checked(
        root,
        cargo_bin().as_str(),
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
        || "resolve the clippy findings above, then re-run the push".to_owned(),
    )?;
    Ok(GateOutcome::Ran)
}

fn gate_test(root: &Path, scope: &Scope) -> Result<GateOutcome> {
    let crates: Vec<String> = match scope {
        Scope::All => workspace_crates(root)?,
        Scope::Changed(paths) => owning_crates(root, paths)?,
        Scope::Skip => return Ok(GateOutcome::Skipped("no push content".to_owned())),
    };
    let commands: ScopedTestCommands = scoped_test_commands(&crates);
    if commands.self_excluded {
        println!(
            "    {SELF_CRATE}'s own tests are not run by this gate, because the gate executes as \
             {SELF_CRATE} and cannot replace its own running binary; the workspace test job covers \
             them instead"
        );
    }
    if commands.selected_crates == 0 {
        if should_validate_nextest_config(scope, commands.selected_crates) {
            run_checked(
                root,
                cargo_bin().as_str(),
                &["nextest", "show-config", "version"],
                || {
                    "install or update cargo-nextest with `cargo install cargo-nextest --locked`; version 0.9.115 or newer is required by .config/nextest.toml, then re-run the push".to_owned()
                },
            )?;
            return Ok(GateOutcome::Ran);
        }
        let reason: &str = if crates.is_empty() {
            "no changed rust crates"
        } else {
            "only xtask changed"
        };
        return Ok(GateOutcome::Skipped(reason.to_owned()));
    }
    run_checked_owned(root, cargo_bin().as_str(), &commands.nextest, || {
        "a selected pre-push test failed, timed out, or leaked a child output handle; fix the named test, or install or update cargo-nextest with `cargo install cargo-nextest --locked` if the command is missing or older than 0.9.115, then re-run the push".to_owned()
    })?;
    run_checked_owned(root, cargo_bin().as_str(), &commands.doctest, || {
        "a committed doctest fails on the state being pushed; fix the named doctest, then re-run the push".to_owned()
    })?;
    Ok(GateOutcome::Ran)
}

fn scoped_test_commands(crates: &[String]) -> ScopedTestCommands {
    let self_excluded: bool = crates.iter().any(|name: &String| name == SELF_CRATE);
    let mut selected: Vec<&str> = crates
        .iter()
        .map(String::as_str)
        .filter(|name: &&str| *name != SELF_CRATE)
        .collect();
    selected.sort_unstable();
    selected.dedup();
    let selected_crates: usize = selected.len();
    let mut nextest: Vec<String> = vec![
        "nextest".to_owned(),
        "run".to_owned(),
        "--profile".to_owned(),
        "pre-push".to_owned(),
    ];
    let mut doctest: Vec<String> = vec!["test".to_owned(), "--doc".to_owned()];
    for name in selected {
        nextest.extend(["-p".to_owned(), name.to_owned()]);
        doctest.extend(["-p".to_owned(), name.to_owned()]);
    }
    ScopedTestCommands {
        nextest,
        doctest,
        self_excluded,
        selected_crates,
    }
}

fn should_validate_nextest_config(scope: &Scope, selected_crates: usize) -> bool {
    selected_crates == 0
        && matches!(
            scope,
            Scope::Changed(paths)
                if paths.iter().any(|path: &Utf8PathBuf| path.as_str() == ".config/nextest.toml")
        )
}

fn touches_regen(path: &Utf8PathBuf) -> bool {
    let text: &str = path.as_str();
    REGEN_TRIGGER_FILES.contains(&text)
        || REGEN_TRIGGER_PREFIXES
            .iter()
            .any(|prefix: &&str| text.starts_with(prefix))
}

fn compute_scope(root: &Path, full: bool) -> Result<Scope> {
    if full {
        return Ok(Scope::All);
    }
    if let Some(scope) = scope_from_stdin(root)? {
        return Ok(scope);
    }
    scope_from_upstream(root)
}

fn scope_from_stdin(root: &Path) -> Result<Option<Scope>> {
    if std::io::stdin().is_terminal() {
        return Ok(None);
    }
    let mut raw: String = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .wrap_err("reading pre-push ref pairs from stdin")?;
    let lines: Vec<&str> = raw
        .lines()
        .filter(|line: &&str| !line.trim().is_empty())
        .collect();
    if lines.is_empty() {
        return Ok(None);
    }
    let mut changed: Vec<Utf8PathBuf> = Vec::new();
    let mut saw_branch: bool = false;
    for line in lines {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [local_ref, local_sha, _remote_ref, remote_sha] = fields.as_slice() else {
            return Ok(None);
        };
        if is_zero_sha(local_sha) {
            continue;
        }
        if !local_ref.starts_with("refs/heads/") {
            continue;
        }
        saw_branch = true;
        let Some(range) = push_range(root, remote_sha, local_sha)? else {
            return Ok(Some(Scope::All));
        };
        changed.extend(diff_names(root, &range)?);
    }
    if !saw_branch {
        return Ok(Some(Scope::Skip));
    }
    dedup(&mut changed);
    Ok(Some(Scope::Changed(changed)))
}

fn scope_from_upstream(root: &Path) -> Result<Scope> {
    let base: String = if rev_exists(root, "@{push}")? {
        "@{push}".to_owned()
    } else if rev_exists(root, "@{upstream}")? {
        "@{upstream}".to_owned()
    } else if let Some(merge_base) = merge_base(root, "origin/main", "HEAD")? {
        merge_base
    } else {
        println!("xtask prepush: no upstream or origin/main to diff against, running full scope");
        return Ok(Scope::All);
    };
    let range: String = format!("{base}..HEAD");
    Ok(Scope::Changed(diff_names(root, &range)?))
}

fn push_range(root: &Path, remote_sha: &str, local_sha: &str) -> Result<Option<String>> {
    if is_zero_sha(remote_sha) {
        return Ok(merge_base(root, "origin/main", local_sha)?
            .map(|base: String| format!("{base}..{local_sha}")));
    }
    Ok(Some(format!("{remote_sha}..{local_sha}")))
}

fn owning_crates(root: &Path, paths: &[Utf8PathBuf]) -> Result<Vec<String>> {
    let members: Vec<CrateDir> = crate_dirs(root)?;
    let mut owners: Vec<String> = Vec::new();
    for path in paths {
        if path.extension() != Some("rs") {
            continue;
        }
        let text: &str = path.as_str();
        let mut best: Option<&CrateDir> = None;
        for member in &members {
            if owns(&member.dir, text)
                && best.is_none_or(|current: &CrateDir| member.dir.len() > current.dir.len())
            {
                best = Some(member);
            }
        }
        if let Some(member) = best
            && !owners.contains(&member.name)
        {
            owners.push(member.name.clone());
        }
    }
    owners.sort();
    Ok(owners)
}

fn owns(dir: &str, file: &str) -> bool {
    file == dir
        || file
            .strip_prefix(dir)
            .is_some_and(|rest: &str| rest.starts_with('/'))
}

fn workspace_crates(root: &Path) -> Result<Vec<String>> {
    let mut names: Vec<String> = crate_dirs(root)?
        .into_iter()
        .map(|member: CrateDir| member.name)
        .collect();
    names.sort();
    Ok(names)
}

#[derive(Debug)]
struct CrateDir {
    name: String,
    dir: String,
}

fn crate_dirs(root: &Path) -> Result<Vec<CrateDir>> {
    let output: std::process::Output = Command::new(cargo_bin().as_str())
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(root)
        .output()
        .wrap_err("spawning cargo metadata")?;
    if !output.status.success() {
        bail!("cargo metadata failed with {}", output.status);
    }
    let meta: Metadata =
        serde_json::from_slice(&output.stdout).wrap_err("parsing cargo metadata json")?;
    let ws_root: &Path = Path::new(&meta.workspace_root);
    let mut members: Vec<CrateDir> = Vec::with_capacity(meta.packages.len());
    for package in meta.packages {
        let manifest: &Path = Path::new(&package.manifest_path);
        let Some(dir) = manifest.parent() else {
            continue;
        };
        let Ok(relative) = dir.strip_prefix(ws_root) else {
            continue;
        };
        let normalized: String = relative.to_string_lossy().replace('\\', "/");
        if normalized.is_empty() {
            continue;
        }
        members.push(CrateDir {
            name: package.name,
            dir: normalized,
        });
    }
    Ok(members)
}

#[derive(Deserialize, Debug)]
struct Metadata {
    packages: Vec<MetaPackage>,
    workspace_root: String,
}

#[derive(Deserialize, Debug)]
struct MetaPackage {
    name: String,
    manifest_path: String,
}

fn diff_names(root: &Path, range: &str) -> Result<Vec<Utf8PathBuf>> {
    let output: std::process::Output = Command::new("git")
        .args(["diff", "--name-only", range])
        .current_dir(root)
        .output()
        .wrap_err_with(|| format!("running git diff --name-only {range}"))?;
    if !output.status.success() {
        bail!("git diff --name-only {range} failed with {}", output.status);
    }
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&output.stdout);
    Ok(text
        .lines()
        .filter(|line: &&str| !line.is_empty())
        .map(Utf8PathBuf::from)
        .collect())
}

fn rev_exists(root: &Path, rev: &str) -> Result<bool> {
    let output: std::process::Output = Command::new("git")
        .args(["rev-parse", "--verify", "--quiet", rev])
        .current_dir(root)
        .output()
        .wrap_err_with(|| format!("running git rev-parse {rev}"))?;
    Ok(output.status.success())
}

fn merge_base(root: &Path, left: &str, right: &str) -> Result<Option<String>> {
    let output: std::process::Output = Command::new("git")
        .args(["merge-base", left, right])
        .current_dir(root)
        .output()
        .wrap_err_with(|| format!("running git merge-base {left} {right}"))?;
    if !output.status.success() {
        return Ok(None);
    }
    let base: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if base.is_empty() {
        Ok(None)
    } else {
        Ok(Some(base))
    }
}

fn run_checked<F: FnOnce() -> String>(
    root: &Path,
    program: &str,
    args: &[&str],
    remediation: F,
) -> Result<()> {
    let status: std::process::ExitStatus = Command::new(program)
        .args(args)
        .current_dir(root)
        .status()
        .wrap_err_with(|| format!("spawning `{program} {}`", args.join(" ")))?;
    if !status.success() {
        bail!(
            "`{program} {}` exited with {status}\n  fix: {}",
            args.join(" "),
            remediation()
        );
    }
    Ok(())
}

fn run_checked_owned<F: FnOnce() -> String>(
    root: &Path,
    program: &str,
    args: &[String],
    remediation: F,
) -> Result<()> {
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    run_checked(root, program, &borrowed, remediation)
}

fn dedup(paths: &mut Vec<Utf8PathBuf>) {
    paths.sort();
    paths.dedup();
}

fn is_zero_sha(sha: &str) -> bool {
    !sha.is_empty() && sha.bytes().all(|byte: u8| byte == b'0')
}

fn cargo_bin() -> Utf8PathBuf {
    std::env::var("CARGO")
        .ok()
        .map_or_else(|| Utf8PathBuf::from("cargo"), Utf8PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::{
        SELF_CRATE, Scope, ScopedTestCommands, scoped_test_commands, should_validate_nextest_config,
    };
    use camino::Utf8PathBuf;

    #[test]
    fn nextest_config_validation_is_reserved_for_config_only_scope() {
        let config_scope: Scope = Scope::Changed(vec![Utf8PathBuf::from(".config/nextest.toml")]);
        let product_scope: Scope =
            Scope::Changed(vec![Utf8PathBuf::from("crates/disrobe-bytes/src/lib.rs")]);

        assert!(should_validate_nextest_config(&config_scope, 0));
        assert!(!should_validate_nextest_config(&config_scope, 1));
        assert!(!should_validate_nextest_config(&product_scope, 0));
    }

    #[test]
    fn scoped_test_commands_are_batched_sorted_and_keep_doctests() {
        let crates: Vec<String> = vec![
            "disrobe-pass-jvm".to_owned(),
            SELF_CRATE.to_owned(),
            "disrobe-bytes".to_owned(),
            "disrobe-pass-jvm".to_owned(),
        ];
        let actual: ScopedTestCommands = scoped_test_commands(&crates);
        assert_eq!(
            actual,
            ScopedTestCommands {
                nextest: vec![
                    "nextest",
                    "run",
                    "--profile",
                    "pre-push",
                    "-p",
                    "disrobe-bytes",
                    "-p",
                    "disrobe-pass-jvm",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
                doctest: vec![
                    "test",
                    "--doc",
                    "-p",
                    "disrobe-bytes",
                    "-p",
                    "disrobe-pass-jvm",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
                self_excluded: true,
                selected_crates: 2,
            }
        );
    }

    #[test]
    fn scoped_test_commands_exclude_the_running_xtask() {
        let actual: ScopedTestCommands = scoped_test_commands(&[SELF_CRATE.to_owned()]);
        assert_eq!(actual.nextest, ["nextest", "run", "--profile", "pre-push"]);
        assert_eq!(actual.doctest, ["test", "--doc"]);
        assert!(actual.self_excluded);
        assert_eq!(actual.selected_crates, 0);
    }
}
