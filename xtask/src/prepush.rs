use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::{IsTerminal, Read};
use std::path::Path;
use std::process::{Command, Stdio};
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

const REGEN_TRIGGER_FILES: &[&str] = &["README.md", "SECURITY.md"];

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
    total += gate("health", || {
        crate::health::run(root, false)?;
        Ok(GateOutcome::Ran)
    })?;
    total += gate("comments", || {
        crate::comments::run_at(root, "HEAD")?;
        Ok(GateOutcome::Ran)
    })?;
    total += gate("clippy", || gate_clippy(root, &scope))?;
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
        let tests_changed: bool = matches!(scope, Scope::Changed(paths) if paths.iter().any(|path: &Utf8PathBuf| path.as_str().starts_with("crates/") && path.as_str().contains("/tests/")));
        if tests_changed {
            crate::skip_census::run(root).wrap_err("the skip-and-return census is stale")?;
            return Ok(GateOutcome::Ran);
        }
        return Ok(GateOutcome::Skipped("no relevant changes".to_owned()));
    }
    crate::regen::run(root, true).wrap_err("generated artifacts are stale")?;
    Ok(GateOutcome::Ran)
}

fn gate_clippy(root: &Path, scope: &Scope) -> Result<GateOutcome> {
    let mut args: Vec<String> = vec!["clippy".to_owned()];
    match scope {
        Scope::Skip => return Ok(GateOutcome::Skipped("no push content".to_owned())),
        Scope::Changed(paths)
            if !paths
                .iter()
                .any(|path: &Utf8PathBuf| is_shared_build_input(path)) =>
        {
            let crates: Vec<String> = owning_crates(root, paths)?;
            if crates.is_empty() {
                return Ok(GateOutcome::Skipped("no changed rust crates".to_owned()));
            }
            for name in crates {
                args.extend(["-p".to_owned(), name]);
            }
        }
        Scope::All | Scope::Changed(_) => args.push("--workspace".to_owned()),
    }
    args.extend(
        [
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
            "-W",
            "unreachable_pub",
            "-W",
            "missing_debug_implementations",
            "-W",
            "unused",
        ]
        .map(str::to_owned),
    );
    run_checked_owned(root, cargo_bin().as_str(), &args, || {
        "resolve the clippy findings above, then re-run the push".to_owned()
    })?;
    Ok(GateOutcome::Ran)
}

fn is_shared_build_input(path: &Utf8PathBuf) -> bool {
    matches!(
        path.file_name(),
        Some("Cargo.toml" | "Cargo.lock" | "clippy.toml" | "rust-toolchain.toml" | "build.rs")
    ) || path.starts_with(".cargo")
}

fn gate_test(root: &Path, scope: &Scope) -> Result<GateOutcome> {
    let members: Vec<CrateDir> = crate_dirs(root)?;
    let plan: BTreeMap<String, TestTargets> = match scope {
        Scope::All => members
            .iter()
            .map(|member: &CrateDir| (member.name.clone(), TestTargets::Crate))
            .collect(),
        Scope::Changed(paths) => test_targets(root, &members, paths)?,
        Scope::Skip => return Ok(GateOutcome::Skipped("no push content".to_owned())),
    };
    let caller_env: Vec<(&str, OsString)> = if plan.keys().any(|name: &String| name != SELF_CRATE) {
        caller_binary_env(root)?
    } else {
        Vec::new()
    };
    for (name, targets) in &plan {
        let TestTargets::Binaries(binaries) = targets else {
            continue;
        };
        if name == SELF_CRATE || binaries.is_empty() {
            continue;
        }
        let args: Vec<String> = binary_test_command(name, binaries);
        println!("    {name}: running only the changed test binaries {binaries:?}");
        run_checked_env(root, cargo_bin().as_str(), &args, &caller_env, || {
            format!("a changed test binary of {name} failed; fix it, then re-run the push")
        })?;
    }
    let crates: Vec<String> = plan
        .iter()
        .filter(|(_, targets): &(&String, &TestTargets)| **targets == TestTargets::Crate)
        .map(|(name, _): (&String, &TestTargets)| name.clone())
        .collect();
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
    let empty: Vec<String> = empty_test_binaries(root, &commands.nextest)?;
    if !empty.is_empty() {
        bail!(
            "selected test binaries compile zero tests ({}) under --all-features, so this gate \
             would count them as passing while they measure nothing: {}\n  fix: remove the binary \
             or the cfg that empties it; a binary built for one platform only says so with a \
             crate-level #![cfg(...)]",
            empty.len(),
            empty.join(", ")
        );
    }
    run_checked_env(
        root,
        cargo_bin().as_str(),
        &commands.nextest,
        &caller_env,
        || {
            "a selected pre-push test failed, timed out, or leaked a child output handle; fix the named test, or install or update cargo-nextest with `cargo install cargo-nextest --locked` if the command is missing or older than 0.9.115, then re-run the push".to_owned()
        },
    )?;
    run_checked_owned(root, cargo_bin().as_str(), &commands.doctest, || {
        "a committed doctest fails on the state being pushed; fix the named doctest, then re-run the push".to_owned()
    })?;
    Ok(GateOutcome::Ran)
}

fn list_command(run_args: &[String]) -> Vec<String> {
    let mut args: Vec<String> = Vec::with_capacity(run_args.len() + 2);
    for arg in run_args {
        match arg.as_str() {
            "run" => args.push("list".to_owned()),
            "--no-fail-fast" => {}
            _ => args.push(arg.clone()),
        }
    }
    args.extend(["--message-format".to_owned(), "json".to_owned()]);
    args
}

#[derive(Deserialize)]
struct NextestListing {
    #[serde(rename = "rust-suites")]
    rust_suites: BTreeMap<String, NextestSuite>,
}

#[derive(Deserialize)]
struct NextestSuite {
    #[serde(default)]
    status: SuiteStatus,
    testcases: BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum SuiteStatus {
    #[default]
    Listed,
    Skipped,
    SkippedDefaultFilter,
}

fn empty_test_binaries(root: &Path, run_args: &[String]) -> Result<Vec<String>> {
    let output: std::process::Output = Command::new(cargo_bin().as_str())
        .args(list_command(run_args))
        .current_dir(root)
        .stderr(Stdio::inherit())
        .output()
        .wrap_err("spawning cargo nextest list")?;
    if !output.status.success() {
        bail!(
            "`cargo nextest list` exited with {}\n  fix: resolve the build errors above, then \
             re-run the push",
            output.status
        );
    }
    let listing: NextestListing =
        serde_json::from_slice(&output.stdout).wrap_err("parsing cargo nextest list json")?;
    let sources: BTreeMap<String, String> = crate_dirs(root)?
        .into_iter()
        .flat_map(|member: CrateDir| {
            let package: String = member.name;
            member
                .test_targets
                .into_iter()
                .map(move |(name, src): (String, String)| (format!("{package}::{name}"), src))
        })
        .collect();
    Ok(empty_suites(&listing, &sources, |src: &str| {
        std::fs::read_to_string(root.join(src)).is_ok_and(|text: String| platform_gated(&text))
    }))
}

fn platform_gated(source: &str) -> bool {
    source
        .lines()
        .any(|line: &str| line.trim_start().starts_with("#![cfg("))
}

fn empty_suites<F: Fn(&str) -> bool>(
    listing: &NextestListing,
    sources: &BTreeMap<String, String>,
    gated: F,
) -> Vec<String> {
    listing
        .rust_suites
        .iter()
        .filter(|(_, suite): &(&String, &NextestSuite)| {
            suite.status == SuiteStatus::Listed && suite.testcases.is_empty()
        })
        .filter(|(id, _): &(&String, &NextestSuite)| {
            sources
                .get(id.as_str())
                .is_some_and(|src: &String| !gated(src))
        })
        .map(|(id, _): (&String, &NextestSuite)| id.clone())
        .collect()
}

fn binary_test_command(name: &str, binaries: &BTreeSet<String>) -> Vec<String> {
    let mut args: Vec<String> = [
        "nextest",
        "run",
        "--profile",
        "pre-push",
        "--ignore-default-filter",
        "--all-features",
        "--no-fail-fast",
        "-p",
        name,
    ]
    .map(str::to_owned)
    .to_vec();
    for binary in binaries {
        args.extend(["--test".to_owned(), binary.clone()]);
    }
    args
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
        "--all-features".to_owned(),
        "--no-fail-fast".to_owned(),
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
        || (text.starts_with("crates/") && text.contains("/src/"))
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
        if let Some(member) = owning_member(&members, path.as_str())
            && !owners.contains(&member.name)
        {
            owners.push(member.name.clone());
        }
    }
    owners.sort();
    Ok(owners)
}

fn owning_member<'a>(members: &'a [CrateDir], file: &str) -> Option<&'a CrateDir> {
    members
        .iter()
        .filter(|member: &&CrateDir| owns(&member.dir, file))
        .max_by_key(|member: &&CrateDir| member.dir.len())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TestTargets {
    Crate,
    Binaries(BTreeSet<String>),
}

fn test_targets(
    root: &Path,
    members: &[CrateDir],
    paths: &[Utf8PathBuf],
) -> Result<BTreeMap<String, TestTargets>> {
    let mut plan: BTreeMap<String, TestTargets> = BTreeMap::new();
    for path in paths {
        if let Some(needles) =
            corpus_needles(path.as_str()).or_else(|| github_needles(path.as_str()))
        {
            for member in members {
                let binaries: BTreeSet<String> = binaries_mentioning(root, member, &needles)?;
                add_binaries(&mut plan, &member.name, binaries);
            }
            continue;
        }
        let Some(member) = owning_member(members, path.as_str()) else {
            continue;
        };
        let relative: &str = path.as_str()[member.dir.len()..].trim_start_matches('/');
        if !relative.starts_with("tests/") {
            if path.extension() == Some("rs") || path.file_name() == Some("Cargo.toml") {
                plan.insert(member.name.clone(), TestTargets::Crate);
            }
            continue;
        }
        let binaries: BTreeSet<String> = binaries_including(root, member, path.as_str(), relative)?;
        add_binaries(&mut plan, &member.name, binaries);
    }
    Ok(plan)
}

fn add_binaries(plan: &mut BTreeMap<String, TestTargets>, name: &str, binaries: BTreeSet<String>) {
    if binaries.is_empty() {
        return;
    }
    let entry: &mut TestTargets = plan
        .entry(name.to_owned())
        .or_insert_with(|| TestTargets::Binaries(BTreeSet::new()));
    if let TestTargets::Binaries(existing) = entry {
        existing.extend(binaries);
    }
}

fn github_needles(path: &str) -> Option<Vec<String>> {
    path.starts_with(".github/")
        .then(|| vec!["\".github\"".to_owned()])
}

fn corpus_needles(path: &str) -> Option<Vec<String>> {
    let rest: &str = path.strip_prefix("corpus/")?;
    let mut parts: std::str::Split<'_, char> = rest.split('/');
    let ecosystem: &str = parts.next()?;
    let mut needles: Vec<String> = vec![
        format!("corpus/{ecosystem}\""),
        format!("corpus/{ecosystem}/\""),
    ];
    if let Some(directory) = parts.next().filter(|_| rest.matches('/').count() >= 2) {
        needles.push(format!("corpus/{ecosystem}/{directory}"));
    } else {
        needles.push(format!("corpus/{rest}"));
    }
    Some(needles)
}

fn binaries_mentioning(
    root: &Path,
    member: &CrateDir,
    needles: &[String],
) -> Result<BTreeSet<String>> {
    let mut found: BTreeSet<String> = BTreeSet::new();
    for (name, src) in &member.test_targets {
        let text: String = std::fs::read_to_string(root.join(src))
            .wrap_err_with(|| format!("reading test target {src}"))?;
        if needles
            .iter()
            .any(|needle: &String| text.contains(needle.as_str()))
        {
            found.insert(name.clone());
        }
    }
    Ok(found)
}

fn binaries_including(
    root: &Path,
    member: &CrateDir,
    file: &str,
    relative: &str,
) -> Result<BTreeSet<String>> {
    if let Some((name, _)) = member
        .test_targets
        .iter()
        .find(|(_, src): &&(String, String)| src == file)
    {
        return Ok(BTreeSet::from([name.clone()]));
    }
    let under_tests: &str = relative.trim_start_matches("tests/");
    let module: &str = under_tests.split('/').next().unwrap_or(under_tests);
    let mut needles: Vec<String> = vec![
        under_tests.to_owned(),
        format!("mod {}", module.trim_end_matches(".rs")),
    ];
    if let Some((directory, _)) = under_tests.rsplit_once('/') {
        needles.push(directory.to_owned());
    }
    binaries_mentioning(root, member, &needles)
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
    test_targets: Vec<(String, String)>,
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
        let test_targets: Vec<(String, String)> = package
            .targets
            .iter()
            .filter(|target: &&MetaTarget| target.kind.iter().any(|kind: &String| kind == "test"))
            .filter_map(|target: &MetaTarget| {
                Path::new(&target.src_path)
                    .strip_prefix(ws_root)
                    .ok()
                    .map(|path: &Path| {
                        (
                            target.name.clone(),
                            path.to_string_lossy().replace('\\', "/"),
                        )
                    })
            })
            .collect();
        members.push(CrateDir {
            name: package.name,
            dir: normalized,
            test_targets,
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
    #[serde(default)]
    targets: Vec<MetaTarget>,
}

#[derive(Deserialize, Debug)]
struct MetaTarget {
    name: String,
    kind: Vec<String>,
    src_path: String,
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

const CALLER_BINARY_VARIABLES: [&str; 2] = ["DISROBE_BIN", "DISROBE_MEASUREMENT_EXECUTABLE"];

fn caller_binary_env(root: &Path) -> Result<Vec<(&'static str, OsString)>> {
    if CALLER_BINARY_VARIABLES
        .iter()
        .all(|name: &&str| std::env::var_os(name).is_some())
    {
        return Ok(Vec::new());
    }
    println!("xtask prepush: building the disrobe CLI that caller tests run");
    let output: std::process::Output = Command::new(cargo_bin().as_str())
        .args([
            "build",
            "-p",
            "disrobe-cli",
            "--bin",
            "disrobe",
            "--message-format=json-render-diagnostics",
        ])
        .current_dir(root)
        .stderr(Stdio::inherit())
        .output()
        .wrap_err("spawning cargo build for the disrobe CLI")?;
    if !output.status.success() {
        bail!(
            "`cargo build -p disrobe-cli --bin disrobe` exited with {}\n  fix: resolve the build \
             errors above, then re-run the push",
            output.status
        );
    }
    let executable: OsString = cli_executable(&String::from_utf8_lossy(&output.stdout))
        .ok_or_else(|| eyre::eyre!("cargo build reported no executable for the disrobe CLI"))?;
    Ok(CALLER_BINARY_VARIABLES
        .iter()
        .filter(|name: &&&str| std::env::var_os(name).is_none())
        .map(|name: &&str| (*name, executable.clone()))
        .collect())
}

fn cli_executable(messages: &str) -> Option<OsString> {
    messages
        .lines()
        .filter_map(|line: &str| serde_json::from_str::<BuildMessage>(line).ok())
        .filter(|message: &BuildMessage| {
            message.reason == "compiler-artifact"
                && message
                    .target
                    .as_ref()
                    .is_some_and(|target: &BuildTarget| target.name == "disrobe")
        })
        .find_map(|message: BuildMessage| message.executable)
        .map(OsString::from)
}

#[derive(Deserialize)]
struct BuildMessage {
    reason: String,
    #[serde(default)]
    target: Option<BuildTarget>,
    #[serde(default)]
    executable: Option<String>,
}

#[derive(Deserialize)]
struct BuildTarget {
    name: String,
}

fn run_checked_env<F: FnOnce() -> String>(
    root: &Path,
    program: &str,
    args: &[String],
    env: &[(&str, OsString)],
    remediation: F,
) -> Result<()> {
    let status: std::process::ExitStatus = Command::new(program)
        .args(args)
        .envs(
            env.iter()
                .map(|(name, value): &(&str, OsString)| (*name, value)),
        )
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
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::OsString;

    use super::{
        CrateDir, NextestListing, SELF_CRATE, Scope, ScopedTestCommands, TestTargets,
        binary_test_command, cli_executable, empty_suites, is_shared_build_input, list_command,
        platform_gated, scoped_test_commands, should_validate_nextest_config, test_targets,
    };
    use camino::Utf8PathBuf;

    #[test]
    fn list_command_lists_what_the_run_would_run() {
        let run: Vec<String> = [
            "nextest",
            "run",
            "--profile",
            "pre-push",
            "--all-features",
            "--no-fail-fast",
            "-p",
            "a",
        ]
        .map(str::to_owned)
        .to_vec();
        assert_eq!(
            list_command(&run),
            [
                "nextest",
                "list",
                "--profile",
                "pre-push",
                "--all-features",
                "-p",
                "a",
                "--message-format",
                "json"
            ]
            .map(str::to_owned)
            .to_vec()
        );
    }

    #[test]
    fn an_empty_binary_fails_unless_platform_gated_or_skipped_by_the_profile() -> eyre::Result<()> {
        let listing: NextestListing = serde_json::from_str(
            r#"{"rust-suites":{
                "a::empty":{"testcases":{}},
                "a::gated":{"testcases":{}},
                "a::filtered":{"status":"skipped-default-filter","testcases":{}},
                "a::named":{"status":"listed","testcases":{}},
                "a::full":{"testcases":{"t":{}}},
                "a":{"testcases":{}}
            }}"#,
        )?;
        let sources: BTreeMap<String, String> = [
            ("a::empty".to_owned(), "tests/empty.rs".to_owned()),
            ("a::gated".to_owned(), "tests/gated.rs".to_owned()),
            ("a::full".to_owned(), "tests/full.rs".to_owned()),
            ("a::filtered".to_owned(), "tests/filtered.rs".to_owned()),
            ("a::named".to_owned(), "tests/named.rs".to_owned()),
        ]
        .into_iter()
        .collect();
        let empty: Vec<String> =
            empty_suites(&listing, &sources, |src: &str| src == "tests/gated.rs");
        assert_eq!(empty, vec!["a::empty".to_owned(), "a::named".to_owned()]);
        assert!(platform_gated("#![allow(x)]\n#![cfg(unix)]\nfn f() {}"));
        assert!(!platform_gated("#![allow(x)]\nfn f() {}"));
        Ok(())
    }

    #[test]
    fn a_test_only_change_runs_just_the_binaries_that_include_it() -> eyre::Result<()> {
        let root: tempfile::TempDir = tempfile::tempdir()?;
        let tests_dir: std::path::PathBuf = root.path().join("crates/c/tests");
        std::fs::create_dir_all(tests_dir.join("support"))?;
        std::fs::write(
            tests_dir.join("a.rs"),
            "#[path = \"support/x.rs\"]\nmod x;\n",
        )?;
        std::fs::write(tests_dir.join("b.rs"), "fn main() {}\n")?;
        std::fs::write(tests_dir.join("support/x.rs"), "pub fn f() {}\n")?;
        let members: Vec<CrateDir> = vec![CrateDir {
            name: "c".to_owned(),
            dir: "crates/c".to_owned(),
            test_targets: vec![
                ("a".to_owned(), "crates/c/tests/a.rs".to_owned()),
                ("b".to_owned(), "crates/c/tests/b.rs".to_owned()),
            ],
        }];
        let support_only: BTreeMap<String, TestTargets> = test_targets(
            root.path(),
            &members,
            &[Utf8PathBuf::from("crates/c/tests/support/x.rs")],
        )?;
        assert_eq!(
            support_only.get("c"),
            Some(&TestTargets::Binaries(BTreeSet::from(["a".to_owned()])))
        );
        let with_source: BTreeMap<String, TestTargets> = test_targets(
            root.path(),
            &members,
            &[
                Utf8PathBuf::from("crates/c/tests/b.rs"),
                Utf8PathBuf::from("crates/c/src/lib.rs"),
            ],
        )?;
        assert_eq!(with_source.get("c"), Some(&TestTargets::Crate));
        Ok(())
    }

    #[test]
    fn a_workflow_change_selects_the_binaries_that_read_github() -> eyre::Result<()> {
        let root: tempfile::TempDir = tempfile::tempdir()?;
        let tests_dir: std::path::PathBuf = root.path().join("crates/c/tests");
        std::fs::create_dir_all(&tests_dir)?;
        std::fs::write(
            tests_dir.join("meta.rs"),
            "fn dir() { root.join(\".github\"); }
",
        )?;
        std::fs::write(
            tests_dir.join("other.rs"),
            "fn f() {}
",
        )?;
        let members: Vec<CrateDir> = vec![CrateDir {
            name: "c".to_owned(),
            dir: "crates/c".to_owned(),
            test_targets: vec![
                ("meta".to_owned(), "crates/c/tests/meta.rs".to_owned()),
                ("other".to_owned(), "crates/c/tests/other.rs".to_owned()),
            ],
        }];
        let plan: BTreeMap<String, TestTargets> = test_targets(
            root.path(),
            &members,
            &[Utf8PathBuf::from(".github/workflows/codeql.yml")],
        )?;
        assert_eq!(
            plan.get("c"),
            Some(&TestTargets::Binaries(BTreeSet::from(["meta".to_owned()])))
        );
        Ok(())
    }

    #[test]
    fn a_corpus_change_selects_the_binaries_that_read_it() -> eyre::Result<()> {
        let root: tempfile::TempDir = tempfile::tempdir()?;
        let tests_dir: std::path::PathBuf = root.path().join("crates/c/tests");
        std::fs::create_dir_all(&tests_dir)?;
        std::fs::write(
            tests_dir.join("sweep.rs"),
            "const ROOT: &str = \"../../corpus/dotnet\";\n",
        )?;
        std::fs::write(
            tests_dir.join("vm.rs"),
            "include_bytes!(\"../../../corpus/dotnet/eazvm/x.dll\");\n",
        )?;
        std::fs::write(
            tests_dir.join("other.rs"),
            "include_bytes!(\"../../../corpus/jvm/a.class\");\n",
        )?;
        let members: Vec<CrateDir> = vec![CrateDir {
            name: "c".to_owned(),
            dir: "crates/c".to_owned(),
            test_targets: vec![
                ("sweep".to_owned(), "crates/c/tests/sweep.rs".to_owned()),
                ("vm".to_owned(), "crates/c/tests/vm.rs".to_owned()),
                ("other".to_owned(), "crates/c/tests/other.rs".to_owned()),
            ],
        }];
        let plan: BTreeMap<String, TestTargets> = test_targets(
            root.path(),
            &members,
            &[Utf8PathBuf::from(
                "corpus/dotnet/eazvm/EazSample.devirt.dll",
            )],
        )?;
        assert_eq!(
            plan.get("c"),
            Some(&TestTargets::Binaries(BTreeSet::from([
                "sweep".to_owned(),
                "vm".to_owned()
            ])))
        );
        Ok(())
    }

    #[test]
    fn the_cli_executable_comes_from_its_compiler_artifact_message() {
        let messages: &str = concat!(
            "{\"reason\":\"compiler-artifact\",\"target\":{\"name\":\"disrobe_core\"},\"executable\":null}\n",
            "not json\n",
            "{\"reason\":\"compiler-artifact\",\"target\":{\"name\":\"disrobe\"},\"executable\":\"/t/debug/disrobe\"}\n",
            "{\"reason\":\"build-finished\",\"success\":true}\n",
        );
        assert_eq!(
            cli_executable(messages),
            Some(OsString::from("/t/debug/disrobe"))
        );
        assert_eq!(cli_executable("{\"reason\":\"build-finished\"}"), None);
    }

    #[test]
    fn binary_commands_select_every_feature_and_each_binary() {
        let binaries: BTreeSet<String> = BTreeSet::from(["a".to_owned(), "b".to_owned()]);
        assert_eq!(
            binary_test_command("c", &binaries),
            [
                "nextest",
                "run",
                "--profile",
                "pre-push",
                "--ignore-default-filter",
                "--all-features",
                "--no-fail-fast",
                "-p",
                "c",
                "--test",
                "a",
                "--test",
                "b"
            ]
        );
    }

    #[test]
    fn shared_build_inputs_widen_clippy_to_the_workspace() {
        for shared in [
            "Cargo.lock",
            "crates/disrobe-core/Cargo.toml",
            ".cargo/config.toml",
            "clippy.toml",
        ] {
            assert!(
                is_shared_build_input(&Utf8PathBuf::from(shared)),
                "{shared}"
            );
        }
        for local in [
            "crates/disrobe-core/src/lib.rs",
            "docs/src/SUMMARY.md",
            "lefthook.yml",
        ] {
            assert!(!is_shared_build_input(&Utf8PathBuf::from(local)), "{local}");
        }
    }

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
                    "--all-features",
                    "--no-fail-fast",
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
        assert_eq!(
            actual.nextest,
            [
                "nextest",
                "run",
                "--profile",
                "pre-push",
                "--all-features",
                "--no-fail-fast"
            ]
        );
        assert_eq!(actual.doctest, ["test", "--doc"]);
        assert!(actual.self_excluded);
        assert_eq!(actual.selected_crates, 0);
    }
}
