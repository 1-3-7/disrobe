use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File};
use std::io::Read as _;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use eyre::{Result, WrapErr, bail, eyre};
use serde::Deserialize;
use walkdir::WalkDir;

use crate::fileio::{read_bytes_bounded, read_text_bounded};

pub(crate) const MANIFEST_PATH: &str = "benches/perf/manifest.toml";
pub(crate) const GOLDEN_PATH: &str = "benches/perf/golden.txt";

const WORK_MARKER: &str = ".xtask-golden";
const CONFIG_NAME: &str = "golden.disrobe.toml";
const WORK_DIRS: [&str; 6] = ["home", "in", "logs", "out", "path", "tmp"];
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_GOLDEN_BYTES: u64 = 16 * 1024 * 1024;
const MAX_INPUT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_OUTPUT_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_JOBS: usize = 8;
const MAX_THREAD_NAME_BYTES: usize = 256;
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const TIMED_FILES: [&str; 4] = ["chain.json", "recovery.json", "report.json", "report.sarif"];
const VOLATILE_JSON_KEYS: [&[u8]; 2] = [b"\"duration_ms\"", b"\"total_ms\""];
const TIMESTAMP_SHAPE: &[u8; 19] = b"0000-00-00T00:00:00";
const PASSTHROUGH_ENV: [&str; 2] = ["SystemRoot", "windir"];
const HOME_ENV: [&str; 8] = [
    "HOME",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
];
const TEMP_ENV: [&str; 3] = ["TEMP", "TMP", "TMPDIR"];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct InputId(String);

impl InputId {
    fn parse(text: &str) -> Result<Self> {
        let valid: bool = !text.is_empty()
            && text
                .bytes()
                .all(|byte: u8| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
        if !valid {
            bail!("golden input id `{text}` must be ASCII letters, digits, `-` or `_`");
        }
        Ok(Self(text.to_owned()))
    }
}

impl fmt::Display for InputId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestFile {
    input: Vec<ManifestRow>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestRow {
    id: String,
    path: String,
    #[serde(default)]
    subset: bool,
}

#[derive(Debug, Clone)]
struct GoldenInput {
    id: InputId,
    path: String,
    subset: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Exit {
    Code(i32),
    Signal(i32),
}

impl Exit {
    fn from_status(status: ExitStatus) -> Result<Self> {
        if let Some(code) = status.code() {
            return Ok(Self::Code(code));
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt as _;
            if let Some(signal) = status.signal() {
                return Ok(Self::Signal(signal));
            }
        }
        bail!("exit status {status} carries neither a code nor a signal")
    }
}

impl fmt::Display for Exit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Code(code) => write!(f, "code {code}"),
            Self::Signal(signal) => write!(f, "signal {signal}"),
        }
    }
}

impl FromStr for Exit {
    type Err = eyre::Report;

    fn from_str(text: &str) -> Result<Self> {
        let (kind, value): (&str, &str) = text
            .split_once(' ')
            .ok_or_else(|| eyre!("exit `{text}` is not `code N` or `signal N`"))?;
        let number: i32 = value
            .parse()
            .wrap_err_with(|| format!("exit `{text}` has a non-integer value"))?;
        match kind {
            "code" => Ok(Self::Code(number)),
            "signal" => Ok(Self::Signal(number)),
            _ => bail!("exit `{text}` is not `code N` or `signal N`"),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct OutputTree {
    dirs: BTreeSet<String>,
    files: BTreeMap<String, blake3::Hash>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Outcome {
    exit: Exit,
    input: blake3::Hash,
    stdout: blake3::Hash,
    stderr: blake3::Hash,
    tree: OutputTree,
}

type Listing = BTreeMap<InputId, Outcome>;

#[derive(Debug)]
pub(crate) struct RunOptions {
    pub(crate) bin: PathBuf,
    pub(crate) repo: PathBuf,
    pub(crate) work: PathBuf,
    pub(crate) subset: bool,
    pub(crate) only: Vec<String>,
    pub(crate) jobs: Option<usize>,
    pub(crate) timeout: Duration,
}

pub(crate) fn record(root: &Path, options: &RunOptions, to: &Path) -> Result<()> {
    let manifest: Vec<GoldenInput> = load_manifest(root)?;
    let selected: Vec<GoldenInput> = select(&manifest, options)?;
    let actual: Listing = run_all(&selected, options)?;
    let partial: bool = selected.len() < manifest.len();
    let mut listing: Listing = if partial && to.is_file() {
        parse_listing(&read_text_bounded(to, MAX_GOLDEN_BYTES)?)?
    } else {
        Listing::new()
    };
    let recorded: usize = actual.len();
    listing.extend(actual);
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent).wrap_err_with(|| format!("creating {}", parent.display()))?;
    }
    fs::write(to, render_listing(&listing))
        .wrap_err_with(|| format!("writing {}", to.display()))?;
    println!(
        "xtask golden: recorded {recorded} input(s) into {} ({} in total)",
        to.display(),
        listing.len()
    );
    Ok(())
}

pub(crate) fn check(root: &Path, options: &RunOptions, against: &Path) -> Result<()> {
    let manifest: Vec<GoldenInput> = load_manifest(root)?;
    let selected: Vec<GoldenInput> = select(&manifest, options)?;
    let recorded: Listing = parse_listing(&read_text_bounded(against, MAX_GOLDEN_BYTES)?)?;
    let listed: BTreeSet<&InputId> = manifest
        .iter()
        .map(|input: &GoldenInput| &input.id)
        .collect();
    let mut differences: Vec<String> = recorded
        .keys()
        .filter(|id: &&InputId| !listed.contains(id))
        .map(|id: &InputId| format!("{id}: recorded but no longer in the manifest"))
        .collect();
    let actual: Listing = run_all(&selected, options)?;
    let wanted: BTreeSet<&InputId> = selected
        .iter()
        .map(|input: &GoldenInput| &input.id)
        .collect();
    let expected: Listing = recorded
        .into_iter()
        .filter(|(id, _): &(InputId, Outcome)| wanted.contains(id))
        .collect();
    differences.extend(compare(&expected, &actual));
    if differences.is_empty() {
        println!(
            "xtask golden: {} input(s) match {}",
            actual.len(),
            against.display()
        );
        return Ok(());
    }
    for difference in &differences {
        eprintln!("  {difference}");
    }
    bail!(
        "xtask golden: {} difference(s) against {}",
        differences.len(),
        against.display()
    )
}

fn load_manifest(root: &Path) -> Result<Vec<GoldenInput>> {
    let path: PathBuf = root.join(MANIFEST_PATH);
    let text: String = read_text_bounded(&path, MAX_MANIFEST_BYTES)?;
    parse_manifest(&text).wrap_err_with(|| format!("reading {}", path.display()))
}

fn parse_manifest(text: &str) -> Result<Vec<GoldenInput>> {
    let file: ManifestFile = toml::from_str(text).wrap_err("parsing the golden manifest")?;
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut inputs: Vec<GoldenInput> = Vec::with_capacity(file.input.len());
    for row in file.input {
        let id: InputId = InputId::parse(&row.id)?;
        let relative: bool = !row.path.is_empty()
            && !row.path.starts_with('/')
            && !row.path.contains(['\\', ':'])
            && row
                .path
                .split('/')
                .all(|part: &str| !part.is_empty() && part != "." && part != "..");
        if !relative {
            bail!(
                "input {id} path `{}` must be a plain relative path",
                row.path
            );
        }
        if !seen.insert(id.0.to_ascii_lowercase()) {
            bail!("input id {id} appears twice, ignoring letter case");
        }
        inputs.push(GoldenInput {
            id,
            path: row.path,
            subset: row.subset,
        });
    }
    if inputs.is_empty() {
        bail!("the golden manifest lists no input");
    }
    Ok(inputs)
}

fn select(manifest: &[GoldenInput], options: &RunOptions) -> Result<Vec<GoldenInput>> {
    let only: BTreeSet<InputId> = options
        .only
        .iter()
        .map(|text: &String| InputId::parse(text))
        .collect::<Result<_>>()?;
    let unknown: Vec<&InputId> = only
        .iter()
        .filter(|id: &&InputId| !manifest.iter().any(|input: &GoldenInput| &input.id == *id))
        .collect();
    if !unknown.is_empty() {
        bail!("--only names input(s) the manifest does not list: {unknown:?}");
    }
    let selected: Vec<GoldenInput> = manifest
        .iter()
        .filter(|input: &&GoldenInput| !options.subset || input.subset)
        .filter(|input: &&GoldenInput| only.is_empty() || only.contains(&input.id))
        .cloned()
        .collect();
    if selected.is_empty() {
        bail!("the selection matches no manifest input");
    }
    Ok(selected)
}

fn run_all(inputs: &[GoldenInput], options: &RunOptions) -> Result<Listing> {
    if !options.bin.is_file() {
        bail!(
            "{} is not a file; build it with `cargo build --profile ci -p disrobe-cli --bin disrobe` and pass --bin",
            options.bin.display()
        );
    }
    require_tracked(&options.repo, inputs)?;
    let sandbox: Sandbox = Sandbox::prepare(&options.work)?;
    let bin_dir: &Path = options
        .bin
        .parent()
        .ok_or_else(|| eyre!("{} has no parent directory", options.bin.display()))?;
    let guard: HostPaths =
        HostPaths::new(&[sandbox.root.as_path(), bin_dir, options.repo.as_path()])?;
    let jobs: usize = options
        .jobs
        .unwrap_or_else(|| {
            thread::available_parallelism()
                .map_or(1, NonZeroUsize::get)
                .min(MAX_JOBS)
        })
        .clamp(1, inputs.len());
    let next: AtomicUsize = AtomicUsize::new(0);
    let results: Mutex<Listing> = Mutex::new(Listing::new());
    let failures: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let started: Instant = Instant::now();
    thread::scope(|scope: &thread::Scope<'_, '_>| {
        for _ in 0..jobs {
            scope.spawn(|| {
                while let Some(input) = inputs.get(next.fetch_add(1, Ordering::Relaxed)) {
                    match run_input(input, options, &sandbox, &guard) {
                        Ok(outcome) => {
                            results
                                .lock()
                                .unwrap_or_else(PoisonError::into_inner)
                                .insert(input.id.clone(), outcome);
                        }
                        Err(err) => failures
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .push(format!("{}: {err:#}", input.id)),
                    }
                }
            });
        }
    });
    let mut failures: Vec<String> = failures
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner);
    let ids: BTreeSet<&str> = inputs
        .iter()
        .map(|input: &GoldenInput| input.id.0.as_str())
        .collect();
    failures.extend(sandbox.strays(&ids)?);
    if !failures.is_empty() {
        failures.sort();
        bail!(
            "xtask golden: {} failure(s):\n  {}",
            failures.len(),
            failures.join("\n  ")
        );
    }
    println!(
        "xtask golden: {} input(s) in {:.1}s with {jobs} job(s)",
        inputs.len(),
        started.elapsed().as_secs_f64()
    );
    Ok(results.into_inner().unwrap_or_else(PoisonError::into_inner))
}

fn require_tracked(repo: &Path, inputs: &[GoldenInput]) -> Result<()> {
    let output: std::process::Output = Command::new("git")
        .args(["ls-files", "-z", "--"])
        .args(inputs.iter().map(|input: &GoldenInput| input.path.as_str()))
        .current_dir(repo)
        .output()
        .wrap_err_with(|| format!("running git ls-files in {}", repo.display()))?;
    if !output.status.success() {
        bail!(
            "git ls-files exited with {} in {}",
            output.status,
            repo.display()
        );
    }
    let listed: String =
        String::from_utf8(output.stdout).wrap_err("git ls-files output is not UTF-8")?;
    let tracked: BTreeSet<&str> = listed
        .split('\0')
        .filter(|entry: &&str| !entry.is_empty())
        .collect();
    let untracked: Vec<&str> = inputs
        .iter()
        .map(|input: &GoldenInput| input.path.as_str())
        .filter(|path: &&str| !tracked.contains(path))
        .collect();
    if !untracked.is_empty() {
        bail!(
            "golden inputs must be tracked by git in {}: {untracked:?}",
            repo.display()
        );
    }
    Ok(())
}

#[derive(Debug)]
struct Sandbox {
    root: PathBuf,
    home: PathBuf,
    path: PathBuf,
}

impl Sandbox {
    fn prepare(work: &Path) -> Result<Self> {
        if work.exists() {
            if !work.join(WORK_MARKER).is_file() {
                bail!(
                    "refusing to clear {}: it does not carry the {WORK_MARKER} marker of a golden work directory",
                    work.display()
                );
            }
            fs::remove_dir_all(work).wrap_err_with(|| format!("clearing {}", work.display()))?;
        }
        for dir in WORK_DIRS {
            let path: PathBuf = work.join(dir);
            fs::create_dir_all(&path).wrap_err_with(|| format!("creating {}", path.display()))?;
        }
        fs::write(work.join(CONFIG_NAME), b"")
            .wrap_err_with(|| format!("writing the pinned config in {}", work.display()))?;
        fs::write(work.join(WORK_MARKER), b"")
            .wrap_err_with(|| format!("marking {}", work.display()))?;
        Ok(Self {
            root: work.to_path_buf(),
            home: work.join("home"),
            path: work.join("path"),
        })
    }

    fn strays(&self, ids: &BTreeSet<&str>) -> Result<Vec<String>> {
        let mut strays: Vec<String> = Vec::new();
        for (dir, place) in [
            (&self.home, "the home directory"),
            (&self.path, "the empty PATH directory"),
        ] {
            for name in stray_entries(dir, false)? {
                strays.push(format!("a run wrote {name} into {place}"));
            }
        }
        for name in entry_names(&self.root)? {
            if !WORK_DIRS.contains(&name.as_str()) && name != CONFIG_NAME && name != WORK_MARKER {
                strays.push(format!("a run wrote {name:?} into the work directory"));
            }
        }
        for dir in ["in", "out", "tmp"] {
            for name in entry_names(&self.root.join(dir))? {
                if !ids.contains(name.as_str()) {
                    strays.push(format!("a run wrote {dir}/{name}"));
                }
            }
        }
        for name in entry_names(&self.root.join("logs"))? {
            let known: bool = name
                .strip_suffix(".stdout")
                .or_else(|| name.strip_suffix(".stderr"))
                .is_some_and(|id: &str| ids.contains(id));
            if !known {
                strays.push(format!("a run wrote logs/{name}"));
            }
        }
        let config: PathBuf = self.root.join(CONFIG_NAME);
        let config_len: u64 = fs::metadata(&config)
            .wrap_err_with(|| format!("stat {}", config.display()))?
            .len();
        if config_len != 0 {
            strays.push(format!("a run wrote into the pinned config {CONFIG_NAME}"));
        }
        Ok(strays)
    }
}

fn run_input(
    input: &GoldenInput,
    options: &RunOptions,
    sandbox: &Sandbox,
    guard: &HostPaths,
) -> Result<Outcome> {
    let source: PathBuf = options.repo.join(&input.path);
    let file_name: &str = Path::new(&input.path)
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| eyre!("input {} path has no file name", input.id))?;
    let source_len: u64 = fs::metadata(&source)
        .wrap_err_with(|| format!("stat {}", source.display()))?
        .len();
    if source_len > MAX_INPUT_BYTES {
        bail!(
            "{} exceeds the {MAX_INPUT_BYTES}-byte input cap",
            source.display()
        );
    }
    let staged_dir: PathBuf = sandbox.root.join("in").join(&input.id.0);
    let staged: PathBuf = staged_dir.join(file_name);
    fs::create_dir_all(&staged_dir)
        .wrap_err_with(|| format!("creating {}", staged_dir.display()))?;
    fs::copy(&source, &staged).wrap_err_with(|| format!("staging {}", source.display()))?;
    let input_hash: blake3::Hash = hash_file(&staged)?;
    let out: PathBuf = sandbox.root.join("out").join(&input.id.0);
    let tmp: PathBuf = sandbox.root.join("tmp").join(&input.id.0);
    let stdout_path: PathBuf = sandbox
        .root
        .join("logs")
        .join(format!("{}.stdout", input.id));
    let stderr_path: PathBuf = sandbox
        .root
        .join("logs")
        .join(format!("{}.stderr", input.id));
    fs::create_dir_all(&tmp).wrap_err_with(|| format!("creating {}", tmp.display()))?;
    let stdout: File = File::create(&stdout_path)
        .wrap_err_with(|| format!("creating {}", stdout_path.display()))?;
    let stderr: File = File::create(&stderr_path)
        .wrap_err_with(|| format!("creating {}", stderr_path.display()))?;
    let mut command: Command = Command::new(&options.bin);
    command
        .args(["--config", CONFIG_NAME, "auto"])
        .arg(format!("in/{}/{file_name}", input.id))
        .arg("-o")
        .arg(format!("out/{}", input.id))
        .args(["--force", "--progress", "never", "--json"])
        .current_dir(&sandbox.root)
        .env_clear()
        .env("PATH", &sandbox.path)
        .env("SOURCE_DATE_EPOCH", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    for key in HOME_ENV {
        command.env(key, &sandbox.home);
    }
    for key in TEMP_ENV {
        command.env(key, &tmp);
    }
    for key in PASSTHROUGH_ENV {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    let started: Instant = Instant::now();
    let mut child: std::process::Child = command
        .spawn()
        .wrap_err_with(|| format!("starting {}", options.bin.display()))?;
    let exit: Exit = loop {
        if let Some(status) = child.try_wait().wrap_err("waiting for the CLI")? {
            break Exit::from_status(status)?;
        }
        if started.elapsed() >= options.timeout {
            child.kill().wrap_err("stopping a timed-out CLI run")?;
            child.wait().wrap_err("reaping a timed-out CLI run")?;
            bail!(
                "timed out after {}s; a timeout is never an expected outcome",
                options.timeout.as_secs()
            );
        }
        thread::sleep(POLL_INTERVAL);
    };
    let seconds: f64 = started.elapsed().as_secs_f64();
    let mut leaks: Vec<String> = Vec::new();
    if hash_file(&staged)? != input_hash {
        leaks.push("modified its staged input".to_owned());
    }
    for name in stray_entries(&staged_dir, false)? {
        if name != file_name {
            leaks.push(format!("wrote {name} next to its input"));
        }
    }
    for name in stray_entries(&tmp, true)? {
        leaks.push(format!("left {name} in its temporary directory"));
    }
    if !leaks.is_empty() {
        bail!("the CLI {}", leaks.join("; "));
    }
    let stdout_bytes: Vec<u8> = read_bytes_bounded(&stdout_path, MAX_OUTPUT_FILE_BYTES)?;
    guard.refuse(&stdout_bytes, "stdout")?;
    let stderr_bytes: Vec<u8> = read_bytes_bounded(&stderr_path, MAX_OUTPUT_FILE_BYTES)?;
    guard.refuse(&stderr_bytes, "stderr")?;
    let outcome: Outcome = Outcome {
        exit,
        input: input_hash,
        stdout: blake3::hash(&blank_volatile_values(&stdout_bytes)),
        stderr: blake3::hash(&normalize_stderr(&stderr_bytes)),
        tree: hash_tree(&out, guard)?,
    };
    println!(
        "  {} {} {} file(s) {seconds:.1}s",
        input.id,
        outcome.exit,
        outcome.tree.files.len()
    );
    Ok(outcome)
}

fn hash_file(path: &Path) -> Result<blake3::Hash> {
    let file: File = File::open(path).wrap_err_with(|| format!("opening {}", path.display()))?;
    let mut hasher: blake3::Hasher = blake3::Hasher::new();
    hasher
        .update_reader(file.take(MAX_INPUT_BYTES.saturating_add(1)))
        .wrap_err_with(|| format!("hashing {}", path.display()))?;
    if hasher.count() > MAX_INPUT_BYTES {
        bail!(
            "{} exceeds the {MAX_INPUT_BYTES}-byte input cap",
            path.display()
        );
    }
    Ok(hasher.finalize())
}

fn relative_name(path: &Path, dir: &Path) -> Result<String> {
    let name: String = path
        .strip_prefix(dir)
        .wrap_err_with(|| format!("{} is outside {}", path.display(), dir.display()))?
        .to_str()
        .ok_or_else(|| eyre!("{} is not a UTF-8 path", path.display()))?
        .replace('\\', "/");
    if name.contains(['\t', '\n', '\r']) {
        bail!("output path {name:?} contains a tab or line break");
    }
    Ok(name)
}

fn entry_names(dir: &Path) -> Result<Vec<String>> {
    let mut names: Vec<String> = Vec::new();
    for entry in fs::read_dir(dir).wrap_err_with(|| format!("reading {}", dir.display()))? {
        let entry: fs::DirEntry = entry.wrap_err_with(|| format!("reading {}", dir.display()))?;
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    Ok(names)
}

fn stray_entries(dir: &Path, allow_dirs: bool) -> Result<Vec<String>> {
    let mut stray: Vec<String> = Vec::new();
    for entry in WalkDir::new(dir).min_depth(1).sort_by_file_name() {
        let entry: walkdir::DirEntry =
            entry.wrap_err_with(|| format!("walking {}", dir.display()))?;
        if allow_dirs && entry.file_type().is_dir() {
            continue;
        }
        stray.push(relative_name(entry.path(), dir)?);
    }
    Ok(stray)
}

fn hash_tree(dir: &Path, guard: &HostPaths) -> Result<OutputTree> {
    let mut tree: OutputTree = OutputTree::default();
    if !dir.exists() {
        return Ok(tree);
    }
    for entry in WalkDir::new(dir).min_depth(1).sort_by_file_name() {
        let entry: walkdir::DirEntry =
            entry.wrap_err_with(|| format!("walking {}", dir.display()))?;
        let relative: String = relative_name(entry.path(), dir)?;
        let kind: fs::FileType = entry.file_type();
        if kind.is_dir() {
            let empty: bool = fs::read_dir(entry.path())
                .wrap_err_with(|| format!("reading {}", entry.path().display()))?
                .next()
                .is_none();
            if empty {
                tree.dirs.insert(relative);
            }
        } else if kind.is_file() {
            let bytes: Vec<u8> = read_bytes_bounded(entry.path(), MAX_OUTPUT_FILE_BYTES)?;
            guard.refuse(&bytes, &relative)?;
            let hash: blake3::Hash = if TIMED_FILES.contains(&relative.as_str()) {
                blake3::hash(&blank_volatile_values(&bytes))
            } else {
                blake3::hash(&bytes)
            };
            tree.files.insert(relative, hash);
        } else {
            bail!("output {relative} is neither a regular file nor a directory");
        }
    }
    Ok(tree)
}

#[derive(Debug)]
struct HostPaths {
    needles: Vec<Vec<u8>>,
}

impl HostPaths {
    fn new(roots: &[&Path]) -> Result<Self> {
        let mut needles: Vec<Vec<u8>> = Vec::new();
        for root in roots {
            let text: &str = root
                .to_str()
                .ok_or_else(|| eyre!("{} is not a UTF-8 path", root.display()))?
                .trim_end_matches(['\\', '/']);
            let named: usize = text
                .split(['\\', '/'])
                .filter(|part: &&str| !part.is_empty() && !part.ends_with(':'))
                .count();
            if named < 2 {
                bail!("{text} is too short to tell apart from the bytes of an input");
            }
            for form in [
                text.to_owned(),
                text.replace('\\', "/"),
                text.replace('\\', "\\\\"),
                text.replace('\\', "\\\\\\\\"),
            ] {
                let form: Vec<u8> = form.into_bytes();
                if !needles.contains(&form) {
                    needles.push(form);
                }
            }
        }
        Ok(Self { needles })
    }

    fn refuse(&self, bytes: &[u8], label: &str) -> Result<()> {
        for needle in &self.needles {
            let hit: bool =
                bytes
                    .windows(needle.len())
                    .enumerate()
                    .any(|(start, window): (usize, &[u8])| {
                        window.eq_ignore_ascii_case(needle)
                            && !continues_name(
                                bytes.get(start + needle.len()..).unwrap_or_default(),
                            )
                    });
            if hit {
                bail!(
                    "{label} embeds the host path `{}`; output that names this machine cannot be compared across machines",
                    String::from_utf8_lossy(needle)
                );
            }
        }
        Ok(())
    }
}

fn continues_name(rest: &[u8]) -> bool {
    match rest {
        [b'.', next, ..] => is_name_byte(*next),
        [byte, ..] => is_name_byte(*byte),
        [] => false,
    }
}

const fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-') || !byte.is_ascii()
}

fn normalize_stderr(bytes: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index: usize = 0;
    while let Some(rest) = bytes.get(index..).filter(|rest: &&[u8]| !rest.is_empty()) {
        if let Some(len) = timestamp_len(rest) {
            out.extend_from_slice(b"<time>");
            index += len;
        } else if let Some((keep, len)) = thread_id_span(rest) {
            out.extend_from_slice(&rest[..keep]);
            out.extend_from_slice(b"<tid>)");
            index += len;
        } else {
            out.push(rest[0]);
            index += 1;
        }
    }
    out
}

fn timestamp_len(bytes: &[u8]) -> Option<usize> {
    let head: &[u8] = bytes.get(..TIMESTAMP_SHAPE.len())?;
    let shaped: bool = head
        .iter()
        .zip(TIMESTAMP_SHAPE)
        .all(|(byte, shape): (&u8, &u8)| {
            if *shape == b'0' {
                byte.is_ascii_digit()
            } else {
                byte == shape
            }
        });
    if !shaped {
        return None;
    }
    let mut len: usize = TIMESTAMP_SHAPE.len();
    if bytes.get(len) == Some(&b'.') {
        let digits: usize = bytes[len + 1..]
            .iter()
            .take_while(|byte: &&u8| byte.is_ascii_digit())
            .count();
        if digits == 0 {
            return None;
        }
        len += 1 + digits;
    }
    (bytes.get(len) == Some(&b'Z')).then_some(len + 1)
}

fn thread_id_span(bytes: &[u8]) -> Option<(usize, usize)> {
    const OPEN: &[u8] = b"thread '";
    const CLOSE: &[u8] = b"' (";
    let name: &[u8] = bytes.strip_prefix(OPEN)?;
    let name_len: usize = name
        .iter()
        .take(MAX_THREAD_NAME_BYTES)
        .position(|byte: &u8| matches!(byte, b'\'' | b'\n'))?;
    let digits_at: &[u8] = name[name_len..].strip_prefix(CLOSE)?;
    let digits: usize = digits_at
        .iter()
        .take_while(|byte: &&u8| byte.is_ascii_digit())
        .count();
    if digits == 0 || digits_at.get(digits) != Some(&b')') {
        return None;
    }
    let keep: usize = OPEN.len() + name_len + CLOSE.len();
    Some((keep, keep + digits + 1))
}

fn blank_volatile_values(bytes: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index: usize = 0;
    while let Some(rest) = bytes.get(index..).filter(|rest: &&[u8]| !rest.is_empty()) {
        let key: Option<&&[u8]> = VOLATILE_JSON_KEYS
            .iter()
            .find(|key: &&&[u8]| rest.starts_with(key));
        let Some(key) = key else {
            out.push(rest[0]);
            index += 1;
            continue;
        };
        let value_start: usize =
            index + key.len() + json_separator_len(&bytes[index + key.len()..]);
        let value_len: usize = json_scalar_len(&bytes[value_start..]);
        if value_start == index + key.len() || value_len == 0 {
            out.extend_from_slice(key);
            index += key.len();
            continue;
        }
        out.extend_from_slice(&bytes[index..value_start]);
        out.extend_from_slice(if bytes[value_start] == b'"' {
            b"\"\""
        } else {
            b"0"
        });
        index = value_start + value_len;
    }
    out
}

fn json_separator_len(bytes: &[u8]) -> usize {
    let before: usize = bytes
        .iter()
        .take_while(|byte: &&u8| is_json_space(**byte))
        .count();
    if bytes.get(before) != Some(&b':') {
        return 0;
    }
    let after: usize = bytes[before + 1..]
        .iter()
        .take_while(|byte: &&u8| is_json_space(**byte))
        .count();
    before + 1 + after
}

fn json_scalar_len(bytes: &[u8]) -> usize {
    match bytes.first() {
        Some(b'"') => {
            let mut index: usize = 1;
            while let Some(byte) = bytes.get(index) {
                match byte {
                    b'\\' => index += 2,
                    b'"' => return index + 1,
                    _ => index += 1,
                }
            }
            0
        }
        Some(_) => bytes
            .iter()
            .take_while(|byte: &&u8| {
                byte.is_ascii_digit() || matches!(byte, b'-' | b'+' | b'.' | b'e' | b'E')
            })
            .count(),
        None => 0,
    }
}

const fn is_json_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

fn render_listing(listing: &Listing) -> String {
    let mut lines: Vec<String> = Vec::new();
    for (id, outcome) in listing {
        lines.push(format!("{id}\texit\t{}", outcome.exit));
        lines.push(format!("{id}\tinput\t{}", outcome.input.to_hex()));
        lines.push(format!("{id}\tstdout\t{}", outcome.stdout.to_hex()));
        lines.push(format!("{id}\tstderr\t{}", outcome.stderr.to_hex()));
        for path in &outcome.tree.dirs {
            lines.push(format!("{id}\tdir\t{path}"));
        }
        for (path, hash) in &outcome.tree.files {
            lines.push(format!("{id}\tfile\t{path}\t{}", hash.to_hex()));
        }
    }
    lines.push(String::new());
    lines.join("\n")
}

fn parse_listing(text: &str) -> Result<Listing> {
    let mut exits: BTreeMap<InputId, Exit> = BTreeMap::new();
    let mut inputs: BTreeMap<InputId, blake3::Hash> = BTreeMap::new();
    let mut stdouts: BTreeMap<InputId, blake3::Hash> = BTreeMap::new();
    let mut stderrs: BTreeMap<InputId, blake3::Hash> = BTreeMap::new();
    let mut trees: BTreeMap<InputId, OutputTree> = BTreeMap::new();
    for (number, line) in text.lines().enumerate() {
        let line_number: usize = number + 1;
        match line.split('\t').collect::<Vec<&str>>().as_slice() {
            [id, "exit", exit] => {
                exits.insert(InputId::parse(id)?, exit.parse()?);
            }
            [id, "input", hash] => {
                inputs.insert(InputId::parse(id)?, parse_hash(hash, line_number)?);
            }
            [id, "stdout", hash] => {
                stdouts.insert(InputId::parse(id)?, parse_hash(hash, line_number)?);
            }
            [id, "stderr", hash] => {
                stderrs.insert(InputId::parse(id)?, parse_hash(hash, line_number)?);
            }
            [id, "dir", path] => {
                trees
                    .entry(InputId::parse(id)?)
                    .or_default()
                    .dirs
                    .insert((*path).to_owned());
            }
            [id, "file", path, hash] => {
                trees
                    .entry(InputId::parse(id)?)
                    .or_default()
                    .files
                    .insert((*path).to_owned(), parse_hash(hash, line_number)?);
            }
            _ => bail!(
                "golden line {line_number} is not an exit, input, stdout, stderr, dir or file record: {line:?}"
            ),
        }
    }
    let mut listing: Listing = Listing::new();
    for (id, exit) in exits {
        let take =
            |records: &mut BTreeMap<InputId, blake3::Hash>, kind: &str| -> Result<blake3::Hash> {
                records
                    .remove(&id)
                    .ok_or_else(|| eyre!("golden input {id} has an exit but no {kind} record"))
            };
        let input: blake3::Hash = take(&mut inputs, "input")?;
        let stdout: blake3::Hash = take(&mut stdouts, "stdout")?;
        let stderr: blake3::Hash = take(&mut stderrs, "stderr")?;
        let tree: OutputTree = trees.remove(&id).unwrap_or_default();
        listing.insert(
            id,
            Outcome {
                exit,
                input,
                stdout,
                stderr,
                tree,
            },
        );
    }
    if let Some(id) = inputs
        .keys()
        .chain(stdouts.keys())
        .chain(stderrs.keys())
        .chain(trees.keys())
        .next()
    {
        bail!("golden input {id} has records but no exit record");
    }
    let rendered: String = render_listing(&listing);
    if rendered != text {
        let line: usize = rendered
            .lines()
            .zip(text.lines())
            .take_while(|(want, got): &(&str, &str)| want == got)
            .count()
            + 1;
        bail!(
            "the golden listing is not in canonical form at line {line}: a line is duplicated, out of order or stray"
        );
    }
    Ok(listing)
}

fn parse_hash(text: &str, line_number: usize) -> Result<blake3::Hash> {
    blake3::Hash::from_hex(text)
        .map_err(|err: blake3::HexError| eyre!("golden line {line_number}: bad BLAKE3 hash: {err}"))
}

fn compare(expected: &Listing, actual: &Listing) -> Vec<String> {
    let mut differences: Vec<String> = Vec::new();
    for (id, want) in expected {
        let Some(got) = actual.get(id) else {
            differences.push(format!("{id}: expected a run, none happened"));
            continue;
        };
        if want.input != got.input {
            differences.push(format!("{id}: the input bytes changed"));
        }
        if want.exit != got.exit {
            differences.push(format!("{id}: exit {} became {}", want.exit, got.exit));
        }
        if want.stdout != got.stdout {
            differences.push(format!("{id}: stdout changed"));
        }
        if want.stderr != got.stderr {
            differences.push(format!("{id}: stderr changed"));
        }
        for path in want.tree.dirs.difference(&got.tree.dirs) {
            differences.push(format!("{id}: empty directory {path} is missing"));
        }
        for path in got.tree.dirs.difference(&want.tree.dirs) {
            differences.push(format!("{id}: empty directory {path} is new"));
        }
        for (path, hash) in &want.tree.files {
            match got.tree.files.get(path) {
                None => differences.push(format!("{id}: {path} is missing")),
                Some(actual_hash) if actual_hash != hash => {
                    differences.push(format!("{id}: {path} changed"));
                }
                Some(_) => {}
            }
        }
        for path in got
            .tree
            .files
            .keys()
            .filter(|path: &&String| !want.tree.files.contains_key(*path))
        {
            differences.push(format!("{id}: {path} is new"));
        }
    }
    for id in actual
        .keys()
        .filter(|id: &&InputId| !expected.contains_key(*id))
    {
        differences.push(format!("{id}: no recorded expectation"));
    }
    differences
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(files: &[(&str, &[u8])]) -> Outcome {
        Outcome {
            exit: Exit::Code(0),
            input: blake3::hash(b"input"),
            stdout: blake3::hash(b"{}"),
            stderr: blake3::hash(b""),
            tree: OutputTree {
                dirs: BTreeSet::new(),
                files: files
                    .iter()
                    .map(|(path, bytes): &(&str, &[u8])| ((*path).to_owned(), blake3::hash(bytes)))
                    .collect(),
            },
        }
    }

    fn error_text<T>(result: Result<T>) -> String {
        result.map_or_else(|err: eyre::Report| err.to_string(), |_: T| String::new())
    }

    fn without_records(text: &str, kind: &str) -> String {
        let marker: String = format!("\t{kind}\t");
        text.lines()
            .filter(|line: &&str| !line.contains(&marker))
            .flat_map(|line: &str| [line, "\n"])
            .collect()
    }

    fn guard() -> Result<HostPaths> {
        HostPaths::new(&[
            Path::new(r"C:\Repo\target\golden"),
            Path::new(r"C:\Repo\target\ci"),
        ])
    }

    #[test]
    fn a_host_path_in_any_spelling_or_case_is_refused() -> Result<()> {
        let guard: HostPaths = guard()?;
        for text in [
            r"C:\Repo\target\golden\out\x",
            r#"{"a":"C:\\Repo\\target\\golden\\out"}"#,
            r#"{"a":"C:\\Repo\\target\\golden"}"#,
            "file:///c:/repo/target/ci/disrobe.exe",
            r"ends in C:\Repo\target\golden",
            r"wrote C:\Repo\target\golden.",
            r#"{"a":"{\"b\":\"C:\\\\Repo\\\\target\\\\golden\"}"}"#,
        ] {
            let error: String = error_text(guard.refuse(text.as_bytes(), "report.json"));
            assert!(
                error.starts_with("report.json embeds the host path"),
                "{text}: {error}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_longer_name_sharing_a_host_path_prefix_is_not_a_host_path() -> Result<()> {
        let guard: HostPaths = guard()?;
        for text in [
            r"C:\Repo\target\golden2\out",
            r"C:\Repo\target\golden.old",
            r"C:\Repo\target\golden_x",
            r"C:\Repo\target\other\x in/a/b.exe",
            "\x00\x01C:\\Repo\\\x02",
        ] {
            guard.refuse(text.as_bytes(), "a")?;
        }
        Ok(())
    }

    #[test]
    fn roots_with_fewer_than_two_named_components_are_refused() -> Result<()> {
        for root in [r"C:\", r"C:\work", "/home", "/"] {
            let error: String = error_text(HostPaths::new(&[Path::new(root)]));
            assert!(error.contains("too short"), "{root}: {error}");
        }
        HostPaths::new(&[Path::new("/home/runner")])?;
        Ok(())
    }

    #[test]
    fn volatile_values_are_blanked_without_touching_their_neighbours() -> Result<()> {
        let input: &[u8] = b"{\"duration_ms\": 1234, \"total_ms\":5.5e3,\"name\":\"duration_ms\",\"x\":\"\\\"duration_ms\\\": 9\"}";
        assert_eq!(
            String::from_utf8(blank_volatile_values(input))?,
            "{\"duration_ms\": 0, \"total_ms\":0,\"name\":\"duration_ms\",\"x\":\"\\\"duration_ms\\\": 9\"}"
        );
        Ok(())
    }

    #[test]
    fn durations_are_blanked_only_in_the_top_level_reports() -> Result<()> {
        let dir: tempfile::TempDir = tempfile::tempdir()?;
        let timed: &[u8] = b"{\"duration_ms\": 17}";
        fs::create_dir_all(dir.path().join("extracted/empty"))?;
        fs::write(dir.path().join("report.json"), timed)?;
        fs::write(dir.path().join("extracted/report.json"), timed)?;
        let tree: OutputTree = hash_tree(dir.path(), &guard()?)?;
        assert_eq!(
            tree.files.get("report.json"),
            Some(&blake3::hash(b"{\"duration_ms\": 0}"))
        );
        assert_eq!(
            tree.files.get("extracted/report.json"),
            Some(&blake3::hash(timed))
        );
        assert_eq!(tree.dirs, BTreeSet::from(["extracted/empty".to_owned()]));
        Ok(())
    }

    #[test]
    fn stderr_timestamps_and_thread_ids_are_normalized_and_nothing_else() -> Result<()> {
        let input: &[u8] = b"\x1b[2m2026-09-25T22:05:37.967078Z\x1b[0m WARN index 12 at 2026-09-25 12:00\nthread 'main' (40512) has overflowed its stack\nthread 'main' panicked\n";
        assert_eq!(
            String::from_utf8(normalize_stderr(input))?,
            "\x1b[2m<time>\x1b[0m WARN index 12 at 2026-09-25 12:00\nthread 'main' (<tid>) has overflowed its stack\nthread 'main' panicked\n"
        );
        Ok(())
    }

    #[test]
    fn listings_round_trip_through_text() -> Result<()> {
        let mut listing: Listing = Listing::new();
        let mut native: Outcome = outcome(&[("chain.json", b"a"), ("extracted/x.c", b"b")]);
        native.tree.dirs.insert("extracted/empty".to_owned());
        listing.insert(InputId::parse("native-pe-small")?, native);
        let mut crashed: Outcome = outcome(&[]);
        crashed.exit = Exit::Code(-1_073_741_571);
        listing.insert(InputId::parse("js-jsfuck-7mb")?, crashed);
        assert_eq!(parse_listing(&render_listing(&listing))?, listing);
        Ok(())
    }

    #[test]
    fn a_timeout_is_never_a_recordable_outcome() {
        let error: String = error_text("timeout".parse::<Exit>());
        assert!(error.contains("is not `code N` or `signal N`"), "{error}");
    }

    #[test]
    fn duplicate_unsorted_and_incomplete_listings_are_rejected() -> Result<()> {
        let listing: Listing =
            Listing::from([(InputId::parse("a")?, outcome(&[("x.json", b"x")]))]);
        let text: String = render_listing(&listing);
        let last: &str = text.lines().last().unwrap_or_default();
        let duplicated: String = format!("{text}{last}\n");
        assert!(error_text(parse_listing(&duplicated)).contains("not in canonical form at line 6"));
        let mut lines: Vec<&str> = text.lines().collect();
        lines.swap(0, 1);
        assert!(
            error_text(parse_listing(&format!("{}\n", lines.join("\n"))))
                .contains("not in canonical form at line 1")
        );
        assert!(
            error_text(parse_listing(&without_records(&text, "stderr")))
                .contains("no stderr record")
        );
        assert!(
            error_text(parse_listing(&without_records(&text, "exit")))
                .contains("golden input a has records but no exit record")
        );
        Ok(())
    }

    #[test]
    fn malformed_listing_lines_are_rejected_with_their_line_number() {
        let error: String = error_text(parse_listing("a\texit\tcode 0\na\tinput\tzz\n"));
        assert!(
            error.starts_with("golden line 2: bad BLAKE3 hash"),
            "{error}"
        );
    }

    #[test]
    fn exits_parse_their_own_rendering() -> Result<()> {
        for exit in [Exit::Code(0), Exit::Code(-1_073_741_571), Exit::Signal(11)] {
            assert_eq!(exit.to_string().parse::<Exit>()?, exit);
        }
        Ok(())
    }

    #[test]
    fn one_changed_output_byte_is_reported_as_that_file() -> Result<()> {
        let id: InputId = InputId::parse("native-pe-small")?;
        let expected: Listing = Listing::from([(
            id.clone(),
            outcome(&[("chain.json", b"0000"), ("report.json", b"x")]),
        )]);
        let actual: Listing = Listing::from([(
            id,
            outcome(&[("chain.json", b"0001"), ("report.json", b"x")]),
        )]);
        assert_eq!(
            compare(&expected, &actual),
            ["native-pe-small: chain.json changed"]
        );
        Ok(())
    }

    #[test]
    fn every_recorded_stream_and_tree_change_is_reported() -> Result<()> {
        let id: InputId = InputId::parse("a")?;
        let mut want: Outcome = outcome(&[("gone.json", b"g")]);
        want.tree.dirs.insert("old".to_owned());
        let mut got: Outcome = outcome(&[("new.json", b"n")]);
        got.exit = Exit::Code(1);
        got.input = blake3::hash(b"other input");
        got.stdout = blake3::hash(b"other stdout");
        got.stderr = blake3::hash(b"other stderr");
        got.tree.dirs.insert("young".to_owned());
        let expected: Listing = Listing::from([(id.clone(), want)]);
        let actual: Listing = Listing::from([(id, got), (InputId::parse("b")?, outcome(&[]))]);
        assert_eq!(
            compare(&expected, &actual),
            [
                "a: the input bytes changed",
                "a: exit code 0 became code 1",
                "a: stdout changed",
                "a: stderr changed",
                "a: empty directory old is missing",
                "a: empty directory young is new",
                "a: gone.json is missing",
                "a: new.json is new",
                "b: no recorded expectation",
            ]
        );
        Ok(())
    }

    #[test]
    fn manifest_paths_must_be_plain_relative_and_ids_unique_ignoring_case() {
        for path in [
            "/abs/x.exe",
            r"corpus\x.exe",
            "C:/x.exe",
            "corpus/../x.exe",
            "corpus//x.exe",
        ] {
            let text: String = format!("[[input]]\nid = \"a\"\npath = {path:?}\n");
            assert!(
                error_text(parse_manifest(&text)).contains("plain relative path"),
                "{path}"
            );
        }
        let twice: &str = "[[input]]\nid = \"Native\"\npath = \"a/x\"\n\n[[input]]\nid = \"native\"\npath = \"a/y\"\n";
        assert!(error_text(parse_manifest(twice)).contains("appears twice"));
    }

    #[test]
    fn a_work_directory_without_the_marker_is_never_cleared() -> Result<()> {
        let dir: tempfile::TempDir = tempfile::tempdir()?;
        let work: PathBuf = dir.path().join("work");
        fs::create_dir_all(&work)?;
        fs::write(work.join("keep.txt"), b"user data")?;
        assert!(error_text(Sandbox::prepare(&work)).starts_with("refusing to clear"));
        assert!(work.join("keep.txt").is_file());
        fs::write(work.join(WORK_MARKER), b"")?;
        let sandbox: Sandbox = Sandbox::prepare(&work)?;
        assert!(!work.join("keep.txt").exists());
        assert!(sandbox.path.is_dir() && work.join(CONFIG_NAME).is_file());
        assert!(sandbox.strays(&BTreeSet::new())?.is_empty());
        Ok(())
    }

    #[test]
    fn writes_outside_the_output_directory_are_strays() -> Result<()> {
        let dir: tempfile::TempDir = tempfile::tempdir()?;
        let sandbox: Sandbox = Sandbox::prepare(&dir.path().join("work"))?;
        fs::create_dir_all(sandbox.home.join(".cache"))?;
        fs::write(sandbox.path.join("clang-format.exe"), b"")?;
        fs::write(sandbox.root.join("stray.log"), b"")?;
        fs::create_dir_all(sandbox.root.join("out").join("a"))?;
        fs::write(sandbox.root.join("out").join("a.tmp"), b"")?;
        fs::write(sandbox.root.join("logs").join("a.stdout"), b"")?;
        fs::write(sandbox.root.join("logs").join("notes.txt"), b"")?;
        fs::write(sandbox.root.join(CONFIG_NAME), b"x = 1")?;
        assert_eq!(
            sandbox.strays(&BTreeSet::from(["a"]))?,
            [
                "a run wrote .cache into the home directory",
                "a run wrote clang-format.exe into the empty PATH directory",
                "a run wrote \"stray.log\" into the work directory",
                "a run wrote out/a.tmp",
                "a run wrote logs/notes.txt",
                "a run wrote into the pinned config golden.disrobe.toml",
            ]
        );
        let tmp: PathBuf = sandbox.root.join("tmp").join("a");
        fs::create_dir_all(tmp.join("disrobe-scratch"))?;
        assert!(stray_entries(&tmp, true)?.is_empty());
        fs::write(tmp.join("disrobe-scratch").join("leak.bin"), b"")?;
        assert_eq!(stray_entries(&tmp, true)?, ["disrobe-scratch/leak.bin"]);
        Ok(())
    }
}
