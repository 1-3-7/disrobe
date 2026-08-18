#![allow(
    dead_code,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::missing_const_for_fn,
    clippy::redundant_pub_crate
)]

use std::collections::BTreeSet;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use super::band::find_interpreter;

pub(crate) const MEASURE_HARNESS: &str = "tests/harness/py_arbitrary_measure.py";
pub(crate) const FAMILY_HARNESS: &str = "tests/harness/py_failure_families.py";
pub(crate) const REACH_HARNESS: &str = "tests/harness/py_band_bytecode_reach.py";
pub(crate) const RECOVERY_JSON: &str = "../../xtask/data/recovery.json";

pub(crate) const FULL_POPULATION: &str = "full-stdlib-574";
pub(crate) const PINNED_POPULATION: &str = "pinned-200";

#[must_use]
pub(crate) fn population_line(population: &str, num: u64, den: u64, modules: u64) -> String {
    let pct: f64 = if den == 0 {
        0.0
    } else {
        (num as f64) * 100.0 / (den as f64)
    };
    format!(
        "population {population}: {num} / {den} code objects over {modules} modules ({pct:.2}% \
         per-code-object)"
    )
}

#[derive(Debug)]
pub(crate) struct Measurement {
    pub listed_modules: u64,
    pub missing_from_lib: u64,
    pub modules: u64,
    pub modules_exact: u64,
    pub module_pct: f64,
    pub code_objects: u64,
    pub objects_ok: u64,
    pub object_pct: f64,
    pub sibling_collisions: u64,
    pub cpython_version: String,
}

#[derive(Debug)]
pub(crate) struct HarnessRun {
    pub success: bool,
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PublishedBar {
    pub value: f64,
    pub num: u64,
    pub den: u64,
    pub modules: u64,
}

#[must_use]
pub(crate) fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[must_use]
pub(crate) fn workspace_target() -> PathBuf {
    let exe: PathBuf = std::env::current_exe().expect("current exe");
    let mut dir: PathBuf = exe.parent().expect("exe dir").to_path_buf();
    while dir
        .file_name()
        .and_then(|part: &std::ffi::OsStr| part.to_str())
        != Some("debug")
        && dir
            .file_name()
            .and_then(|part: &std::ffi::OsStr| part.to_str())
            != Some("release")
    {
        assert!(
            dir.pop(),
            "walking up from {} never reached a debug or release directory, so the target \
             directory cannot be located; a manifest-relative path would be wrong under any \
             custom CARGO_TARGET_DIR",
            exe.display()
        );
    }
    dir.pop();
    dir
}

#[must_use]
pub(crate) fn find_disrobe() -> Option<PathBuf> {
    let exe: &str = if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    };
    let target: PathBuf = workspace_target();
    for profile in ["release", "debug"] {
        let candidate: PathBuf = target.join(profile).join(exe);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[must_use]
pub(crate) fn find_python_314() -> Option<PathBuf> {
    find_interpreter("3.14")
}

pub(crate) fn interpreter_version(python: &Path) -> Option<(u8, u8)> {
    let output: std::process::Output = Command::new(python)
        .args([
            "-c",
            "import sys;print(f'{sys.version_info.major}.{sys.version_info.minor}')",
        ])
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let (maj, min): (&str, &str) = raw.split_once('.')?;
    Some((maj.parse::<u8>().ok()?, min.parse::<u8>().ok()?))
}

pub(crate) fn interpreter_release(python: &Path) -> Option<String> {
    let output: std::process::Output = Command::new(python)
        .args(["-c", "import platform;print(platform.python_version())"])
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if raw.is_empty() { None } else { Some(raw) }
}

pub(crate) fn interpreter_stdlib(python: &Path) -> Option<PathBuf> {
    let output: std::process::Output = Command::new(python)
        .args(["-c", "import sysconfig;print(sysconfig.get_path('stdlib'))"])
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let path: PathBuf = PathBuf::from(raw);
    if path.is_dir() { Some(path) } else { None }
}

#[must_use]
pub(crate) fn run_measure(python: &Path, disrobe: &Path, lib: &Path, modules: &Path) -> HarnessRun {
    run_measure_with_ledger(python, disrobe, lib, modules, None)
}

#[must_use]
pub(crate) fn run_measure_with_ledger(
    python: &Path,
    disrobe: &Path,
    lib: &Path,
    modules: &Path,
    ledger: Option<&Path>,
) -> HarnessRun {
    let harness: PathBuf = manifest_dir().join(MEASURE_HARNESS);
    let mut command: Command = Command::new(python);
    command
        .arg(&harness)
        .arg("--disrobe")
        .arg(disrobe)
        .arg("--lib")
        .arg(lib)
        .arg("--modules")
        .arg(modules);
    if let Some(ledger_path) = ledger {
        command.arg("--object-ledger").arg(ledger_path);
    }
    let output: std::process::Output = command
        .stdin(Stdio::null())
        .output()
        .expect("spawn recompile-equivalence harness");
    HarnessRun {
        success: output.status.success(),
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

#[must_use]
pub(crate) fn run_strict_measure(
    python: &Path,
    disrobe: &Path,
    lib: &Path,
    modules: &Path,
    require_version: &str,
    require_magic: Option<&str>,
) -> HarnessRun {
    let harness: PathBuf = manifest_dir().join(MEASURE_HARNESS);
    let mut command: Command = Command::new(python);
    command
        .arg(&harness)
        .arg("--disrobe")
        .arg(disrobe)
        .arg("--lib")
        .arg(lib)
        .arg("--modules")
        .arg(modules)
        .arg("--strict-tier")
        .arg("--require-version")
        .arg(require_version);
    if let Some(magic) = require_magic {
        command.arg("--require-magic").arg(magic);
    }
    let output: std::process::Output = command
        .stdin(Stdio::null())
        .output()
        .expect("spawn the strict-tier recompile-equivalence harness");
    HarnessRun {
        success: output.status.success(),
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

#[must_use]
pub(crate) fn run_measure_bounded(
    python: &Path,
    disrobe: &Path,
    lib: &Path,
    modules: &Path,
    limit: Duration,
    tag: &str,
) -> HarnessRun {
    const POLL: Duration = Duration::from_millis(250);

    let harness: PathBuf = manifest_dir().join(MEASURE_HARNESS);
    let capture: PathBuf = workspace_target().join("py-band-measure");
    std::fs::create_dir_all(&capture)
        .unwrap_or_else(|e: std::io::Error| panic!("create {}: {e}", capture.display()));
    let out_path: PathBuf = capture.join(format!("{tag}.stdout"));
    let err_path: PathBuf = capture.join(format!("{tag}.stderr"));
    let out_file: File = File::create(&out_path)
        .unwrap_or_else(|e: std::io::Error| panic!("create {}: {e}", out_path.display()));
    let err_file: File = File::create(&err_path)
        .unwrap_or_else(|e: std::io::Error| panic!("create {}: {e}", err_path.display()));

    let mut child: Child = Command::new(python)
        .arg(&harness)
        .arg("--disrobe")
        .arg(disrobe)
        .arg("--lib")
        .arg(lib)
        .arg("--modules")
        .arg(modules)
        .stdin(Stdio::null())
        .stdout(Stdio::from(out_file))
        .stderr(Stdio::from(err_file))
        .spawn()
        .expect("spawn recompile-equivalence harness");

    let deadline: Instant = Instant::now() + limit;
    let finished: Option<ExitStatus> = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(POLL);
            }
            Err(e) => panic!("wait on the recompile-equivalence harness: {e}"),
        }
    };

    let stdout: String = std::fs::read_to_string(&out_path).unwrap_or_default();
    let stderr: String = std::fs::read_to_string(&err_path).unwrap_or_default();
    match finished {
        Some(status) => HarnessRun {
            success: status.success(),
            code: status.code(),
            stdout,
            stderr,
        },
        None => HarnessRun {
            success: false,
            code: None,
            stdout,
            stderr: format!(
                "{stderr}\nthe recompile-equivalence harness was killed after {} seconds, the wall \
                 clock this band allows one measurement. A band that cannot finish inside its \
                 budget has measured no population and must report none",
                limit.as_secs()
            ),
        },
    }
}

#[derive(Debug, Clone)]
pub(crate) struct BandReach {
    pub cpython_version: String,
    pub pinned: u64,
    pub missing_from_lib: u64,
    pub modules: u64,
    pub code_objects: u64,
    pub posonly_objects: u64,
    pub opnames: BTreeSet<String>,
}

#[must_use]
pub(crate) fn run_reach(python: &Path, lib: &Path, modules: &Path) -> HarnessRun {
    let harness: PathBuf = manifest_dir().join(REACH_HARNESS);
    let output: std::process::Output = Command::new(python)
        .arg(&harness)
        .arg("--lib")
        .arg(lib)
        .arg("--modules")
        .arg(modules)
        .stdin(Stdio::null())
        .output()
        .expect("spawn band bytecode-reach harness");
    HarnessRun {
        success: output.status.success(),
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

pub(crate) fn parse_reach(stdout: &str) -> Result<BandReach, String> {
    let line: &str = stdout
        .lines()
        .find(|l: &&str| l.trim_start().starts_with('{'))
        .ok_or_else(|| format!("no JSON object on reach harness stdout:\n{stdout}"))?;
    let doc: serde_json::Value =
        serde_json::from_str(line).map_err(|e: serde_json::Error| format!("parse {line}: {e}"))?;
    let scalar = |key: &str| -> Result<u64, String> {
        doc.get(key)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| format!("the reach report carries no {key}: {line}"))
    };
    let raw: &Vec<serde_json::Value> = doc
        .get("opnames")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| format!("the reach report carries no opnames array: {line}"))?;
    let mut opnames: BTreeSet<String> = BTreeSet::new();
    for entry in raw {
        let name: &str = entry
            .as_str()
            .ok_or_else(|| format!("an opname entry is not a string: {entry}"))?;
        opnames.insert(name.to_owned());
    }
    Ok(BandReach {
        cpython_version: doc
            .get("cpython_version")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("the reach report carries no cpython_version: {line}"))?
            .to_owned(),
        pinned: scalar("pinned")?,
        missing_from_lib: scalar("missing_from_lib")?,
        modules: scalar("modules")?,
        code_objects: scalar("code_objects")?,
        posonly_objects: scalar("posonly_objects")?,
        opnames,
    })
}

#[must_use]
pub(crate) fn run_family(python: &Path, disrobe: &Path, lib: &Path, modules: &Path) -> HarnessRun {
    let harness: PathBuf = manifest_dir().join(FAMILY_HARNESS);
    let output: std::process::Output = Command::new(python)
        .arg(&harness)
        .arg("--disrobe")
        .arg(disrobe)
        .arg("--lib")
        .arg(lib)
        .arg("--modules")
        .arg(modules)
        .stdin(Stdio::null())
        .output()
        .expect("spawn failure-family harness");
    HarnessRun {
        success: output.status.success(),
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FailureFamily {
    pub family: String,
    pub objects: u64,
    pub modules: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct FamilyReport {
    pub cpython_version: String,
    pub modules: u64,
    pub code_objects: u64,
    pub objects_ok: u64,
    pub failing_objects: u64,
    pub families: Vec<FailureFamily>,
}

pub(crate) fn parse_family_report(stdout: &str) -> Result<FamilyReport, String> {
    let line: &str = stdout
        .lines()
        .find(|l: &&str| l.trim_start().starts_with('{'))
        .ok_or_else(|| format!("no JSON object on family harness stdout:\n{stdout}"))?;
    let doc: serde_json::Value =
        serde_json::from_str(line).map_err(|e: serde_json::Error| format!("parse {line}: {e}"))?;
    let scalar = |key: &str| -> Result<u64, String> {
        doc.get(key)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| format!("family report carries no {key}: {line}"))
    };
    let raw: &Vec<serde_json::Value> = doc
        .get("families")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| format!("family report carries no families array: {line}"))?;
    let mut families: Vec<FailureFamily> = Vec::with_capacity(raw.len());
    for entry in raw {
        let family: String = entry
            .get("family")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("family row carries no name: {entry}"))?
            .to_owned();
        let objects: u64 = entry
            .get("objects")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| format!("family row `{family}` carries no object count"))?;
        let modules: u64 = entry
            .get("modules")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| format!("family row `{family}` carries no module count"))?;
        families.push(FailureFamily {
            family,
            objects,
            modules,
        });
    }
    Ok(FamilyReport {
        cpython_version: doc
            .get("cpython_version")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("family report carries no cpython_version: {line}"))?
            .to_owned(),
        modules: scalar("modules")?,
        code_objects: scalar("code_objects")?,
        objects_ok: scalar("objects_ok")?,
        failing_objects: scalar("failing_objects")?,
        families,
    })
}

fn json_scalar<'a>(line: &'a str, key: &str) -> Result<&'a str, String> {
    let needle: String = format!("\"{key}\"");
    let after_key: &str = line
        .find(&needle)
        .map(|i: usize| &line[i + needle.len()..])
        .ok_or_else(|| format!("missing field {key} in {line}"))?;
    let after_colon: &str = after_key
        .find(':')
        .map(|i: usize| after_key[i + 1..].trim_start())
        .ok_or_else(|| format!("malformed field {key} in {line}"))?;
    let end: usize = after_colon
        .find([',', '}'])
        .ok_or_else(|| format!("unterminated field {key} in {line}"))?;
    Ok(after_colon[..end].trim().trim_matches('"'))
}

pub(crate) fn parse_measurement(stdout: &str) -> Result<Measurement, String> {
    let line: &str = stdout
        .lines()
        .find(|l: &&str| l.trim_start().starts_with('{'))
        .ok_or_else(|| format!("no JSON object on harness stdout:\n{stdout}"))?;
    let get_u64 = |key: &str| -> Result<u64, String> {
        json_scalar(line, key)?
            .parse::<u64>()
            .map_err(|e: std::num::ParseIntError| format!("field {key} is not u64: {e} in {line}"))
    };
    let get_f64 = |key: &str| -> Result<f64, String> {
        json_scalar(line, key)?
            .parse::<f64>()
            .map_err(|e: std::num::ParseFloatError| {
                format!("field {key} is not f64: {e} in {line}")
            })
    };
    Ok(Measurement {
        listed_modules: get_u64("pinned")?,
        missing_from_lib: get_u64("missing_from_lib")?,
        modules: get_u64("modules")?,
        modules_exact: get_u64("modules_exact")?,
        module_pct: get_f64("module_pct")?,
        code_objects: get_u64("code_objects")?,
        objects_ok: get_u64("objects_ok")?,
        object_pct: get_f64("object_pct")?,
        sibling_collisions: get_u64("sibling_collisions")?,
        cpython_version: json_scalar(line, "cpython_version")?.to_owned(),
    })
}

#[must_use]
pub(crate) fn recovery_document() -> serde_json::Value {
    let path: PathBuf = manifest_dir().join(RECOVERY_JSON);
    let raw: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|e: serde_json::Error| panic!("parse {}: {e}", path.display()))
}

fn matching_bars<'a>(doc: &'a serde_json::Value, label: &str) -> Vec<&'a serde_json::Value> {
    let mut found: Vec<&'a serde_json::Value> = Vec::new();
    let Some(groups): Option<&Vec<serde_json::Value>> =
        doc.get("groups").and_then(serde_json::Value::as_array)
    else {
        return found;
    };
    for group in groups {
        let Some(bars): Option<&Vec<serde_json::Value>> =
            group.get("bars").and_then(serde_json::Value::as_array)
        else {
            continue;
        };
        for bar in bars {
            if bar.get("label").and_then(serde_json::Value::as_str) == Some(label) {
                found.push(bar);
            }
        }
    }
    found
}

fn sole_bar<'a>(doc: &'a serde_json::Value, label: &str) -> Result<&'a serde_json::Value, String> {
    let found: Vec<&'a serde_json::Value> = matching_bars(doc, label);
    match found.len() {
        1 => found
            .first()
            .copied()
            .ok_or_else(|| String::from("unreachable")),
        0 => Err(format!("recovery.json carries no bar labelled {label}")),
        n => Err(format!(
            "recovery.json carries {n} bars labelled {label}; a duplicated label lets one \
             population be read where the other was published"
        )),
    }
}

pub(crate) fn published_bar(doc: &serde_json::Value, label: &str) -> Result<PublishedBar, String> {
    let bar: &serde_json::Value = sole_bar(doc, label)?;
    let value: f64 = bar
        .get("value")
        .and_then(serde_json::Value::as_f64)
        .ok_or_else(|| format!("bar {label} carries no numeric value"))?;
    let num: u64 = bar
        .get("num")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("bar {label} carries no numerator"))?;
    let den: u64 = bar
        .get("den")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("bar {label} carries no denominator"))?;
    let modules: u64 = bar
        .get("modules")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("bar {label} carries no module count"))?;
    Ok(PublishedBar {
        value,
        num,
        den,
        modules,
    })
}

pub(crate) fn published_detail(doc: &serde_json::Value, label: &str) -> Result<String, String> {
    let bar: &serde_json::Value = sole_bar(doc, label)?;
    bar.get("detail")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("bar {label} carries no detail string"))
}

#[must_use]
pub(crate) fn bar_disagreements(bar: &PublishedBar, floor: f64) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    if bar.den == 0 {
        found.push("denominator is zero".to_owned());
        return found;
    }
    let derived: f64 = (bar.num as f64) * 100.0 / (bar.den as f64);
    if (derived - bar.value).abs() > 0.05 {
        found.push(format!(
            "published value {} disagrees with its own {}/{} = {derived:.4}",
            bar.value, bar.num, bar.den
        ));
    }
    if (bar.value - floor).abs() > 0.0001 {
        found.push(format!(
            "published value {} is not the floor {floor} this crate enforces",
            bar.value
        ));
    }
    found
}

pub(crate) fn read_module_list(path: &Path) -> Result<Vec<String>, String> {
    let raw: String = std::fs::read_to_string(path)
        .map_err(|e: std::io::Error| format!("read {}: {e}", path.display()))?;
    Ok(raw
        .lines()
        .map(str::trim)
        .filter(|line: &&str| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect())
}
