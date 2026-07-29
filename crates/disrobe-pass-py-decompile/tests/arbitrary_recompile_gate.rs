#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_lines,
    clippy::doc_markdown
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const HARNESS: &str = "tests/harness/py_arbitrary_measure.py";
const PINNED_MODULES: &str = "tests/harness/pinned_modules_314.txt";

const OBJECT_PCT_FLOOR: f64 = 96.60;

const RECOVERY_JSON: &str = "../../xtask/data/recovery.json";
const PINNED_BAR_LABEL: &str = "200-module pinned corpus";

#[derive(Debug)]
struct Measurement {
    modules: u64,
    code_objects: u64,
    objects_ok: u64,
    object_pct: f64,
    module_pct: f64,
    sibling_collisions: u64,
    missing_from_lib: u64,
    cpython_version: String,
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn workspace_target() -> PathBuf {
    manifest_dir().join("../../target")
}

#[must_use]
fn find_disrobe() -> Option<PathBuf> {
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
fn interpreter_hidden(alias: &str) -> bool {
    std::env::var("DISROBE_TEST_HIDE_PY").is_ok_and(|hidden: String| {
        hidden
            .split(',')
            .map(str::trim)
            .any(|entry: &str| entry == alias)
    })
}

#[must_use]
fn find_python_314() -> Option<PathBuf> {
    if interpreter_hidden("3.14") {
        return None;
    }
    if let Some(output) = Command::new("uv")
        .args(["python", "find", "3.14"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()
        && output.status.success()
    {
        let raw: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        let path: PathBuf = PathBuf::from(raw);
        if path.is_file() {
            return Some(path);
        }
    }
    let candidates: [PathBuf; 3] = [
        PathBuf::from("C:/Python314/python.exe"),
        PathBuf::from("/usr/bin/python3.14"),
        PathBuf::from("/usr/local/bin/python3.14"),
    ];
    candidates.into_iter().find(|p: &PathBuf| p.is_file())
}

fn interpreter_version(python: &Path) -> Option<(u8, u8)> {
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

fn interpreter_stdlib(python: &Path) -> Option<PathBuf> {
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

fn json_scalar<'a>(line: &'a str, key: &str) -> Result<&'a str, String> {
    let needle: String = format!("\"{key}\"");
    let after_key: &str = line
        .find(&needle)
        .map(|i| &line[i + needle.len()..])
        .ok_or_else(|| format!("missing field {key} in {line}"))?;
    let after_colon: &str = after_key
        .find(':')
        .map(|i| after_key[i + 1..].trim_start())
        .ok_or_else(|| format!("malformed field {key} in {line}"))?;
    let end: usize = after_colon
        .find([',', '}'])
        .ok_or_else(|| format!("unterminated field {key} in {line}"))?;
    Ok(after_colon[..end].trim().trim_matches('"'))
}

fn parse_measurement(stdout: &str) -> Result<Measurement, String> {
    let line: &str = stdout
        .lines()
        .find(|l| l.trim_start().starts_with('{'))
        .ok_or_else(|| format!("no JSON object on harness stdout:\n{stdout}"))?;
    let get_u64 = |key: &str| -> Result<u64, String> {
        json_scalar(line, key)?
            .parse::<u64>()
            .map_err(|e| format!("field {key} is not u64: {e} in {line}"))
    };
    let get_f64 = |key: &str| -> Result<f64, String> {
        json_scalar(line, key)?
            .parse::<f64>()
            .map_err(|e| format!("field {key} is not f64: {e} in {line}"))
    };
    Ok(Measurement {
        modules: get_u64("modules")?,
        code_objects: get_u64("code_objects")?,
        objects_ok: get_u64("objects_ok")?,
        object_pct: get_f64("object_pct")?,
        module_pct: get_f64("module_pct")?,
        sibling_collisions: get_u64("sibling_collisions")?,
        missing_from_lib: get_u64("missing_from_lib")?,
        cpython_version: json_scalar(line, "cpython_version")?.to_owned(),
    })
}

#[derive(Debug, Clone, Copy)]
struct PublishedBar {
    value: f64,
    num: u64,
    den: u64,
}

fn recovery_document() -> serde_json::Value {
    let path: PathBuf = manifest_dir().join(RECOVERY_JSON);
    let raw: String = std::fs::read_to_string(&path)
        .unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|e: serde_json::Error| panic!("parse {}: {e}", path.display()))
}

fn published_bar(doc: &serde_json::Value, label: &str) -> Result<PublishedBar, String> {
    let groups: &Vec<serde_json::Value> =
        doc.get("groups")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| "recovery.json carries no groups array".to_owned())?;
    for group in groups {
        let Some(bars): Option<&Vec<serde_json::Value>> =
            group.get("bars").and_then(serde_json::Value::as_array)
        else {
            continue;
        };
        for bar in bars {
            if bar.get("label").and_then(serde_json::Value::as_str) != Some(label) {
                continue;
            }
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
            return Ok(PublishedBar { value, num, den });
        }
    }
    Err(format!("recovery.json carries no bar labelled {label}"))
}

fn bar_disagreements(bar: &PublishedBar, floor: f64) -> Vec<String> {
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

#[test]
fn published_pinned_bar_agrees_with_the_enforced_floor() {
    let doc: serde_json::Value = recovery_document();
    let bar: PublishedBar =
        published_bar(&doc, PINNED_BAR_LABEL).unwrap_or_else(|e: String| panic!("{e}"));
    let disagreements: Vec<String> = bar_disagreements(&bar, OBJECT_PCT_FLOOR);
    assert!(
        disagreements.is_empty(),
        "xtask/data/recovery.json and this crate describe different numbers, and every document \
         renders the JSON: {disagreements:?}"
    );
}

#[test]
fn published_bar_check_rejects_a_corrupted_bar() {
    let doc: serde_json::Value = recovery_document();
    let real: PublishedBar =
        published_bar(&doc, PINNED_BAR_LABEL).unwrap_or_else(|e: String| panic!("{e}"));

    let corrupted: PublishedBar = PublishedBar {
        value: 90.0,
        ..real
    };
    assert_eq!(
        bar_disagreements(&corrupted, OBJECT_PCT_FLOOR).len(),
        2,
        "a bar republished at the old 90 floor must fail both its own ratio and the enforced \
         floor, otherwise this check would pass over the number the documents used to print"
    );

    let ratio_only: PublishedBar = PublishedBar {
        num: real.num / 2,
        ..real
    };
    assert_eq!(
        bar_disagreements(&ratio_only, OBJECT_PCT_FLOOR).len(),
        1,
        "halving the numerator must break the ratio leg alone"
    );

    assert!(
        bar_disagreements(&real, OBJECT_PCT_FLOOR).is_empty(),
        "the committed bar itself must stay clean"
    );
}

#[test]
fn arbitrary_recompile_equivalence_gate() {
    let Some(disrobe): Option<PathBuf> = find_disrobe() else {
        panic!(
            "disrobe binary not found under {}/(release|debug); build it first \
             (cargo build --release -p disrobe-cli --bin disrobe) - the recompile-equivalence \
             gate measures the real CLI, it cannot run without it",
            workspace_target().display()
        );
    };

    let Some(python): Option<PathBuf> = find_python_314() else {
        panic!(
            "no CPython 3.14 interpreter found (uv python find 3.14 / known install paths). This \
             gate is the reference behind the published per-code-object figure, so its absence \
             fails the run rather than passing it: a skip here would leave floor \
             {OBJECT_PCT_FLOOR} unenforced while the suite still reported green. Install one with \
             `uv python install 3.14`."
        );
    };

    let Some((maj, min)): Option<(u8, u8)> = interpreter_version(&python) else {
        panic!(
            "could not read version of interpreter at {}",
            python.display()
        );
    };
    assert_eq!(
        (maj, min),
        (3, 14),
        "resolved interpreter at {} is {maj}.{min}, not 3.14; the pinned corpus is 3.14-specific",
        python.display()
    );

    let Some(lib): Option<PathBuf> = interpreter_stdlib(&python) else {
        panic!(
            "could not resolve the stdlib Lib directory of {}",
            python.display()
        );
    };

    let harness: PathBuf = manifest_dir().join(HARNESS);
    let modules: PathBuf = manifest_dir().join(PINNED_MODULES);
    assert!(
        harness.is_file(),
        "harness missing at {}",
        harness.display()
    );
    assert!(
        modules.is_file(),
        "pinned module list missing at {}",
        modules.display()
    );

    let output: std::process::Output = Command::new(&python)
        .arg(&harness)
        .arg("--disrobe")
        .arg(&disrobe)
        .arg("--lib")
        .arg(&lib)
        .arg("--modules")
        .arg(&modules)
        .stdin(Stdio::null())
        .output()
        .expect("spawn recompile-equivalence harness");

    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    println!("=== ARBITRARY RECOMPILE-EQUIVALENCE HARNESS ===");
    println!("interpreter : {} ({maj}.{min})", python.display());
    println!("lib         : {}", lib.display());
    println!("disrobe     : {}", disrobe.display());
    println!("--- harness taxonomy (stderr) ---\n{stderr}");

    assert!(
        output.status.success(),
        "harness exited {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status.code()
    );

    let m: Measurement = parse_measurement(&stdout).expect("parse harness measurement");
    println!(
        "measured on CPython {}: {}/{} code objects ({:.2}%) across {} modules; whole-module \
         exact {:.2}%; sibling-count collisions {}; pinned modules absent from this Lib {}",
        m.cpython_version,
        m.objects_ok,
        m.code_objects,
        m.object_pct,
        m.modules,
        m.module_pct,
        m.sibling_collisions,
        m.missing_from_lib
    );

    assert!(
        m.modules >= 180,
        "only {} of the 200 pinned modules were measured ({} absent from this Lib); the corpus has \
         drifted too far to be representative - refresh the pin against the current 3.14 stdlib",
        m.modules,
        m.missing_from_lib
    );
    assert!(
        m.code_objects >= 5000,
        "only {} code objects measured; expected ~6000+ from the pinned corpus, the sample is too \
         thin to gate on",
        m.code_objects
    );
    assert!(
        m.object_pct >= OBJECT_PCT_FLOOR,
        "per-code-object recompile-equivalence regressed: {:.2}% < floor {OBJECT_PCT_FLOOR}% \
         ({}/{} objects on {} modules, CPython {}). The floor is pinned at the exact figure this \
         corpus measures, so any drop is a real regression unless the stdlib sources themselves \
         moved: if this run is on a different 3.14 patch release than the one the floor was pinned \
         against, re-measure and re-pin rather than lowering the floor",
        m.object_pct,
        m.objects_ok,
        m.code_objects,
        m.modules,
        m.cpython_version
    );

    let doc: serde_json::Value = recovery_document();
    let bar: PublishedBar =
        published_bar(&doc, PINNED_BAR_LABEL).unwrap_or_else(|e: String| panic!("{e}"));
    assert_eq!(
        (bar.num, bar.den),
        (m.objects_ok, m.code_objects),
        "xtask/data/recovery.json publishes {}/{} for the pinned corpus and every document \
         renders that pair, but this run measured {}/{} on CPython {}",
        bar.num,
        bar.den,
        m.objects_ok,
        m.code_objects,
        m.cpython_version
    );
}
