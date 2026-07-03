#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_lines,
    clippy::doc_markdown
)]

//! Per-code-object recompile-equivalence gate over the pinned stdlib corpus, measured under a real
//! CPython 3.10 interpreter.
//!
//! Companion to `arbitrary_recompile_gate.rs` (3.14), `arbitrary_recompile_gate_312.rs` (3.12), and
//! `arbitrary_recompile_gate_315.rs` (3.15). The harness is reused verbatim; only the interpreter is
//! different. 3.10 is the weakest supported band because pre-3.11 exception handling is structured
//! from SETUP_FINALLY block ops rather than a zero-cost exception table: the handler region of a
//! module-scope try/except must terminate at that construct's own re-raise, not the last re-raise in
//! the whole module, or every continuation statement (and the classes and functions defined after the
//! try) is dropped. disrobe bounds the pre-3.11 handler region to the owning construct, recovering the
//! continuation that a whole-module scan loses. This gate locks the recovery so a regression cannot
//! return silently.
//!
//! The oracle is non-circular: the harness grades disrobe's recovered source against a real CPython
//! 3.10 recompile of that source, never against disrobe's own re-emission. Absent a 3.10 interpreter
//! the gate is skipped explicitly (it cannot measure), never passed silently.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const HARNESS: &str = "tests/harness/py_arbitrary_measure.py";
const PINNED_MODULES: &str = "tests/harness/pinned_modules_314.txt";

/// Floor enforced in CI. The measured per-code-object recompile-equivalence on the pinned corpus
/// under CPython 3.10.20 is 92.74% (5062 of 5458 code objects across 161 of the 200 pinned modules;
/// 39 pinned 3.14 modules are absent from the 3.10 Lib). Recovering the pre-3.11 subscript augmented
/// assignment (DUP_TOP_TWO was collapsed to a single-value dup, mangling the store target), the
/// pre-3.11 ROT-run simultaneous tuple assignment, classifying an unconditional back-edge whose
/// last in-loop conditional is a bottom test as a genuine `while COND:` (keeping the body's own
/// leading operand load instead of dropping it to a synthesized `None`), and recovering a `while True:`
/// that wraps a `try` whose only exits are inner breaks (instead of dropping the loop) lifted the
/// measured value over the prior 91.96%. The floor sits below the measured value so a real regression
/// trips it while normal interpreter-patch jitter does not. Raise it only with a measured run behind
/// the change; never lower it to mask a regression.
const OBJECT_PCT_FLOOR: f64 = 90.0;

#[derive(Debug)]
struct Measurement {
    modules: u64,
    code_objects: u64,
    objects_ok: u64,
    object_pct: f64,
    module_pct: f64,
    sibling_collisions: u64,
    missing_from_lib: u64,
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

fn find_python_310() -> Option<PathBuf> {
    if interpreter_hidden("3.10") {
        return None;
    }
    if let Some(output) = Command::new("uv")
        .args(["python", "find", "3.10"])
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
        PathBuf::from("C:/Python310/python.exe"),
        PathBuf::from("/usr/bin/python3.10"),
        PathBuf::from("/usr/local/bin/python3.10"),
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
    })
}

#[test]
fn arbitrary_recompile_equivalence_gate_310() {
    let Some(disrobe): Option<PathBuf> = find_disrobe() else {
        panic!(
            "disrobe binary not found under {}/(release|debug); build it first \
             (cargo build --release -p disrobe-cli --bin disrobe) - the recompile-equivalence \
             gate measures the real CLI, it cannot run without it",
            workspace_target().display()
        );
    };

    let Some(python): Option<PathBuf> = find_python_310() else {
        eprintln!(
            "skip: no CPython 3.10 interpreter found (uv python find 3.10 / known install paths). \
             Per-code-object recompile-equivalence on 3.10 cannot be measured here; floor \
             {OBJECT_PCT_FLOOR} not enforced this run. Install one with `uv python install 3.10`."
        );
        return;
    };

    let Some((maj, min)): Option<(u8, u8)> = interpreter_version(&python) else {
        panic!(
            "could not read version of interpreter at {}",
            python.display()
        );
    };
    assert_eq!(
        (maj, min),
        (3, 10),
        "resolved interpreter at {} is {maj}.{min}, not 3.10",
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
    println!("=== ARBITRARY RECOMPILE-EQUIVALENCE HARNESS (3.10) ===");
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
        "measured: {}/{} code objects ({:.2}%) across {} modules; whole-module exact {:.2}%; \
         sibling-count collisions {}; pinned modules absent from this Lib {}",
        m.objects_ok,
        m.code_objects,
        m.object_pct,
        m.modules,
        m.module_pct,
        m.sibling_collisions,
        m.missing_from_lib
    );

    assert!(
        m.modules >= 150,
        "only {} of the 200 pinned modules were measured ({} absent from this Lib); the 3.14-pinned \
         corpus has drifted too far from the 3.10 stdlib to be representative",
        m.modules,
        m.missing_from_lib
    );
    assert!(
        m.code_objects >= 5000,
        "only {} code objects measured; expected ~5400+ from the pinned corpus on 3.10, the sample \
         is too thin to gate on",
        m.code_objects
    );
    assert!(
        m.object_pct >= OBJECT_PCT_FLOOR,
        "per-code-object recompile-equivalence regressed on 3.10: {:.2}% < floor {OBJECT_PCT_FLOOR}% \
         ({}/{} objects on {} modules)",
        m.object_pct,
        m.objects_ok,
        m.code_objects,
        m.modules
    );
}
