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
//! CPython 3.12 interpreter.
//!
//! Companion to `arbitrary_recompile_gate.rs` (3.14) and `arbitrary_recompile_gate_315.rs` (3.15).
//! The harness is reused verbatim; only the interpreter is different. 3.12 is the weakest stable
//! band because its compiler picks an inlined-comprehension filter jump polarity from the physical
//! source layout (`POP_JUMP_IF_FALSE` fall-through when the `if` clause sits on a later line than
//! the element, `POP_JUMP_IF_TRUE` when they share a line); 3.13+ always emit the `POP_JUMP_IF_TRUE`
//! form. disrobe reproduces the 3.12 fall-through form by rendering such filters on their own line,
//! recovering the bytecode parity that single-line rendering loses. This gate locks the recovery so
//! that regression cannot return silently.
//!
//! The oracle is non-circular: the harness grades disrobe's recovered source against a real CPython
//! 3.12 recompile of that source, never against disrobe's own re-emission. Absent a 3.12 interpreter
//! the gate is skipped explicitly (it cannot measure), never passed silently.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const HARNESS: &str = "tests/harness/py_arbitrary_measure.py";
const PINNED_MODULES: &str = "tests/harness/pinned_modules_314.txt";

/// Floor enforced in CI. The measured per-code-object recompile-equivalence on the pinned corpus
/// under CPython 3.12 is 92.51% (5235 of 5659 code objects across 177 of the 200 pinned modules;
/// 23 pinned 3.14 modules are absent from the 3.12 Lib). A `JUMP_BACKWARD` that lives inside a
/// post-3.11 `PUSH_EXC_INFO` handler cold-block and re-loops an outer construct (its protected try
/// body begins before the candidate header) is the handler's success-path continue of that
/// enclosing for-loop, not the back-edge of a fresh infinite `while`; `find_infinite_while` now
/// rejects it (`back_edge_inside_exc_handler_cold_block`) so the real for-loop is no longer split
/// and the try body no longer duplicated. The guard is scoped to the outer-try case so a genuine
/// `while True:` whose own body holds a `try` is untouched (3.10/3.11/3.14/3.15 unchanged, 3.12 +2,
/// 3.13 +1, zero regressions across all bands). A loop-body `if COND: <try>` whose guard
/// jump-if-true targets the try and whose fall-through is the loop back-edge is now recovered as the
/// positive `if COND:` wrapping the try instead of an inverted `if not COND: continue` prelude, so an
/// `in`/`is` guard keeps its `CONTAINS_OP`/`IS_OP` jump polarity; the same positive form now also
/// covers a jump-if-true `if COND:` whose only fall-through is a bare continue back-edge. A
/// `while True:` loop whose body wraps a `try` (or a `for`) and whose only exits are inner breaks is
/// recovered as the infinite loop
/// instead of being dropped: `find_infinite_while` accepts an unconditional back-edge with no
/// controlling top/bottom test past the back-edge, and `strip_trailing_implicit_return` no longer
/// recurses into an infinite-while body (a trailing `return None` there is a `break`, not the
/// function's implicit return). This is the `while 1: try: ... except: break` `except_flow` shape.
/// The earlier gain came from negating a jump-if-true guard whose fall-through arm carries the true
/// body and continues to the loop head so `if not COND: ... elif/else: ...` recovers with the right
/// jump polarity. Both fixes are cross-version (3.10 through 3.15 each gained the same one or two
/// objects, so neither is version-gated). The floor sits below the measured value so a real
/// regression trips it while normal interpreter-patch jitter does not; it counts only the modules
/// present in the running interpreter's Lib and skips entirely when no 3.12 is installed. Raise it
/// only with a measured run behind the change; never lower it to mask a regression.
const OBJECT_PCT_FLOOR: f64 = 91.0;

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

fn find_python_312() -> Option<PathBuf> {
    if interpreter_hidden("3.12") {
        return None;
    }
    if let Some(output) = Command::new("uv")
        .args(["python", "find", "3.12"])
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
        PathBuf::from("C:/Python312/python.exe"),
        PathBuf::from("/usr/bin/python3.12"),
        PathBuf::from("/usr/local/bin/python3.12"),
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
fn arbitrary_recompile_equivalence_gate_312() {
    let Some(disrobe): Option<PathBuf> = find_disrobe() else {
        panic!(
            "disrobe binary not found under {}/(release|debug); build it first \
             (cargo build --release -p disrobe-cli --bin disrobe) - the recompile-equivalence \
             gate measures the real CLI, it cannot run without it",
            workspace_target().display()
        );
    };

    let Some(python): Option<PathBuf> = find_python_312() else {
        eprintln!(
            "skip: no CPython 3.12 interpreter found (uv python find 3.12 / known install paths). \
             Per-code-object recompile-equivalence on 3.12 cannot be measured here; floor \
             {OBJECT_PCT_FLOOR} not enforced this run. Install one with `uv python install 3.12`."
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
        (3, 12),
        "resolved interpreter at {} is {maj}.{min}, not 3.12",
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
    println!("=== ARBITRARY RECOMPILE-EQUIVALENCE HARNESS (3.12) ===");
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
        m.modules >= 170,
        "only {} of the 200 pinned modules were measured ({} absent from this Lib); the 3.14-pinned \
         corpus has drifted too far from the 3.12 stdlib to be representative",
        m.modules,
        m.missing_from_lib
    );
    assert!(
        m.code_objects >= 5000,
        "only {} code objects measured; expected ~5600+ from the pinned corpus on 3.12, the sample \
         is too thin to gate on",
        m.code_objects
    );
    assert!(
        m.object_pct >= OBJECT_PCT_FLOOR,
        "per-code-object recompile-equivalence regressed on 3.12: {:.2}% < floor {OBJECT_PCT_FLOOR}% \
         ({}/{} objects on {} modules)",
        m.object_pct,
        m.objects_ok,
        m.code_objects,
        m.modules
    );
}
