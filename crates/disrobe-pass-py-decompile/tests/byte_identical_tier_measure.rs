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

#[derive(Debug)]
struct StrictMeasurement {
    modules: u64,
    code_objects: u64,
    objects_ok: u64,
    object_pct: f64,
    strict_recompile_equivalent: u64,
    strict_byte_identical: u64,
    strict_byte_identical_pct: f64,
    strict_position_lines_ok: u64,
    strict_position_lines_total: u64,
    strict_position_lines_pct: f64,
    strict_position_full_ok: u64,
    strict_position_full_total: u64,
    strict_position_full_pct: f64,
    strict_alignment_coverage_pct: f64,
    strict_no_debug_ranges_objects: u64,
    cpython_version: String,
    magic_number: String,
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

fn parse_strict_measurement(stdout: &str) -> Result<StrictMeasurement, String> {
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
    let get_str = |key: &str| -> Result<String, String> { Ok(json_scalar(line, key)?.to_owned()) };
    Ok(StrictMeasurement {
        modules: get_u64("modules")?,
        code_objects: get_u64("code_objects")?,
        objects_ok: get_u64("objects_ok")?,
        object_pct: get_f64("object_pct")?,
        strict_recompile_equivalent: get_u64("strict_recompile_equivalent")?,
        strict_byte_identical: get_u64("strict_byte_identical")?,
        strict_byte_identical_pct: get_f64("strict_byte_identical_pct")?,
        strict_position_lines_ok: get_u64("strict_position_lines_ok")?,
        strict_position_lines_total: get_u64("strict_position_lines_total")?,
        strict_position_lines_pct: get_f64("strict_position_lines_pct")?,
        strict_position_full_ok: get_u64("strict_position_full_ok")?,
        strict_position_full_total: get_u64("strict_position_full_total")?,
        strict_position_full_pct: get_f64("strict_position_full_pct")?,
        strict_alignment_coverage_pct: get_f64("strict_alignment_coverage_pct")?,
        strict_no_debug_ranges_objects: get_u64("strict_no_debug_ranges_objects")?,
        cpython_version: get_str("cpython_version")?,
        magic_number: get_str("magic_number")?,
    })
}

#[test]
fn byte_identical_tier_over_pinned_corpus() {
    let Some(disrobe): Option<PathBuf> = find_disrobe() else {
        eprintln!(
            "skip: disrobe binary not found under {}/(release|debug); this is an optional \
             measurement tier, not a gate - build the CLI first with \
             `cargo build -p disrobe-cli --bin disrobe` to run it",
            workspace_target().display()
        );
        return;
    };

    let Some(python): Option<PathBuf> = find_python_314() else {
        eprintln!(
            "skip: no CPython 3.14 interpreter found (uv python find 3.14 / known install \
             paths); the byte-identical tier is an optional measurement, not enforced here"
        );
        return;
    };

    let Some((maj, min)): Option<(u8, u8)> = interpreter_version(&python) else {
        eprintln!(
            "skip: could not read version of interpreter at {}",
            python.display()
        );
        return;
    };
    if (maj, min) != (3, 14) {
        eprintln!(
            "skip: resolved interpreter at {} is {maj}.{min}, not 3.14; the pinned corpus is \
             3.14-specific",
            python.display()
        );
        return;
    }

    let Some(lib): Option<PathBuf> = interpreter_stdlib(&python) else {
        eprintln!(
            "skip: could not resolve the stdlib Lib directory of {}",
            python.display()
        );
        return;
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
        .arg("--strict-tier")
        .stdin(Stdio::null())
        .output()
        .expect("spawn byte-identical tier harness");

    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    println!("=== BYTE-IDENTICAL TIER (OPTIONAL, NON-GATING) ===");
    println!("interpreter : {} ({maj}.{min})", python.display());
    println!("lib         : {}", lib.display());
    println!("disrobe     : {}", disrobe.display());
    println!("--- harness taxonomy (stderr) ---\n{stderr}");

    assert!(
        output.status.success(),
        "harness exited {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status.code()
    );

    let m: StrictMeasurement = parse_strict_measurement(&stdout).expect("parse strict measurement");
    println!("cpython {} (magic {})", m.cpython_version, m.magic_number);
    println!(
        "normalized recompile-equivalence: {}/{} code objects ({:.2}%) across {} modules",
        m.objects_ok, m.code_objects, m.object_pct, m.modules
    );
    println!(
        "{} recompile-equivalent; of those, {} byte-identical ({:.2}%); positions: lines \
         {:.2}%, full {:.2}% (alignment coverage {:.2}%, {} objects scored lines-only, no debug \
         ranges)",
        m.strict_recompile_equivalent,
        m.strict_byte_identical,
        m.strict_byte_identical_pct,
        m.strict_position_lines_pct,
        m.strict_position_full_pct,
        m.strict_alignment_coverage_pct,
        m.strict_no_debug_ranges_objects
    );
    println!(
        "counts: byte_identical {}/{}, position_lines {}/{}, position_full {}/{}",
        m.strict_byte_identical,
        m.strict_recompile_equivalent,
        m.strict_position_lines_ok,
        m.strict_position_lines_total,
        m.strict_position_full_ok,
        m.strict_position_full_total
    );

    assert!(
        m.modules >= 180,
        "only {} of the 200 pinned modules were measured; the corpus has drifted too far from \
         this Lib to be representative for the strict tier either",
        m.modules
    );
    assert!(
        m.strict_recompile_equivalent >= 4000,
        "only {} code objects entered the strict tier (normalized recompile-equivalent \
         subset); expected several thousand from the pinned corpus, the sample is too thin to \
         report a meaningful measurement",
        m.strict_recompile_equivalent
    );
    assert!(
        m.strict_byte_identical <= m.strict_recompile_equivalent,
        "byte-identical count {} exceeds its own denominator {} - measurement is broken",
        m.strict_byte_identical,
        m.strict_recompile_equivalent
    );
    assert!(
        m.strict_position_lines_ok <= m.strict_position_lines_total,
        "position line-match count {} exceeds its own denominator {} - measurement is broken",
        m.strict_position_lines_ok,
        m.strict_position_lines_total
    );
    assert!(
        m.strict_position_full_ok <= m.strict_position_full_total,
        "position full-match count {} exceeds its own denominator {} - measurement is broken",
        m.strict_position_full_ok,
        m.strict_position_full_total
    );
}
