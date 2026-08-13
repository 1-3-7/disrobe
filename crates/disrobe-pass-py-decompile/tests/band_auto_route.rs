#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::doc_markdown
)]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use common::band::band_scratch;
use common::band_gate::{
    BandToolchain, CPYTHON_310, CPYTHON_311, CPYTHON_313, resolve_band_interpreter,
};
use common::stdlib_measure::{find_disrobe, workspace_target};

const SOURCE: &str = r"def summarize(records, default):
    totals = {}
    for name, value in records:
        try:
            totals[name] = totals[name] + value
        except KeyError:
            totals[name] = default
    ordered = sorted(totals.items())
    return [(name, total) for name, total in ordered if total > 0]
";

const EXPECTED: &[&str] = &[
    "def summarize(records, default):",
    "for name, value in records:",
    "totals[name] = totals[name] + value",
    "except KeyError:",
    "totals[name] = default",
    "ordered = sorted(totals.items())",
    "if total > 0]",
];

fn compile_to_pyc(interpreter: &Path, source: &Path, pyc: &Path) {
    let script: &str =
        "import py_compile,sys;py_compile.compile(sys.argv[1],cfile=sys.argv[2],doraise=True)";
    let output: std::process::Output = Command::new(interpreter)
        .args(["-c", script])
        .arg(source)
        .arg(pyc)
        .env("PYTHONHASHSEED", "0")
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error: std::io::Error| panic!("spawn {}: {error}", interpreter.display()));
    assert!(
        output.status.success(),
        "{} failed to compile the auto-route fixture: {}",
        interpreter.display(),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn interpreter_accepts(interpreter: &Path, recovered: &Path) -> Result<(), String> {
    let script: &str = "import sys;compile(open(sys.argv[1],encoding='utf-8').read(),sys.argv[1],\
                        'exec',dont_inherit=True)";
    let output: std::process::Output = Command::new(interpreter)
        .args(["-c", script])
        .arg(recovered)
        .stdin(Stdio::null())
        .output()
        .map_err(|error: std::io::Error| format!("spawn {}: {error}", interpreter.display()))?;
    if output.status.success() {
        return Ok(());
    }
    Err(String::from_utf8_lossy(&output.stderr).into_owned())
}

fn captured_decompile_source(out_dir: &Path) -> Option<PathBuf> {
    let entries: std::fs::ReadDir = std::fs::read_dir(out_dir).ok()?;
    let mut stages: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry: std::fs::DirEntry| entry.path())
        .filter(|path: &PathBuf| {
            path.is_dir()
                && path.file_name().is_some_and(|name: &std::ffi::OsStr| {
                    name.to_string_lossy().contains("py-decompile")
                })
        })
        .collect();
    stages.sort();
    stages
        .into_iter()
        .map(|stage: PathBuf| stage.join("output.bin"))
        .find(|output: &PathBuf| output.is_file())
}

fn chain_passes(chain: &serde_json::Value) -> Vec<String> {
    chain
        .get("nodes")
        .and_then(serde_json::Value::as_array)
        .map(|nodes: &Vec<serde_json::Value>| {
            nodes
                .iter()
                .filter_map(|node: &serde_json::Value| {
                    node.get("pass")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                })
                .collect()
        })
        .unwrap_or_default()
}

fn auto_reaches_py_decompile(toolchain: &BandToolchain) {
    let Some(disrobe): Option<PathBuf> = find_disrobe() else {
        panic!(
            "disrobe binary not found under {}/(release|debug); build it first \
             (cargo build --release -p disrobe-cli --bin disrobe) - this case proves the band \
             interpreters reach py.decompile through the real `disrobe auto` route, so it cannot \
             run without the binary",
            workspace_target().display()
        );
    };

    let graded: String = format!(
        "the claim that `disrobe auto` routes a CPython {} .pyc to py.decompile and emits source \
         the same interpreter accepts",
        toolchain.alias
    );
    let Some(python): Option<PathBuf> = resolve_band_interpreter(toolchain, &graded) else {
        return;
    };

    let scratch: PathBuf = band_scratch(&format!("auto-route-{}", toolchain.alias));
    let source: PathBuf = scratch.join("summarize.py");
    let pyc: PathBuf = scratch.join("summarize.pyc");
    let out: PathBuf = scratch.join("out");
    let _ = std::fs::remove_dir_all(&out);
    std::fs::write(&source, SOURCE).expect("write auto-route fixture source");
    compile_to_pyc(&python, &source, &pyc);

    let output: std::process::Output = Command::new(&disrobe)
        .arg("auto")
        .arg(&pyc)
        .arg("--out")
        .arg(&out)
        .arg("--max-depth")
        .arg("3")
        .arg("--capture-stages")
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error: std::io::Error| panic!("spawn disrobe auto: {error}"));
    assert!(
        output.status.success(),
        "`disrobe auto` failed on a CPython {} .pyc: {}",
        toolchain.alias,
        String::from_utf8_lossy(&output.stderr)
    );

    let chain_raw: String = std::fs::read_to_string(out.join("chain.json"))
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", out.display()));
    let chain: serde_json::Value =
        serde_json::from_str(&chain_raw).expect("parse the auto chain.json");
    let passes: Vec<String> = chain_passes(&chain);
    assert!(
        passes.iter().any(|name: &String| name == "py.decompile"),
        "`disrobe auto` on a CPython {} .pyc never reached py.decompile, so the band is measured \
         through a route no user command takes; chain passes: {passes:?}",
        toolchain.alias
    );

    let recovered_path: PathBuf = captured_decompile_source(&out).unwrap_or_else(|| {
        panic!(
            "`disrobe auto` recorded py.decompile for CPython {} but captured no stage output to \
             read the recovered source from",
            toolchain.alias
        )
    });
    let recovered: String = std::fs::read_to_string(&recovered_path)
        .unwrap_or_else(|error: std::io::Error| panic!("read the captured stage output: {error}"));
    println!(
        "=== auto route, CPython {} ===\n{recovered}",
        toolchain.alias
    );

    if let Err(rejection) = interpreter_accepts(&python, &recovered_path) {
        panic!(
            "CPython {} rejected the source `disrobe auto` recovered from its own .pyc, so the \
             route emits text that is not a program on the version it came from: {rejection}\n\
             {recovered}",
            toolchain.alias
        );
    }

    for needle in EXPECTED {
        assert!(
            recovered.contains(needle),
            "the source `disrobe auto` recovered from a CPython {} .pyc is missing `{needle}`:\n\
             {recovered}",
            toolchain.alias
        );
    }
}

#[test]
fn auto_routes_a_cpython_310_pyc_to_py_decompile() {
    auto_reaches_py_decompile(&CPYTHON_310);
}

#[test]
fn auto_routes_a_cpython_311_pyc_to_py_decompile() {
    auto_reaches_py_decompile(&CPYTHON_311);
}

#[test]
fn auto_routes_a_cpython_313_pyc_to_py_decompile() {
    auto_reaches_py_decompile(&CPYTHON_313);
}
