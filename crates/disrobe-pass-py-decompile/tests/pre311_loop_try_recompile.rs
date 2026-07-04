#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::engine::{build_real_source, marshal_to_decompile};
use disrobe_pass_py_decompile::roundtrip::{Verdict, semantic_equiv};
use disrobe_py_marshal::{CodeObject, Object, PyVersion as MarshalVersion, PycFile, read_pyc};

const TRY_INSIDE_LOOP: &str = concat!(
    "def v_tuple(get, cache):\n",
    "    thread = current()\n",
    "    while True:\n",
    "        try:\n",
    "            task = get()\n",
    "        except (OSError, EOFError):\n",
    "            log('exit')\n",
    "            return\n",
    "        if thread.state != RUN:\n",
    "            break\n",
    "        if task is None:\n",
    "            break\n",
    "        cache.add(task)\n",
    "\n",
    "\n",
    "def v_single(get):\n",
    "    while True:\n",
    "        try:\n",
    "            item = get()\n",
    "        except KeyError:\n",
    "            return\n",
    "        if item is None:\n",
    "            break\n",
    "        handle(item)\n",
    "\n",
    "\n",
    "def v_return_val(q):\n",
    "    total = 0\n",
    "    while True:\n",
    "        try:\n",
    "            n = q.pop()\n",
    "        except IndexError:\n",
    "            return total\n",
    "        total += n\n",
);

const TRY_WRAPPING_LOOP: &str = concat!(
    "def worker(flag, stop, work, cleanup):\n",
    "    if flag:\n",
    "        try:\n",
    "            setup()\n",
    "        except OSError:\n",
    "            log('setup')\n",
    "            return\n",
    "    try:\n",
    "        while True:\n",
    "            if stop():\n",
    "                break\n",
    "            work()\n",
    "    except OSError:\n",
    "        cleanup()\n",
);

const ALIASES: &[&str] = &["3.8", "3.9", "3.10", "3.11"];
const PRE311_ALIASES: &[&str] = &["3.8", "3.9", "3.10"];

fn find_interpreter(alias: &str) -> Option<PathBuf> {
    let output: std::process::Output = Command::new("uv")
        .args(["python", "find", alias])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let path: PathBuf = PathBuf::from(raw);
    path.is_file().then_some(path)
}

fn compile_source(interpreter: &Path, source_path: &Path, pyc_path: &Path) -> Result<(), String> {
    let script: &str =
        "import py_compile,sys;py_compile.compile(sys.argv[1],cfile=sys.argv[2],doraise=True)";
    let output: std::process::Output = Command::new(interpreter)
        .args([
            "-c",
            script,
            source_path.to_str().unwrap_or(""),
            pyc_path.to_str().unwrap_or(""),
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|e: std::io::Error| format!("spawn: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "exit={:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn read_code(pyc_path: &Path) -> Result<(CodeObject, MarshalVersion), String> {
    let bytes: Vec<u8> = fs::read(pyc_path).map_err(|e: std::io::Error| format!("read: {e}"))?;
    let pyc: PycFile = read_pyc(&bytes).map_err(|e| format!("read_pyc: {e}"))?;
    let ver: MarshalVersion = pyc.header.version;
    match pyc.code {
        Object::Code(boxed) => Ok((*boxed, ver)),
        other => Err(format!("top-level not code: {other:?}")),
    }
}

fn recover(
    scratch: &Path,
    alias: &str,
    fixture: &str,
) -> Option<(CodeObject, MarshalVersion, String)> {
    let interpreter: PathBuf = find_interpreter(alias)?;
    let source_path: PathBuf = scratch.join(format!("src.{alias}.py"));
    fs::write(&source_path, fixture).expect("write fixture");
    let orig_pyc: PathBuf = scratch.join(format!("orig.{alias}.pyc"));
    if let Err(e) = compile_source(&interpreter, &source_path, &orig_pyc) {
        eprintln!("SKIP {alias}: orig compile {e}");
        return None;
    }
    let (original, marshal_version): (CodeObject, MarshalVersion) =
        read_code(&orig_pyc).unwrap_or_else(|e| panic!("{alias} read orig: {e}"));
    let version: PyVersion = marshal_to_decompile(marshal_version)
        .unwrap_or_else(|e| panic!("{alias} version map: {e:?}"));
    let source: String = build_real_source(&original, &version, marshal_version)
        .unwrap_or_else(|e| panic!("{alias} decompile: {e}"));
    Some((original, marshal_version, source))
}

#[test]
fn try_inside_loop_recompiles_equivalent() {
    let scratch: PathBuf = PathBuf::from("../../target/py-try-inside-loop");
    fs::create_dir_all(&scratch).expect("scratch");

    let mut checked: usize = 0;
    let mut failures: Vec<String> = Vec::new();
    for &alias in ALIASES {
        let Some((original, marshal_version, source)): Option<(
            CodeObject,
            MarshalVersion,
            String,
        )> = recover(&scratch, alias, TRY_INSIDE_LOOP) else {
            continue;
        };
        let recovered_path: PathBuf = scratch.join(format!("recovered.{alias}.py"));
        fs::write(&recovered_path, &source).expect("write recovered");
        checked += 1;
        let interpreter: PathBuf = find_interpreter(alias).expect("interpreter re-resolve");
        let recompiled_pyc: PathBuf = scratch.join(format!("recovered.{alias}.pyc"));
        if let Err(e) = compile_source(&interpreter, &recovered_path, &recompiled_pyc) {
            failures.push(format!(
                "py{alias}: recovered does not parse: {e}\n{source}"
            ));
            continue;
        }
        let (recompiled, _): (CodeObject, MarshalVersion) =
            read_code(&recompiled_pyc).unwrap_or_else(|e| panic!("{alias} read recompiled: {e}"));
        match semantic_equiv(&original, &recompiled, marshal_version) {
            Verdict::Perfect | Verdict::Semantic => {}
            Verdict::CodeDiff(detail) => {
                failures.push(format!("py{alias}: not equivalent ({detail:?})\n{source}"));
            }
        }
    }

    assert!(
        checked > 0,
        "no CPython 3.8-3.11 interpreter resolvable via uv; the try-inside-loop proof is vacuous"
    );
    assert!(
        failures.is_empty(),
        "{} try-inside-loop recompile failures:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

#[test]
fn try_wrapping_loop_handler_not_orphaned() {
    let scratch: PathBuf = PathBuf::from("../../target/py-try-wrapping-loop");
    fs::create_dir_all(&scratch).expect("scratch");

    let mut checked: usize = 0;
    let mut failures: Vec<String> = Vec::new();
    for &alias in PRE311_ALIASES {
        let Some((_, _, source)): Option<(CodeObject, MarshalVersion, String)> =
            recover(&scratch, alias, TRY_WRAPPING_LOOP)
        else {
            continue;
        };
        let recovered_path: PathBuf = scratch.join(format!("recovered.{alias}.py"));
        fs::write(&recovered_path, &source).expect("write recovered");
        checked += 1;
        if source.contains("exception matches") {
            failures.push(format!(
                "py{alias}: except handler leaked as exc-match:\n{source}"
            ));
            continue;
        }
        if !source.contains("except OSError") {
            failures.push(format!("py{alias}: except handler dropped:\n{source}"));
            continue;
        }
        let interpreter: PathBuf = find_interpreter(alias).expect("interpreter re-resolve");
        let recompiled_pyc: PathBuf = scratch.join(format!("recovered.{alias}.pyc"));
        if let Err(e) = compile_source(&interpreter, &recovered_path, &recompiled_pyc) {
            failures.push(format!(
                "py{alias}: recovered does not parse: {e}\n{source}"
            ));
        }
    }

    assert!(
        checked > 0,
        "no CPython 3.8-3.10 interpreter resolvable via uv; the try-wrapping-loop proof is vacuous"
    );
    assert!(
        failures.is_empty(),
        "{} try-wrapping-loop structuring failures:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}
