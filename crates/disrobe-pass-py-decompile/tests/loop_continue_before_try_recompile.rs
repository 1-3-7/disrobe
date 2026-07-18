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

const FIXTURE: &str = concat!(
    "def safe_import(self, fromlist, name, caller, level):\n",
    "    for sub in fromlist:\n",
    "        fullname = name + '.' + sub\n",
    "        if fullname in self.badmodules:\n",
    "            self._add_badmodule(fullname, caller)\n",
    "            continue\n",
    "        try:\n",
    "            self.import_hook(name, caller, [sub], level=level)\n",
    "        except ImportError as msg:\n",
    "            self._add_badmodule(fullname, caller)\n",
    "\n",
    "\n",
    "def bare_handler(items, seen, out):\n",
    "    for it in items:\n",
    "        if it in seen:\n",
    "            out.append(it)\n",
    "            continue\n",
    "        try:\n",
    "            out.append(it.value)\n",
    "        except AttributeError:\n",
    "            out.append(None)\n",
    "        seen.add(it)\n",
    "\n",
    "\n",
    "def handler_continues(self, name, caller, fromlist, level):\n",
    "    try:\n",
    "        self.import_hook(name, caller, level=level)\n",
    "    except ImportError as msg:\n",
    "        self._add_badmodule(name, caller)\n",
    "    else:\n",
    "        for sub in fromlist:\n",
    "            fullname = name + '.' + sub\n",
    "            if fullname in self.badmodules:\n",
    "                self._add_badmodule(fullname, caller)\n",
    "                continue\n",
    "            try:\n",
    "                self.import_hook(name, caller, [sub], level=level)\n",
    "            except ImportError as msg:\n",
    "                self._add_badmodule(fullname, caller)\n",
    "\n",
    "\n",
    "def nested_loop_tail(rows, out):\n",
    "    for row in rows:\n",
    "        if row is None:\n",
    "            out.append(0)\n",
    "            continue\n",
    "        for cell in row:\n",
    "            out.append(cell)\n",
);

const ALIASES: &[&str] = &["3.11", "3.12", "3.13", "3.14"];

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

#[test]
fn loop_continue_before_try_recompiles_equivalent() {
    let scratch: PathBuf = PathBuf::from("../../target/py-continue-before-try");
    fs::create_dir_all(&scratch).expect("scratch");
    let source_path: PathBuf = scratch.join("fixture.py");
    fs::write(&source_path, FIXTURE).expect("write fixture");

    let mut checked: usize = 0;
    let mut failures: Vec<String> = Vec::new();
    for &alias in ALIASES {
        let Some(interpreter): Option<PathBuf> = find_interpreter(alias) else {
            eprintln!("SKIP {alias}: no interpreter");
            continue;
        };
        let orig_pyc: PathBuf = scratch.join(format!("orig.{alias}.pyc"));
        if let Err(e) = compile_source(&interpreter, &source_path, &orig_pyc) {
            eprintln!("SKIP {alias}: orig compile {e}");
            continue;
        }
        let (original, marshal_version): (CodeObject, MarshalVersion) =
            read_code(&orig_pyc).unwrap_or_else(|e| panic!("{alias} read orig: {e}"));
        let version: PyVersion = marshal_to_decompile(marshal_version)
            .unwrap_or_else(|e| panic!("{alias} version map: {e:?}"));
        let source: String = build_real_source(&original, &version, marshal_version)
            .unwrap_or_else(|e| panic!("{alias} decompile: {e}"));
        let recovered_path: PathBuf = scratch.join(format!("recovered.{alias}.py"));
        fs::write(&recovered_path, &source).expect("write recovered");

        checked += 1;
        let recompiled_pyc: PathBuf = scratch.join(format!("recovered.{alias}.pyc"));
        match compile_source(&interpreter, &recovered_path, &recompiled_pyc) {
            Ok(()) => {}
            Err(e) => {
                failures.push(format!(
                    "py{alias}: recovered source does not parse: {e}\n{source}"
                ));
                continue;
            }
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
        "no CPython 3.11-3.14 interpreter resolvable via uv; the continue-before-try proof is vacuous"
    );
    assert!(
        failures.is_empty(),
        "{} continue-before-try recompile failures:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}
