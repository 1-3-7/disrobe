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

const WHILE_OR_CONTINUE_BEFORE_TRY: &str = r#"
def guarded_divide(values, primary, secondary):
    out = []
    position = 0
    while position < len(values):
        value = values[position]
        position += 1
        if primary(value) or secondary(value):
            out.append(("guard", value))
            continue
        try:
            out.append(("value", 12 // value))
        except ZeroDivisionError:
            break
    out.append(("tail", position))
    return out
"#;

const TRY_ELSE_POST_EFFECTS: &str = r#"
def guarded_divide(values, primary, secondary):
    out = []
    position = 0
    while position < len(values):
        value = values[position]
        position += 1
        if primary(value) or secondary(value):
            out.append(("guard", value))
            continue
        try:
            out.append(("value", 12 // value))
        except ZeroDivisionError:
            break
        else:
            out.append(("success", value))
            if value == 3:
                continue
        out.append(("post", value))
    out.append(("tail", position))
    return out
"#;

const WALRUS_OR_CONTINUE_BEFORE_TRY: &str = r#"
def guarded_divide(values, primary, secondary):
    out = []
    position = 0
    while position < len(values):
        value = values[position]
        position += 1
        if primary(value) or (seen := secondary(value)):
            out.append(("guard", value))
            continue
        try:
            out.append(("value", 12 // value))
        except ZeroDivisionError:
            break
        out.append(("post", value))
    out.append(("tail", position))
    return out
"#;

const EARLY_WALRUS_SIMPLE_CONTINUE_BEFORE_TRY: &str = r#"
def guarded_divide(values, primary, secondary):
    out = []
    position = 0
    while position < len(values):
        value = values[position]
        position += 1
        observed = (seen := secondary(value))
        if primary(value):
            out.append(("guard", value, observed, seen))
            continue
        try:
            out.append(("value", 12 // value))
        except ZeroDivisionError:
            break
        out.append(("post", value))
    out.append(("tail", position))
    return out
"#;

const ALIASES: &[&str] = &["3.11", "3.12", "3.13", "3.14"];
const TARGET_ALIASES: &[&str] = &["3.12", "3.14", "3.15"];

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

fn execute_fixture(interpreter: &Path, source_path: &Path) -> Result<String, String> {
    let script: &str = "import runpy,sys;ns=runpy.run_path(sys.argv[1]);f=ns['guarded_divide'];p=lambda value:value==2;s=lambda value:value==9;print(f([2,3,0,4],p,s));print(f([5,7],p,s));z=lambda value:value==0;print(f([0,3],z,s))";
    let output: std::process::Output = Command::new(interpreter)
        .args(["-c", script])
        .arg(source_path)
        .env("PYTHONHASHSEED", "0")
        .stdin(Stdio::null())
        .output()
        .map_err(|e: std::io::Error| format!("spawn execution: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "exit={:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout).map_err(|e: std::string::FromUtf8Error| e.to_string())
}

#[test]
fn top_tested_while_or_continue_before_try_recompiles_and_executes_equivalently() {
    let scratch: PathBuf = PathBuf::from("../../target/py-while-or-continue-before-try");
    fs::create_dir_all(&scratch).expect("scratch");
    let source_path: PathBuf = scratch.join("fixture.py");
    fs::write(&source_path, WHILE_OR_CONTINUE_BEFORE_TRY).expect("write fixture");

    let mut checked: usize = 0;
    let mut failures: Vec<String> = Vec::new();
    for &alias in TARGET_ALIASES {
        let Some(interpreter): Option<PathBuf> = find_interpreter(alias) else {
            failures.push(format!("py{alias}: interpreter unavailable"));
            continue;
        };
        let original_output: String = execute_fixture(&interpreter, &source_path)
            .unwrap_or_else(|e: String| panic!("py{alias} execute original: {e}"));
        let orig_pyc: PathBuf = scratch.join(format!("orig.{alias}.pyc"));
        compile_source(&interpreter, &source_path, &orig_pyc)
            .unwrap_or_else(|e: String| panic!("py{alias} compile original: {e}"));
        let (original, marshal_version): (CodeObject, MarshalVersion) =
            read_code(&orig_pyc).unwrap_or_else(|e: String| panic!("py{alias} read original: {e}"));
        let version: PyVersion = marshal_to_decompile(marshal_version)
            .unwrap_or_else(|e| panic!("py{alias} version map: {e:?}"));
        let recovered: String = build_real_source(&original, &version, marshal_version)
            .unwrap_or_else(|e| panic!("py{alias} decompile: {e}"));
        let recovered_path: PathBuf = scratch.join(format!("recovered.{alias}.py"));
        fs::write(&recovered_path, &recovered).expect("write recovered");
        let recompiled_pyc: PathBuf = scratch.join(format!("recompiled.{alias}.pyc"));
        if let Err(e) = compile_source(&interpreter, &recovered_path, &recompiled_pyc) {
            failures.push(format!(
                "py{alias}: recovered source does not compile: {e}\n{recovered}"
            ));
            continue;
        }
        let (recompiled, _): (CodeObject, MarshalVersion) = read_code(&recompiled_pyc)
            .unwrap_or_else(|e: String| panic!("py{alias} read recompiled: {e}"));
        if let Verdict::CodeDiff(detail) = semantic_equiv(&original, &recompiled, marshal_version) {
            failures.push(format!(
                "py{alias}: bytecode differs ({detail:?})\n{recovered}"
            ));
            continue;
        }
        let recovered_output: String = execute_fixture(&interpreter, &recovered_path)
            .unwrap_or_else(|e: String| panic!("py{alias} execute recovered: {e}"));
        if recovered_output != original_output {
            failures.push(format!(
                "py{alias}: execution differs\noriginal: {original_output:?}\nrecovered: {recovered_output:?}\n{recovered}"
            ));
            continue;
        }
        checked += 1;
        assert_eq!(
            recovered.matches("while position < len(values):").count(),
            1
        );
        assert_eq!(
            recovered
                .matches("if primary(value) or secondary(value):")
                .count(),
            1
        );
        assert_eq!(recovered.matches("position += 1").count(), 1);
        assert_eq!(recovered.matches("continue").count(), 1);
        assert_eq!(recovered.matches("except ZeroDivisionError:").count(), 1);
        assert_eq!(recovered.matches("break").count(), 1);
        assert_eq!(
            recovered
                .matches("out.append((\"tail\", position))")
                .count(),
            1
        );
    }

    assert_eq!(checked, TARGET_ALIASES.len(), "{}", failures.join("\n\n"));
}

#[test]
fn try_else_continue_and_post_try_effects_are_preserved() {
    let scratch: PathBuf = PathBuf::from("../../target/py-try-else-continue-effects");
    fs::create_dir_all(&scratch).expect("scratch");
    let source_path: PathBuf = scratch.join("fixture.py");
    fs::write(&source_path, TRY_ELSE_POST_EFFECTS).expect("write fixture");

    let mut checked: usize = 0;
    let mut failures: Vec<String> = Vec::new();
    for &alias in TARGET_ALIASES {
        let Some(interpreter): Option<PathBuf> = find_interpreter(alias) else {
            failures.push(format!("py{alias}: interpreter unavailable"));
            continue;
        };
        let original_output: String = execute_fixture(&interpreter, &source_path)
            .unwrap_or_else(|e: String| panic!("py{alias} execute original: {e}"));
        let original_pyc: PathBuf = scratch.join(format!("orig.{alias}.pyc"));
        compile_source(&interpreter, &source_path, &original_pyc)
            .unwrap_or_else(|e: String| panic!("py{alias} compile original: {e}"));
        let (original, marshal_version): (CodeObject, MarshalVersion) = read_code(&original_pyc)
            .unwrap_or_else(|e: String| panic!("py{alias} read original: {e}"));
        let version: PyVersion = marshal_to_decompile(marshal_version)
            .unwrap_or_else(|e| panic!("py{alias} version map: {e:?}"));
        let recovered: String = build_real_source(&original, &version, marshal_version)
            .unwrap_or_else(|e| panic!("py{alias} decompile: {e}"));
        let recovered_path: PathBuf = scratch.join(format!("recovered.{alias}.py"));
        fs::write(&recovered_path, &recovered).expect("write recovered");
        let recovered_pyc: PathBuf = scratch.join(format!("recovered.{alias}.pyc"));
        compile_source(&interpreter, &recovered_path, &recovered_pyc)
            .unwrap_or_else(|e: String| panic!("py{alias} compile recovered: {e}\n{recovered}"));
        let recovered_output: String = execute_fixture(&interpreter, &recovered_path)
            .unwrap_or_else(|e: String| panic!("py{alias} execute recovered: {e}"));
        if recovered_output != original_output {
            failures.push(format!(
                "py{alias}: execution differs\noriginal: {original_output:?}\nrecovered: {recovered_output:?}\n{recovered}"
            ));
            continue;
        }
        checked += 1;
        assert_eq!(recovered.matches("continue").count(), 2);
        assert_eq!(recovered.matches("else:").count(), 1);
        assert_eq!(recovered.matches("if value == 3:").count(), 1);
        assert_eq!(
            recovered
                .matches("out.append((\"success\", value))")
                .count(),
            1
        );
        assert_eq!(
            recovered.matches("out.append((\"post\", value))").count(),
            1
        );
        assert_eq!(
            recovered
                .matches("out.append((\"tail\", position))")
                .count(),
            1
        );
    }

    assert_eq!(checked, TARGET_ALIASES.len(), "{}", failures.join("\n\n"));
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

#[test]
fn effectful_walrus_or_continue_before_try_fails_closed() {
    let scratch: PathBuf = PathBuf::from("../../target/py-walrus-or-continue-before-try");
    fs::create_dir_all(&scratch).expect("scratch");
    let source_path: PathBuf = scratch.join("fixture.py");
    fs::write(&source_path, WALRUS_OR_CONTINUE_BEFORE_TRY).expect("write fixture");

    let mut checked: usize = 0;
    let mut failures: Vec<String> = Vec::new();
    for &alias in TARGET_ALIASES {
        let Some(interpreter): Option<PathBuf> = find_interpreter(alias) else {
            failures.push(format!("py{alias}: interpreter unavailable"));
            continue;
        };
        let pyc_path: PathBuf = scratch.join(format!("orig.{alias}.pyc"));
        compile_source(&interpreter, &source_path, &pyc_path)
            .unwrap_or_else(|e: String| panic!("py{alias} compile original: {e}"));
        let (original, marshal_version): (CodeObject, MarshalVersion) =
            read_code(&pyc_path).unwrap_or_else(|e: String| panic!("py{alias} read original: {e}"));
        let version: PyVersion = marshal_to_decompile(marshal_version)
            .unwrap_or_else(|e| panic!("py{alias} version map: {e:?}"));
        let refused: String = build_real_source(&original, &version, marshal_version)
            .unwrap_or_else(|e| panic!("py{alias} refusal rendering: {e}"));
        checked += 1;
        if !refused.contains("decompile-error: ast builder desync at offset ")
            || !refused.contains(
                "effectful walrus continue guard before try requires dedicated structuring",
            )
            || refused.contains("except ZeroDivisionError:")
            || refused.contains("out.append((\"tail\", position))")
        {
            failures.push(format!(
                "py{alias}: unsafe or unexpected refusal:\n{refused}"
            ));
        }

        let unrelated_source: PathBuf = scratch.join(format!("unrelated.{alias}.py"));
        let unrelated_pyc: PathBuf = scratch.join(format!("unrelated.{alias}.pyc"));
        fs::write(&unrelated_source, EARLY_WALRUS_SIMPLE_CONTINUE_BEFORE_TRY)
            .expect("write unrelated walrus fixture");
        compile_source(&interpreter, &unrelated_source, &unrelated_pyc)
            .unwrap_or_else(|e: String| panic!("py{alias} compile unrelated walrus: {e}"));
        let (unrelated, unrelated_version): (CodeObject, MarshalVersion) =
            read_code(&unrelated_pyc)
                .unwrap_or_else(|e: String| panic!("py{alias} read unrelated walrus: {e}"));
        let unrelated_decompile_version: PyVersion = marshal_to_decompile(unrelated_version)
            .unwrap_or_else(|e| panic!("py{alias} unrelated version map: {e:?}"));
        let unrelated_output: String =
            build_real_source(&unrelated, &unrelated_decompile_version, unrelated_version)
                .unwrap_or_else(|e| panic!("py{alias} unrelated walrus rendering: {e}"));
        if unrelated_output
            .contains("effectful walrus continue guard before try requires dedicated structuring")
        {
            failures.push(format!(
                "py{alias}: unrelated walrus was attributed to the final guard:\n{unrelated_output}"
            ));
        }
    }

    assert_eq!(checked, TARGET_ALIASES.len(), "{}", failures.join("\n\n"));
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
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
