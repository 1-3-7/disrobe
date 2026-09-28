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

const STDLIB_FUNCTION: &str = "register_standard_browsers";

const STDLIB_ALIASES: &[&str] = &["3.12", "3.13"];

const TRY_ELSE_IN_GUARD: &str = concat!(
    "def f():\n",
    "    if b:\n",
    "        try:\n",
    "            y()\n",
    "        except E:\n",
    "            pass\n",
    "        else:\n",
    "            z = 1\n",
    "        w()\n",
    "    v()\n",
);

const ELSE_ARM_CONTINUES_AFTER_TRY: &str = concat!(
    "def f():\n",
    "    if a:\n",
    "        x()\n",
    "    else:\n",
    "        if b or c:\n",
    "            try:\n",
    "                y()\n",
    "            except E:\n",
    "                pass\n",
    "            else:\n",
    "                z = 1\n",
    "            w()\n",
    "        if t:\n",
    "            u()\n",
    "    if q:\n",
    "        v()\n",
);

const THEN_ARM_ENDS_IN_IF: &str = concat!(
    "def f():\n",
    "    if p[:3] == 'win':\n",
    "        r(3)\n",
    "        if w(4):\n",
    "            r(4)\n",
    "    else:\n",
    "        if e('D') or e('W'):\n",
    "            try:\n",
    "                c = 1\n",
    "            except A:\n",
    "                pass\n",
    "            else:\n",
    "                g = c\n",
    "            X()\n",
    "        if e('T'):\n",
    "            r(5)\n",
    "    if 'B' in env:\n",
    "        u = 1\n",
);

const FIXTURES: &[(&str, &str)] = &[
    ("try_else_in_guard", TRY_ELSE_IN_GUARD),
    ("else_arm_continues_after_try", ELSE_ARM_CONTINUES_AFTER_TRY),
    ("then_arm_ends_in_if", THEN_ARM_ENDS_IN_IF),
];

const FIXTURE_ALIASES: &[&str] = &["3.11", "3.12", "3.13", "3.14", "3.15"];

fn find_interpreter(alias: &str) -> PathBuf {
    let output: std::process::Output = Command::new("uv")
        .args(["python", "find", alias])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("CPython {alias} is required; `uv python find` failed: {e}"));
    let raw: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let path: PathBuf = PathBuf::from(raw);
    assert!(
        output.status.success() && path.is_file(),
        "CPython {alias} is required (probed `uv python find {alias}`); CI provisions it"
    );
    path
}

fn run_python(interpreter: &Path, args: &[&str]) -> Result<String, String> {
    let output: std::process::Output = Command::new(interpreter)
        .args(args)
        .env("PYTHONHASHSEED", "0")
        .stdin(Stdio::null())
        .output()
        .map_err(|e: std::io::Error| format!("spawn: {e}"))?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned());
    }
    Err(format!(
        "exit={:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn stdlib_webbrowser(interpreter: &Path) -> PathBuf {
    let lib: String = run_python(
        interpreter,
        &["-c", "import sysconfig;print(sysconfig.get_path('stdlib'))"],
    )
    .unwrap_or_else(|e| panic!("stdlib path of {}: {e}", interpreter.display()));
    let module: PathBuf = PathBuf::from(lib).join("webbrowser.py");
    assert!(
        module.is_file(),
        "{} ships no webbrowser.py at {}",
        interpreter.display(),
        module.display()
    );
    module
}

fn compile_source(interpreter: &Path, source: &Path, pyc: &Path) -> Result<(), String> {
    run_python(
        interpreter,
        &[
            "-c",
            "import py_compile,sys;py_compile.compile(sys.argv[1],cfile=sys.argv[2],doraise=True)",
            source.to_str().unwrap_or(""),
            pyc.to_str().unwrap_or(""),
        ],
    )
    .map(|_| ())
}

fn read_code(pyc_path: &Path) -> (CodeObject, MarshalVersion) {
    let bytes: Vec<u8> = fs::read(pyc_path).expect("read pyc");
    let pyc: PycFile = read_pyc(&bytes).expect("read_pyc");
    let version: MarshalVersion = pyc.header.version;
    match pyc.code {
        Object::Code(boxed) => (*boxed, version),
        other => panic!("top-level not code: {other:?}"),
    }
}

const fn code_name(code: &CodeObject) -> Option<&str> {
    match &code.name {
        Object::String { value, .. } | Object::ShortAscii { value, .. } => Some(value.as_str()),
        _ => None,
    }
}

fn find_function<'a>(code: &'a CodeObject, name: &str) -> Vec<&'a CodeObject> {
    let mut found: Vec<&'a CodeObject> = Vec::new();
    if code_name(code) == Some(name) {
        found.push(code);
    }
    for constant in &code.consts {
        if let Object::Code(child) = constant {
            found.extend(find_function(child, name));
        }
    }
    found
}

fn function_source<'a>(source: &'a str, name: &str) -> &'a str {
    let start: usize = source.find(&format!("def {name}(")).unwrap_or(0);
    let end: usize = source[start + 1..]
        .find("\ndef ")
        .map_or(source.len(), |n: usize| start + 1 + n);
    &source[start..end]
}

fn recompile_function(
    interpreter: &Path,
    source_path: &Path,
    scratch: &Path,
    label: &str,
    function: &str,
) -> Result<(), String> {
    let stem: String = label.replace('/', "-");
    let orig_pyc: PathBuf = scratch.join(format!("{stem}.orig.pyc"));
    compile_source(interpreter, source_path, &orig_pyc)
        .unwrap_or_else(|e| panic!("{label}: compiling the reference source: {e}"));
    let (original, marshal_version): (CodeObject, MarshalVersion) = read_code(&orig_pyc);
    let originals: Vec<&CodeObject> = find_function(&original, function);
    let [original_fn]: [&CodeObject; 1] = originals.as_slice().try_into().unwrap_or_else(|_| {
        panic!(
            "{label}: the reference source defines {function} {} times, not once",
            originals.len()
        )
    });
    let version: PyVersion = marshal_to_decompile(marshal_version)
        .unwrap_or_else(|e| panic!("{label}: version map: {e:?}"));
    let source: String = build_real_source(&original, &version, marshal_version)
        .map_err(|e| format!("{label}: decompile failed: {e}"))?;
    let recovered_path: PathBuf = scratch.join(format!("{stem}.rec.py"));
    fs::write(&recovered_path, &source).expect("write recovered");
    let recompiled_pyc: PathBuf = scratch.join(format!("{stem}.rec.pyc"));
    compile_source(interpreter, &recovered_path, &recompiled_pyc)
        .map_err(|e| format!("{label}: recovered source does not compile: {e}"))?;
    let (recompiled, _): (CodeObject, MarshalVersion) = read_code(&recompiled_pyc);
    let recovered: Vec<&CodeObject> = find_function(&recompiled, function);
    let [recovered_fn]: [&CodeObject; 1] = recovered.as_slice().try_into().map_err(|_| {
        format!(
            "{label}: recovered source defines {function} {} times\n{source}",
            recovered.len()
        )
    })?;
    match semantic_equiv(original_fn, recovered_fn, marshal_version) {
        Verdict::Perfect | Verdict::Semantic => Ok(()),
        Verdict::CodeDiff(detail) => Err(format!(
            "{label}: {function} not equivalent ({detail:?})\n{}",
            function_source(&source, function)
        )),
    }
}

#[test]
fn register_standard_browsers_recompiles_equivalent() {
    let scratch_dir: tempfile::TempDir = tempfile::tempdir().expect("scratch");
    let failures: Vec<String> = STDLIB_ALIASES
        .iter()
        .filter_map(|&alias: &&str| {
            let interpreter: PathBuf = find_interpreter(alias);
            let module: PathBuf = stdlib_webbrowser(&interpreter);
            recompile_function(
                &interpreter,
                &module,
                scratch_dir.path(),
                &format!("py{alias}/webbrowser"),
                STDLIB_FUNCTION,
            )
            .err()
        })
        .collect();
    assert!(
        failures.is_empty(),
        "{} {STDLIB_FUNCTION} failures:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

#[test]
fn guarded_try_else_arms_recompile_equivalent() {
    let scratch_dir: tempfile::TempDir = tempfile::tempdir().expect("scratch");
    let mut failures: Vec<String> = Vec::new();
    for &alias in FIXTURE_ALIASES {
        let interpreter: PathBuf = find_interpreter(alias);
        for &(label, fixture) in FIXTURES {
            let source_path: PathBuf = scratch_dir.path().join(format!("{label}.{alias}.py"));
            fs::write(&source_path, fixture).expect("write fixture");
            if let Err(failure) = recompile_function(
                &interpreter,
                &source_path,
                scratch_dir.path(),
                &format!("py{alias}/{label}"),
                "f",
            ) {
                failures.push(failure);
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} guarded try/else failures:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}
