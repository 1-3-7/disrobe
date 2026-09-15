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

const PLAIN_AFTER_UNPACK: &str = concat!(
    "def load_file(mgr, pathname):\n",
    "    base, name = split(pathname)\n",
    "    name, ext = splitext(name)\n",
    "    with open_code(pathname) as fp:\n",
    "        stuff = (ext, \"rb\", 1)\n",
    "        mgr.load(name, fp, pathname, stuff)\n",
);

const MULTI_ITEM: &str = concat!(
    "def compare(f1, f2):\n",
    "    with open(f1, \"rb\") as a, open(f2, \"rb\") as b:\n",
    "        return a.read() == b.read()\n",
);

const WITH_IN_LOOP: &str = concat!(
    "def scan(paths):\n",
    "    total = 0\n",
    "    for p in paths:\n",
    "        with open(p) as fp:\n",
    "            total += len(fp.read())\n",
    "    return total\n",
);

const WITH_BODY_RETURNS: &str = concat!(
    "def read_all(path):\n",
    "    prefix, name = split(path)\n",
    "    with open(path) as fp:\n",
    "        return fp.read()\n",
);

const FIXTURES: &[(&str, &str)] = &[
    ("plain_after_unpack", PLAIN_AFTER_UNPACK),
    ("multi_item", MULTI_ITEM),
    ("with_in_loop", WITH_IN_LOOP),
    ("with_body_returns", WITH_BODY_RETURNS),
];

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
fn with_regions_recompile_equivalent() {
    let scratch: PathBuf = PathBuf::from("../../target/py-with-recompile");
    fs::create_dir_all(&scratch).expect("scratch");

    let mut checked: usize = 0;
    let mut failures: Vec<String> = Vec::new();
    for &alias in ALIASES {
        let Some(interpreter): Option<PathBuf> = find_interpreter(alias) else {
            eprintln!("SKIP {alias}: no interpreter");
            continue;
        };
        for &(label, fixture) in FIXTURES {
            let source_path: PathBuf = scratch.join(format!("{label}.{alias}.py"));
            fs::write(&source_path, fixture).expect("write fixture");
            let orig_pyc: PathBuf = scratch.join(format!("{label}.orig.{alias}.pyc"));
            if let Err(e) = compile_source(&interpreter, &source_path, &orig_pyc) {
                eprintln!("SKIP {alias}/{label}: orig compile {e}");
                continue;
            }
            let (original, marshal_version): (CodeObject, MarshalVersion) =
                read_code(&orig_pyc).unwrap_or_else(|e| panic!("{alias}/{label} read orig: {e}"));
            let version: PyVersion = marshal_to_decompile(marshal_version)
                .unwrap_or_else(|e| panic!("{alias}/{label} version map: {e:?}"));
            let source: String = build_real_source(&original, &version, marshal_version)
                .unwrap_or_else(|e| panic!("{alias}/{label} decompile: {e}"));
            assert!(
                !source.contains("with None")
                    && !source.contains("__exit__(None")
                    && !source.contains("None(None, None, None)"),
                "py{alias}/{label}: leaked a with placeholder\n{source}"
            );
            let recovered_path: PathBuf = scratch.join(format!("{label}.rec.{alias}.py"));
            fs::write(&recovered_path, &source).expect("write recovered");

            checked += 1;
            let recompiled_pyc: PathBuf = scratch.join(format!("{label}.rec.{alias}.pyc"));
            match compile_source(&interpreter, &recovered_path, &recompiled_pyc) {
                Ok(()) => {}
                Err(e) => {
                    failures.push(format!(
                        "py{alias}/{label}: recovered source does not parse: {e}\n{source}"
                    ));
                    continue;
                }
            }
            let (recompiled, _): (CodeObject, MarshalVersion) = read_code(&recompiled_pyc)
                .unwrap_or_else(|e| panic!("{alias}/{label} read recompiled: {e}"));
            match semantic_equiv(&original, &recompiled, marshal_version) {
                Verdict::Perfect | Verdict::Semantic => {}
                Verdict::CodeDiff(detail) => {
                    failures.push(format!(
                        "py{alias}/{label}: not equivalent ({detail:?})\n{source}"
                    ));
                }
            }
        }
    }

    assert!(
        checked > 0,
        "no CPython 3.11-3.14 interpreter resolvable via uv; the with-recompile proof is vacuous"
    );
    assert!(
        failures.is_empty(),
        "{} with-recompile failures:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}
