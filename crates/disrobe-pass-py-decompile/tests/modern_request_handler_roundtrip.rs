#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::format_push_string
)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use disrobe_pass_py_decompile::engine::{build_real_source, marshal_to_decompile};
use disrobe_pass_py_decompile::roundtrip::{Verdict, semantic_equiv};
use disrobe_py_marshal::{CodeObject, Object, PyVersion as MarshalVersion, PycFile, read_pyc};

const FIXTURE: &str = "../../corpus/python/decompile/construct/cases/modern_request_handler.py";
const REPORT_DIR: &str = "../../target/py-modern-request-handler";

const VERSIONS: &[(u8, u8, &str)] = &[
    (3, 11, "3.11"),
    (3, 12, "3.12"),
    (3, 13, "3.13"),
    (3, 14, "3.14"),
];

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
    if path.is_file() { Some(path) } else { None }
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
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    let sig: String = stderr
        .lines()
        .rfind(|l: &&str| !l.trim().is_empty())
        .unwrap_or("")
        .chars()
        .take(200)
        .collect();
    Err(format!("exit={:?}: {sig}", output.status.code()))
}

fn read_code(pyc_path: &Path) -> Result<(CodeObject, MarshalVersion), String> {
    let bytes: Vec<u8> =
        fs::read(pyc_path).map_err(|e: std::io::Error| format!("read pyc: {e}"))?;
    let pyc: PycFile =
        read_pyc(&bytes).map_err(|e: disrobe_py_marshal::Error| format!("read_pyc: {e}"))?;
    let ver: MarshalVersion = pyc.header.version;
    match pyc.code {
        Object::Code(boxed) => Ok((*boxed, ver)),
        other => Err(format!("top-level not code: {other:?}")),
    }
}

/// Round-trips the `modern_request_handler` module on each available 3.11-3.14 interpreter.
#[test]
fn modern_request_handler_structural_recovery_and_gap() {
    let _ = fs::create_dir_all(REPORT_DIR);
    let scratch: PathBuf = PathBuf::from(REPORT_DIR).join("scratch");
    let _ = fs::create_dir_all(&scratch);

    let source_path: PathBuf = PathBuf::from(FIXTURE);
    assert!(
        source_path.is_file(),
        "missing fixture {}",
        source_path.display()
    );

    let mut interpreters: BTreeMap<&'static str, PathBuf> = BTreeMap::new();
    for &(_, _, alias) in VERSIONS {
        if let Some(p) = find_interpreter(alias) {
            interpreters.insert(alias, p);
        }
    }
    assert!(
        !interpreters.is_empty(),
        "no CPython 3.11-3.14 interpreter resolvable via uv; cannot exercise the fixture"
    );

    let mut report: String = String::with_capacity(1024);
    report.push_str("version\tfn_recovered\ttaskgroup_recovered\tmatch_recovered\tkwd_literals_recovered\tkwd_capture_recovered\texcept_star_recovered\tfor_loop_recovered\twalrus_guard_recovered\thandler_verdict\tsemantic_verdict\n");

    let mut checked: usize = 0;
    let mut semantic_ok: usize = 0;
    let mut handler_ok: usize = 0;
    for &(_, _, alias) in VERSIONS {
        let Some(interpreter): Option<&PathBuf> = interpreters.get(alias) else {
            continue;
        };
        checked += 1;
        let orig_pyc: PathBuf = scratch.join(format!("orig.{alias}.pyc"));
        compile_source(interpreter, &source_path, &orig_pyc)
            .unwrap_or_else(|e: String| panic!("py{alias} orig compile: {e}"));
        let (original_code, marshal_version): (CodeObject, MarshalVersion) =
            read_code(&orig_pyc).unwrap_or_else(|e: String| panic!("py{alias} read orig: {e}"));
        let decompile_version: disrobe_pass_py_decompile::bytecode::version::PyVersion =
            marshal_to_decompile(marshal_version)
                .unwrap_or_else(|e| panic!("py{alias} version map: {e:?}"));
        let source: String = build_real_source(&original_code, &decompile_version, marshal_version)
            .unwrap_or_else(|e: disrobe_pass_py_decompile::error::DecompileError| {
                panic!("py{alias} decompile: {e}")
            });
        let recovered_path: PathBuf = scratch.join(format!("recovered.{alias}.py"));
        fs::write(&recovered_path, &source).expect("write recovered");

        let fn_recovered: bool = source.contains("def modern_request_handler");
        let taskgroup_recovered: bool = source.contains("asyncio.TaskGroup()");
        let match_recovered: bool = source.contains("match ") && source.contains("case ");
        let except_star_recovered: bool =
            source.contains("except* ConnectionError") && source.contains("except* ValueError");
        let for_loop_recovered: bool = source.contains("for resp in payloads");
        let kwd_literals_recovered: bool = source.contains("HttpResponse(status=200, body=b\"\")");
        let kwd_capture_recovered: bool = source.contains("HttpResponse(status=200, body=body)");
        let walrus_guard_recovered: bool =
            source.contains("(size := len(body)) > 0") && source.contains("if code >= 400");

        let semantic_verdict: &str = match semantic_equiv_of_recovered(
            interpreter,
            &recovered_path,
            &original_code,
            marshal_version,
            &scratch,
            alias,
        ) {
            Some(true) => {
                semantic_ok += 1;
                "Semantic"
            }
            Some(false) => "CodeDiff",
            None => "RecompileFailed",
        };

        let handler_verdict: &str = match handler_roundtrip_verdict(
            interpreter,
            &recovered_path,
            &original_code,
            marshal_version,
            &scratch,
            alias,
        ) {
            Some(true) => {
                handler_ok += 1;
                "HandlerByteEqual"
            }
            Some(false) => "HandlerCodeDiff",
            None => "HandlerMissing",
        };

        report.push_str(&format!(
            "{alias}\t{fn_recovered}\t{taskgroup_recovered}\t{match_recovered}\t{kwd_literals_recovered}\t{kwd_capture_recovered}\t{except_star_recovered}\t{for_loop_recovered}\t{walrus_guard_recovered}\t{handler_verdict}\t{semantic_verdict}\n"
        ));

        assert!(
            fn_recovered,
            "py{alias}: recovered source dropped the handler function entirely:\n{source}"
        );
        assert!(
            taskgroup_recovered,
            "py{alias}: recovered source dropped the asyncio.TaskGroup() context:\n{source}"
        );
        assert!(
            match_recovered,
            "py{alias}: recovered source dropped the match/case dispatch:\n{source}"
        );
        assert!(
            kwd_literals_recovered,
            "py{alias}: BUG 3 regression - keyword LITERAL class sub-patterns lost; expected \
             `HttpResponse(status=200, body=b\"\")`:\n{source}"
        );
        assert!(
            kwd_capture_recovered,
            "py{alias}: BUG 3 regression - keyword literal+capture mis-bound; expected \
             `HttpResponse(status=200, body=body)`:\n{source}"
        );
        assert!(
            except_star_recovered,
            "py{alias}: BUG 1 regression - the PEP 654 `except* ConnectionError`/`except* ValueError` \
             wrapper around the `async with asyncio.TaskGroup()` body was dropped:\n{source}"
        );
        assert!(
            for_loop_recovered,
            "py{alias}: BUG 2 regression - `for resp in payloads:` collapsed (the loop inside the \
             `async with` body was hoisted or flattened):\n{source}"
        );
        assert!(
            walrus_guard_recovered,
            "py{alias}: refutable-pattern match guards lost; expected \
             `if (size := len(body)) > 0` and `if code >= 400`:\n{source}"
        );
    }
    assert!(
        checked > 0,
        "no interpreter exercised; the proof is vacuous"
    );

    let report_path: PathBuf = PathBuf::from(REPORT_DIR).join("recovery_matrix.tsv");
    fs::write(&report_path, &report).expect("write report");
    println!("=== modern_request_handler recovery matrix ===\n{report}");
    println!("wrote {}", report_path.display());

    assert!(
        handler_ok >= HANDLER_BYTE_EQUAL_FLOOR,
        "modern_request_handler byte-equal round-trip regressed: {handler_ok}/{checked} versions \
         (floor {HANDLER_BYTE_EQUAL_FLOOR}); see {}",
        report_path.display()
    );

    if EXPECT_SEMANTIC {
        assert_eq!(
            semantic_ok,
            checked,
            "EXPECT_SEMANTIC is set but only {semantic_ok}/{checked} versions round-tripped \
             semantically; see {}",
            report_path.display()
        );
    } else {
        println!(
            "RESIDUAL: whole-MODULE semantic equivalence not yet universal - {semantic_ok}/{checked} \
             versions round-tripped semantically, {handler_ok}/{checked} byte-identical at the handler. \
             EXPECT_SEMANTIC stays false until every available 3.11-3.14 interpreter is Some(true); see \
             {}.",
            report_path.display()
        );
    }
}

/// Whether whole-module semantic equality is expected across 3.11-3.14.
const EXPECT_SEMANTIC: bool = true;

/// Minimum 3.11-3.14 interpreters on which the handler function must round-trip byte-identical.
const HANDLER_BYTE_EQUAL_FLOOR: usize = 4;

/// Recompiles the recovered source and compares it to the original code object.
fn semantic_equiv_of_recovered(
    interpreter: &Path,
    recovered_path: &Path,
    original_code: &CodeObject,
    marshal_version: MarshalVersion,
    scratch: &Path,
    alias: &str,
) -> Option<bool> {
    let recompiled_pyc: PathBuf = scratch.join(format!("recovered.{alias}.pyc"));
    compile_source(interpreter, recovered_path, &recompiled_pyc).ok()?;
    let (recompiled_code, _): (CodeObject, MarshalVersion) = read_code(&recompiled_pyc).ok()?;
    match semantic_equiv(original_code, &recompiled_code, marshal_version) {
        Verdict::Perfect | Verdict::Semantic => Some(true),
        Verdict::CodeDiff(_) => Some(false),
    }
}

/// Recompiles and compares only the nested `modern_request_handler` code object against the original.
fn handler_roundtrip_verdict(
    interpreter: &Path,
    recovered_path: &Path,
    original_code: &CodeObject,
    _marshal_version: MarshalVersion,
    scratch: &Path,
    alias: &str,
) -> Option<bool> {
    let recompiled_pyc: PathBuf = scratch.join(format!("recovered.handler.{alias}.pyc"));
    compile_source(interpreter, recovered_path, &recompiled_pyc).ok()?;
    let (recompiled_code, _): (CodeObject, MarshalVersion) = read_code(&recompiled_pyc).ok()?;
    let original_handler: &CodeObject = find_nested_code(original_code, "modern_request_handler")?;
    let recompiled_handler: &CodeObject =
        find_nested_code(&recompiled_code, "modern_request_handler")?;
    Some(
        original_handler.code == recompiled_handler.code
            && original_handler.consts == recompiled_handler.consts
            && original_handler.names == recompiled_handler.names
            && original_handler.varnames == recompiled_handler.varnames,
    )
}

/// Depth-first search for the nested code object whose `name` is `target`.
fn find_nested_code<'a>(code: &'a CodeObject, target: &str) -> Option<&'a CodeObject> {
    for konst in &code.consts {
        let Object::Code(boxed): &Object = konst else {
            continue;
        };
        if code_name(boxed).as_deref() == Some(target) {
            return Some(boxed);
        }
        if let Some(found) = find_nested_code(boxed, target) {
            return Some(found);
        }
    }
    None
}

fn code_name(code: &CodeObject) -> Option<String> {
    match &code.name {
        Object::String { value, .. } | Object::ShortAscii { value, .. } => Some(value.clone()),
        _ => None,
    }
}
