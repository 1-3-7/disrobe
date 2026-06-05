#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::missing_const_for_fn,
    clippy::items_after_statements,
    clippy::too_many_lines,
    clippy::cast_precision_loss,
    clippy::format_push_string,
    dead_code
)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use disrobe_pass_py_decompile::engine::{build_real_source, marshal_to_decompile};
use disrobe_pass_py_decompile::roundtrip::{Verdict, semantic_equiv};
use disrobe_py_marshal::{CodeObject, Object, PyVersion as MarshalVersion, PycFile, read_pyc};

const CASES_DIR: &str = "../../corpus/python/decompile/construct/cases";
const MANIFEST: &str = "../../corpus/python/decompile/construct/manifest.tsv";
const REPORT_DIR: &str = "../../target/py-construct-metric";

/// Recovery floor across the per-version construct matrix (`Perfect`+`Semantic`).
const THRESHOLD_PCT: f64 = 100.0;

const VERSIONS: &[(u8, u8, &str)] = &[
    (3, 6, "3.6"),
    (3, 7, "3.7"),
    (3, 8, "3.8"),
    (3, 9, "3.9"),
    (3, 10, "3.10"),
    (3, 11, "3.11"),
    (3, 12, "3.12"),
    (3, 13, "3.13"),
    (3, 14, "3.14"),
    (3, 15, "3.15"),
];

#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Perfect,
    Semantic,
    CodeDiff,
    SyntaxFail,
    RecompileFailed,
    PipelineFailure,
    InterpreterMissing,
}

#[derive(Debug, Clone)]
struct Row {
    construct: String,
    version: String,
    outcome: Outcome,
    detail: String,
}

/// Whether `version` is a pre-release excluded from the gating recovery floor.
fn is_prerelease(version: &str) -> bool {
    version
        .split_once('.')
        .and_then(|(maj, min): (&str, &str)| {
            Some((maj.parse::<u8>().ok()?, min.parse::<u8>().ok()?))
        })
        .is_some_and(|(maj, min): (u8, u8)| (maj, min) >= (3, 15))
}

fn find_interpreter(alias: &str) -> Option<PathBuf> {
    if let Some(p) = find_interpreter_via_uv(alias) {
        return Some(p);
    }
    find_interpreter_on_disk(alias)
}

fn find_interpreter_via_uv(alias: &str) -> Option<PathBuf> {
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

/// Falls back to canonical Windows python.org install locations for `alias`.
fn find_interpreter_on_disk(alias: &str) -> Option<PathBuf> {
    let base: &str = "C:/Users/-/AppData/Local/Programs/Python";
    let tag: String = alias.replace('.', "");
    let candidates: [PathBuf; 3] = [
        PathBuf::from(format!("{base}/Python{tag}/python.exe")),
        PathBuf::from(format!("C:/Python{tag}/python.exe")),
        PathBuf::from(format!("C:/Python{tag}-32/python.exe")),
    ];
    candidates.into_iter().find(|p: &PathBuf| p.is_file())
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
    if !output.status.success() {
        let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
        let sig: String = stderr
            .lines()
            .rfind(|l| !l.trim().is_empty())
            .unwrap_or("")
            .chars()
            .take(200)
            .collect();
        return Err(format!("exit={:?}: {sig}", output.status.code()));
    }
    Ok(())
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

fn evaluate(
    construct: &str,
    source_path: &Path,
    floor: (u8, u8),
    interpreters: &BTreeMap<&'static str, PathBuf>,
    scratch: &Path,
) -> Vec<Row> {
    let mut rows: Vec<Row> = Vec::new();
    for &(maj, min, alias) in VERSIONS {
        if (maj, min) < floor {
            continue;
        }
        let version_label: String = format!("{maj}.{min}");
        let Some(interpreter): Option<&PathBuf> = interpreters.get(alias) else {
            rows.push(Row {
                construct: construct.to_owned(),
                version: version_label,
                outcome: Outcome::InterpreterMissing,
                detail: format!("no interpreter for {alias}"),
            });
            continue;
        };
        let orig_pyc: PathBuf = scratch.join(format!("{construct}.{alias}.orig.pyc"));
        if let Err(e) = compile_source(interpreter, source_path, &orig_pyc) {
            rows.push(Row {
                construct: construct.to_owned(),
                version: version_label,
                outcome: Outcome::PipelineFailure,
                detail: format!("orig compile failed: {e}"),
            });
            continue;
        }
        let (original_code, marshal_version): (CodeObject, MarshalVersion) =
            match read_code(&orig_pyc) {
                Ok(c) => c,
                Err(e) => {
                    rows.push(Row {
                        construct: construct.to_owned(),
                        version: version_label,
                        outcome: Outcome::PipelineFailure,
                        detail: format!("read orig pyc: {e}"),
                    });
                    continue;
                }
            };
        let decompile_version: disrobe_pass_py_decompile::bytecode::version::PyVersion =
            match marshal_to_decompile(marshal_version) {
                Ok(v) => v,
                Err(e) => {
                    rows.push(Row {
                        construct: construct.to_owned(),
                        version: version_label,
                        outcome: Outcome::PipelineFailure,
                        detail: format!("version map: {e:?}"),
                    });
                    continue;
                }
            };
        let source: String =
            match build_real_source(&original_code, &decompile_version, marshal_version) {
                Ok(s) => s,
                Err(e) => {
                    rows.push(Row {
                        construct: construct.to_owned(),
                        version: version_label,
                        outcome: Outcome::PipelineFailure,
                        detail: format!("decompile: {e}"),
                    });
                    continue;
                }
            };
        let recovered_path: PathBuf = scratch.join(format!("{construct}.{alias}.dec.py"));
        if let Err(e) = fs::write(&recovered_path, &source) {
            rows.push(Row {
                construct: construct.to_owned(),
                version: version_label,
                outcome: Outcome::PipelineFailure,
                detail: format!("write recovered: {e}"),
            });
            continue;
        }
        let recompiled_pyc: PathBuf = scratch.join(format!("{construct}.{alias}.dec.pyc"));
        if let Err(e) = compile_source(interpreter, &recovered_path, &recompiled_pyc) {
            rows.push(Row {
                construct: construct.to_owned(),
                version: version_label,
                outcome: Outcome::SyntaxFail,
                detail: format!("recompile failed: {e}"),
            });
            continue;
        }
        let (recompiled_code, _): (CodeObject, MarshalVersion) = match read_code(&recompiled_pyc) {
            Ok(c) => c,
            Err(e) => {
                rows.push(Row {
                    construct: construct.to_owned(),
                    version: version_label,
                    outcome: Outcome::PipelineFailure,
                    detail: format!("read recompiled: {e}"),
                });
                continue;
            }
        };
        let verdict: Verdict = semantic_equiv(&original_code, &recompiled_code, marshal_version);
        let (outcome, detail): (Outcome, String) = match verdict {
            Verdict::Perfect => (Outcome::Perfect, String::new()),
            Verdict::Semantic => (Outcome::Semantic, String::new()),
            Verdict::CodeDiff(d) => (
                Outcome::CodeDiff,
                format!(
                    "{} @ {}: {} vs {} ({})",
                    d.qualname, d.first_diff_offset, d.original_op, d.recompiled_op, d.note
                ),
            ),
        };
        rows.push(Row {
            construct: construct.to_owned(),
            version: version_label,
            outcome,
            detail,
        });
    }
    rows
}

fn load_manifest() -> Vec<(String, (u8, u8))> {
    let text: String = fs::read_to_string(MANIFEST).expect("read manifest");
    let mut out: Vec<(String, (u8, u8))> = Vec::new();
    for line in text.lines().skip(1) {
        let Some((construct, floor)): Option<(&str, &str)> = line.split_once('\t') else {
            continue;
        };
        let Some((maj, min)): Option<(&str, &str)> = floor.split_once('.') else {
            continue;
        };
        let maj: u8 = maj.parse().expect("major");
        let min: u8 = min.parse().expect("minor");
        out.push((construct.to_owned(), (maj, min)));
    }
    out
}

#[test]
fn construct_roundtrip_per_version() {
    let _ = fs::create_dir_all(REPORT_DIR);
    let scratch: PathBuf = PathBuf::from(REPORT_DIR).join("scratch");
    let _ = fs::create_dir_all(&scratch);

    let mut interpreters: BTreeMap<&'static str, PathBuf> = BTreeMap::new();
    for &(_, _, alias) in VERSIONS {
        if let Some(p) = find_interpreter(alias) {
            interpreters.insert(alias, p);
        }
    }
    println!("=== INTERPRETERS ===");
    for (k, v) in &interpreters {
        println!("  {k}: {}", v.display());
    }

    let manifest: Vec<(String, (u8, u8))> = load_manifest();
    assert!(
        manifest.len() >= 100,
        "expected >= 100 construct fixtures, got {}",
        manifest.len()
    );

    let mut missing_claimed: Vec<&'static str> = Vec::new();
    for &(maj, min, alias) in VERSIONS {
        if (maj, min) >= (3, 15) {
            continue;
        }
        let claimed: bool = manifest
            .iter()
            .any(|(_, floor): &(String, (u8, u8))| *floor <= (maj, min));
        if claimed && !interpreters.contains_key(alias) {
            missing_claimed.push(alias);
        }
    }
    assert!(
        missing_claimed.is_empty(),
        "interpreters missing for claimed-support versions {missing_claimed:?}; '100%' cannot be \
         proven while these cells are silently skipped. Install them (uv python install <v> or a \
         python.org build) or remove the version from the support matrix.",
    );

    let mut all_rows: Vec<Row> = Vec::new();
    for (construct, floor) in &manifest {
        let source_path: PathBuf = PathBuf::from(CASES_DIR).join(format!("{construct}.py"));
        assert!(
            source_path.is_file(),
            "missing fixture {}",
            source_path.display()
        );
        let rows: Vec<Row> = evaluate(construct, &source_path, *floor, &interpreters, &scratch);
        all_rows.extend(rows);
    }

    let mut by_version: BTreeMap<String, BTreeMap<&'static str, usize>> = BTreeMap::new();
    let mut totals: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut evaluated: usize = 0;
    let mut prerelease_evaluated: usize = 0;
    let mut prerelease_recovered: usize = 0;
    for r in &all_rows {
        let key: &'static str = match r.outcome {
            Outcome::Perfect => "Perfect",
            Outcome::Semantic => "Semantic",
            Outcome::CodeDiff => "CodeDiff",
            Outcome::SyntaxFail => "SyntaxFail",
            Outcome::RecompileFailed => "RecompileFailed",
            Outcome::PipelineFailure => "PipelineFailure",
            Outcome::InterpreterMissing => "InterpreterMissing",
        };
        *totals.entry(key).or_insert(0) += 1;
        if r.outcome != Outcome::InterpreterMissing {
            *by_version
                .entry(r.version.clone())
                .or_default()
                .entry(key)
                .or_insert(0) += 1;
            if is_prerelease(&r.version) {
                prerelease_evaluated += 1;
                if matches!(r.outcome, Outcome::Perfect | Outcome::Semantic) {
                    prerelease_recovered += 1;
                }
            } else {
                evaluated += 1;
            }
        }
    }

    let mut buf: String = String::with_capacity(8192);
    buf.push_str("construct\tversion\toutcome\tdetail\n");
    for r in &all_rows {
        buf.push_str(&format!(
            "{}\t{}\t{:?}\t{}\n",
            r.construct,
            r.version,
            r.outcome,
            r.detail.replace('\t', "  ").replace('\n', " | ")
        ));
    }
    let tsv: PathBuf = PathBuf::from(REPORT_DIR).join("construct_roundtrip.tsv");
    let _ = fs::write(&tsv, &buf);

    let recovered_total: usize =
        totals.get("Perfect").copied().unwrap_or(0) + totals.get("Semantic").copied().unwrap_or(0);
    let recovered: usize = recovered_total - prerelease_recovered;
    let pct: f64 = if evaluated == 0 {
        0.0
    } else {
        (recovered as f64 / evaluated as f64) * 100.0
    };
    let prerelease_pct: f64 = if prerelease_evaluated == 0 {
        0.0
    } else {
        (prerelease_recovered as f64 / prerelease_evaluated as f64) * 100.0
    };

    println!("=== CONSTRUCT ROUNDTRIP SUMMARY ===");
    println!("stable-matrix evaluated (excl. interpreter-missing + pre-release): {evaluated}");
    println!(
        "pre-release (3.15) exploratory: {prerelease_recovered}/{prerelease_evaluated} ({prerelease_pct:.1}%) — reported, not gating"
    );
    for k in [
        "Perfect",
        "Semantic",
        "CodeDiff",
        "SyntaxFail",
        "RecompileFailed",
        "PipelineFailure",
        "InterpreterMissing",
    ] {
        let n: usize = totals.get(k).copied().unwrap_or(0);
        println!("  {k:20} {n:>4}");
    }
    println!("RECOVERED stable matrix (Perfect+Semantic): {recovered}/{evaluated} ({pct:.1}%)");
    println!("--- per version ---");
    for (ver, counts) in &by_version {
        let p: usize = counts.get("Perfect").copied().unwrap_or(0);
        let s: usize = counts.get("Semantic").copied().unwrap_or(0);
        let cd: usize = counts.get("CodeDiff").copied().unwrap_or(0);
        let sf: usize = counts.get("SyntaxFail").copied().unwrap_or(0);
        let pf: usize = counts.get("PipelineFailure").copied().unwrap_or(0);
        let tv: usize = p + s + cd + sf + pf;
        let vp: f64 = if tv == 0 {
            0.0
        } else {
            ((p + s) as f64 / tv as f64) * 100.0
        };
        println!(
            "  py {ver:<5} P={p} S={s} CodeDiff={cd} SyntaxFail={sf} PipelineFail={pf} | recovered={vp:.1}%"
        );
    }

    let pipeline_failures: usize = totals.get("PipelineFailure").copied().unwrap_or(0);
    assert_eq!(
        pipeline_failures,
        0,
        "{pipeline_failures} pipeline failures (decompiler crashed / emitted nothing); see {}",
        tsv.display()
    );

    let stable_syntax_fails: usize = all_rows
        .iter()
        .filter(|r: &&Row| !is_prerelease(&r.version) && r.outcome == Outcome::SyntaxFail)
        .count();
    assert_eq!(
        stable_syntax_fails,
        0,
        "{stable_syntax_fails} stable-matrix syntax failures (emitter produced invalid source); see {}",
        tsv.display()
    );
    assert!(
        pct >= THRESHOLD_PCT,
        "real round-trip recovery {pct:.1}% fell below honest floor {THRESHOLD_PCT:.1}%; see {}",
        tsv.display()
    );
}

/// Regression: `try/except/else/finally` preserves its post-finally tail `return` on 3.12+.
#[test]
fn try_else_finally_tail_return_preserved_3_12_plus() {
    let mut interpreters: BTreeMap<&'static str, PathBuf> = BTreeMap::new();
    for &(_, _, alias) in VERSIONS {
        if let Some(p) = find_interpreter(alias) {
            interpreters.insert(alias, p);
        }
    }
    let scratch: PathBuf = PathBuf::from(REPORT_DIR).join("tail-return-scratch");
    let _ = fs::create_dir_all(&scratch);
    let source_path: PathBuf = PathBuf::from(CASES_DIR).join("try_except_else_finally.py");
    assert!(
        source_path.is_file(),
        "missing fixture {}",
        source_path.display()
    );

    let mut checked: usize = 0;
    for alias in ["3.12", "3.13", "3.14"] {
        let Some(interpreter): Option<&PathBuf> = interpreters.get(alias) else {
            continue;
        };
        checked += 1;
        let orig_pyc: PathBuf = scratch.join(format!("orig.{alias}.pyc"));
        compile_source(interpreter, &source_path, &orig_pyc)
            .unwrap_or_else(|e| panic!("orig compile {alias}: {e}"));
        let (original_code, marshal_version): (CodeObject, MarshalVersion) =
            read_code(&orig_pyc).unwrap_or_else(|e| panic!("read orig {alias}: {e}"));
        let decompile_version: disrobe_pass_py_decompile::bytecode::version::PyVersion =
            marshal_to_decompile(marshal_version)
                .unwrap_or_else(|e| panic!("version map {alias}: {e:?}"));
        let source: String = build_real_source(&original_code, &decompile_version, marshal_version)
            .unwrap_or_else(|e| panic!("decompile {alias}: {e}"));
        assert!(
            source.contains("return total"),
            "py{alias}: recovered try/except/else/finally must preserve the construct-exit \
             `return total`; got:\n{source}"
        );
        let recovered_path: PathBuf = scratch.join(format!("recovered.{alias}.py"));
        fs::write(&recovered_path, &source).expect("write recovered");
        let value: i64 = eval_f_106(interpreter, &recovered_path);
        assert_eq!(
            value, 106,
            "py{alias}: recovered f([1,2,3]) must equal 106 (else +100 over sum 6), got {value}"
        );
    }
    assert!(
        checked > 0,
        "no 3.12+ interpreter available to validate tail-return regression"
    );
}

/// Regression: nested-`for` mid-loop `return (i, j)` is preserved on 3.15 (#79).
#[test]
fn for_nested_mid_loop_return_preserved_3_15() {
    let Some(interpreter): Option<PathBuf> = find_interpreter("3.15") else {
        return;
    };
    let scratch: PathBuf = PathBuf::from(REPORT_DIR).join("for-nested-scratch");
    let _ = fs::create_dir_all(&scratch);
    let source_path: PathBuf = PathBuf::from(CASES_DIR).join("for_nested.py");
    assert!(
        source_path.is_file(),
        "missing fixture {}",
        source_path.display()
    );

    let orig_pyc: PathBuf = scratch.join("orig.3.15.pyc");
    compile_source(&interpreter, &source_path, &orig_pyc)
        .unwrap_or_else(|e| panic!("orig compile 3.15: {e}"));
    let (original_code, marshal_version): (CodeObject, MarshalVersion) =
        read_code(&orig_pyc).unwrap_or_else(|e| panic!("read orig 3.15: {e}"));
    let decompile_version: disrobe_pass_py_decompile::bytecode::version::PyVersion =
        marshal_to_decompile(marshal_version).unwrap_or_else(|e| panic!("version map: {e:?}"));
    let source: String = build_real_source(&original_code, &decompile_version, marshal_version)
        .unwrap_or_else(|e| panic!("decompile 3.15: {e}"));
    assert!(
        source.contains("return (i, j)"),
        "py3.15: nested-for mid-loop return must recover `return (i, j)`, not a bare expr; got:\n{source}"
    );
    let recovered_path: PathBuf = scratch.join("recovered.3.15.py");
    fs::write(&recovered_path, &source).expect("write recovered");
    let value: (i64, i64) = eval_f_matrix(&interpreter, &recovered_path);
    assert_eq!(
        value,
        (1, 1),
        "py3.15: recovered f([[1,2],[3,4]], 4) must equal (1, 1)"
    );
}

/// Runs `f([[1,2],[3,4]], 4)` from `script` and returns the recovered `(row, col)` tuple.
fn eval_f_matrix(interpreter: &Path, script: &Path) -> (i64, i64) {
    let driver: String = format!(
        "import importlib.util,sys;\
         spec=importlib.util.spec_from_file_location('m',r'{}');\
         m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);\
         r=m.f([[1,2],[3,4]],4);sys.stdout.write('RESULT=%d,%d'%(r[0],r[1]))",
        script.display()
    );
    let output: std::process::Output = Command::new(interpreter)
        .args(["-c", &driver])
        .stdin(Stdio::null())
        .output()
        .expect("spawn interpreter");
    assert!(
        output.status.success(),
        "running recovered module failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let marker: &str = stdout.rsplit("RESULT=").next().unwrap_or("").trim();
    let (a, b): (&str, &str) = marker
        .split_once(',')
        .unwrap_or_else(|| panic!("f did not print a pair, got {stdout:?}"));
    (
        a.parse::<i64>()
            .unwrap_or_else(|_| panic!("bad row in {stdout:?}")),
        b.parse::<i64>()
            .unwrap_or_else(|_| panic!("bad col in {stdout:?}")),
    )
}

/// Runs `f([1,2,3])` from `script` under `interpreter` and returns its integer result.
fn eval_f_106(interpreter: &Path, script: &Path) -> i64 {
    let driver: String = format!(
        "import importlib.util,sys;\
         spec=importlib.util.spec_from_file_location('m',r'{}');\
         m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);\
         sys.stdout.write('RESULT='+str(m.f([1,2,3])))",
        script.display()
    );
    let output: std::process::Output = Command::new(interpreter)
        .args(["-c", &driver])
        .stdin(Stdio::null())
        .output()
        .expect("spawn interpreter");
    assert!(
        output.status.success(),
        "running recovered module failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let marker: &str = stdout.rsplit("RESULT=").next().unwrap_or("").trim();
    marker
        .parse::<i64>()
        .unwrap_or_else(|_| panic!("f([1,2,3]) did not print an int, got {stdout:?}"))
}

/// Compiles `fixture` on 3.14, decompiles and recompiles, returning `(recovered_source, verdict)`.
fn decompile_and_roundtrip_3_14(
    interpreter: &Path,
    fixture: &str,
    scratch_name: &str,
) -> (String, Verdict) {
    let scratch: PathBuf = PathBuf::from(REPORT_DIR).join(scratch_name);
    let _ = fs::create_dir_all(&scratch);
    let source_path: PathBuf = PathBuf::from(CASES_DIR).join(fixture);
    assert!(
        source_path.is_file(),
        "missing fixture {}",
        source_path.display()
    );

    let orig_pyc: PathBuf = scratch.join("orig.3.14.pyc");
    compile_source(interpreter, &source_path, &orig_pyc)
        .unwrap_or_else(|e| panic!("orig compile 3.14: {e}"));
    let (original_code, marshal_version): (CodeObject, MarshalVersion) =
        read_code(&orig_pyc).unwrap_or_else(|e| panic!("read orig 3.14: {e}"));
    let decompile_version: disrobe_pass_py_decompile::bytecode::version::PyVersion =
        marshal_to_decompile(marshal_version).unwrap_or_else(|e| panic!("version map: {e:?}"));
    let source: String = build_real_source(&original_code, &decompile_version, marshal_version)
        .unwrap_or_else(|e| panic!("decompile 3.14: {e}"));

    let recovered_path: PathBuf = scratch.join("recovered.3.14.py");
    fs::write(&recovered_path, &source).expect("write recovered");
    let recompiled_pyc: PathBuf = scratch.join("recovered.3.14.pyc");
    compile_source(interpreter, &recovered_path, &recompiled_pyc)
        .unwrap_or_else(|e| panic!("recompile 3.14:\n{source}\n--- error: {e}"));
    let (recompiled_code, _): (CodeObject, MarshalVersion) =
        read_code(&recompiled_pyc).unwrap_or_else(|e| panic!("read recompiled 3.14: {e}"));
    let verdict: Verdict = semantic_equiv(&original_code, &recompiled_code, marshal_version);
    (source, verdict)
}

/// Regression: outer `as name` bindings on structured match patterns survive across 3.10-3.14.
#[test]
fn match_structured_as_bindings_survive() {
    let mut interpreters: BTreeMap<&'static str, PathBuf> = BTreeMap::new();
    for &(_, _, alias) in VERSIONS {
        if let Some(p) = find_interpreter(alias) {
            interpreters.insert(alias, p);
        }
    }
    let scratch: PathBuf = PathBuf::from(REPORT_DIR).join("match-as-scratch");
    let _ = fs::create_dir_all(&scratch);

    let expectations: &[(&str, &[&str], &[&str])] = &[
        ("match_class_as", &["int() as n", "str() as t"], &[]),
        ("match_class_as_guard", &["str() as t", "if t"], &[]),
        ("match_sequence_as", &["[a] as whole"], &["a, whole]"]),
        (
            "match_mapping_as",
            &["} as m", "vv", "rest"],
            &["**m", "**vv"],
        ),
    ];

    let mut checked: usize = 0;
    for alias in ["3.10", "3.11", "3.12", "3.13", "3.14"] {
        let Some(interpreter): Option<&PathBuf> = interpreters.get(alias) else {
            continue;
        };
        for (construct, must, must_not) in expectations {
            let source_path: PathBuf = PathBuf::from(CASES_DIR).join(format!("{construct}.py"));
            let orig_pyc: PathBuf = scratch.join(format!("{construct}.{alias}.pyc"));
            compile_source(interpreter, &source_path, &orig_pyc)
                .unwrap_or_else(|e| panic!("compile {construct} {alias}: {e}"));
            let (code, marshal_version): (CodeObject, MarshalVersion) =
                read_code(&orig_pyc).unwrap_or_else(|e| panic!("read {construct} {alias}: {e}"));
            let decompile_version: disrobe_pass_py_decompile::bytecode::version::PyVersion =
                marshal_to_decompile(marshal_version)
                    .unwrap_or_else(|e| panic!("version map {alias}: {e:?}"));
            let src: String = build_real_source(&code, &decompile_version, marshal_version)
                .unwrap_or_else(|e| panic!("decompile {construct} {alias}: {e}"));
            for needle in *must {
                assert!(
                    src.contains(needle),
                    "py{alias} {construct}: lost `{needle}` in:\n{src}"
                );
            }
            for forbidden in *must_not {
                assert!(
                    !src.contains(forbidden),
                    "py{alias} {construct}: corrupt `{forbidden}` in:\n{src}"
                );
            }
            checked += 1;
        }
    }
    assert!(
        checked > 0,
        "no 3.10-3.14 interpreter to validate structured `as` bindings"
    );
}

/// Regression: module-level decorated classes recover with no placeholder leak on 3.14.
#[test]
fn decorated_class_recovers_no_placeholder_3_14() {
    let Some(interpreter): Option<PathBuf> = find_interpreter("3.14") else {
        return;
    };
    let (source, verdict): (String, Verdict) = decompile_and_roundtrip_3_14(
        &interpreter,
        "class_decorated.py",
        "decorated-class-scratch",
    );
    assert!(
        !source.contains("__DR_BUILD_CLASS__") && !source.contains("__DR_CODE_CONST_"),
        "decorated class leaked a placeholder; got:\n{source}"
    );
    assert!(
        source.contains("@dataclass") && source.contains("class B"),
        "decorated class must recover `@dataclass`/`class B`; got:\n{source}"
    );
    assert!(
        matches!(verdict, Verdict::Perfect | Verdict::Semantic),
        "decorated class round-trip not equivalent: {verdict:?}\nsource:\n{source}"
    );
}

/// Regression: stacked class decorators recover in source order and round-trip on 3.14.
#[test]
fn stacked_decorated_class_order_3_14() {
    let Some(interpreter): Option<PathBuf> = find_interpreter("3.14") else {
        return;
    };
    let (source, verdict): (String, Verdict) = decompile_and_roundtrip_3_14(
        &interpreter,
        "class_decorated_stacked.py",
        "stacked-decorated-class-scratch",
    );
    assert!(
        !source.contains("__DR_BUILD_CLASS__") && !source.contains("__DR_CODE_CONST_"),
        "stacked decorated class leaked a placeholder; got:\n{source}"
    );
    assert!(
        source.contains("@tag") && source.contains("@seal") && source.contains("class S(dict)"),
        "stacked decorated class must recover `@tag`/`@seal`/`class S(dict)`; got:\n{source}"
    );
    let tag_at: usize = source.find("@tag").expect("@tag present");
    let seal_at: usize = source.find("@seal").expect("@seal present");
    assert!(
        tag_at < seal_at,
        "decorator order wrong: `@tag` must precede `@seal`; got:\n{source}"
    );
    assert!(
        matches!(verdict, Verdict::Perfect | Verdict::Semantic),
        "stacked decorated class round-trip not equivalent: {verdict:?}\nsource:\n{source}"
    );
}
