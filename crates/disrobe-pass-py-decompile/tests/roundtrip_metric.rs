#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::missing_const_for_fn,
    clippy::items_after_statements,
    clippy::too_many_lines,
    clippy::default_trait_access,
    clippy::match_same_arms,
    clippy::cast_precision_loss,
    clippy::format_push_string,
    clippy::cognitive_complexity,
    clippy::map_unwrap_or,
    clippy::or_fun_call,
    clippy::needless_collect,
    dead_code
)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use disrobe_pass_py_decompile::ast::{AstBuilder, AstModule, DefaultAstBuilder};
use disrobe_pass_py_decompile::bytecode::version::PyVersion as DecompileVersion;
use disrobe_pass_py_decompile::codegen::{CodeEmitter, DefaultEmitter};
use disrobe_pass_py_decompile::frame_tree::{FrameTree, builder_for};
use disrobe_pass_py_decompile::roundtrip::{Verdict, semantic_equiv};
use disrobe_py_marshal::{CodeObject, Object, PyVersion as MarshalVersion, PycFile, read_pyc};

const PYCACHE_DIR: &str = "../../corpus/python/decompile/playground/__pycache__";
const STANDALONE_PYC_2_7: &str = "../../corpus/python/decompile/playground/edge_cases_2_7.pyc";
const REPORT_DIR: &str = "../../target/v0.8-close-5-pydec-metric";

#[derive(Debug, Clone, PartialEq, Eq)]
enum Stage {
    ReadFailed,
    UnwrapFailed,
    FrameTreeFailed,
    AstBuildFailed,
    EmitFailed,
    RecompilerNotAvailable,
    RecompileFailed,
    RecompiledReadFailed,
    Compared,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MetricVerdict {
    Perfect,
    Semantic,
    CodeDiff,
    SyntaxFail,
    RecompilerUnavailable,
    PipelineFailure,
}

#[derive(Debug, Clone)]
struct Record {
    fixture: String,
    band: String,
    compiler_tag: String,
    pyc_version: String,
    stage: Stage,
    verdict: MetricVerdict,
    detail: String,
    decompiled_loc: u32,
    recompile_command: String,
}

#[derive(Debug, Clone)]
struct InterpreterSpec {
    tag: &'static str,
    uv_alias: &'static str,
}

const INTERPRETERS: &[InterpreterSpec] = &[
    InterpreterSpec {
        tag: "cpython-2.7",
        uv_alias: "2.7",
    },
    InterpreterSpec {
        tag: "cpython-3.6",
        uv_alias: "3.6",
    },
    InterpreterSpec {
        tag: "cpython-3.7",
        uv_alias: "3.7",
    },
    InterpreterSpec {
        tag: "cpython-3.8",
        uv_alias: "3.8",
    },
    InterpreterSpec {
        tag: "cpython-3.9",
        uv_alias: "3.9",
    },
    InterpreterSpec {
        tag: "cpython-3.10",
        uv_alias: "3.10",
    },
    InterpreterSpec {
        tag: "cpython-3.11",
        uv_alias: "3.11",
    },
    InterpreterSpec {
        tag: "cpython-3.12",
        uv_alias: "3.12",
    },
    InterpreterSpec {
        tag: "cpython-3.13",
        uv_alias: "3.13",
    },
    InterpreterSpec {
        tag: "cpython-3.14",
        uv_alias: "3.14",
    },
    InterpreterSpec {
        tag: "cpython-3.15",
        uv_alias: "3.15",
    },
    InterpreterSpec {
        tag: "pypy-3.10",
        uv_alias: "pypy3.10",
    },
];

#[must_use]
fn marshal_to_decompile(v: MarshalVersion) -> DecompileVersion {
    match (v.major, v.minor) {
        (2, 7) => DecompileVersion::V2_7,
        (3, 6) => DecompileVersion::V3_6,
        (3, 7) => DecompileVersion::V3_7,
        (3, 8) => DecompileVersion::V3_8,
        (3, 9) => DecompileVersion::V3_9,
        (3, 10) => DecompileVersion::V3_10,
        (3, 11) => DecompileVersion::V3_11,
        (3, 12) => DecompileVersion::V3_12,
        (3, 13) => DecompileVersion::V3_13,
        (3, 14) => DecompileVersion::V3_14,
        (3, 15) => DecompileVersion::V3_15,
        _ => DecompileVersion::V3_14,
    }
}

#[must_use]
fn marshal_to_uv_alias(v: MarshalVersion) -> &'static str {
    match (v.major, v.minor) {
        (2, 7) => "2.7",
        (3, 6) => "3.6",
        (3, 7) => "3.7",
        (3, 8) => "3.8",
        (3, 9) => "3.9",
        (3, 10) => "3.10",
        (3, 11) => "3.11",
        (3, 12) => "3.12",
        (3, 13) => "3.13",
        (3, 14) => "3.14",
        (3, 15) => "3.15",
        _ => "3.14",
    }
}

#[must_use]
fn classify_filename(name: &str) -> (String, String) {
    let stem: &str = name.rsplit_once('.').map_or(name, |(s, _)| s);
    if let Some((band, suffix)) = stem.split_once(".cpython-") {
        return (band.to_owned(), format!("cpython-{suffix}"));
    }
    if let Some((band, suffix)) = stem.split_once(".pypy") {
        return (band.to_owned(), format!("pypy{suffix}"));
    }
    (stem.to_owned(), "self".to_owned())
}

#[must_use]
fn collect_pyc_paths() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let standalone: PathBuf = PathBuf::from(STANDALONE_PYC_2_7);
    if standalone.exists() {
        out.push(standalone);
    }
    if let Ok(rd) = fs::read_dir(PYCACHE_DIR) {
        for entry in rd.flatten() {
            let path: PathBuf = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("pyc") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

#[must_use]
fn find_interpreter(uv_alias: &str) -> Option<PathBuf> {
    let output: std::process::Output = Command::new("uv")
        .args(["python", "find", uv_alias])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if raw.is_empty() {
        return None;
    }
    let path: PathBuf = PathBuf::from(raw);
    if path.is_file() { Some(path) } else { None }
}

#[derive(Debug, Clone)]
struct DecompileResult {
    source: String,
    decompile_version: DecompileVersion,
    marshal_version: MarshalVersion,
    original_code: CodeObject,
}

fn decompile_pyc(path: &Path) -> Result<DecompileResult, (Stage, String)> {
    let bytes: Vec<u8> = fs::read(path)
        .map_err(|e: std::io::Error| (Stage::ReadFailed, format!("fs::read: {e}")))?;
    let pyc: PycFile = read_pyc(&bytes)
        .map_err(|e: disrobe_py_marshal::Error| (Stage::ReadFailed, format!("read_pyc: {e}")))?;
    let code: CodeObject = match pyc.code {
        Object::Code(boxed) => *boxed,
        other => {
            return Err((
                Stage::UnwrapFailed,
                format!("top-level not Code: {other:?}"),
            ));
        }
    };
    let marshal_version: MarshalVersion = pyc.header.version;
    let decompile_version: DecompileVersion = marshal_to_decompile(marshal_version);
    let tree: FrameTree = builder_for(marshal_version)
        .build(&code, marshal_version)
        .map_err(|e| (Stage::FrameTreeFailed, format!("frame_tree::build: {e:?}")))?;
    let module: AstModule = DefaultAstBuilder::new()
        .build_module(&code, &tree, &decompile_version)
        .map_err(|e| {
            (
                Stage::AstBuildFailed,
                format!("AstBuilder::build_module: {e:?}"),
            )
        })?;
    let emitter: DefaultEmitter = DefaultEmitter::new();
    let text: String = emitter.emit_module(&module, &decompile_version);
    if text.is_empty() {
        return Err((Stage::EmitFailed, "empty emitted source".to_owned()));
    }
    Ok(DecompileResult {
        source: text,
        decompile_version,
        marshal_version,
        original_code: code,
    })
}

fn recompile_via_interpreter(interpreter: &Path, source_path: &Path) -> Result<PathBuf, String> {
    let parent: &Path = source_path.parent().ok_or_else(|| "no parent".to_owned())?;
    let stem: &str = source_path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| "no stem".to_owned())?;
    let direct_pyc: PathBuf = parent.join(format!("{stem}.recompiled.pyc"));
    let script: &str =
        "import py_compile, sys; py_compile.compile(sys.argv[1], cfile=sys.argv[2], doraise=True)";
    let output: std::process::Output = Command::new(interpreter)
        .args([
            "-c",
            script,
            source_path.to_str().unwrap_or(""),
            direct_pyc.to_str().unwrap_or(""),
        ])
        .output()
        .map_err(|e: std::io::Error| format!("spawn: {e}"))?;
    if !output.status.success() {
        let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
        let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
        let combined: String = format!("{stdout}\n{stderr}");
        let signature: String = combined
            .lines()
            .rfind(|l| !l.trim().is_empty())
            .unwrap_or("")
            .chars()
            .take(200)
            .collect();
        return Err(format!("exit={:?}: {signature}", output.status.code()));
    }
    if !direct_pyc.is_file() {
        return Err(format!("no .pyc produced at {}", direct_pyc.display()));
    }
    Ok(direct_pyc)
}

fn evaluate_one(path: &Path, interpreters: &BTreeMap<&'static str, PathBuf>) -> Record {
    let fname: String = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_owned();
    let (band, compiler_tag): (String, String) = classify_filename(&fname);
    let dec: DecompileResult = match decompile_pyc(path) {
        Ok(d) => d,
        Err((stage, msg)) => {
            return Record {
                fixture: fname,
                band,
                compiler_tag,
                pyc_version: String::new(),
                stage,
                verdict: MetricVerdict::PipelineFailure,
                detail: msg,
                decompiled_loc: 0,
                recompile_command: String::new(),
            };
        }
    };
    let pyc_version: String = format!(
        "{}.{}",
        dec.marshal_version.major, dec.marshal_version.minor
    );
    let decompiled_loc: u32 = u32::try_from(dec.source.lines().count()).unwrap_or(u32::MAX);
    let uv_alias: &'static str = marshal_to_uv_alias(dec.marshal_version);
    let interpreter: &PathBuf = match interpreters.get(uv_alias) {
        Some(p) => p,
        None => {
            return Record {
                fixture: fname,
                band,
                compiler_tag,
                pyc_version,
                stage: Stage::RecompilerNotAvailable,
                verdict: MetricVerdict::RecompilerUnavailable,
                detail: format!("no interpreter for {uv_alias}"),
                decompiled_loc,
                recompile_command: String::new(),
            };
        }
    };
    let temp_dir: PathBuf = PathBuf::from(REPORT_DIR).join("scratch");
    let _ = fs::create_dir_all(&temp_dir);
    let source_path: PathBuf = temp_dir.join(format!("{band}.{compiler_tag}.py"));
    if let Err(e) = fs::write(&source_path, &dec.source) {
        return Record {
            fixture: fname,
            band,
            compiler_tag,
            pyc_version,
            stage: Stage::EmitFailed,
            verdict: MetricVerdict::PipelineFailure,
            detail: format!("write source: {e}"),
            decompiled_loc,
            recompile_command: String::new(),
        };
    }
    let recompile_cmd: String = format!(
        "{} -m py_compile {}",
        interpreter.display(),
        source_path.display()
    );
    let recompiled_path: PathBuf = match recompile_via_interpreter(interpreter, &source_path) {
        Ok(p) => p,
        Err(e) => {
            return Record {
                fixture: fname,
                band,
                compiler_tag,
                pyc_version,
                stage: Stage::RecompileFailed,
                verdict: MetricVerdict::SyntaxFail,
                detail: e,
                decompiled_loc,
                recompile_command: recompile_cmd,
            };
        }
    };
    let recomp_bytes: Vec<u8> = match fs::read(&recompiled_path) {
        Ok(b) => b,
        Err(e) => {
            return Record {
                fixture: fname,
                band,
                compiler_tag,
                pyc_version,
                stage: Stage::RecompiledReadFailed,
                verdict: MetricVerdict::PipelineFailure,
                detail: format!("read recompiled: {e}"),
                decompiled_loc,
                recompile_command: recompile_cmd,
            };
        }
    };
    let recomp_pyc: PycFile = match read_pyc(&recomp_bytes) {
        Ok(p) => p,
        Err(e) => {
            return Record {
                fixture: fname,
                band,
                compiler_tag,
                pyc_version,
                stage: Stage::RecompiledReadFailed,
                verdict: MetricVerdict::PipelineFailure,
                detail: format!("read_pyc recompiled: {e}"),
                decompiled_loc,
                recompile_command: recompile_cmd,
            };
        }
    };
    let recomp_code: CodeObject = match recomp_pyc.code {
        Object::Code(boxed) => *boxed,
        other => {
            return Record {
                fixture: fname,
                band,
                compiler_tag,
                pyc_version,
                stage: Stage::RecompiledReadFailed,
                verdict: MetricVerdict::PipelineFailure,
                detail: format!("recompiled top-level not Code: {other:?}"),
                decompiled_loc,
                recompile_command: recompile_cmd,
            };
        }
    };
    let verdict_raw: Verdict =
        semantic_equiv(&dec.original_code, &recomp_code, dec.marshal_version);
    let (verdict, detail): (MetricVerdict, String) = match verdict_raw {
        Verdict::Perfect => (
            MetricVerdict::Perfect,
            "byte-identical post-norm".to_owned(),
        ),
        Verdict::Semantic => (MetricVerdict::Semantic, "norm-equivalent only".to_owned()),
        Verdict::CodeDiff(d) => (
            MetricVerdict::CodeDiff,
            format!(
                "{}: {} -> {} ({})",
                d.qualname, d.original_op, d.recompiled_op, d.note
            ),
        ),
    };
    Record {
        fixture: fname,
        band,
        compiler_tag,
        pyc_version,
        stage: Stage::Compared,
        verdict,
        detail,
        decompiled_loc,
        recompile_command: recompile_cmd,
    }
}

fn resolve_interpreters() -> BTreeMap<&'static str, PathBuf> {
    let mut out: BTreeMap<&'static str, PathBuf> = BTreeMap::new();
    for spec in INTERPRETERS {
        if let Some(p) = find_interpreter(spec.uv_alias) {
            out.insert(spec.uv_alias, p);
        }
    }
    out
}

fn write_tsv_report(records: &[Record], path: &Path) {
    let mut buf: String = String::with_capacity(8192);
    buf.push_str("fixture\tband\tcompiler_tag\tpyc_version\tstage\tverdict\tdecompiled_loc\tdetail\trecompile_cmd\n");
    for r in records {
        buf.push_str(&format!(
            "{}\t{}\t{}\t{}\t{:?}\t{:?}\t{}\t{}\t{}\n",
            r.fixture,
            r.band,
            r.compiler_tag,
            r.pyc_version,
            r.stage,
            r.verdict,
            r.decompiled_loc,
            r.detail.replace('\t', "  ").replace('\n', " | "),
            r.recompile_command.replace('\t', "  ").replace('\n', " | "),
        ));
    }
    let _ = fs::write(path, buf);
}

fn write_summary(records: &[Record], path: &Path) {
    let mut by_version: BTreeMap<String, BTreeMap<&'static str, usize>> = BTreeMap::new();
    let mut totals: BTreeMap<&'static str, usize> = BTreeMap::new();
    for r in records {
        let key: &'static str = match r.verdict {
            MetricVerdict::Perfect => "Perfect",
            MetricVerdict::Semantic => "Semantic",
            MetricVerdict::CodeDiff => "CodeDiff",
            MetricVerdict::SyntaxFail => "SyntaxFail",
            MetricVerdict::RecompilerUnavailable => "RecompilerUnavailable",
            MetricVerdict::PipelineFailure => "PipelineFailure",
        };
        *totals.entry(key).or_insert(0) += 1;
        let ver: String = if r.pyc_version.is_empty() {
            "<unknown>".to_owned()
        } else {
            r.pyc_version.clone()
        };
        *by_version.entry(ver).or_default().entry(key).or_insert(0) += 1;
    }
    let mut buf: String = String::with_capacity(2048);
    buf.push_str("=== ROUNDTRIP METRIC SUMMARY ===\n\n");
    buf.push_str(&format!("Total fixtures evaluated: {}\n\n", records.len()));
    buf.push_str("--- Aggregate verdict counts ---\n");
    for k in [
        "Perfect",
        "Semantic",
        "CodeDiff",
        "SyntaxFail",
        "RecompilerUnavailable",
        "PipelineFailure",
    ] {
        let n: usize = totals.get(k).copied().unwrap_or(0);
        let pct: f64 = if records.is_empty() {
            0.0
        } else {
            (n as f64 / records.len() as f64) * 100.0
        };
        buf.push_str(&format!("  {k:24} {n:>4}  ({pct:>5.1}%)\n"));
    }
    let recovered: usize =
        totals.get("Perfect").copied().unwrap_or(0) + totals.get("Semantic").copied().unwrap_or(0);
    let pct_recovered: f64 = if records.is_empty() {
        0.0
    } else {
        (recovered as f64 / records.len() as f64) * 100.0
    };
    buf.push_str(&format!(
        "\nRECOVERED CORRECT (Perfect+Semantic): {recovered}/{} ({pct_recovered:.1}%)\n\n",
        records.len()
    ));
    buf.push_str("--- Per-version breakdown ---\n");
    for (ver, counts) in &by_version {
        let total_v: usize = counts.values().sum();
        let p: usize = counts.get("Perfect").copied().unwrap_or(0);
        let s: usize = counts.get("Semantic").copied().unwrap_or(0);
        let cd: usize = counts.get("CodeDiff").copied().unwrap_or(0);
        let sf: usize = counts.get("SyntaxFail").copied().unwrap_or(0);
        let ru: usize = counts.get("RecompilerUnavailable").copied().unwrap_or(0);
        let pf: usize = counts.get("PipelineFailure").copied().unwrap_or(0);
        let pct: f64 = if total_v == 0 {
            0.0
        } else {
            ((p + s) as f64 / total_v as f64) * 100.0
        };
        buf.push_str(&format!(
            "  py {ver:<5} total={total_v:>3} | Perfect={p} Semantic={s} CodeDiff={cd} SyntaxFail={sf} RecompUnavail={ru} PipelineFail={pf} | recovered={pct:.1}%\n"
        ));
    }
    let _ = fs::write(path, buf);
}

#[test]
fn roundtrip_metric_edge_cases_bands() {
    let _ = fs::create_dir_all(REPORT_DIR);
    let interpreters: BTreeMap<&'static str, PathBuf> = resolve_interpreters();
    println!("=== AVAILABLE INTERPRETERS ===");
    for (k, v) in &interpreters {
        println!("  {k}: {}", v.display());
    }
    if interpreters.is_empty() {
        eprintln!(
            "WARNING: no Python interpreters resolved via uv. Will mark all as RecompilerUnavailable."
        );
    }
    let paths: Vec<PathBuf> = collect_pyc_paths();
    assert!(
        paths.len() >= 30,
        "expected at least 30 pyc fixtures, got {}",
        paths.len()
    );
    println!("=== EVALUATING {} fixtures ===", paths.len());
    let mut records: Vec<Record> = Vec::with_capacity(paths.len());
    for (i, path) in paths.iter().enumerate() {
        let rec: Record = evaluate_one(path, &interpreters);
        println!(
            "  [{:>2}/{}] {} | stage={:?} verdict={:?}",
            i + 1,
            paths.len(),
            rec.fixture,
            rec.stage,
            rec.verdict
        );
        records.push(rec);
    }
    let tsv_path: PathBuf = PathBuf::from(REPORT_DIR).join("roundtrip_metric.tsv");
    let summary_path: PathBuf = PathBuf::from(REPORT_DIR).join("roundtrip_metric_summary.txt");
    write_tsv_report(&records, &tsv_path);
    write_summary(&records, &summary_path);
    println!("=== WROTE {} ===", tsv_path.display());
    println!("=== WROTE {} ===", summary_path.display());
    let summary_text: String = fs::read_to_string(&summary_path).unwrap_or_default();
    println!("{summary_text}");
    let pipeline_failures: usize = records
        .iter()
        .filter(|r| matches!(r.verdict, MetricVerdict::PipelineFailure))
        .count();
    assert_eq!(
        pipeline_failures, 0,
        "{pipeline_failures} pipeline failures detected (read/marshal/ast/emit broke); see TSV"
    );

    let evaluated: usize = records
        .iter()
        .filter(|r| !matches!(r.verdict, MetricVerdict::RecompilerUnavailable))
        .count();
    let recovered: usize = records
        .iter()
        .filter(|r| matches!(r.verdict, MetricVerdict::Perfect | MetricVerdict::Semantic))
        .count();
    let pct: f64 = if evaluated == 0 {
        0.0
    } else {
        (recovered as f64 / evaluated as f64) * 100.0
    };
    if evaluated == 0 {
        eprintln!(
            "skip: no Python interpreter resolved for edge_cases recompile - whole-module recovery \
             floor not enforced; pipeline integrity ({} records) still asserted",
            records.len()
        );
    } else {
        assert!(
            pct >= WHOLE_MODULE_FLOOR_PCT,
            "real whole-module recovery {pct:.1}% ({recovered}/{evaluated}) fell below honest floor \
             {WHOLE_MODULE_FLOOR_PCT:.1}%; the edge_cases monolith round-trips this fraction. \
             Ratchet WHOLE_MODULE_FLOOR_PCT up as the engine improves; never lower it. See TSV."
        );
    }
}

/// Honest floor on the monolithic `edge_cases` corpus (one `CodeDiff` anywhere fails the whole
/// module, so this rises slowly). Ratchet UP per commit as recovery improves; never down.
const WHOLE_MODULE_FLOOR_PCT: f64 = 46.0;

const TSTRING_SNIPPET: &str = "x = 1\nw = 4\n\n\ndef f():\n    return t\"{x!r:>{w}} done\"\n";

fn tstring_snippet_roundtrip(interpreter: &Path, tag: &str) {
    let scratch: PathBuf = PathBuf::from(REPORT_DIR).join("tstring_snippet");
    let _ = fs::create_dir_all(&scratch);
    let src_path: PathBuf = scratch.join(format!("tstring_{tag}.py"));
    let pyc_path: PathBuf = scratch.join(format!("tstring_{tag}.pyc"));
    fs::write(&src_path, TSTRING_SNIPPET).expect("write snippet");

    let compile_script: &str =
        "import py_compile, sys; py_compile.compile(sys.argv[1], cfile=sys.argv[2], doraise=True)";
    let status: std::process::ExitStatus = Command::new(interpreter)
        .args([
            "-c",
            compile_script,
            src_path.to_str().unwrap_or(""),
            pyc_path.to_str().unwrap_or(""),
        ])
        .status()
        .expect("compile snippet");
    assert!(status.success(), "[{tag}] snippet compile failed");

    let dec: DecompileResult = decompile_pyc(&pyc_path)
        .unwrap_or_else(|(stage, msg)| panic!("[{tag}] decompile: {stage:?} {msg}"));
    assert!(
        dec.source.contains("t\""),
        "[{tag}] decompiled snippet lost its t-string:\n{}",
        dec.source
    );

    let rt_src: PathBuf = scratch.join(format!("tstring_{tag}_rt.py"));
    fs::write(&rt_src, &dec.source).expect("write rt snippet");
    let recompiled: PathBuf = recompile_via_interpreter(interpreter, &rt_src)
        .unwrap_or_else(|e| panic!("[{tag}] recompile: {e}\nsource:\n{}", dec.source));

    let rt_bytes: Vec<u8> = fs::read(&recompiled).expect("read rt pyc");
    let rt_pyc: PycFile = read_pyc(&rt_bytes).expect("parse rt pyc");
    let rt_code: CodeObject = match rt_pyc.code {
        Object::Code(boxed) => *boxed,
        other => panic!("[{tag}] rt top-level not code: {other:?}"),
    };
    let verdict: Verdict = semantic_equiv(&dec.original_code, &rt_code, dec.marshal_version);
    assert!(
        matches!(verdict, Verdict::Perfect | Verdict::Semantic),
        "[{tag}] t-string snippet not equivalent: {verdict:?}\nsource:\n{}",
        dec.source
    );
}

#[test]
fn roundtrip_metric_tstring_snippet() {
    let interpreters: BTreeMap<&'static str, PathBuf> = resolve_interpreters();
    let Some(py314): Option<&PathBuf> = interpreters.get("3.14") else {
        eprintln!("skip roundtrip_metric_tstring_snippet: no 3.14 interpreter");
        return;
    };
    tstring_snippet_roundtrip(py314, "3.14");
    if let Some(py315) = interpreters.get("3.15") {
        tstring_snippet_roundtrip(py315, "3.15");
    } else {
        eprintln!("note: 3.15 interpreter unavailable; t-string snippet verified on 3.14 only");
    }
}
