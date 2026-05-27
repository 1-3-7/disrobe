#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_const_for_fn,
    clippy::items_after_statements,
    clippy::too_many_lines,
    clippy::default_trait_access,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::match_same_arms,
    clippy::map_unwrap_or,
    clippy::format_push_string,
    clippy::or_fun_call,
    clippy::cast_precision_loss
)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use disrobe_pass_py_decompile::ast::{AstBuilder, AstModule, DefaultAstBuilder};
use disrobe_pass_py_decompile::bytecode::version::PyVersion as DecompileVersion;
use disrobe_pass_py_decompile::codegen::{CodeEmitter, DefaultEmitter};
use disrobe_pass_py_decompile::frame_tree::{FrameTree, builder_for};
use disrobe_py_marshal::{CodeObject, Object, PyVersion as MarshalVersion, PycFile, read_pyc};

const PYCACHE_DIR: &str = "../../corpus/python/decompile/playground/__pycache__";
const STANDALONE_PYC_2_7: &str = "../../corpus/python/decompile/playground/edge_cases_2_7.pyc";
const REPORT_DIR: &str = "../../target/v0.8-w6";

#[derive(Debug, Clone, PartialEq, Eq)]
enum Stage {
    Read,
    UnwrapCode,
    BuildFrameTree,
    BuildAst,
    EmitSource,
    EmitNonEmpty,
}

#[derive(Debug, Clone)]
struct Outcome {
    band: String,
    compiler: String,
    pyc_bytes: u64,
    reached: Stage,
    error: Option<String>,
    recovered_loc: u32,
    first_emitted_line: String,
}

fn classify_filename(name: &str) -> Option<(String, String)> {
    let (stem, _ext): (&str, &str) = name.rsplit_once('.')?;
    if let Some((band, suffix)) = stem.split_once(".cpython-") {
        return Some((band.to_owned(), format!("cpython-{suffix}")));
    }
    if let Some((band, suffix)) = stem.split_once(".pypy") {
        return Some((band.to_owned(), format!("pypy{suffix}")));
    }
    Some((stem.to_owned(), "self".to_owned()))
}

fn marshal_to_decompile(version: MarshalVersion) -> DecompileVersion {
    match (version.major, version.minor) {
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
        _ => DecompileVersion::V3_14,
    }
}

fn classify_outcome_for(path: &Path, band: String, compiler: String) -> Outcome {
    let pyc_bytes: u64 = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let bytes: Vec<u8> = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            return Outcome {
                band,
                compiler,
                pyc_bytes,
                reached: Stage::Read,
                error: Some(format!("fs::read failed: {e}")),
                recovered_loc: 0,
                first_emitted_line: String::new(),
            };
        }
    };
    let pyc: PycFile = match read_pyc(&bytes) {
        Ok(p) => p,
        Err(e) => {
            return Outcome {
                band,
                compiler,
                pyc_bytes,
                reached: Stage::Read,
                error: Some(format!("read_pyc failed: {e}")),
                recovered_loc: 0,
                first_emitted_line: String::new(),
            };
        }
    };
    let code: CodeObject = match pyc.code {
        Object::Code(boxed) => *boxed,
        other => {
            return Outcome {
                band,
                compiler,
                pyc_bytes,
                reached: Stage::UnwrapCode,
                error: Some(format!("top-level object is not Code: {other:?}")),
                recovered_loc: 0,
                first_emitted_line: String::new(),
            };
        }
    };

    let decompile_version: DecompileVersion = marshal_to_decompile(pyc.header.version);
    let frame_tree: FrameTree =
        match builder_for(pyc.header.version).build(&code, pyc.header.version) {
            Ok(t) => t,
            Err(e) => {
                return Outcome {
                    band,
                    compiler,
                    pyc_bytes,
                    reached: Stage::BuildFrameTree,
                    error: Some(format!("frame_tree::build failed: {e:?}")),
                    recovered_loc: 0,
                    first_emitted_line: String::new(),
                };
            }
        };

    let module: AstModule =
        match DefaultAstBuilder::new().build_module(&code, &frame_tree, &decompile_version) {
            Ok(m) => m,
            Err(e) => {
                return Outcome {
                    band,
                    compiler,
                    pyc_bytes,
                    reached: Stage::BuildAst,
                    error: Some(format!("AstBuilder::build_module failed: {e:?}")),
                    recovered_loc: 0,
                    first_emitted_line: String::new(),
                };
            }
        };

    let emitter: DefaultEmitter = DefaultEmitter::new();
    let text: String = emitter.emit_module(&module, &decompile_version);
    let recovered_loc: u32 = u32::try_from(text.lines().count()).unwrap_or(u32::MAX);
    let first_line: String = text
        .lines()
        .next()
        .unwrap_or("")
        .chars()
        .take(120)
        .collect();

    let stage: Stage = if recovered_loc > 0 {
        Stage::EmitNonEmpty
    } else {
        Stage::EmitSource
    };

    Outcome {
        band,
        compiler,
        pyc_bytes,
        reached: stage,
        error: None,
        recovered_loc,
        first_emitted_line: first_line,
    }
}

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

fn write_tsv_report(outcomes: &[Outcome]) {
    let _ = fs::create_dir_all(REPORT_DIR);
    let tsv_path: PathBuf = PathBuf::from(REPORT_DIR).join("verification_matrix.tsv");
    let mut buf: String = String::with_capacity(4096);
    buf.push_str(
        "band\tcompiler\tpyc_bytes\treached_stage\trecovered_loc\tfirst_emitted_line\terror\n",
    );
    for o in outcomes {
        let stage_str: &str = match o.reached {
            Stage::Read => "Read",
            Stage::UnwrapCode => "UnwrapCode",
            Stage::BuildFrameTree => "BuildFrameTree",
            Stage::BuildAst => "BuildAst",
            Stage::EmitSource => "EmitSource",
            Stage::EmitNonEmpty => "EmitNonEmpty",
        };
        let err_str: &str = o.error.as_deref().unwrap_or("");
        buf.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            o.band,
            o.compiler,
            o.pyc_bytes,
            stage_str,
            o.recovered_loc,
            o.first_emitted_line.replace('\t', "  "),
            err_str.replace('\t', "  ").replace('\n', " | "),
        ));
    }
    let _ = fs::write(&tsv_path, buf);
}

#[test]
fn megafile_roundtrip_full_matrix() {
    let pyc_paths: Vec<PathBuf> = collect_pyc_paths();
    assert!(
        pyc_paths.len() >= 30,
        "expected at least 30 pyc fixtures, got {} (run py_compile across all bands first)",
        pyc_paths.len()
    );

    let mut outcomes: Vec<Outcome> = Vec::with_capacity(pyc_paths.len());
    for path in &pyc_paths {
        let fname: String = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_owned();
        let (band, compiler): (String, String) =
            classify_filename(&fname).unwrap_or((fname.clone(), "unknown".to_owned()));
        let outcome: Outcome = classify_outcome_for(path, band, compiler);
        outcomes.push(outcome);
    }

    write_tsv_report(&outcomes);

    let mut stage_counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for o in &outcomes {
        let key: &'static str = match o.reached {
            Stage::Read => "Read",
            Stage::UnwrapCode => "UnwrapCode",
            Stage::BuildFrameTree => "BuildFrameTree",
            Stage::BuildAst => "BuildAst",
            Stage::EmitSource => "EmitSource",
            Stage::EmitNonEmpty => "EmitNonEmpty",
        };
        *stage_counts.entry(key).or_insert(0) += 1;
    }
    println!("=== megafile_roundtrip_full_matrix: stage distribution ===");
    for (k, v) in &stage_counts {
        println!("  {k}: {v}");
    }

    let read_failures: usize = outcomes
        .iter()
        .filter(|o| matches!(o.reached, Stage::Read))
        .count();
    assert_eq!(
        read_failures,
        0,
        "py-marshal failed to parse {read_failures}/{} pyc files: {:?}",
        outcomes.len(),
        outcomes
            .iter()
            .filter(|o| matches!(o.reached, Stage::Read))
            .map(|o| format!(
                "{}/{}: {}",
                o.band,
                o.compiler,
                o.error.clone().unwrap_or_default()
            ))
            .collect::<Vec<_>>()
    );

    let emit_nonempty: usize = outcomes
        .iter()
        .filter(|o| matches!(o.reached, Stage::EmitNonEmpty))
        .count();
    let read_ok: usize = outcomes.len() - read_failures;
    let pct: f64 = (emit_nonempty as f64 / read_ok as f64) * 100.0;
    println!("EmitNonEmpty: {emit_nonempty}/{read_ok} ({pct:.1}%) of readable pycs");
    for o in &outcomes {
        if let Some(err) = &o.error {
            println!(
                "  {} / {}: stage={:?} err={}",
                o.band, o.compiler, o.reached, err
            );
        }
    }
}

#[test]
fn megafile_roundtrip_per_version_coverage() {
    let pyc_paths: Vec<PathBuf> = collect_pyc_paths();
    let mut by_compiler: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for path in &pyc_paths {
        let fname: String = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_owned();
        if let Some((band, compiler)) = classify_filename(&fname) {
            by_compiler.entry(compiler).or_default().push(band);
        }
    }
    let expected_compilers: &[&str] = &[
        "cpython-36",
        "cpython-37",
        "cpython-38",
        "cpython-39",
        "cpython-310",
        "cpython-311",
        "cpython-312",
        "cpython-313",
        "cpython-314",
        "pypy310",
        "self",
    ];
    for compiler in expected_compilers {
        assert!(
            by_compiler.contains_key(*compiler),
            "missing pyc fixture for compiler {compiler}; have: {:?}",
            by_compiler.keys().collect::<Vec<_>>()
        );
    }
}
