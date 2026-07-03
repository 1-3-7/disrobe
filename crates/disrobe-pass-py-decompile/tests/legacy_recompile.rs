#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::items_after_statements,
    clippy::too_many_lines,
    clippy::cast_precision_loss,
    clippy::doc_markdown
)]

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use common::tokenize::{render, tokenize};

use disrobe_pass_py_decompile::bytecode::version::PyVersion as DecompileVersion;
use disrobe_pass_py_decompile::engine::{build_real_source, marshal_to_decompile};
use disrobe_pass_py_decompile::roundtrip::{Verdict, semantic_equiv};
use disrobe_py_marshal::{CodeObject, Object, PyVersion as MarshalVersion, PycFile, read_pyc};

const COMPILED_DIR: &str = "../../corpus/python/decompile/legacy/compiled";
const SOURCE_DIR: &str = "../../corpus/python/decompile/legacy/source";
const SCRATCH_DIR: &str = "../../target/py-legacy-recompile";

const PROVEN_CORRECT_FLOOR: usize = 150;
const SOURCE_TOKEN_FLOOR: usize = 86;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    RecompileEquiv,
    RecompileDiff,
    SourceTokenMatch,
    SourceTokenDiff,
    NoInterpreterNoSource,
    DecodeFailed,
    NoSource,
}

#[derive(Debug, Clone)]
struct Row {
    fixture: String,
    version: String,
    outcome: Outcome,
    detail: String,
}

fn interpreter_hidden(alias: &str) -> bool {
    std::env::var("DISROBE_TEST_HIDE_PY").is_ok_and(|hidden: String| {
        hidden
            .split(',')
            .map(str::trim)
            .any(|entry: &str| entry == alias)
    })
}

fn find_interpreter(alias: &str) -> Option<PathBuf> {
    if interpreter_hidden(alias) {
        return None;
    }
    let output: Option<std::process::Output> = Command::new("uv")
        .args(["python", "find", alias])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok();
    if let Some(out) = output
        && out.status.success()
    {
        let raw: String = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        let path: PathBuf = PathBuf::from(raw);
        if path.is_file() {
            return Some(path);
        }
    }
    let tag: String = alias.replace('.', "");
    if cfg!(windows) {
        let base: &str = "C:/Users/-/AppData/Local/Programs/Python";
        let candidates: [PathBuf; 3] = [
            PathBuf::from(format!("{base}/Python{tag}/python.exe")),
            PathBuf::from(format!("C:/Python{tag}/python.exe")),
            PathBuf::from(format!("C:/Python{tag}-32/python.exe")),
        ];
        return candidates.into_iter().find(|p: &PathBuf| p.is_file());
    }
    let candidates: [PathBuf; 3] = [
        PathBuf::from(format!("/usr/bin/python{alias}")),
        PathBuf::from(format!("/usr/local/bin/python{alias}")),
        PathBuf::from(format!("/opt/homebrew/bin/python{tag}")),
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
    let bytes: Vec<u8> = fs::read(pyc_path).map_err(|e: std::io::Error| format!("read: {e}"))?;
    let pyc: PycFile =
        read_pyc(&bytes).map_err(|e: disrobe_py_marshal::Error| format!("read_pyc: {e}"))?;
    let ver: MarshalVersion = pyc.header.version;
    match pyc.code {
        Object::Code(boxed) => Ok((*boxed, ver)),
        other => Err(format!("top-level not code: {other:?}")),
    }
}

fn fixture_stem(pyc_name: &str) -> String {
    let no_ext: &str = pyc_name.strip_suffix(".pyc").unwrap_or(pyc_name);
    let parts: Vec<&str> = no_ext.rsplitn(3, '.').collect();
    if parts.len() == 3 {
        parts[2].to_owned()
    } else {
        no_ext.to_owned()
    }
}

fn source_path_for(stem: &str) -> Option<PathBuf> {
    let direct: PathBuf = PathBuf::from(SOURCE_DIR).join(format!("{stem}.py"));
    if direct.is_file() {
        return Some(direct);
    }
    let demoted: &str = stem.strip_suffix("_py3").unwrap_or(stem);
    let fallback: PathBuf = PathBuf::from(SOURCE_DIR).join(format!("{demoted}.py"));
    if fallback.is_file() {
        return Some(fallback);
    }
    None
}

fn normalize(s: &str) -> String {
    s.replace("\r\n", "\n").trim_end().to_owned()
}

fn source_token_equiv(recovered: &str, source: &str) -> bool {
    let recovered_lf: String = recovered.replace("\r\n", "\n");
    let source_lf: String = source.replace("\r\n", "\n");
    let (Ok(a), Ok(b)) = (tokenize(&recovered_lf), tokenize(&source_lf)) else {
        return false;
    };
    normalize(&render(&a)) == normalize(&render(&b))
}

#[test]
fn legacy_recompile_correctness_oracle() {
    let compiled: PathBuf = PathBuf::from(COMPILED_DIR);
    assert!(
        compiled.is_dir(),
        "vendored legacy corpus missing at {}",
        compiled.display()
    );
    assert!(
        PathBuf::from(SOURCE_DIR).is_dir(),
        "vendored legacy source missing at {SOURCE_DIR}"
    );
    let scratch: PathBuf = PathBuf::from(SCRATCH_DIR);
    let _ = fs::create_dir_all(&scratch);

    let mut files: Vec<PathBuf> = fs::read_dir(&compiled)
        .expect("read compiled dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("pyc"))
        .collect();
    files.sort();

    let mut interpreters: BTreeMap<String, Option<PathBuf>> = BTreeMap::new();
    let mut rows: Vec<Row> = Vec::new();

    for pyc in &files {
        let name: String = pyc.file_name().unwrap().to_string_lossy().into_owned();
        let stem: String = fixture_stem(&name);
        let (code, ver): (CodeObject, MarshalVersion) = match read_code(pyc) {
            Ok(c) => c,
            Err(e) => {
                rows.push(Row {
                    fixture: name.clone(),
                    version: "?".to_owned(),
                    outcome: Outcome::DecodeFailed,
                    detail: e,
                });
                continue;
            }
        };
        let vtag: String = format!("{}.{}", ver.major, ver.minor);
        let dver: DecompileVersion = match marshal_to_decompile(ver) {
            Ok(v) => v,
            Err(e) => {
                rows.push(Row {
                    fixture: name.clone(),
                    version: vtag,
                    outcome: Outcome::DecodeFailed,
                    detail: format!("version map {e:?}"),
                });
                continue;
            }
        };
        let recovered: String = match build_real_source(&code, &dver, ver) {
            Ok(s) => s,
            Err(e) => {
                rows.push(Row {
                    fixture: name.clone(),
                    version: vtag,
                    outcome: Outcome::DecodeFailed,
                    detail: e.to_string(),
                });
                continue;
            }
        };
        let Some(source_path): Option<PathBuf> = source_path_for(&stem) else {
            rows.push(Row {
                fixture: name.clone(),
                version: vtag,
                outcome: Outcome::NoSource,
                detail: format!("no source for stem {stem}"),
            });
            continue;
        };

        let interpreter: Option<PathBuf> = interpreters
            .entry(vtag.clone())
            .or_insert_with(|| find_interpreter(&vtag))
            .clone();

        if let Some(interp) = interpreter.as_ref() {
            let recovered_path: PathBuf = scratch.join(format!("{stem}.{vtag}.rec.py"));
            let recompiled_pyc: PathBuf = scratch.join(format!("{stem}.{vtag}.rec.pyc"));
            if fs::write(&recovered_path, &recovered).is_ok()
                && compile_source(interp, &recovered_path, &recompiled_pyc).is_ok()
                && let Ok((rec_code, _)) = read_code(&recompiled_pyc)
            {
                let verdict: Verdict = semantic_equiv(&code, &rec_code, ver);
                let (outcome, detail): (Outcome, String) = match verdict {
                    Verdict::Perfect | Verdict::Semantic => {
                        (Outcome::RecompileEquiv, String::new())
                    }
                    Verdict::CodeDiff(d) => (
                        Outcome::RecompileDiff,
                        format!(
                            "{}@{}: {} vs {}",
                            d.qualname, d.first_diff_offset, d.original_op, d.recompiled_op
                        ),
                    ),
                };
                rows.push(Row {
                    fixture: name.clone(),
                    version: vtag,
                    outcome,
                    detail,
                });
                continue;
            }
        }

        let Ok(source): Result<String, _> = fs::read_to_string(&source_path) else {
            rows.push(Row {
                fixture: name.clone(),
                version: vtag,
                outcome: Outcome::NoSource,
                detail: "source unreadable".to_owned(),
            });
            continue;
        };
        let (outcome, detail): (Outcome, String) = if source_token_equiv(&recovered, &source) {
            (Outcome::SourceTokenMatch, String::new())
        } else if interpreter.is_none() {
            (Outcome::SourceTokenDiff, "token diff vs source".to_owned())
        } else {
            (
                Outcome::NoInterpreterNoSource,
                "recompile-fail + token-diff".to_owned(),
            )
        };
        rows.push(Row {
            fixture: name,
            version: vtag,
            outcome,
            detail,
        });
    }

    let count = |o: Outcome| -> usize { rows.iter().filter(|r| r.outcome == o).count() };
    let recompile_equiv: usize = count(Outcome::RecompileEquiv);
    let source_match: usize = count(Outcome::SourceTokenMatch);
    let recompile_diff: usize = count(Outcome::RecompileDiff);
    let source_diff: usize = count(Outcome::SourceTokenDiff);
    let no_interp_no_src: usize = count(Outcome::NoInterpreterNoSource);
    let decode_failed: usize = count(Outcome::DecodeFailed);
    let no_source: usize = count(Outcome::NoSource);

    println!("=== LEGACY RECOMPILE-EQUIVALENCE ORACLE (pycdc-independent) ===");
    println!("  recompile_equiv     = {recompile_equiv}");
    println!("  source_token_match  = {source_match}");
    println!("  recompile_diff      = {recompile_diff}");
    println!("  source_token_diff   = {source_diff}");
    println!("  recompile+token fail= {no_interp_no_src}");
    println!("  decode_failed       = {decode_failed}");
    println!("  no_source           = {no_source}");
    println!(
        "  proven correct      = {}/{}",
        recompile_equiv + source_match,
        files.len()
    );

    let mut per_version: BTreeMap<String, [usize; 3]> = BTreeMap::new();
    for r in &rows {
        let slot: &mut [usize; 3] = per_version.entry(r.version.clone()).or_insert([0, 0, 0]);
        slot[0] += 1;
        match r.outcome {
            Outcome::RecompileEquiv => slot[1] += 1,
            Outcome::SourceTokenMatch => slot[2] += 1,
            _ => {}
        }
    }
    println!("  --- per-version (total / recompile-equiv / token-match) ---");
    for (v, s) in &per_version {
        println!(
            "    {v:<5} total={} recompile_equiv={} token_match={}",
            s[0], s[1], s[2]
        );
    }

    for r in &rows {
        if matches!(
            r.outcome,
            Outcome::RecompileDiff
                | Outcome::SourceTokenDiff
                | Outcome::NoInterpreterNoSource
                | Outcome::DecodeFailed
        ) {
            println!(
                "  - [{:?}] {} ({}): {}",
                r.outcome, r.fixture, r.version, r.detail
            );
        }
    }

    let recompile_eligible: usize = rows
        .iter()
        .filter(|r| {
            interpreters
                .get(&r.version)
                .is_some_and(|slot: &Option<PathBuf>| slot.is_some())
        })
        .count();
    println!("  recompile_eligible  = {recompile_eligible} (interpreter present for this version)");

    assert_eq!(decode_failed, 0, "decode regressions in recompile oracle");

    let proven_correct: usize = recompile_equiv + source_match;
    assert!(
        proven_correct >= PROVEN_CORRECT_FLOOR,
        "proven-correct regressed: {proven_correct} < floor {PROVEN_CORRECT_FLOOR} \
         (platform-stable: recompile-equiv union token-match, minimum is the pure token-match count)"
    );
    assert!(
        source_match >= SOURCE_TOKEN_FLOOR,
        "source-token match regressed: {source_match} < floor {SOURCE_TOKEN_FLOOR}"
    );

    assert_eq!(
        recompile_diff, 0,
        "recompile-equivalence regressed: {recompile_diff} fixture(s) recompiled to a \
         non-equivalent code object"
    );
    assert_eq!(
        no_interp_no_src, 0,
        "recovery regressed: {no_interp_no_src} fixture(s) with a present interpreter neither \
         recompiled nor token-matched their source"
    );

    if recompile_eligible == 0 {
        eprintln!(
            "skip: no legacy interpreter present; recompile-equivalence ratchet not enforced - \
             {proven_correct} proven correct via token-match"
        );
    } else {
        assert!(
            recompile_equiv >= recompile_eligible,
            "recompile-equivalence regressed: only {recompile_equiv} of {recompile_eligible} \
             fixtures with a present interpreter recompiled to an equivalent code object"
        );
    }
}
