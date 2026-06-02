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

/// Honest floors for the pycdc-INDEPENDENT correctness oracle. `recompile_equiv` proves disrobe's
/// recovered source recompiles to value-key-identical bytecode against the original `.pyc` on a real
/// interpreter (3.6+, the only Windows-available builds); `source_token_match` proves token equivalence
/// against the ORIGINAL source for versions with no interpreter (1.0-3.5). Both ratchet UP, never down.
/// `source_token_match` rose 92 -> 94 after the bare-tuple-subscript paren-suppression fix
/// (`emit_subscript_slice` now flattens a folded `LOAD_CONST (tuple)` index the same way it already
/// flattened a `BUILD_TUPLE` index, so `testme[40, 41, 42]` is no longer mis-rendered `testme[(40,41,42)]`
/// on 2.5 where the compiler folds the index to a const tuple): `test_del.2.5` + `test_slices.2.5` flipped
/// to `SourceTokenMatch`. Proven correct = 161/191 (async_for.3.7 now RecompileEquiv - pre-3.8 deep
/// async-for nest recovered faithfully, see below).
///
/// === STILL-NOT-PROVEN LEDGER (30 fixtures; DOCUMENTATION, not an allowlist - the oracle still measures
/// these as RecompileDiff/SourceTokenDiff and the floors stay below the measured pass-count) ===
/// Each is classified REAL_BUG / LOST_LITERAL / STALE_SOURCE. No fixture here is silently marked proven.
///
/// REAL_BUG (0): async_for.3.7 is now proven RecompileEquiv. All four functions of the pathological pre-3.8
///   nest (async-for inside a plain for inside an async-for, with an inner `if x==3: ...; break` and
///   try/except siblings) recover correctly. Three fixes, each version-gated to pre-3.11 so the construct and
///   megafile gates are untouched: (1) `legacy_async_for_enclosed_by_loop` defers a `find_legacy_async_for`
///   region nested inside a synchronous `for`/`while` to `find_loop`, so the enclosing loop structures first
///   and recurses into its body (was: async-for hoisted out, the for body closed with a phantom `pass`);
///   (2) `resolve_fused_extended_arg_target` rounds a pre-3.10 jump target that lands on a swallowed
///   `EXTENDED_ARG` prefix byte up to the fused op, so the `if x==3` guard jump resolves (was: target byte
///   absent from `offsets`, the cond-jump lost, the `if` flattened to a bare statement); (3)
///   `append_pre311_break_loop` re-materializes a trailing `BREAK_LOOP` (which decodes to `Nop`) as
///   `Stmt::Break` in a non-empty branch body (was: the `break` silently dropped).
///
/// STALE_SOURCE (4) - vendored `.py` is a LATER revision than the `.pyc`; disrobe recovers the `.pyc`
/// faithfully, corroborated by the pycdc golden being byte-for-byte what disrobe emits:
///   test_global.2.2, test_global.2.5 - module-level bytecode is `STORE_GLOBAL i`/`STORE_GLOBAL j` (not
///     `STORE_NAME`), which CPython only emits when the source carried a module-level `global i, j`. The
///     vendored `.py` lacks it; disrobe recovers it (a WIN over the golden, which also drops it). Residual
///     surface diff is the `'''`-docstring rendered as an escaped one-line `"..."` (LOST_LITERAL).
///   test_functions_py3.3.0, test_functions_py3.3.4 - the `.pyc` holds 13 defs (x0..x7a subset); the
///     vendored `.py` holds 21 (x0..x7d). disrobe recovers exactly the golden's 13 defs with correct
///     kw-only-default args. The extra 8 source defs were never compiled into this `.pyc`.
///
/// LOST_LITERAL (26) - value-equivalent surface that the marshalled bytecode cannot carry; disrobe's form
/// recompiles identically and matches the pycdc golden where one exists. Subclassed:
///   nan-const-fold (2): nan_inf.2.7, nan_inf.3.8 - a,b are the `nan` const (`inf*0`); no Python float
///     literal folds to nan, so the only faithful rendering is `float('-nan')`, which recompiles to a CALL
///     not the original folded `LOAD_CONST` (hence RecompileDiff). disrobe DOES recover c,d's `inf` via the
///     folding `1e309` literal (a WIN over the golden's non-round-tripping `float('inf')`).
///   redundant-parens (1): op_precedence.3.5 - source `a / ((b ** c) * d)`; `**` already binds tighter than
///     `*`, so disrobe's `a / (b ** c * d)` is identical bytecode and matches the golden. Source parens lost.
///   print-paren (5): test_class.{1.5,2.2,2.5}, test_class_method.{2.2,2.5} - source `print('x')` vs
///     disrobe `print "x"`; in Py2 `print(expr)` is the print statement over a parenthesized expr, identical
///     `PRINT_ITEM` bytecode. Matches the golden's `print 'x'`.
///   print-comma-merge (5): test_yield.{2.2,2.5}, test_misc.{1.5,2.2,2.5} - consecutive `print a,` / `print
///     b` emit the same `PRINT_ITEM` run as a single `print a, b`; disrobe merges (matches the golden).
///   hex/L-suffix (4): test_integers.{1.5,2.2,2.5}, test_integers_py3.3.5 - source `-0x80000000L` vs disrobe
///     `-2147483648`; the marshalled const holds only the value, not the hex/`L` surface. disrobe is more
///     correct than the golden's mis-tokenized `- 0 x80000000L`.
///   u/b-prefix + quote-style (4): unicode.2.6, unicode_future.{2.6,3.3}, unicode_py3.3.3 - `b'Bytes'` is the
///     identical `str` const as `'Bytes'` in Py2.6, and `unicode_literals` makes the `u` prefix redundant;
///     disrobe matches the golden, diffing from source only by the irrecoverable prefix and quote choice.
///   unpack-target-parens (5): unpack_assign.{1.0,1.5,2.2,2.5,3.0} - `UNPACK_SEQUENCE` does not record
///     whether the source wrote `a, b, c = x` or `(a, b, c) = x`; disrobe emits the parenthesized form, the
///     same canonical form as the golden (`( a , b , c ) = x`). Identical bytecode either way.
const RECOMPILE_EQUIV_FLOOR: usize = 67;
const SOURCE_TOKEN_FLOOR: usize = 94;
const PROVEN_CORRECT_FLOOR: usize = 140;

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

fn find_interpreter(alias: &str) -> Option<PathBuf> {
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

    assert_eq!(decode_failed, 0, "decode regressions in recompile oracle");

    let proven_correct: usize = recompile_equiv + source_match;
    assert!(
        proven_correct >= PROVEN_CORRECT_FLOOR,
        "proven-correct regressed: {proven_correct} < floor {PROVEN_CORRECT_FLOOR}"
    );
    assert!(
        source_match >= SOURCE_TOKEN_FLOOR,
        "source-token match regressed: {source_match} < floor {SOURCE_TOKEN_FLOOR}"
    );

    let recompiles_attempted: usize = recompile_equiv + recompile_diff;
    if recompiles_attempted >= RECOMPILE_EQUIV_FLOOR {
        assert!(
            recompile_equiv >= RECOMPILE_EQUIV_FLOOR,
            "recompile-equivalence regressed: {recompile_equiv} < floor {RECOMPILE_EQUIV_FLOOR}"
        );
    } else {
        eprintln!(
            "skip: legacy interpreter zoo absent ({recompiles_attempted} recompiles attempted < {RECOMPILE_EQUIV_FLOOR}); \
             recompile-equivalence floor not enforced - {proven_correct} proven correct via token-match"
        );
    }
}
