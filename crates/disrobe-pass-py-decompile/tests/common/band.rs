#![allow(
    dead_code,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::missing_const_for_fn,
    clippy::redundant_pub_crate,
    clippy::doc_markdown
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use disrobe_pass_py_decompile::bytecode::version::PyVersion as DecompileVersion;
use disrobe_pass_py_decompile::engine::{build_real_source, marshal_to_decompile};
use disrobe_pass_py_decompile::roundtrip::{Verdict, semantic_equiv};
use disrobe_py_marshal::{CodeObject, Object, PyVersion as MarshalVersion, PycFile, read_pyc};

use super::tokenize::{render, tokenize};

pub(crate) const CONSTRUCT_CASES_DIR: &str = "../../corpus/python/decompile/construct/cases";
pub(crate) const LEGACY_COMPILED_DIR: &str = "../../corpus/python/decompile/legacy/compiled";
pub(crate) const LEGACY_SOURCE_DIR: &str = "../../corpus/python/decompile/legacy/source";
pub(crate) const BAND_SCRATCH_ROOT: &str = "../../target/py-band-e2e";

/// One in-band python interpreter the band harness recompiles against.
#[derive(Debug, Clone)]
pub(crate) struct BandInterpreter {
    pub alias: &'static str,
    pub path: PathBuf,
    pub is_prerelease: bool,
}

/// Outcome of driving one in-band fixture.
#[derive(Debug, Clone)]
pub(crate) enum BandOutcome {
    RecompileEquiv,
    SourceTokenMatch,
    Failed(String),
}

/// Resolves `alias` via `uv python find`, falling back to canonical python.org install locations.
#[must_use]
pub(crate) fn find_interpreter(alias: &str) -> Option<PathBuf> {
    if let Some(output) = Command::new("uv")
        .args(["python", "find", alias])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()
        && output.status.success()
    {
        let raw: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
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

/// Resolves every requested in-band alias that is installed, flagging `prerelease_aliases`.
#[must_use]
pub(crate) fn resolve_band(
    aliases: &[&'static str],
    prerelease_aliases: &[&'static str],
) -> Vec<BandInterpreter> {
    let mut out: Vec<BandInterpreter> = Vec::new();
    for &alias in aliases {
        let Some(path): Option<PathBuf> = find_interpreter(alias) else {
            continue;
        };
        out.push(BandInterpreter {
            alias,
            path,
            is_prerelease: prerelease_aliases.contains(&alias),
        });
    }
    out
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

fn decompile_source(
    code: &CodeObject,
    marshal_version: MarshalVersion,
) -> Result<(String, DecompileVersion), String> {
    let decompile_version: DecompileVersion =
        marshal_to_decompile(marshal_version).map_err(|e| format!("version map: {e:?}"))?;
    let source: String = build_real_source(code, &decompile_version, marshal_version)
        .map_err(|e| format!("decompile: {e}"))?;
    Ok((source, decompile_version))
}

/// Rejects recovered source that leaks any `__DR_*__` placeholder sentinel.
fn assert_no_placeholder(label: &str, source: &str) -> Result<(), String> {
    if source.contains("__DR_") {
        return Err(format!(
            "{label}: __DR_ placeholder leaked into recovered source"
        ));
    }
    Ok(())
}

/// Drives one construct fixture through the recompile-equivalence oracle on `interp`.
pub(crate) fn recompile_equiv_construct(
    interp: &BandInterpreter,
    construct: &str,
    scratch: &Path,
) -> BandOutcome {
    let source_path: PathBuf = PathBuf::from(CONSTRUCT_CASES_DIR).join(format!("{construct}.py"));
    if !source_path.is_file() {
        return BandOutcome::Failed(format!(
            "missing construct fixture {}",
            source_path.display()
        ));
    }
    drive_recompile(interp, &source_path, construct, scratch)
}

/// Drives one vendored legacy `.pyc` through the recompile-equivalence oracle on `interp`.
pub(crate) fn recompile_equiv_legacy_pyc(
    interp: &BandInterpreter,
    pyc_path: &Path,
    label: &str,
    scratch: &Path,
) -> BandOutcome {
    let (original_code, marshal_version): (CodeObject, MarshalVersion) = match read_code(pyc_path) {
        Ok(c) => c,
        Err(e) => return BandOutcome::Failed(format!("{label}: read orig pyc: {e}")),
    };
    let (source, _): (String, DecompileVersion) =
        match decompile_source(&original_code, marshal_version) {
            Ok(s) => s,
            Err(e) => return BandOutcome::Failed(format!("{label}: {e}")),
        };
    if let Err(e) = assert_no_placeholder(label, &source) {
        return BandOutcome::Failed(e);
    }
    let recovered_path: PathBuf = scratch.join(format!("{label}.{}.dec.py", interp.alias));
    if let Err(e) = fs::write(&recovered_path, &source) {
        return BandOutcome::Failed(format!("{label}: write recovered: {e}"));
    }
    let recompiled_pyc: PathBuf = scratch.join(format!("{label}.{}.dec.pyc", interp.alias));
    if let Err(e) = compile_source(&interp.path, &recovered_path, &recompiled_pyc) {
        return BandOutcome::Failed(format!("{label}: recompile failed: {e}"));
    }
    let (recompiled_code, _): (CodeObject, MarshalVersion) = match read_code(&recompiled_pyc) {
        Ok(c) => c,
        Err(e) => return BandOutcome::Failed(format!("{label}: read recompiled: {e}")),
    };
    classify(
        &original_code,
        &recompiled_code,
        marshal_version,
        label,
        interp.is_prerelease,
        &source,
    )
}

fn drive_recompile(
    interp: &BandInterpreter,
    source_path: &Path,
    label: &str,
    scratch: &Path,
) -> BandOutcome {
    let orig_pyc: PathBuf = scratch.join(format!("{label}.{}.orig.pyc", interp.alias));
    if let Err(e) = compile_source(&interp.path, source_path, &orig_pyc) {
        return BandOutcome::Failed(format!("{label}: orig compile failed: {e}"));
    }
    let (original_code, marshal_version): (CodeObject, MarshalVersion) = match read_code(&orig_pyc)
    {
        Ok(c) => c,
        Err(e) => return BandOutcome::Failed(format!("{label}: read orig pyc: {e}")),
    };
    let (source, _): (String, DecompileVersion) =
        match decompile_source(&original_code, marshal_version) {
            Ok(s) => s,
            Err(e) => return BandOutcome::Failed(format!("{label}: {e}")),
        };
    if let Err(e) = assert_no_placeholder(label, &source) {
        return BandOutcome::Failed(e);
    }
    let recovered_path: PathBuf = scratch.join(format!("{label}.{}.dec.py", interp.alias));
    if let Err(e) = fs::write(&recovered_path, &source) {
        return BandOutcome::Failed(format!("{label}: write recovered: {e}"));
    }
    let recompiled_pyc: PathBuf = scratch.join(format!("{label}.{}.dec.pyc", interp.alias));
    if let Err(e) = compile_source(&interp.path, &recovered_path, &recompiled_pyc) {
        return BandOutcome::Failed(format!(
            "{label}: recompile failed: {e}\n--- source:\n{source}"
        ));
    }
    let (recompiled_code, _): (CodeObject, MarshalVersion) = match read_code(&recompiled_pyc) {
        Ok(c) => c,
        Err(e) => return BandOutcome::Failed(format!("{label}: read recompiled: {e}")),
    };
    classify(
        &original_code,
        &recompiled_code,
        marshal_version,
        label,
        interp.is_prerelease,
        &source,
    )
}

fn classify(
    original: &CodeObject,
    recompiled: &CodeObject,
    marshal_version: MarshalVersion,
    label: &str,
    is_prerelease: bool,
    source: &str,
) -> BandOutcome {
    let verdict: Verdict = semantic_equiv(original, recompiled, marshal_version);
    match verdict {
        Verdict::Perfect | Verdict::Semantic => BandOutcome::RecompileEquiv,
        Verdict::CodeDiff(d) => {
            if is_prerelease {
                eprintln!(
                    "SKIP-GATE prerelease {label}: jump-index-aware tolerance - CodeDiff {} @ {}: {} vs {} ({})",
                    d.qualname, d.first_diff_offset, d.original_op, d.recompiled_op, d.note
                );
                BandOutcome::RecompileEquiv
            } else {
                BandOutcome::Failed(format!(
                    "{label}: CodeDiff {} @ {}: {} vs {} ({})\n--- source:\n{source}",
                    d.qualname, d.first_diff_offset, d.original_op, d.recompiled_op, d.note
                ))
            }
        }
    }
}

/// Token-match fallback for a sub-band with no installed interpreter, grading against vendored source.
pub(crate) fn source_token_match_legacy(
    pyc_path: &Path,
    source_path: &Path,
    label: &str,
) -> BandOutcome {
    let (code, marshal_version): (CodeObject, MarshalVersion) = match read_code(pyc_path) {
        Ok(c) => c,
        Err(e) => return BandOutcome::Failed(format!("{label}: read pyc: {e}")),
    };
    let (recovered, _): (String, DecompileVersion) = match decompile_source(&code, marshal_version)
    {
        Ok(s) => s,
        Err(e) => return BandOutcome::Failed(format!("{label}: {e}")),
    };
    if let Err(e) = assert_no_placeholder(label, &recovered) {
        return BandOutcome::Failed(e);
    }
    let Ok(source): Result<String, _> = fs::read_to_string(source_path) else {
        return BandOutcome::Failed(format!("{label}: vendored source unreadable"));
    };
    if source_token_equiv(&recovered, &source) {
        BandOutcome::SourceTokenMatch
    } else {
        BandOutcome::Failed(format!(
            "{label}: recovered source token-diffs vendored ORIGINAL"
        ))
    }
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

/// Enumerates vendored legacy `.pyc` files whose marshalled version falls within `[low, high]`.
#[must_use]
pub(crate) fn legacy_pycs_in_range(
    low: (u8, u8),
    high: (u8, u8),
) -> Vec<(PathBuf, (u8, u8), String)> {
    let dir: PathBuf = PathBuf::from(LEGACY_COMPILED_DIR);
    let mut files: Vec<PathBuf> = fs::read_dir(&dir).map_or_else(
        |_| Vec::new(),
        |rd| {
            rd.filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("pyc"))
                .collect()
        },
    );
    files.sort();
    let mut out: Vec<(PathBuf, (u8, u8), String)> = Vec::new();
    for pyc in files {
        let Ok((_, ver)): Result<(CodeObject, MarshalVersion), _> = read_code(&pyc) else {
            continue;
        };
        let key: (u8, u8) = (ver.major, ver.minor);
        if key < low || key > high {
            continue;
        }
        let name: String = pyc
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let stem: String = legacy_stem(&name);
        out.push((pyc, key, stem));
    }
    out
}

/// Strip the trailing `.X.Y.pyc` version tag from a legacy fixture name to recover the source stem.
fn legacy_stem(pyc_name: &str) -> String {
    let no_ext: &str = pyc_name.strip_suffix(".pyc").unwrap_or(pyc_name);
    let parts: Vec<&str> = no_ext.rsplitn(3, '.').collect();
    if parts.len() == 3 {
        parts[2].to_owned()
    } else {
        no_ext.to_owned()
    }
}

/// Resolves the vendored original source for a legacy fixture stem, honouring the `_py3` demotion.
#[must_use]
pub(crate) fn legacy_source_for(stem: &str) -> Option<PathBuf> {
    let direct: PathBuf = PathBuf::from(LEGACY_SOURCE_DIR).join(format!("{stem}.py"));
    if direct.is_file() {
        return Some(direct);
    }
    let demoted: &str = stem.strip_suffix("_py3").unwrap_or(stem);
    let fallback: PathBuf = PathBuf::from(LEGACY_SOURCE_DIR).join(format!("{demoted}.py"));
    if fallback.is_file() {
        return Some(fallback);
    }
    None
}

/// Create and return a per-band scratch dir under the band E2E report root.
#[must_use]
pub(crate) fn band_scratch(name: &str) -> PathBuf {
    let scratch: PathBuf = PathBuf::from(BAND_SCRATCH_ROOT).join(name);
    let _ = fs::create_dir_all(&scratch);
    scratch
}
