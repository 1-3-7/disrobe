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

use std::collections::BTreeMap;

use disrobe_pass_py_decompile::bytecode::version::PyVersion as DecompileVersion;
use disrobe_pass_py_decompile::engine::{build_real_source, marshal_to_decompile};
use disrobe_pass_py_decompile::roundtrip::{
    Verdict, compare_normalized, normalize_sequence, qualname_of, semantic_equiv,
};
use disrobe_py_marshal::{CodeObject, Object, PyVersion as MarshalVersion, PycFile, read_pyc};

pub(crate) const CONSTRUCT_CASES_DIR: &str = "../../corpus/python/decompile/construct/cases";
pub(crate) const BAND_SCRATCH_ROOT: &str = concat!(env!("CARGO_TARGET_TMPDIR"), "/py-band-e2e");

#[derive(Debug, Clone)]
pub(crate) struct BandInterpreter {
    pub alias: &'static str,
    pub path: PathBuf,
    pub is_prerelease: bool,
}

#[derive(Debug, Clone)]
pub(crate) enum BandOutcome {
    RecompileEquiv,
    Tolerated(String),
    Failed(String),
}

#[must_use]
pub(crate) fn interpreter_hidden(alias: &str) -> bool {
    std::env::var("DISROBE_TEST_HIDE_PY").is_ok_and(|hidden: String| {
        hidden
            .split(',')
            .map(str::trim)
            .any(|entry: &str| entry == alias)
    })
}

#[must_use]
pub(crate) fn find_interpreter(alias: &str) -> Option<PathBuf> {
    if interpreter_hidden(alias) {
        return None;
    }
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
    let tag: String = alias.replace('.', "");
    if cfg!(windows) {
        let mut candidates: Vec<PathBuf> = Vec::with_capacity(3);
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            candidates.push(PathBuf::from(format!(
                "{local}/Programs/Python/Python{tag}/python.exe"
            )));
        }
        candidates.push(PathBuf::from(format!("C:/Python{tag}/python.exe")));
        candidates.push(PathBuf::from(format!("C:/Python{tag}-32/python.exe")));
        return candidates.into_iter().find(|p: &PathBuf| p.is_file());
    }
    let candidates: [PathBuf; 3] = [
        PathBuf::from(format!("/usr/bin/python{alias}")),
        PathBuf::from(format!("/usr/local/bin/python{alias}")),
        PathBuf::from(format!("/opt/homebrew/bin/python{tag}")),
    ];
    candidates.into_iter().find(|p: &PathBuf| p.is_file())
}

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
        .env("PYTHONHASHSEED", "0")
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

fn assert_no_placeholder(label: &str, source: &str) -> Result<(), String> {
    if source.contains("__DR_") {
        return Err(format!(
            "{label}: __DR_ placeholder leaked into recovered source"
        ));
    }
    Ok(())
}

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

pub(crate) fn recompile_equiv_inline(
    interp: &BandInterpreter,
    program: &str,
    label: &str,
    scratch: &Path,
) -> (BandOutcome, String) {
    let source_path: PathBuf = scratch.join(format!("{label}.{}.src.py", interp.alias));
    if let Err(e) = fs::write(&source_path, program) {
        return (
            BandOutcome::Failed(format!("{label}: write source: {e}")),
            String::new(),
        );
    }
    let orig_pyc: PathBuf = scratch.join(format!("{label}.{}.orig.pyc", interp.alias));
    if let Err(e) = compile_source(&interp.path, &source_path, &orig_pyc) {
        return (
            BandOutcome::Failed(format!("{label}: orig compile failed: {e}")),
            String::new(),
        );
    }
    let (original_code, marshal_version): (CodeObject, MarshalVersion) = match read_code(&orig_pyc)
    {
        Ok(c) => c,
        Err(e) => {
            return (
                BandOutcome::Failed(format!("{label}: read orig pyc: {e}")),
                String::new(),
            );
        }
    };
    let (source, _): (String, DecompileVersion) =
        match decompile_source(&original_code, marshal_version) {
            Ok(s) => s,
            Err(e) => return (BandOutcome::Failed(format!("{label}: {e}")), String::new()),
        };
    if let Err(e) = assert_no_placeholder(label, &source) {
        return (BandOutcome::Failed(e), source);
    }
    let recovered_path: PathBuf = scratch.join(format!("{label}.{}.dec.py", interp.alias));
    if let Err(e) = fs::write(&recovered_path, &source) {
        return (
            BandOutcome::Failed(format!("{label}: write recovered: {e}")),
            source,
        );
    }
    let recompiled_pyc: PathBuf = scratch.join(format!("{label}.{}.dec.pyc", interp.alias));
    if let Err(e) = compile_source(&interp.path, &recovered_path, &recompiled_pyc) {
        return (
            BandOutcome::Failed(format!("{label}: recompile failed: {e}")),
            source,
        );
    }
    let (recompiled_code, _): (CodeObject, MarshalVersion) = match read_code(&recompiled_pyc) {
        Ok(c) => c,
        Err(e) => {
            return (
                BandOutcome::Failed(format!("{label}: read recompiled: {e}")),
                source,
            );
        }
    };
    let outcome: BandOutcome = classify(
        &original_code,
        &recompiled_code,
        marshal_version,
        label,
        interp.is_prerelease,
        &source,
    );
    (outcome, source)
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
                let detail: String = format!(
                    "{label}: prerelease tolerated CodeDiff {} @ {}: {} vs {} ({})",
                    d.qualname, d.first_diff_offset, d.original_op, d.recompiled_op, d.note
                );
                eprintln!("TOLERATED prerelease {detail}");
                BandOutcome::Tolerated(detail)
            } else {
                BandOutcome::Failed(format!(
                    "{label}: CodeDiff {} @ {}: {} vs {} ({})\n--- source:\n{source}",
                    d.qualname, d.first_diff_offset, d.original_op, d.recompiled_op, d.note
                ))
            }
        }
    }
}

#[must_use]
pub(crate) fn band_scratch(name: &str) -> PathBuf {
    let scratch: PathBuf = PathBuf::from(BAND_SCRATCH_ROOT).join(name);
    let _ = fs::create_dir_all(&scratch);
    scratch
}

#[derive(Debug, Clone)]
pub(crate) struct ObjectFailure {
    pub qualname: String,
    pub kind: &'static str,
    pub note: String,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct ObjectTally {
    pub total: u64,
    pub ok: u64,
    pub missing: u64,
    pub collision: u64,
    pub code_diff: u64,
    pub sig_diff: u64,
    pub sibling_collisions: u64,
    pub failures: Vec<ObjectFailure>,
}

impl ObjectTally {
    #[must_use]
    pub(crate) fn object_pct(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            100.0 * (self.ok as f64) / (self.total as f64)
        }
    }
}

fn const_code_children(code: &CodeObject) -> Vec<&CodeObject> {
    code.consts
        .iter()
        .filter_map(|c: &Object| match c {
            Object::Code(boxed) => Some(boxed.as_ref()),
            _ => None,
        })
        .collect()
}

fn code_short_name(code: &CodeObject) -> String {
    match &code.name {
        Object::String { value, .. } | Object::ShortAscii { value, .. } => value.clone(),
        _ => qualname_of(code),
    }
}

fn walk_code<'a>(code: &'a CodeObject, qual: &str, out: &mut Vec<(String, &'a CodeObject)>) {
    out.push((qual.to_owned(), code));
    for child in const_code_children(code) {
        let child_name: String = code_short_name(child);
        if child_name == "__annotate__" {
            continue;
        }
        let child_qual: String = format!("{qual}.{child_name}");
        walk_code(child, &child_qual, out);
    }
}

fn group_by_qual(code: &CodeObject) -> BTreeMap<String, Vec<&CodeObject>> {
    let mut flat: Vec<(String, &CodeObject)> = Vec::new();
    walk_code(code, "<module>", &mut flat);
    let mut grouped: BTreeMap<String, Vec<&CodeObject>> = BTreeMap::new();
    for (qual, obj) in flat {
        grouped.entry(qual).or_default().push(obj);
    }
    grouped
}

fn own_equiv(
    original: &CodeObject,
    recompiled: &CodeObject,
    version: MarshalVersion,
) -> Result<(), (&'static str, String)> {
    let norm_a = normalize_sequence(original, version);
    let norm_b = normalize_sequence(recompiled, version);
    if let Some(detail) = compare_normalized(&norm_a, &norm_b, qualname_of(original)) {
        return Err((
            "code",
            format!(
                "@ {}: {} vs {} ({})",
                detail.first_diff_offset, detail.original_op, detail.recompiled_op, detail.note
            ),
        ));
    }
    if original.argcount != recompiled.argcount
        || original.posonlyargcount != recompiled.posonlyargcount
        || original.kwonlyargcount != recompiled.kwonlyargcount
    {
        return Err((
            "sig",
            format!(
                "argcount {}/{}/{} vs {}/{}/{}",
                original.argcount,
                original.posonlyargcount,
                original.kwonlyargcount,
                recompiled.argcount,
                recompiled.posonlyargcount,
                recompiled.kwonlyargcount,
            ),
        ));
    }
    Ok(())
}

#[must_use]
pub(crate) fn measure_per_object(
    original: &CodeObject,
    recompiled: &CodeObject,
    version: MarshalVersion,
) -> ObjectTally {
    let group_a: BTreeMap<String, Vec<&CodeObject>> = group_by_qual(original);
    let group_b: BTreeMap<String, Vec<&CodeObject>> = group_by_qual(recompiled);
    let mut tally: ObjectTally = ObjectTally::default();
    for (qual, alist) in &group_a {
        tally.total += alist.len() as u64;
        let empty: Vec<&CodeObject> = Vec::new();
        let blist: &Vec<&CodeObject> = group_b.get(qual).unwrap_or(&empty);
        if blist.len() != alist.len() {
            if alist.len().max(blist.len()) > 1 {
                tally.sibling_collisions += 1;
            }
            for (i, _) in alist.iter().enumerate() {
                if i >= blist.len() {
                    tally.missing += 1;
                    push_failure(
                        &mut tally,
                        qual,
                        "missing",
                        format!("{} orig vs {} rec", alist.len(), blist.len()),
                    );
                } else {
                    tally.collision += 1;
                    push_failure(
                        &mut tally,
                        qual,
                        "collision",
                        format!("{} orig vs {} rec", alist.len(), blist.len()),
                    );
                }
            }
            continue;
        }
        for (ac, bc) in alist.iter().zip(blist.iter()) {
            match own_equiv(ac, bc, version) {
                Ok(()) => tally.ok += 1,
                Err((kind, note)) => {
                    if kind == "sig" {
                        tally.sig_diff += 1;
                    } else {
                        tally.code_diff += 1;
                    }
                    push_failure(&mut tally, qual, kind, note);
                }
            }
        }
    }
    tally
}

fn push_failure(tally: &mut ObjectTally, qualname: &str, kind: &'static str, note: String) {
    if tally.failures.len() < 64 {
        tally.failures.push(ObjectFailure {
            qualname: qualname.to_owned(),
            kind,
            note,
        });
    }
}

#[derive(Debug, Clone)]
pub(crate) enum CorpusMeasurement {
    Measured(ObjectTally),
    Unmeasurable(String),
}

#[must_use]
pub(crate) fn measure_corpus_file(
    interp: &BandInterpreter,
    source_path: &Path,
    label: &str,
    scratch: &Path,
) -> CorpusMeasurement {
    let orig_pyc: PathBuf = scratch.join(format!("{label}.{}.orig.pyc", interp.alias));
    if let Err(e) = compile_source(&interp.path, source_path, &orig_pyc) {
        return CorpusMeasurement::Unmeasurable(format!("{label}: orig compile failed: {e}"));
    }
    let (original_code, marshal_version): (CodeObject, MarshalVersion) = match read_code(&orig_pyc)
    {
        Ok(c) => c,
        Err(e) => return CorpusMeasurement::Unmeasurable(format!("{label}: read orig pyc: {e}")),
    };
    let (source, _): (String, DecompileVersion) =
        match decompile_source(&original_code, marshal_version) {
            Ok(s) => s,
            Err(e) => return CorpusMeasurement::Unmeasurable(format!("{label}: decompile: {e}")),
        };
    if source.contains("__DR_") {
        return CorpusMeasurement::Unmeasurable(format!(
            "{label}: __DR_ placeholder leaked into recovered source"
        ));
    }
    let recovered_path: PathBuf = scratch.join(format!("{label}.{}.dec.py", interp.alias));
    if let Err(e) = fs::write(&recovered_path, &source) {
        return CorpusMeasurement::Unmeasurable(format!("{label}: write recovered: {e}"));
    }
    let recompiled_pyc: PathBuf = scratch.join(format!("{label}.{}.dec.pyc", interp.alias));
    if let Err(e) = compile_source(&interp.path, &recovered_path, &recompiled_pyc) {
        return CorpusMeasurement::Unmeasurable(format!("{label}: recompile failed: {e}"));
    }
    let (recompiled_code, _): (CodeObject, MarshalVersion) = match read_code(&recompiled_pyc) {
        Ok(c) => c,
        Err(e) => return CorpusMeasurement::Unmeasurable(format!("{label}: read recompiled: {e}")),
    };
    CorpusMeasurement::Measured(measure_per_object(
        &original_code,
        &recompiled_code,
        marshal_version,
    ))
}
