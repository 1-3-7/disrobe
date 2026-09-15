use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_py_marshal::{CodeObject, Object, PyVersion as MarshalVersion, PycFile, read_pyc};

use crate::bytecode::version::PyVersion as DecompileVersion;
use crate::roundtrip::{self, Verdict};

const PROBE_TIMEOUT_SECS: u64 = 5;
const RECOMPILE_TIMEOUT_SECS: u64 = 60;
const MAX_PROBE_CAPTURE: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoundtripStatus {
    Perfect,
    Semantic,
    CodeDiff { detail: String },
    NoInterpreter { hint: String },
    RecompileFailed { stderr: String },
    Skipped,
}

impl RoundtripStatus {
    #[must_use]
    pub fn as_label(&self) -> &'static str {
        match self {
            Self::Perfect => "perfect",
            Self::Semantic => "semantic",
            Self::CodeDiff { .. } => "code-diff",
            Self::NoInterpreter { .. } => "no-interpreter",
            Self::RecompileFailed { .. } => "recompile-failed",
            Self::Skipped => "skipped",
        }
    }
}

#[must_use]
pub fn roundtrip_skipped() -> RoundtripOutcome {
    RoundtripOutcome {
        status: RoundtripStatus::Skipped,
        interpreter_path: None,
        interpreter_version: None,
    }
}

#[derive(Debug, Clone)]
pub struct RoundtripOutcome {
    pub status: RoundtripStatus,
    pub interpreter_path: Option<PathBuf>,
    pub interpreter_version: Option<String>,
}

#[must_use]
pub fn roundtrip_native(
    recovered_source: &str,
    original_code: &CodeObject,
    decompile_version: &DecompileVersion,
    marshal_version: MarshalVersion,
) -> RoundtripOutcome {
    let Some((interpreter, ver_label)): Option<(PathBuf, String)> =
        locate_interpreter(marshal_version)
    else {
        return RoundtripOutcome {
            status: RoundtripStatus::NoInterpreter {
                hint: format!(
                    "no python{}.{} on PATH",
                    marshal_version.major, marshal_version.minor
                ),
            },
            interpreter_path: None,
            interpreter_version: None,
        };
    };

    match recompile_via_interpreter(&interpreter, recovered_source) {
        Ok(recompiled) => {
            let verdict: Verdict =
                roundtrip::semantic_equiv(original_code, &recompiled, marshal_version);
            let status: RoundtripStatus = match verdict {
                Verdict::Perfect => RoundtripStatus::Perfect,
                Verdict::Semantic => RoundtripStatus::Semantic,
                Verdict::CodeDiff(d) => RoundtripStatus::CodeDiff {
                    detail: format!(
                        "{} @ idx {}: {} vs {} ({})",
                        d.qualname, d.first_diff_offset, d.original_op, d.recompiled_op, d.note
                    ),
                },
            };
            let _: &DecompileVersion = decompile_version;
            RoundtripOutcome {
                status,
                interpreter_path: Some(interpreter),
                interpreter_version: Some(ver_label),
            }
        }
        Err(stderr) => RoundtripOutcome {
            status: RoundtripStatus::RecompileFailed { stderr },
            interpreter_path: Some(interpreter),
            interpreter_version: Some(ver_label),
        },
    }
}

fn locate_interpreter(target: MarshalVersion) -> Option<(PathBuf, String)> {
    let candidates: [String; 4] = [
        format!("python{}.{}", target.major, target.minor),
        format!("python{}", target.major),
        "python3".to_owned(),
        "python".to_owned(),
    ];
    for cand in &candidates {
        let Some(found): Option<(PathBuf, MarshalVersion)> = probe_python(cand) else {
            continue;
        };
        if found.1.major == target.major && found.1.minor == target.minor {
            let label: String = format!("python{}.{}", found.1.major, found.1.minor);
            return Some((found.0, label));
        }
    }
    None
}

fn probe_python(name: &str) -> Option<(PathBuf, MarshalVersion)> {
    let exe: PathBuf = which_on_path(name)?;
    let captured: disrobe_core::subprocess::CapturedOutput =
        disrobe_core::subprocess::run_captured(
            &exe,
            &[
                "-c",
                "import sys;print(f'{sys.version_info.major}.{sys.version_info.minor}')",
            ],
            Duration::from_secs(PROBE_TIMEOUT_SECS),
            MAX_PROBE_CAPTURE,
        )
        .ok()
        .flatten()?;
    if captured.exit_code != Some(0) {
        return None;
    }
    let text: String = String::from_utf8_lossy(&captured.stdout).trim().to_owned();
    let (maj, min): (&str, &str) = text.split_once('.')?;
    let major: u8 = maj.parse().ok()?;
    let minor: u8 = min.parse().ok()?;
    Some((exe, MarshalVersion { major, minor }))
}

fn which_on_path(exe: &str) -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        if dir.as_os_str().is_empty() || !dir.is_absolute() {
            continue;
        }
        for variant in [exe, &format!("{exe}.exe")] {
            let candidate: PathBuf = dir.join(variant);
            if candidate.is_absolute() && candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn py_path_literal(path: &Path) -> String {
    let s: String = path.to_string_lossy().into_owned();
    let escaped: String = s.replace('\\', r"\\").replace('\'', r"\'");
    format!("'{escaped}'")
}

const ROUNDTRIP_SCRATCH_PURPOSE: &str = "py-decompile-roundtrip";
const ROUNDTRIP_SOURCE_STEM: &str = "recovered";

fn recompile_via_interpreter(interpreter: &Path, source: &str) -> Result<CodeObject, String> {
    let scratch: ScratchDir = ScratchDir::create(ROUNDTRIP_SCRATCH_PURPOSE)
        .map_err(|e: std::io::Error| format!("create scratch directory: {e}"))?;
    let src_path: PathBuf = scratch.path().join(format!("{ROUNDTRIP_SOURCE_STEM}.py"));
    let pyc_path: PathBuf = scratch.path().join(format!("{ROUNDTRIP_SOURCE_STEM}.pyc"));
    std::fs::write(&src_path, source.as_bytes()).map_err(|e| format!("write temp source: {e}"))?;
    let src_lit: String = py_path_literal(&src_path);
    let pyc_lit: String = py_path_literal(&pyc_path);
    let script: String = format!(
        "import py_compile,sys\n\
try:\n    py_compile.compile({src_lit}, cfile={pyc_lit}, doraise=True)\n\
except Exception as e:\n    sys.stderr.write(str(e));sys.exit(2)\n"
    );
    let captured: disrobe_core::subprocess::CapturedOutput =
        disrobe_core::subprocess::run_captured(
            interpreter,
            &["-c", &script],
            Duration::from_secs(RECOMPILE_TIMEOUT_SECS),
            MAX_PROBE_CAPTURE,
        )
        .map_err(|e| format!("spawn interpreter: {e}"))?
        .ok_or_else(|| {
            format!("interpreter timed out after {RECOMPILE_TIMEOUT_SECS}s and was killed")
        })?;
    if captured.exit_code != Some(0) {
        let stderr: String = String::from_utf8_lossy(&captured.stderr).trim().to_owned();
        return Err(if stderr.is_empty() {
            format!("py_compile exit {:?}", captured.exit_code)
        } else {
            stderr
        });
    }
    let bytes: Vec<u8> = std::fs::read(&pyc_path).map_err(|e| format!("read pyc: {e}"))?;
    let pyc: PycFile =
        read_pyc(&bytes).map_err(|e: disrobe_py_marshal::Error| format!("parse pyc: {e}"))?;
    match pyc.code {
        Object::Code(boxed) => Ok(*boxed),
        other => Err(format!("recompiled pyc lacks code object: {other:?}")),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    use disrobe_core::scratch::scratch_root;

    fn entries_named(root: &Path, prefix: &str) -> Vec<PathBuf> {
        let Ok(entries): std::io::Result<std::fs::ReadDir> = std::fs::read_dir(root) else {
            return Vec::new();
        };
        entries
            .flatten()
            .map(|entry: std::fs::DirEntry| entry.path())
            .filter(|path: &PathBuf| {
                path.file_name()
                    .and_then(|name: &std::ffi::OsStr| name.to_str())
                    .is_some_and(|name: &str| name.starts_with(prefix))
            })
            .collect()
    }

    fn roundtrip_scratch_leftovers() -> Vec<PathBuf> {
        let prefix: String = format!("{ROUNDTRIP_SCRATCH_PURPOSE}-{}-", std::process::id());
        entries_named(&scratch_root(), &prefix)
    }

    fn temp_root_names() -> std::collections::BTreeSet<String> {
        let Ok(entries): std::io::Result<std::fs::ReadDir> =
            std::fs::read_dir(std::env::temp_dir())
        else {
            return std::collections::BTreeSet::new();
        };
        let pid: String = std::process::id().to_string();
        entries
            .flatten()
            .filter_map(|entry: std::fs::DirEntry| {
                entry
                    .file_name()
                    .to_str()
                    .filter(|name: &&str| name.contains("disrobe") && name.contains(&pid))
                    .map(str::to_owned)
            })
            .collect()
    }

    #[test]
    fn an_interpreter_that_cannot_be_spawned_leaves_no_recovered_source_behind() {
        let recovered: &str = "SAMPLE_SECRET_IDENTIFIER = 'recovered from the operator sample'\n";
        let unspawnable: PathBuf = scratch_root().join("py-decompile-absent-interpreter");
        let temp_before: std::collections::BTreeSet<String> = temp_root_names();

        let error: String = recompile_via_interpreter(&unspawnable, recovered)
            .expect_err("an interpreter path that does not exist cannot be spawned");
        assert!(
            error.starts_with("spawn interpreter:"),
            "the spawn failure path must be the one exercised, got: {error}"
        );

        let scratch_left: Vec<PathBuf> = roundtrip_scratch_leftovers();
        assert!(
            scratch_left.is_empty(),
            "the guard must remove its directory when the interpreter never starts, found: {scratch_left:?}"
        );
        let temp_after: std::collections::BTreeSet<String> = temp_root_names();
        let gained: Vec<&String> = temp_after.difference(&temp_before).collect();
        assert!(
            gained.is_empty(),
            "recovered source must never be written loose in the shared temp root, gained: {gained:?}"
        );
    }
}
