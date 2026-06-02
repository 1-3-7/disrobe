use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use disrobe_py_marshal::{CodeObject, Object, PyVersion as MarshalVersion, PycFile, read_pyc};

use crate::bytecode::version::PyVersion as DecompileVersion;
use crate::roundtrip::{self, Verdict};

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
    let out: std::process::Output = Command::new(&exe)
        .args([
            "-c",
            "import sys;print(f'{sys.version_info.major}.{sys.version_info.minor}')",
        ])
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text: String = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    let (maj, min): (&str, &str) = text.split_once('.')?;
    let major: u8 = maj.parse().ok()?;
    let minor: u8 = min.parse().ok()?;
    Some((exe, MarshalVersion { major, minor }))
}

/// Resolves `exe` to an absolute interpreter path using `PATH` entries only.
///
/// Empty and relative `PATH` entries are skipped so that the current working
/// directory is never searched. On Windows an empty entry denotes the cwd; a
/// malware-dropped `python.exe` in the analyst's directory must never shadow a
/// legitimate install. Only an absolute path to an existing file is accepted.
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

static ROUNDTRIP_SEQ: AtomicU64 = AtomicU64::new(0);

fn recompile_via_interpreter(interpreter: &Path, source: &str) -> Result<CodeObject, String> {
    let tmp_root: PathBuf = std::env::temp_dir();
    let pid: u32 = std::process::id();
    let seq: u64 = ROUNDTRIP_SEQ.fetch_add(1, Ordering::Relaxed);
    let src_path: PathBuf = tmp_root.join(format!("disrobe-rt-{pid}-{seq}.py"));
    let pyc_path: PathBuf = tmp_root.join(format!("disrobe-rt-{pid}-{seq}.pyc"));
    std::fs::write(&src_path, source.as_bytes()).map_err(|e| format!("write temp source: {e}"))?;
    let src_lit: String = py_path_literal(&src_path);
    let pyc_lit: String = py_path_literal(&pyc_path);
    let script: String = format!(
        "import py_compile,sys\n\
try:\n    py_compile.compile({src_lit}, cfile={pyc_lit}, doraise=True)\n\
except Exception as e:\n    sys.stderr.write(str(e));sys.exit(2)\n"
    );
    let out: std::process::Output = Command::new(interpreter)
        .args(["-c", &script])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("spawn interpreter: {e}"))?;
    let _: std::io::Result<()> = std::fs::remove_file(&src_path);
    if !out.status.success() {
        let _: std::io::Result<()> = std::fs::remove_file(&pyc_path);
        let stderr: String = String::from_utf8_lossy(&out.stderr).trim().to_owned();
        return Err(if stderr.is_empty() {
            format!("py_compile exit {:?}", out.status.code())
        } else {
            stderr
        });
    }
    let bytes: Vec<u8> = std::fs::read(&pyc_path).map_err(|e| format!("read pyc: {e}"))?;
    let _: std::io::Result<()> = std::fs::remove_file(&pyc_path);
    let pyc: PycFile =
        read_pyc(&bytes).map_err(|e: disrobe_py_marshal::Error| format!("parse pyc: {e}"))?;
    match pyc.code {
        Object::Code(boxed) => Ok(*boxed),
        other => Err(format!("recompiled pyc lacks code object: {other:?}")),
    }
}
