use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_testkit::{CommandSpec, ToolOutput, tool_output};

pub(crate) const CALL_TIMEOUT: Duration = Duration::from_secs(45);

pub(crate) const PINNED_RELEASE: &str = "4.6.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Toolchain {
    pub(crate) program: &'static str,
    pub(crate) binary_var: &'static str,
    pub(crate) prerequisite: &'static str,
    pub(crate) install_hint: &'static str,
}

pub(crate) const RSCRIPT: Toolchain = Toolchain {
    program: "Rscript",
    binary_var: "DISROBE_RSCRIPT_BIN",
    prerequisite: "disrobe-pass-scriptlang::rscript-4.6.0",
    install_hint: "install R 4.6.0 and put Rscript on PATH, or point DISROBE_RSCRIPT_BIN at the \
                   binary",
};

pub(crate) const TCLSH: Toolchain = Toolchain {
    program: "tclsh",
    binary_var: "DISROBE_TCLSH_BIN",
    prerequisite: "disrobe-pass-scriptlang::tclsh",
    install_hint: "install Tcl 8.6 or newer and put tclsh on PATH, or point DISROBE_TCLSH_BIN at \
                   the binary",
};

#[derive(Debug, Clone)]
pub(crate) struct TclRuntime {
    pub(crate) tclsh: PathBuf,
    pub(crate) patchlevel: String,
}

#[derive(Debug, Clone)]
pub(crate) struct RRuntime {
    pub(crate) rscript: PathBuf,
    pub(crate) release: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Finished {
    pub(crate) success: bool,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

pub(crate) fn find_on_path(name: &str) -> Option<PathBuf> {
    let path_var: OsString = std::env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) {
        &["", ".exe", ".bat", ".cmd"]
    } else {
        &[""]
    };
    for dir in std::env::split_paths(&path_var) {
        for ext in exts {
            let candidate: PathBuf = dir.join(format!("{name}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

pub(crate) fn run_bounded<I, S>(program: &Path, args: I) -> Option<Finished>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let spec: CommandSpec = CommandSpec::new(program, CALL_TIMEOUT)
        .args(args.into_iter().map(|arg: S| arg.as_ref().to_os_string()));
    let output: ToolOutput = tool_output(spec).ok()?;
    if output.timed_out {
        return None;
    }
    Some(Finished {
        success: output.success,
        stdout: output.stdout_text(),
        stderr: output.stderr_text(),
    })
}

fn unavailable(toolchain: &Toolchain, graded: &str, defect: &str) {
    let what: String = format!(
        "{program} for {graded}: {defect}; to fix it, {hint}",
        program = toolchain.program,
        hint = toolchain.install_hint,
    );
    if let Err(error) = disrobe_testkit::require::<()>(toolchain.prerequisite, &what, None) {
        panic!("{graded}: {error}");
    }
}

pub(crate) fn locate(toolchain: &Toolchain) -> Option<PathBuf> {
    if let Some(raw) = std::env::var_os(toolchain.binary_var) {
        let candidate: PathBuf = PathBuf::from(raw);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    find_on_path(toolchain.program)
}

pub(crate) fn require_r(graded: &str) -> Option<RRuntime> {
    let Some(rscript): Option<PathBuf> = locate(&RSCRIPT) else {
        unavailable(
            &RSCRIPT,
            graded,
            "`Rscript` is not on PATH and DISROBE_RSCRIPT_BIN does not name a file, so R is not \
             installed here",
        );
        return None;
    };
    match release(&rscript) {
        Ok(found) if found == PINNED_RELEASE => Some(RRuntime {
            rscript,
            release: found,
        }),
        Ok(found) => {
            unavailable(
                &RSCRIPT,
                graded,
                &format!(
                    "`Rscript` at {} reports R {found}, but corpus/r/MANIFEST.toml records R \
                     {PINNED_RELEASE} as the release that wrote every committed object, so a \
                     comparison against this interpreter would grade a different R",
                    rscript.display()
                ),
            );
            None
        }
        Err(defect) => {
            unavailable(&RSCRIPT, graded, &defect);
            None
        }
    }
}

pub(crate) fn require_tclsh(graded: &str, scratch: &Path) -> Option<TclRuntime> {
    let Some(tclsh): Option<PathBuf> = locate(&TCLSH) else {
        unavailable(
            &TCLSH,
            graded,
            "`tclsh` is not on PATH and DISROBE_TCLSH_BIN does not name a file, so Tcl is not \
             installed here",
        );
        return None;
    };
    match patchlevel(&tclsh, scratch) {
        Ok(found) => Some(TclRuntime {
            tclsh,
            patchlevel: found,
        }),
        Err(defect) => {
            unavailable(&TCLSH, graded, &defect);
            None
        }
    }
}

fn patchlevel(tclsh: &Path, scratch: &Path) -> Result<String, String> {
    let probe: PathBuf = scratch.join("probe.tcl");
    std::fs::write(&probe, b"puts [info patchlevel]\n").map_err(|error: std::io::Error| {
        format!("could not write the Tcl probe script: {error}")
    })?;
    let finished: Finished = run_bounded(tclsh, [&probe]).ok_or_else(|| {
        format!(
            "`tclsh` at {} did not start or did not exit within {CALL_TIMEOUT:?}",
            tclsh.display()
        )
    })?;
    let reported: &str = finished.stdout.trim();
    let major: Option<u32> = reported
        .split('.')
        .next()
        .and_then(|part: &str| part.parse::<u32>().ok());
    match (finished.success, major) {
        (true, Some(major)) if major >= 8 => Ok(reported.to_owned()),
        _ => Err(format!(
            "`tclsh` at {} did not answer a `puts [info patchlevel]` script (stdout {reported:?}, \
             stderr {:?}), so Tcl is installed and unusable rather than absent",
            tclsh.display(),
            finished.stderr.trim()
        )),
    }
}

fn release(rscript: &Path) -> Result<String, String> {
    match run_bounded(rscript, ["-e", "cat(as.character(getRversion()))"]) {
        Some(finished) if finished.success && !finished.stdout.trim().is_empty() => {
            Ok(finished.stdout.trim().to_owned())
        }
        Some(finished) => Err(format!(
            "`Rscript` is present at {} but did not report its release (stdout {:?}, stderr {:?}), \
             so R is installed and unusable rather than absent",
            rscript.display(),
            finished.stdout.trim(),
            finished.stderr.trim()
        )),
        None => Err(format!(
            "`Rscript` at {} did not start or did not exit within {CALL_TIMEOUT:?}",
            rscript.display()
        )),
    }
}

pub(crate) fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}
