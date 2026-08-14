use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::JoinHandle;
use std::time::Duration;

use wait_timeout::ChildExt;

pub(crate) const CALL_TIMEOUT: Duration = Duration::from_secs(45);

pub(crate) const PINNED_RELEASE: &str = "4.6.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Toolchain {
    pub(crate) program: &'static str,
    pub(crate) binary_var: &'static str,
    pub(crate) require_var: &'static str,
    pub(crate) install_hint: &'static str,
}

pub(crate) const RSCRIPT: Toolchain = Toolchain {
    program: "Rscript",
    binary_var: "DISROBE_RSCRIPT_BIN",
    require_var: "DISROBE_REQUIRE_R",
    install_hint: "install R 4.6.0 and put Rscript on PATH, or point DISROBE_RSCRIPT_BIN at the \
                   binary",
};

pub(crate) const TCLSH: Toolchain = Toolchain {
    program: "tclsh",
    binary_var: "DISROBE_TCLSH_BIN",
    require_var: "DISROBE_REQUIRE_TCL",
    install_hint: "install Tcl 8.6 or newer and put tclsh on PATH, or point DISROBE_TCLSH_BIN at \
                   the binary",
};

#[derive(Debug, Clone)]
pub(crate) struct TclRuntime {
    pub(crate) tclsh: PathBuf,
    pub(crate) patchlevel: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Requirement {
    Optional,
    Mandatory,
}

#[derive(Debug, Clone)]
pub(crate) struct RRuntime {
    pub(crate) rscript: PathBuf,
    pub(crate) release: String,
}

pub(crate) fn requirement(toolchain: &Toolchain) -> Requirement {
    let Some(raw): Option<OsString> = std::env::var_os(toolchain.require_var) else {
        return Requirement::Optional;
    };
    match raw.to_string_lossy().trim().to_ascii_lowercase().as_str() {
        "" | "0" | "false" | "no" | "off" | "optional" => Requirement::Optional,
        _ => Requirement::Mandatory,
    }
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

fn drain(stream: Option<impl Read + Send + 'static>) -> JoinHandle<String> {
    std::thread::spawn(move || {
        let mut text: String = String::new();
        if let Some(mut handle) = stream {
            drop(handle.read_to_string(&mut text));
        }
        text
    })
}

pub(crate) fn run_bounded(mut cmd: Command) -> Option<(bool, String, String)> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child: std::process::Child = cmd.spawn().ok()?;
    let stdout: JoinHandle<String> = drain(child.stdout.take());
    let stderr: JoinHandle<String> = drain(child.stderr.take());
    let finished: Option<std::process::ExitStatus> = child.wait_timeout(CALL_TIMEOUT).ok()?;
    if finished.is_none() {
        drop(child.kill());
        drop(child.wait());
    }
    let out: String = stdout.join().unwrap_or_default();
    let err: String = stderr.join().unwrap_or_default();
    finished.map(|status: std::process::ExitStatus| (status.success(), out, err))
}

pub(crate) fn skip_or_fail(toolchain: &Toolchain, graded: &str, defect: &str) {
    assert!(
        requirement(toolchain) == Requirement::Optional,
        "{var} makes the {program} toolchain mandatory for this run, so {graded} cannot be \
         measured and this case must not report success: {defect}. To fix it, {hint}; to permit a \
         run that measures nothing here, clear {var}.",
        var = toolchain.require_var,
        program = toolchain.program,
        hint = toolchain.install_hint,
    );
    announce_unmeasured(toolchain, graded, defect);
}

fn announce_unmeasured(toolchain: &Toolchain, graded: &str, defect: &str) {
    let line: String = format!(
        "\nNOT MEASURED: {graded} compared nothing and graded nothing, because {defect}. Set \
         {var}=1 to fail instead of skipping when {program} cannot be run.\n",
        var = toolchain.require_var,
        program = toolchain.program,
    );
    let mut sink: std::io::StdoutLock<'static> = std::io::stdout().lock();
    drop(sink.write_all(line.as_bytes()));
    drop(sink.flush());
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
        skip_or_fail(
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
            skip_or_fail(
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
            skip_or_fail(&RSCRIPT, graded, &defect);
            None
        }
    }
}

pub(crate) fn require_tclsh(graded: &str, scratch: &Path) -> Option<TclRuntime> {
    let Some(tclsh): Option<PathBuf> = locate(&TCLSH) else {
        skip_or_fail(
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
            skip_or_fail(&TCLSH, graded, &defect);
            None
        }
    }
}

fn patchlevel(tclsh: &Path, scratch: &Path) -> Result<String, String> {
    let probe: PathBuf = scratch.join("probe.tcl");
    std::fs::write(&probe, b"puts [info patchlevel]\n").map_err(|error: std::io::Error| {
        format!("could not write the Tcl probe script: {error}")
    })?;
    let mut cmd: Command = Command::new(tclsh);
    cmd.arg(&probe);
    let (ok, out, err): (bool, String, String) = run_bounded(cmd).ok_or_else(|| {
        format!(
            "`tclsh` at {} did not exit within {CALL_TIMEOUT:?}",
            tclsh.display()
        )
    })?;
    let reported: &str = out.trim();
    let major: Option<u32> = reported
        .split('.')
        .next()
        .and_then(|part: &str| part.parse::<u32>().ok());
    match (ok, major) {
        (true, Some(major)) if major >= 8 => Ok(reported.to_owned()),
        _ => Err(format!(
            "`tclsh` at {} did not answer a `puts [info patchlevel]` script (stdout {reported:?}, \
             stderr {:?}), so Tcl is installed and unusable rather than absent",
            tclsh.display(),
            err.trim()
        )),
    }
}

fn release(rscript: &Path) -> Result<String, String> {
    let mut cmd: Command = Command::new(rscript);
    cmd.arg("-e").arg("cat(as.character(getRversion()))");
    match run_bounded(cmd) {
        Some((true, out, _)) if !out.trim().is_empty() => Ok(out.trim().to_owned()),
        Some((_, out, err)) => Err(format!(
            "`Rscript` is present at {} but did not report its release (stdout {:?}, stderr {:?}), \
             so R is installed and unusable rather than absent",
            rscript.display(),
            out.trim(),
            err.trim()
        )),
        None => Err(format!(
            "`Rscript` at {} did not exit within {CALL_TIMEOUT:?}",
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
