use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use wait_timeout::ChildExt;

pub const CALL_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Toolchain {
    pub program: &'static str,
    pub require_var: &'static str,
    pub install_hint: &'static str,
}

pub const ERLC: Toolchain = Toolchain {
    program: "erlc",
    require_var: "DISROBE_REQUIRE_ERLANG",
    install_hint: "install Erlang/OTP and put erlc on PATH",
};

pub const ERL: Toolchain = Toolchain {
    program: "erl",
    require_var: "DISROBE_REQUIRE_ERLANG",
    install_hint: "install Erlang/OTP and put erl on PATH",
};

pub const ELIXIRC: Toolchain = Toolchain {
    program: "elixirc",
    require_var: "DISROBE_REQUIRE_ELIXIR",
    install_hint: "install Elixir and put elixirc on PATH",
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement {
    Optional,
    Mandatory,
}

#[derive(Debug, Clone)]
pub struct Erlang {
    pub erlc: PathBuf,
    pub erl: PathBuf,
    pub release: String,
}

pub fn requirement(toolchain: &Toolchain) -> Requirement {
    let Some(raw): Option<OsString> = std::env::var_os(toolchain.require_var) else {
        return Requirement::Optional;
    };
    match raw.to_string_lossy().trim().to_ascii_lowercase().as_str() {
        "" | "0" | "false" | "no" | "off" | "optional" => Requirement::Optional,
        _ => Requirement::Mandatory,
    }
}

pub fn find_on_path(name: &str) -> Option<PathBuf> {
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

pub fn command_for(program: &Path) -> Command {
    let is_script: bool = program
        .extension()
        .and_then(|ext: &std::ffi::OsStr| ext.to_str())
        .is_some_and(|ext: &str| {
            ext.eq_ignore_ascii_case("bat") || ext.eq_ignore_ascii_case("cmd")
        });
    if cfg!(windows) && is_script {
        let mut cmd: Command = Command::new("cmd");
        cmd.arg("/C").arg(program);
        return cmd;
    }
    Command::new(program)
}

pub fn run_bounded(mut cmd: Command) -> Option<(bool, String, String)> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child: std::process::Child = cmd.spawn().expect("spawn subprocess");
    match child.wait_timeout(CALL_TIMEOUT).expect("wait_timeout") {
        Some(status) => {
            let mut so: String = String::new();
            let mut se: String = String::new();
            if let Some(mut h) = child.stdout.take() {
                let _ = h.read_to_string(&mut so);
            }
            if let Some(mut h) = child.stderr.take() {
                let _ = h.read_to_string(&mut se);
            }
            Some((status.success(), so, se))
        }
        None => {
            let _ = child.kill();
            let _ = child.wait();
            None
        }
    }
}

pub fn skip_or_fail(toolchain: &Toolchain, graded: &str, defect: &str) {
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

pub fn require(toolchain: &Toolchain, graded: &str) -> Option<PathBuf> {
    match find_on_path(toolchain.program) {
        Some(path) => Some(path),
        None => {
            skip_or_fail(
                toolchain,
                graded,
                &format!(
                    "`{}` is not on PATH, so the toolchain is not installed here",
                    toolchain.program
                ),
            );
            None
        }
    }
}

pub fn require_erlang(graded: &str) -> Option<Erlang> {
    let erlc: PathBuf = require(&ERLC, graded)?;
    let erl: PathBuf = require(&ERL, graded)?;
    match otp_release(&erl) {
        Ok(release) => Some(Erlang { erlc, erl, release }),
        Err(defect) => {
            skip_or_fail(&ERL, graded, &defect);
            None
        }
    }
}

fn otp_release(erl: &Path) -> Result<String, String> {
    let mut cmd: Command = Command::new(erl);
    cmd.arg("-noshell")
        .arg("-eval")
        .arg("io:format(\"~s\", [erlang:system_info(otp_release)]), halt().");
    match run_bounded(cmd) {
        Some((true, so, _)) if !so.trim().is_empty() => Ok(so.trim().to_owned()),
        Some((_, so, se)) => Err(format!(
            "`erl` is present at {} but did not report its release (stdout {:?}, stderr {:?}), so \
             the toolchain is installed and unusable rather than absent",
            erl.display(),
            so.trim(),
            se.trim()
        )),
        None => Err(format!(
            "`erl` at {} did not exit within {CALL_TIMEOUT:?}",
            erl.display()
        )),
    }
}

pub fn otp_version(erl: &Path) -> Result<String, String> {
    let expression: &str = "Release = erlang:system_info(otp_release), Path = filename:join([code:root_dir(), \"releases\", Release, \"OTP_VERSION\"]), case file:read_file(Path) of {ok, Version} -> io:format(\"~s\", [string:trim(binary_to_list(Version))]), halt(0); {error, Reason} -> io:format(standard_error, \"~p\", [Reason]), halt(1) end.";
    let mut cmd: Command = Command::new(erl);
    cmd.arg("-noshell").arg("-eval").arg(expression);
    match run_bounded(cmd) {
        Some((true, so, _)) if !so.trim().is_empty() => Ok(so.trim().to_owned()),
        Some((_, so, se)) => Err(format!(
            "`erl` is present at {} but could not read its OTP_VERSION file (stdout {:?}, stderr {:?})",
            erl.display(),
            so.trim(),
            se.trim()
        )),
        None => Err(format!(
            "`erl` at {} did not report its full OTP version within {CALL_TIMEOUT:?}",
            erl.display()
        )),
    }
}
