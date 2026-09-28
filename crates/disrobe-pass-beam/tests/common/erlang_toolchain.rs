#![allow(clippy::panic)]

use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use wait_timeout::ChildExt;

pub const CALL_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Toolchain {
    pub program: &'static str,
    pub install_hint: &'static str,
}

pub const ERLC: Toolchain = Toolchain {
    program: "erlc",
    install_hint: "install Erlang/OTP 27.3.4, the release CI pins, and put erlc on PATH",
};

pub const ERL: Toolchain = Toolchain {
    program: "erl",
    install_hint: "install Erlang/OTP 27.3.4, the release CI pins, and put erl on PATH",
};

pub const ELIXIRC: Toolchain = Toolchain {
    program: "elixirc",
    install_hint: "install Elixir 1.18.4, the release CI pins, and put elixirc on PATH",
};

#[derive(Debug, Clone)]
pub struct Erlang {
    pub erlc: PathBuf,
    pub erl: PathBuf,
    pub release: String,
}

pub fn find_on_path(name: &str) -> Option<PathBuf> {
    let path_var: OsString = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        for ext in candidate_extensions() {
            let candidate: PathBuf = dir.join(format!("{name}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn candidate_extensions() -> &'static [&'static str] {
    if cfg!(windows) {
        &[".cmd", ".bat", ".exe", ""]
    } else {
        &[""]
    }
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

#[allow(clippy::panic)]
fn missing(toolchain: &Toolchain, graded: &str, defect: &str) -> ! {
    panic!(
        "{graded} is graded only by running {program}, and every CI job that runs these tests \
         provisions it, so this case fails rather than report a success that measured nothing: \
         {defect}. To fix it, {hint}.",
        program = toolchain.program,
        hint = toolchain.install_hint,
    )
}

pub fn require(toolchain: &Toolchain, graded: &str) -> PathBuf {
    find_on_path(toolchain.program).unwrap_or_else(|| {
        missing(
            toolchain,
            graded,
            &format!(
                "`{}` is not on PATH, so the toolchain is not installed here",
                toolchain.program
            ),
        )
    })
}

pub fn require_erlang(graded: &str) -> Erlang {
    let erlc: PathBuf = require(&ERLC, graded);
    let erl: PathBuf = require(&ERL, graded);
    let release: String =
        otp_release(&erl).unwrap_or_else(|defect: String| missing(&ERL, graded, &defect));
    Erlang { erlc, erl, release }
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

#[cfg(test)]
mod tests {
    use super::candidate_extensions;

    #[test]
    fn windows_prefers_command_wrappers_before_extensionless_launchers() {
        let actual: &[&str] = candidate_extensions();
        let expected: &[&str] = if cfg!(windows) {
            &[".cmd", ".bat", ".exe", ""]
        } else {
            &[""]
        };
        assert_eq!(actual, expected);
    }
}
