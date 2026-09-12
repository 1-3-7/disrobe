use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use disrobe_core::subprocess::{self, CapturedOutput};

pub(crate) const REQUIREMENT_VAR: &str = "DISROBE_TYPEREC_CC";
pub(crate) const GCC_BIN_VAR: &str = "DISROBE_GCC_BIN";
pub(crate) const OBJCOPY_BIN_VAR: &str = "DISROBE_OBJCOPY_BIN";

pub(crate) const CALL_TIMEOUT: Duration = Duration::from_mins(2);
const CAPTURE_CAP: usize = 1 << 20;
const NEUTRAL_BUILD_DIRECTORY: &str = "/disrobe/typerec";
const GCC_NAMES: [&str; 3] = ["gcc", "cc", "gcc-14"];
const OBJCOPY_NAMES: [&str; 2] = ["objcopy", "llvm-objcopy"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Requirement {
    RequireGnu,
    RequirePresent,
    Optional,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CcToolchain {
    pub(crate) gcc: PathBuf,
    pub(crate) objcopy: PathBuf,
    pub(crate) identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Probe {
    Usable(Box<CcToolchain>),
    NotGnu { identity: String },
    Missing { defect: String },
}

pub(crate) fn requirement() -> Requirement {
    let Some(raw): Option<OsString> = std::env::var_os(REQUIREMENT_VAR) else {
        return Requirement::RequirePresent;
    };
    match raw.to_string_lossy().trim().to_ascii_lowercase().as_str() {
        "" | "0" | "false" | "no" | "off" | "optional" => Requirement::Optional,
        "gnu" | "require-gnu" | "strict" => Requirement::RequireGnu,
        _ => Requirement::RequirePresent,
    }
}

const fn executable_suffixes() -> &'static [&'static str] {
    if cfg!(windows) {
        &["", ".exe", ".bat", ".cmd"]
    } else {
        &[""]
    }
}

pub(crate) fn find_on_path(names: &[&str], binary_var: &str) -> Option<PathBuf> {
    if let Some(raw) = std::env::var_os(binary_var) {
        let candidate: PathBuf = PathBuf::from(raw);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    let path_var: OsString = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path_var) {
        for name in names {
            for suffix in executable_suffixes() {
                let candidate: PathBuf = directory.join(format!("{name}{suffix}"));
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

pub(crate) fn run_bounded(mut command: Command) -> Option<CapturedOutput> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child: Child = command.spawn().ok()?;
    subprocess::wait_with_output_timeout(child, CALL_TIMEOUT, CAPTURE_CAP)
}

fn first_line(output: &CapturedOutput) -> String {
    let mut printed: String = String::from_utf8_lossy(&output.stdout).into_owned();
    if printed.trim().is_empty() {
        printed = String::from_utf8_lossy(&output.stderr).into_owned();
    }
    printed.lines().next().unwrap_or_default().trim().to_owned()
}

fn identity_of(program: &Path) -> Result<String, String> {
    let mut command: Command = Command::new(program);
    command.arg("--version");
    let Some(output): Option<CapturedOutput> = run_bounded(command) else {
        return Err(format!(
            "`{} --version` did not exit within {CALL_TIMEOUT:?}",
            program.display()
        ));
    };
    if output.exit_code != Some(0) {
        return Err(format!(
            "`{} --version` exited with {:?}",
            program.display(),
            output.exit_code
        ));
    }
    let line: String = first_line(&output);
    if line.is_empty() {
        return Err(format!(
            "`{} --version` printed nothing, so it cannot be identified",
            program.display()
        ));
    }
    Ok(line)
}

fn announces_gnu(identity: &str) -> bool {
    let lowered: String = identity.to_ascii_lowercase();
    if lowered.contains("clang") {
        return false;
    }
    lowered.contains("gcc") || lowered.contains("free software foundation")
}

pub(crate) fn probe() -> Probe {
    let Some(gcc): Option<PathBuf> = find_on_path(&GCC_NAMES, GCC_BIN_VAR) else {
        return Probe::Missing {
            defect: format!(
                "none of {} is on PATH and {GCC_BIN_VAR} does not name a file",
                GCC_NAMES.join(", ")
            ),
        };
    };
    let identity: String = match identity_of(&gcc) {
        Ok(identity) => identity,
        Err(defect) => return Probe::Missing { defect },
    };
    if !announces_gnu(&identity) {
        return Probe::NotGnu { identity };
    }
    let Some(objcopy): Option<PathBuf> = find_on_path(&OBJCOPY_NAMES, OBJCOPY_BIN_VAR) else {
        return Probe::Missing {
            defect: format!(
                "{} names a usable gcc but none of {} is on PATH, so a stripped input cannot be \
                 produced",
                gcc.display(),
                OBJCOPY_NAMES.join(", ")
            ),
        };
    };
    if let Err(defect) = identity_of(&objcopy) {
        return Probe::Missing { defect };
    }
    Probe::Usable(Box::new(CcToolchain {
        gcc,
        objcopy,
        identity,
    }))
}

#[allow(clippy::panic, clippy::print_stderr)]
pub(crate) fn require(graded: &str) -> Option<CcToolchain> {
    match probe() {
        Probe::Usable(toolchain) => Some(*toolchain),
        Probe::NotGnu { identity } => {
            assert!(
                requirement() != Requirement::RequireGnu,
                "{REQUIREMENT_VAR} demands a GNU C compiler on this host, so {graded} was measured \
                 against nothing and this case must not report success: the compiler here \
                 announces itself as {identity:?}. Install gcc, or point {GCC_BIN_VAR} at one; to \
                 permit a run that measures nothing here, set {REQUIREMENT_VAR}=optional."
            );
            eprintln!(
                "\nNOT MEASURED: {graded} graded nothing, because the C compiler on this host \
                 announces itself as {identity:?} rather than GNU cc, and this grade reads the \
                 debug information GNU cc emits. Set {REQUIREMENT_VAR}=gnu to fail instead.\n"
            );
            None
        }
        Probe::Missing { defect } => {
            assert!(
                requirement() == Requirement::Optional,
                "a GNU C compiler is mandatory for this run, so {graded} was measured against \
                 nothing and this case must not report success: {defect}. Install gcc and \
                 binutils, or point {GCC_BIN_VAR} and {OBJCOPY_BIN_VAR} at them; to permit a run \
                 that measures nothing here, set {REQUIREMENT_VAR}=optional."
            );
            eprintln!(
                "\nNOT MEASURED: {graded} graded nothing, because {defect}. {REQUIREMENT_VAR} is \
                 set to optional for this run.\n"
            );
            None
        }
    }
}

fn describe(program: &Path, arguments: &[OsString], output: &CapturedOutput) -> String {
    let printed: Vec<String> = arguments
        .iter()
        .map(|argument: &OsString| argument.to_string_lossy().into_owned())
        .collect();
    format!(
        "`{} {}` exited with {:?} and printed stdout {:?} and stderr {:?}",
        program.display(),
        printed.join(" "),
        output.exit_code,
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    )
}

fn call(program: &Path, arguments: &[OsString], work: &Path) -> Result<(), String> {
    let mut command: Command = Command::new(program);
    command.args(arguments).current_dir(work);
    let Some(output): Option<CapturedOutput> = run_bounded(command) else {
        return Err(format!(
            "`{}` did not exit within {CALL_TIMEOUT:?}",
            program.display()
        ));
    };
    if output.exit_code == Some(0) {
        return Ok(());
    }
    Err(describe(program, arguments, &output))
}

pub(crate) fn compile(
    toolchain: &CcToolchain,
    work: &Path,
    source: &OsStr,
    output: &OsStr,
    flags: &[&str],
) -> Result<(), String> {
    let mut arguments: Vec<OsString> = vec![OsString::from(format!(
        "-fdebug-prefix-map={}={NEUTRAL_BUILD_DIRECTORY}",
        work.display()
    ))];
    arguments.extend(flags.iter().map(OsString::from));
    arguments.push(OsString::from("-o"));
    arguments.push(output.to_owned());
    arguments.push(source.to_owned());
    call(&toolchain.gcc, &arguments, work)
}

pub(crate) fn strip_debug(
    toolchain: &CcToolchain,
    work: &Path,
    input: &OsStr,
    output: &OsStr,
) -> Result<(), String> {
    let arguments: Vec<OsString> = vec![
        OsString::from("--strip-debug"),
        input.to_owned(),
        output.to_owned(),
    ];
    call(&toolchain.objcopy, &arguments, work)
}

pub(crate) fn accepts_flag(toolchain: &CcToolchain, work: &Path, flag: &str) -> bool {
    let probe_source: PathBuf = work.join("disrobe_flag_probe.c");
    if std::fs::write(
        &probe_source,
        b"int disrobe_flag_probe(void) { return 0; }\n",
    )
    .is_err()
    {
        return false;
    }
    let arguments: Vec<OsString> = vec![
        OsString::from(flag),
        OsString::from("-c"),
        OsString::from("-o"),
        OsString::from("disrobe_flag_probe.o"),
        OsString::from("disrobe_flag_probe.c"),
    ];
    call(&toolchain.gcc, &arguments, work).is_ok()
}

pub(crate) fn stage_source(work: &Path, source: &Path) -> Result<OsString, String> {
    let Some(name): Option<&OsStr> = source.file_name() else {
        return Err(format!("{} has no file name", source.display()));
    };
    let staged: PathBuf = work.join(name);
    std::fs::copy(source, &staged).map_err(|error: std::io::Error| {
        format!("copy {} to {}: {error}", source.display(), staged.display())
    })?;
    Ok(name.to_owned())
}
