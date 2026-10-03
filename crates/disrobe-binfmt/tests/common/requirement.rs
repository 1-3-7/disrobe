use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use super::{corpus_binfmt_root, fixture_path};

const WINDOWS_EXECUTABLE_SUFFIXES: [&str; 5] = [".exe", ".com", ".bat", ".cmd", ""];
const POSIX_EXECUTABLE_SUFFIXES: [&str; 1] = [""];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Toolchain {
    pub program: &'static str,
    pub programs: &'static [&'static str],
    pub install_paths: &'static [&'static str],
    pub identity: Option<&'static str>,
    pub probe_arguments: &'static [&'static str],
    pub prerequisite: &'static str,
    pub install_hint: &'static str,
}

pub const MAKECAB: Toolchain = Toolchain {
    program: "makecab",
    programs: &["makecab"],
    install_paths: &[],
    identity: None,
    probe_arguments: &[],
    prerequisite: "disrobe-binfmt::makecab",
    install_hint: "run on Windows, where makecab.exe ships in System32, or put makecab on PATH",
};

pub const SEVEN_ZIP: Toolchain = Toolchain {
    program: "7z",
    programs: &["7z", "7za", "7zz", "7zr"],
    install_paths: &[],
    identity: Some("7-Zip"),
    probe_arguments: &[],
    prerequisite: "disrobe-binfmt::7z",
    install_hint: "install 7-Zip and put 7z, 7za, 7zz or 7zr on PATH",
};

pub const WIX: Toolchain = Toolchain {
    program: "wix",
    programs: &["wix"],
    install_paths: &[],
    identity: None,
    probe_arguments: &[],
    prerequisite: "disrobe-binfmt::wix",
    install_hint: "install the WiX toolset and put candle.exe and light.exe, or wix.exe, on PATH",
};

pub const MAKENSIS: Toolchain = Toolchain {
    program: "makensis",
    programs: &["makensis"],
    install_paths: &[],
    identity: None,
    probe_arguments: &[],
    prerequisite: "disrobe-binfmt::makensis",
    install_hint: "install NSIS and put makensis on PATH",
};

pub const PYTHON: Toolchain = Toolchain {
    program: "python",
    programs: &["python", "python3"],
    install_paths: &[],
    identity: Some("Python 3"),
    probe_arguments: &["--version"],
    prerequisite: "disrobe-binfmt::python",
    install_hint: "install CPython 3.8 or newer and put python on PATH",
};

pub const LLVM_READOBJ: Toolchain = Toolchain {
    program: "llvm-readobj",
    programs: &["llvm-readobj"],
    install_paths: &[],
    identity: None,
    probe_arguments: &[],
    prerequisite: "disrobe-binfmt::llvm-readobj",
    install_hint: "install llvm (llvm-readobj) and put it on PATH",
};

pub const BUN: Toolchain = Toolchain {
    program: "bun",
    programs: &["bun"],
    install_paths: &[],
    identity: None,
    probe_arguments: &[],
    prerequisite: "disrobe-binfmt::bun",
    install_hint: "install Bun and put bun on PATH",
};

pub const CABEXTRACT: Toolchain = Toolchain {
    program: "cabextract",
    programs: &["cabextract"],
    install_paths: &[],
    identity: Some("cabextract"),
    probe_arguments: &[],
    prerequisite: "disrobe-binfmt::cabextract",
    install_hint: "install cabextract and put it on PATH",
};

pub const READELF: Toolchain = Toolchain {
    program: "readelf",
    programs: &["readelf", "llvm-readelf", "eu-readelf"],
    install_paths: &[],
    identity: None,
    probe_arguments: &[],
    prerequisite: "disrobe-binfmt::readelf",
    install_hint: "install binutils (readelf), llvm (llvm-readelf) or elfutils (eu-readelf) and put \
                   it on PATH",
};

const fn executable_suffixes() -> &'static [&'static str] {
    if cfg!(windows) {
        &WINDOWS_EXECUTABLE_SUFFIXES
    } else {
        &POSIX_EXECUTABLE_SUFFIXES
    }
}

pub fn path_directories() -> Vec<PathBuf> {
    let Some(path_var): Option<OsString> = std::env::var_os("PATH") else {
        return Vec::new();
    };
    std::env::split_paths(&path_var).collect()
}

fn candidates(
    toolchain: &Toolchain,
    directories: &[PathBuf],
    install_paths: &[&str],
) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();
    let mut remember = |candidate: PathBuf| {
        if candidate.is_file() && !found.contains(&candidate) {
            found.push(candidate);
        }
    };
    for program in toolchain.programs {
        for directory in directories {
            for suffix in executable_suffixes() {
                remember(directory.join(format!("{program}{suffix}")));
            }
        }
    }
    for literal in install_paths {
        remember(PathBuf::from(literal));
    }
    found
}

const BUSY_EXECUTABLE_ATTEMPTS: u32 = 20;
const BUSY_EXECUTABLE_BACKOFF: std::time::Duration = std::time::Duration::from_millis(25);

fn run_candidate(candidate: &Path, arguments: &[&str]) -> std::io::Result<Output> {
    let mut attempt: u32 = 1;
    loop {
        match Command::new(candidate)
            .args(arguments)
            .stdin(Stdio::null())
            .output()
        {
            Err(error)
                if error.kind() == std::io::ErrorKind::ExecutableFileBusy
                    && attempt < BUSY_EXECUTABLE_ATTEMPTS =>
            {
                attempt += 1;
                std::thread::sleep(BUSY_EXECUTABLE_BACKOFF);
            }
            outcome => return outcome,
        }
    }
}

fn starts(candidate: &Path, toolchain: &Toolchain) -> Result<(), String> {
    let outcome: std::io::Result<Output> = run_candidate(candidate, toolchain.probe_arguments);
    let output: Output = match outcome {
        Ok(output) => output,
        Err(error) => {
            return Err(format!(
                "this process cannot start {} ({error})",
                candidate.display()
            ));
        }
    };
    let Some(identity): Option<&'static str> = toolchain.identity else {
        return Ok(());
    };
    let mut printed: String = String::from_utf8_lossy(&output.stdout).into_owned();
    printed.push('\n');
    printed.push_str(&String::from_utf8_lossy(&output.stderr));
    let announces: bool = printed
        .lines()
        .any(|line: &str| line.trim_start().starts_with(identity));
    if announces {
        return Ok(());
    }
    Err(format!(
        "{} started but never named itself {identity}, so it is a different program that carries \
         the same name",
        candidate.display()
    ))
}

fn resolve(
    toolchain: &Toolchain,
    directories: &[PathBuf],
    install_paths: &[&str],
) -> Result<PathBuf, String> {
    let candidates: Vec<PathBuf> = candidates(toolchain, directories, install_paths);
    if candidates.is_empty() {
        return Err(format!(
            "no {names} file exists on PATH",
            names = toolchain.programs.join(", ")
        ));
    }
    let mut refused: Vec<String> = Vec::new();
    for candidate in candidates {
        match starts(&candidate, toolchain) {
            Ok(()) => return Ok(candidate),
            Err(reason) => refused.push(reason),
        }
    }
    Err(format!(
        "a file named {names} exists here but none of them is a usable {program}: {reasons}",
        names = toolchain.programs.join(", "),
        program = toolchain.program,
        reasons = refused.join("; ")
    ))
}

pub fn locate(toolchain: &Toolchain) -> Result<PathBuf, String> {
    resolve(toolchain, &path_directories(), toolchain.install_paths)
}

pub fn locate_in(toolchain: &Toolchain, directories: &[PathBuf]) -> Result<PathBuf, String> {
    resolve(toolchain, directories, &[])
}

pub fn describe_run(program: &Path, arguments: &[&str], output: &Output) -> String {
    format!(
        "`{} {}` exited with {} and printed stdout {:?} and stderr {:?}",
        program.display(),
        arguments.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    )
}

#[allow(clippy::panic)]
pub fn unmeasured(toolchain: &Toolchain, graded: &str, defect: &str) {
    let what: String = format!(
        "a usable {program} ({defect}); to fix it, {hint}",
        program = toolchain.program,
        hint = toolchain.install_hint,
    );
    if let Err(error) = disrobe_testkit::require::<()>(toolchain.prerequisite, &what, None) {
        panic!("{graded} was measured against nothing and must not report success: {error}");
    }
}

#[allow(clippy::panic)]
pub fn regenerable_fixture(format_dir: &str, filename: &str, graded: &str) -> Option<Vec<u8>> {
    let path: PathBuf = fixture_path(format_dir, filename);
    let found: Option<Vec<u8>> = std::fs::read(&path).ok();
    let what: String = format!(
        "{}, a local-only artifact kept out of the tree that corpus/binfmt/MANIFEST.toml records \
         how to rebuild for {format_dir}",
        path.display()
    );
    let prerequisite: String = format!("disrobe-binfmt::regenerable::{format_dir}");
    match disrobe_testkit::require(&prerequisite, &what, found) {
        Ok(available) => available.present(),
        Err(error) => panic!("{graded} graded nothing and must not report success: {error}"),
    }
}

#[allow(clippy::panic)]
pub fn required_fixture(format_dir: &str, filename: &str) -> Vec<u8> {
    let path: PathBuf = fixture_path(format_dir, filename);
    std::fs::read(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "corpus/binfmt/{format_dir}/{filename} is tracked in git and this case grades nothing \
             without it, so its absence is a damaged checkout and not an optional dependency: \
             {error} ({})",
            path.display()
        )
    })
}

pub fn corpus_path(relative: &str) -> PathBuf {
    let mut root: PathBuf = corpus_binfmt_root();
    root.pop();
    root.join(relative)
}

#[allow(clippy::panic)]
pub fn required_corpus(relative: &str) -> Vec<u8> {
    let path: PathBuf = corpus_path(relative);
    std::fs::read(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "corpus/{relative} is tracked in git and this case grades nothing without it, so its \
             absence is a damaged checkout and not an optional dependency: {error} ({})",
            path.display()
        )
    })
}
