use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use super::{corpus_binfmt_root, fixture_path};

pub const REQUIRE_ALL_VAR: &str = "DISROBE_REQUIRE_BINFMT_TOOLS";
pub const REQUIRE_FIXTURES_VAR: &str = "DISROBE_REQUIRE_BINFMT_FIXTURES";

const WINDOWS_EXECUTABLE_SUFFIXES: [&str; 5] = [".exe", ".com", ".bat", ".cmd", ""];
const POSIX_EXECUTABLE_SUFFIXES: [&str; 1] = [""];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Toolchain {
    pub program: &'static str,
    pub programs: &'static [&'static str],
    pub install_paths: &'static [&'static str],
    pub identity: Option<&'static str>,
    pub require_var: &'static str,
    pub install_hint: &'static str,
}

pub const MAKECAB: Toolchain = Toolchain {
    program: "makecab",
    programs: &["makecab"],
    install_paths: &[r"C:\Windows\System32\makecab.exe"],
    identity: None,
    require_var: "DISROBE_REQUIRE_MAKECAB",
    install_hint: "run on Windows, where makecab.exe ships in System32, or put makecab on PATH",
};

pub const SEVEN_ZIP: Toolchain = Toolchain {
    program: "7z",
    programs: &["7z", "7za", "7zz", "7zr"],
    install_paths: &[
        r"C:\Program Files\7-Zip\7z.exe",
        r"C:\Program Files (x86)\7-Zip\7z.exe",
    ],
    identity: Some("7-Zip"),
    require_var: "DISROBE_REQUIRE_SEVEN_ZIP",
    install_hint: "install 7-Zip and put 7z, 7za, 7zz or 7zr on PATH",
};

pub const WIX: Toolchain = Toolchain {
    program: "wix",
    programs: &["wix"],
    install_paths: &[
        r"C:\Program Files\WiX Toolset v7.0\bin\wix.exe",
        r"C:\Program Files\WiX Toolset v6.0\bin\wix.exe",
        r"C:\Program Files (x86)\WiX Toolset v7.0\bin\wix.exe",
    ],
    identity: None,
    require_var: "DISROBE_REQUIRE_WIX",
    install_hint: "install the WiX toolset and put candle.exe and light.exe, or wix.exe, on PATH",
};

pub const MAKENSIS: Toolchain = Toolchain {
    program: "makensis",
    programs: &["makensis"],
    install_paths: &[
        r"C:\Program Files (x86)\NSIS\makensis.exe",
        r"C:\Program Files\NSIS\makensis.exe",
    ],
    identity: None,
    require_var: "DISROBE_REQUIRE_MAKENSIS",
    install_hint: "install NSIS and put makensis on PATH",
};

pub const READELF: Toolchain = Toolchain {
    program: "readelf",
    programs: &["readelf", "llvm-readelf", "eu-readelf"],
    install_paths: &[],
    identity: None,
    require_var: "DISROBE_REQUIRE_READELF",
    install_hint: "install binutils (readelf), llvm (llvm-readelf) or elfutils (eu-readelf) and put \
                   it on PATH",
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement {
    Optional,
    Mandatory,
}

pub fn requirement_from_values(per_tool: Option<&OsStr>, blanket: Option<&OsStr>) -> Requirement {
    if asks_for_it(per_tool) || asks_for_it(blanket) {
        return Requirement::Mandatory;
    }
    Requirement::Optional
}

pub fn requirement(toolchain: &Toolchain) -> Requirement {
    let per_tool: Option<OsString> = std::env::var_os(toolchain.require_var);
    let blanket: Option<OsString> = std::env::var_os(REQUIRE_ALL_VAR);
    requirement_from_values(per_tool.as_deref(), blanket.as_deref())
}

fn asks_for_it(value: Option<&OsStr>) -> bool {
    let Some(raw): Option<&OsStr> = value else {
        return false;
    };
    !matches!(
        raw.to_string_lossy().trim().to_ascii_lowercase().as_str(),
        "" | "0" | "false" | "no" | "off" | "optional"
    )
}

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

fn starts(candidate: &Path, toolchain: &Toolchain) -> Result<(), String> {
    let outcome: std::io::Result<Output> = Command::new(candidate).stdin(Stdio::null()).output();
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
            "no {names} file exists on PATH or in the standard install directories",
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

pub fn unmeasured(toolchain: &Toolchain, graded: &str, defect: &str) {
    enforce(toolchain, graded, defect, requirement(toolchain));
}

#[allow(clippy::panic, clippy::print_stderr)]
pub fn enforce(toolchain: &Toolchain, graded: &str, defect: &str, requirement: Requirement) {
    assert!(
        requirement != Requirement::Mandatory,
        "{var} (or {all}) makes the {program} toolchain mandatory for this run, so {graded} was \
         measured against nothing and this case must not report success: {defect}. To fix it, \
         {hint}; to permit a run that measures nothing here, clear both variables.",
        var = toolchain.require_var,
        all = REQUIRE_ALL_VAR,
        program = toolchain.program,
        hint = toolchain.install_hint,
    );
    eprintln!(
        "\nNOT MEASURED: {graded} was compared against nothing and graded nothing, because the \
         {program} toolchain is not usable here ({defect}). Set {var}=1 (or {all}=1) to fail \
         instead of skipping when {program} cannot produce the reference archive.\n",
        program = toolchain.program,
        var = toolchain.require_var,
        all = REQUIRE_ALL_VAR,
    );
}

#[allow(clippy::print_stderr)]
pub fn regenerable_fixture(format_dir: &str, filename: &str, graded: &str) -> Option<Vec<u8>> {
    let path: PathBuf = fixture_path(format_dir, filename);
    if let Ok(bytes) = std::fs::read(&path) {
        return Some(bytes);
    }
    assert!(
        !asks_for_it(std::env::var_os(REQUIRE_FIXTURES_VAR).as_deref()),
        "{REQUIRE_FIXTURES_VAR} makes the regenerable binfmt fixtures mandatory for this run, so \
         {graded} was measured against nothing and this case must not report success: {} is \
         absent. Build it with the recipe corpus/binfmt/MANIFEST.toml records for {format_dir}; to \
         permit a run that grades nothing here, clear {REQUIRE_FIXTURES_VAR}.",
        path.display()
    );
    eprintln!(
        "\nNOT MEASURED: {graded} graded nothing, because {} is absent. It is a multi-megabyte \
         artifact a blanket .gitignore rule keeps out of the tree; corpus/binfmt/MANIFEST.toml \
         records how to rebuild it. Set {REQUIRE_FIXTURES_VAR}=1 to fail instead of skipping.\n",
        path.display()
    );
    None
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
