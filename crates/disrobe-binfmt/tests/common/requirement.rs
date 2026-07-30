use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use super::{corpus_binfmt_root, fixture_path};

pub const REQUIRE_ALL_VAR: &str = "DISROBE_REQUIRE_BINFMT_TOOLS";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Toolchain {
    pub program: &'static str,
    pub require_var: &'static str,
    pub install_hint: &'static str,
}

pub const MAKECAB: Toolchain = Toolchain {
    program: "makecab",
    require_var: "DISROBE_REQUIRE_MAKECAB",
    install_hint: "run on Windows, where makecab.exe ships in System32, or put makecab on PATH",
};

pub const SEVEN_ZIP: Toolchain = Toolchain {
    program: "7z",
    require_var: "DISROBE_REQUIRE_SEVEN_ZIP",
    install_hint: "install 7-Zip and put 7z, 7za, 7zz or 7zr on PATH",
};

pub const WIX: Toolchain = Toolchain {
    program: "wix",
    require_var: "DISROBE_REQUIRE_WIX",
    install_hint: "install the WiX toolset and put candle.exe and light.exe, or wix.exe, on PATH",
};

pub const MAKENSIS: Toolchain = Toolchain {
    program: "makensis",
    require_var: "DISROBE_REQUIRE_MAKENSIS",
    install_hint: "install NSIS and put makensis on PATH",
};

pub const READELF: Toolchain = Toolchain {
    program: "readelf",
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

pub fn find_on_path(name: &str) -> Option<PathBuf> {
    let path_var: OsString = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path_var) {
        for suffix in ["", ".exe", ".bat", ".cmd"] {
            let candidate: PathBuf = directory.join(format!("{name}{suffix}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
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
