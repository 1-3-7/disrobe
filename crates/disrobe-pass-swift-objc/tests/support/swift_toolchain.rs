use std::ffi::OsString;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};

pub(crate) const DEMANGLER_PREREQUISITE: &str = "disrobe-pass-swift-objc::swift-demangle";
pub(crate) const SWIFTC_PREREQUISITE: &str = "disrobe-pass-swift-objc::swiftc";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerifiedToolchain {
    pub(crate) swift_banner: &'static str,
    pub(crate) demangler_banner: &'static str,
    pub(crate) host_triple: &'static str,
    pub(crate) verified_on: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CaptureToolchain {
    Unrecorded,
    Recorded(&'static str),
}

pub(crate) const REFERENCE_COLUMN_CAPTURED_FROM: CaptureToolchain = CaptureToolchain::Unrecorded;

pub(crate) const REFERENCE_COLUMN_REPRODUCED_BY: VerifiedToolchain = VerifiedToolchain {
    swift_banner: "Swift version 6.3.2 (swift-6.3.2-RELEASE)",
    demangler_banner: "LLVM version 21.1.6",
    host_triple: "x86_64-unknown-windows-msvc",
    verified_on: "2026-07-30",
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ToolchainIdentity {
    Reported {
        swift_banner: String,
        demangler_banner: String,
    },
    Unidentifiable {
        defect: String,
    },
}

impl ToolchainIdentity {
    pub(crate) fn describe(&self) -> String {
        match self {
            Self::Reported {
                swift_banner,
                demangler_banner,
            } => format!("{swift_banner} ({demangler_banner})"),
            Self::Unidentifiable { defect } => {
                format!("an unidentifiable Swift toolchain ({defect})")
            }
        }
    }

    pub(crate) fn is_the_reproducing_toolchain(&self) -> bool {
        match self {
            Self::Reported { swift_banner, .. } => {
                swift_banner.contains(REFERENCE_COLUMN_REPRODUCED_BY.swift_banner)
            }
            Self::Unidentifiable { .. } => false,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ReferenceDemangler {
    pub(crate) tool: PathBuf,
    pub(crate) identity: ToolchainIdentity,
}

fn executable(stem: &str) -> String {
    if cfg!(windows) {
        format!("{stem}.exe")
    } else {
        stem.to_owned()
    }
}

pub(crate) fn find_on_path(stem: &str) -> Option<PathBuf> {
    let exe: String = executable(stem);
    let path_var: OsString = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var)
        .map(|dir: PathBuf| dir.join(&exe))
        .find(|candidate: &PathBuf| candidate.is_file())
}

pub(crate) fn resolve_reference_demangler(graded: &str) -> Option<ReferenceDemangler> {
    let Some(tool): Option<PathBuf> = find_on_path("swift-demangle") else {
        absent(
            DEMANGLER_PREREQUISITE,
            graded,
            "swift-demangle is not on PATH",
        );
        return None;
    };
    let identity: ToolchainIdentity = identify(&tool);
    Some(ReferenceDemangler { tool, identity })
}

pub(crate) fn resolve_swift_compiler(graded: &str) -> Option<PathBuf> {
    let Some(tool): Option<PathBuf> = find_on_path("swiftc") else {
        absent(SWIFTC_PREREQUISITE, graded, "swiftc is not on PATH");
        return None;
    };
    Some(tool)
}

fn identify(tool: &Path) -> ToolchainIdentity {
    let demangler_banner: Result<String, String> = version_line(tool, &["--version"]);
    let swift: Option<PathBuf> = sibling_swift(tool).or_else(|| find_on_path("swift"));
    let swift_banner: Result<String, String> = swift.map_or_else(
        || Err("no swift executable sits beside swift-demangle or on PATH".to_owned()),
        |swift: PathBuf| version_line(&swift, &["--version"]),
    );
    match (swift_banner, demangler_banner) {
        (Ok(swift_banner), Ok(demangler_banner)) => ToolchainIdentity::Reported {
            swift_banner,
            demangler_banner,
        },
        (Err(defect), _) | (_, Err(defect)) => ToolchainIdentity::Unidentifiable { defect },
    }
}

fn sibling_swift(tool: &Path) -> Option<PathBuf> {
    let candidate: PathBuf = tool.parent()?.join(executable("swift"));
    candidate.is_file().then_some(candidate)
}

fn version_line(program: &Path, args: &[&str]) -> Result<String, String> {
    let output: Output = match Command::new(program).args(args).output() {
        Ok(output) => output,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Err(format!("{} disappeared before it ran", program.display()));
        }
        Err(error) => {
            return Err(format!(
                "{} could not be launched ({error})",
                program.display()
            ));
        }
    };
    if !output.status.success() {
        return Err(format!(
            "{} --version exited with {}",
            program.display(),
            output.status
        ));
    }
    let text: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    let combined: String = format!("{text}\n{stderr}");
    let versioned: Option<&str> = combined
        .lines()
        .map(str::trim)
        .filter(|line: &&str| !line.is_empty())
        .find(|line: &&str| line.to_ascii_lowercase().contains("version"));
    let fallback: Option<&str> = combined
        .lines()
        .map(str::trim)
        .find(|line: &&str| !line.is_empty());
    versioned.or(fallback).map(str::to_owned).ok_or_else(|| {
        format!(
            "{} --version printed nothing that names a version",
            program.display()
        )
    })
}

pub(crate) fn absent(prerequisite: &str, graded: &str, defect: &str) {
    let what: String =
        format!("a Swift toolchain on PATH to compare {graded} against the real tool ({defect})");
    if let Err(error) = disrobe_testkit::require::<()>(prerequisite, &what, None) {
        panic!("{error}");
    }
}

pub(crate) fn provenance_note(identity: &ToolchainIdentity) -> String {
    let capture: String = match REFERENCE_COLUMN_CAPTURED_FROM {
        CaptureToolchain::Unrecorded => "the pinned reference text records no capture toolchain, \
                                        so nothing here names the Swift release it was first \
                                        taken from"
            .to_owned(),
        CaptureToolchain::Recorded(banner) => {
            format!("the pinned reference text was captured from {banner}")
        }
    };
    let reproduced: String = format!(
        "it was reproduced byte for byte by {} / {} on {} ({})",
        REFERENCE_COLUMN_REPRODUCED_BY.swift_banner,
        REFERENCE_COLUMN_REPRODUCED_BY.demangler_banner,
        REFERENCE_COLUMN_REPRODUCED_BY.host_triple,
        REFERENCE_COLUMN_REPRODUCED_BY.verified_on
    );
    let verdict: &str = if identity.is_the_reproducing_toolchain() {
        "this run uses that same Swift release, so a difference here is a change in the pinned \
         text rather than drift between toolchains"
    } else {
        "this run uses a different Swift release, and swift-demangle output is known to drift \
         across releases (specialization text most of all), so a difference here may be drift \
         rather than a recovery regression; reproduce it on the release named above before \
         re-pinning anything"
    };
    format!(
        "{capture}, but {reproduced}. This run demangled with {}. {verdict}.",
        identity.describe()
    )
}

pub(crate) fn reference_demangle(demangler: &ReferenceDemangler, symbols: &[&str]) -> Vec<String> {
    let joined: String = symbols.join("\n");
    let tool: &Path = demangler.tool.as_path();
    let mut child: Child = Command::new(tool)
        .arg("--compact")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|error: std::io::Error| {
            panic!(
                "{} is on PATH but could not be started ({error}); a reference demangler that is \
                 present and unusable is never a skip",
                tool.display()
            )
        });
    let mut stdin: std::process::ChildStdin = child
        .stdin
        .take()
        .expect("the child was spawned with a piped stdin");
    stdin
        .write_all(joined.as_bytes())
        .expect("write the symbol list to the reference demangler");
    drop(stdin);
    let output: Output = child
        .wait_with_output()
        .expect("collect the reference demangler output");
    assert!(
        output.status.success(),
        "{} exited with {}; a reference demangler that is present and failing is never a skip",
        tool.display(),
        output.status
    );
    let text: String = String::from_utf8(output.stdout)
        .expect("the reference demangler emits utf-8 on its stdout");
    let lines: Vec<String> = text.lines().map(str::to_owned).collect();
    assert_eq!(
        lines.len(),
        symbols.len(),
        "{} answered {} of {} symbols; a partial reference answer is never a skip",
        tool.display(),
        lines.len(),
        symbols.len()
    );
    lines
}
