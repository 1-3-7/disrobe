use std::ffi::{OsStr, OsString};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Toolchain {
    pub(crate) program: &'static str,
    pub(crate) binary_var: &'static str,
    pub(crate) require_var: &'static str,
    pub(crate) install_hint: &'static str,
}

pub(crate) const PHP: Toolchain = Toolchain {
    program: "php",
    binary_var: "DISROBE_PHP_BIN",
    require_var: "DISROBE_REQUIRE_PHP",
    install_hint: "install php 8.x and put it on PATH, or point DISROBE_PHP_BIN at the binary",
};

pub(crate) const PHP_OPCACHE: Toolchain = Toolchain {
    program: "php opcache",
    binary_var: "DZOA_OPCACHE_DLL",
    require_var: "DISROBE_REQUIRE_PHP_OPCACHE",
    install_hint: "install the opcache extension beside the php binary, or point DZOA_OPCACHE_DLL \
                   at it",
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ToolchainRequirement {
    Optional,
    Mandatory,
}

#[derive(Debug, Clone)]
pub(crate) struct PhpRuntime {
    pub(crate) binary: PathBuf,
    pub(crate) banner: String,
}

#[derive(Debug, Clone)]
pub(crate) struct PhpRun {
    pub(crate) exited_clean: bool,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: String,
}

pub(crate) fn requirement_from_value(value: Option<&OsStr>) -> ToolchainRequirement {
    let Some(raw): Option<&OsStr> = value else {
        return ToolchainRequirement::Optional;
    };
    let text: String = raw.to_string_lossy().trim().to_ascii_lowercase();
    match text.as_str() {
        "" | "0" | "false" | "no" | "off" | "optional" => ToolchainRequirement::Optional,
        _ => ToolchainRequirement::Mandatory,
    }
}

pub(crate) fn requirement(toolchain: &Toolchain) -> ToolchainRequirement {
    let raw: Option<OsString> = std::env::var_os(toolchain.require_var);
    requirement_from_value(raw.as_deref())
}

pub(crate) fn enforce_requirement(
    toolchain: &Toolchain,
    graded: &str,
    defect: &str,
    requirement: ToolchainRequirement,
) {
    assert!(
        requirement == ToolchainRequirement::Optional,
        "{var} makes the {program} toolchain mandatory for this run, so {graded} cannot be measured \
         and this case must not report success: {defect}. To fix it, {hint}; to permit a run that \
         measures nothing here, clear {var}.",
        var = toolchain.require_var,
        program = toolchain.program,
        hint = toolchain.install_hint,
    );
    announce_unmeasured(toolchain, graded, defect);
}

fn announce_unmeasured(toolchain: &Toolchain, graded: &str, defect: &str) {
    let line: String = format!(
        "\nNOT MEASURED: {graded} was compared against nothing and graded nothing, because the \
         {program} toolchain is not usable here ({defect}). Set {var}=1 to fail instead of skipping \
         when {program} cannot be run.\n",
        program = toolchain.program,
        var = toolchain.require_var,
    );
    let mut sink: std::io::StdoutLock<'static> = std::io::stdout().lock();
    drop(sink.write_all(line.as_bytes()));
    drop(sink.flush());
}

fn configured_binary(toolchain: &Toolchain) -> Result<PathBuf, String> {
    let Some(explicit): Option<OsString> = std::env::var_os(toolchain.binary_var) else {
        return Ok(PathBuf::from(toolchain.program));
    };
    let path: PathBuf = PathBuf::from(&explicit);
    if path.as_os_str().is_empty() {
        return Ok(PathBuf::from(toolchain.program));
    }
    if path.exists() {
        return Ok(path);
    }
    Err(format!(
        "{var} points at {} which does not exist",
        path.display(),
        var = toolchain.binary_var
    ))
}

fn version_output(toolchain: &Toolchain, binary: &Path, graded: &str) -> Result<Output, String> {
    match Command::new(binary).arg("--version").output() {
        Ok(output) if output.status.success() => Ok(output),
        Ok(output) => panic!(
            "{program} was launched from {} but `{program} --version` exited with {status}, so \
             {graded} cannot be measured. A toolchain that runs and fails is never a skip, because \
             that is how a half-installed interpreter silently stops grading.",
            binary.display(),
            program = toolchain.program,
            status = output.status,
        ),
        Err(err) if err.kind() == ErrorKind::NotFound => {
            Err(format!("{} was not found on PATH", toolchain.program))
        }
        Err(err) => panic!(
            "{program} could not be launched from {} ({err}), so {graded} cannot be measured. A \
             toolchain that is present but unrunnable is never a skip, because that is how a \
             permissions or quarantine problem silently stops grading.",
            binary.display(),
            program = toolchain.program,
        ),
    }
}

pub(crate) fn require_with_requirement(
    toolchain: &Toolchain,
    graded: &str,
    requirement: ToolchainRequirement,
) -> Option<PhpRuntime> {
    let binary: PathBuf = match configured_binary(toolchain) {
        Ok(binary) => binary,
        Err(defect) => {
            enforce_requirement(toolchain, graded, &defect, requirement);
            return None;
        }
    };
    let output: Output = match version_output(toolchain, &binary, graded) {
        Ok(output) => output,
        Err(defect) => {
            enforce_requirement(toolchain, graded, &defect, requirement);
            return None;
        }
    };
    let banner: String = String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned();
    Some(PhpRuntime { binary, banner })
}

pub(crate) fn require_php(graded: &str) -> Option<PhpRuntime> {
    require_with_requirement(&PHP, graded, requirement(&PHP))
}

pub(crate) fn unmeasured(toolchain: &Toolchain, graded: &str, defect: &str) {
    enforce_requirement(toolchain, graded, defect, requirement(toolchain));
}

static SCRATCH_SEQ: AtomicU64 = AtomicU64::new(0);

impl PhpRuntime {
    pub(crate) fn run(&self, label: &str, source: &[u8]) -> PhpRun {
        self.run_with(label, source, &["error_reporting=0", "display_errors=0"])
    }

    pub(crate) fn run_reporting_errors(&self, label: &str, source: &[u8]) -> PhpRun {
        self.run_with(
            label,
            source,
            &["error_reporting=E_ALL", "display_errors=1"],
        )
    }

    fn run_with(&self, label: &str, source: &[u8], settings: &[&str]) -> PhpRun {
        let seq: u64 = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
        let purpose: String = format!("disrobe_php_run_{}_{seq}", std::process::id());
        let (scratch, mut file): (disrobe_core::scratch::ScratchFile, std::fs::File) =
            disrobe_core::scratch::ScratchFile::create(&purpose, "php").unwrap_or_else(
                |err: std::io::Error| {
                    panic!("{label}: could not create a scratch php file to grade against: {err}")
                },
            );
        let path: PathBuf = scratch.path().to_path_buf();
        file.write_all(source)
            .unwrap_or_else(|err: std::io::Error| {
                panic!("{label}: could not write the php source to grade: {err}")
            });
        drop(file);
        let mut command: Command = Command::new(&self.binary);
        for setting in settings {
            command.arg("-d").arg(setting);
        }
        let output: Output = command
            .arg(&path)
            .output()
            .unwrap_or_else(|err: std::io::Error| {
                panic!(
                    "{label}: {} answered --version a moment ago but could not run {}: {err}",
                    self.binary.display(),
                    path.display()
                )
            });
        PhpRun {
            exited_clean: output.status.success(),
            stdout: output.stdout,
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        }
    }

    pub(crate) fn stdout_of(&self, label: &str, source: &[u8]) -> Vec<u8> {
        let run: PhpRun = self.run(label, source);
        assert!(
            run.exited_clean,
            "{label}: php exited with a failure, so this case graded nothing; stderr `{}`\n--- \
             source ---\n{}",
            run.stderr,
            String::from_utf8_lossy(source)
        );
        run.stdout
    }
}

pub(crate) fn with_open_tag(source: &str) -> String {
    let trimmed: &str = source.trim_start();
    if trimmed.starts_with("<?php") || trimmed.starts_with("<?") {
        source.to_owned()
    } else {
        format!("<?php {source}")
    }
}

pub(crate) const DECODE_PRIMITIVES: [&str; 16] = [
    "base64_decode",
    "gzinflate",
    "gzuncompress",
    "gzdecode",
    "str_rot13",
    "strrev",
    "hex2bin",
    "convert_uudecode",
    "urldecode",
    "rawurldecode",
    "create_function",
    "preg_replace",
    "eval(",
    "assert(",
    "pack(",
    "strtr(",
];

pub(crate) fn residual_decode_primitives(source: &str) -> Vec<&'static str> {
    DECODE_PRIMITIVES
        .iter()
        .copied()
        .filter(|needle: &&'static str| source.contains(needle))
        .collect()
}

pub(crate) fn repo_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root
}

pub(crate) fn corpus_path(rel: &str) -> PathBuf {
    let mut path: PathBuf = repo_root();
    path.push("corpus");
    path.push("php");
    for seg in rel.split('/') {
        path.push(seg);
    }
    path
}

pub(crate) fn required_corpus(rel: &str) -> Vec<u8> {
    let path: PathBuf = corpus_path(rel);
    let bytes: Vec<u8> = std::fs::read(&path).unwrap_or_else(|err: std::io::Error| {
        let cause: &str = if err.kind() == ErrorKind::NotFound {
            "absent from this checkout"
        } else {
            "present but unreadable"
        };
        panic!(
            "corpus/php/{rel} is tracked in this repository and graded here, so a run that cannot \
             read it must fail rather than measure nothing: {} is {cause} ({err}). Restore it with \
             `git checkout -- corpus/php/{rel}`.",
            path.display()
        )
    });
    assert!(
        !bytes.is_empty(),
        "corpus/php/{rel} read back empty at {}; a truncated input grades nothing and must never \
         report success",
        path.display()
    );
    bytes
}

pub(crate) fn fixture_path(rel: &str) -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    for seg in rel.split('/') {
        path.push(seg);
    }
    path
}

pub(crate) fn required_fixture(rel: &str) -> Vec<u8> {
    let path: PathBuf = fixture_path(rel);
    let bytes: Vec<u8> = std::fs::read(&path).unwrap_or_else(|err: std::io::Error| {
        let cause: &str = if err.kind() == ErrorKind::NotFound {
            "absent from this checkout"
        } else {
            "present but unreadable"
        };
        panic!(
            "tests/fixtures/{rel} is tracked in this repository and graded here, so a run that \
             cannot read it must fail rather than measure nothing: {} is {cause} ({err})",
            path.display()
        )
    });
    assert!(
        !bytes.is_empty(),
        "tests/fixtures/{rel} read back empty at {}; a truncated input grades nothing and must \
         never report success",
        path.display()
    );
    bytes
}
