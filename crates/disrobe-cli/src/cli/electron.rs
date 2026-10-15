use std::path::{Path, PathBuf};

use disrobe_binfmt::electron::{
    ArchiveIntegrity, DeclaredIntegrity, ExecutableReport, FileStatus, FuseState, check_archive,
    declared_integrity_from_plist, inspect_executable,
};
use serde::Serialize;

use crate::cli::output::{self, OutputFormat};

const MAX_INPUT_BYTES: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Debug, Serialize)]
struct ArchiveReport {
    path: String,
    integrity: ArchiveIntegrity,
    #[serde(skip_serializing_if = "Option::is_none")]
    declared_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    header_matches_declared: Option<bool>,
}

#[derive(Debug, Serialize)]
struct ElectronReport {
    executable: ExecutableReport,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    info_plist_integrity: Vec<DeclaredIntegrity>,
    archives: Vec<ArchiveReport>,
    problems: Vec<String>,
}

fn read_bounded(path: &Path) -> miette::Result<Vec<u8>> {
    let size: u64 = std::fs::metadata(path)
        .map_err(|e| miette::miette!("DR-CLI-0417: cannot read {}: {e}", path.display()))?
        .len();
    if size > MAX_INPUT_BYTES {
        return Err(miette::miette!(
            "DR-CLI-0417: {} is {size} bytes, above the {MAX_INPUT_BYTES}-byte limit",
            path.display()
        ));
    }
    std::fs::read(path)
        .map_err(|e| miette::miette!("DR-CLI-0417: cannot read {}: {e}", path.display()))
}

fn bundle_contents(executable: &Path) -> Option<PathBuf> {
    executable
        .ancestors()
        .find(|ancestor: &&Path| {
            ancestor.file_name().is_some_and(|name| name == "Contents")
                && ancestor
                    .parent()
                    .and_then(Path::extension)
                    .is_some_and(|extension| extension == "app")
        })
        .map(Path::to_path_buf)
}

fn discover_archives(executable: &Path) -> Vec<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(contents) = bundle_contents(executable) {
        candidates.push(contents.join("Resources").join("app.asar"));
    }
    if let Some(dir) = executable.parent() {
        candidates.push(dir.join("resources").join("app.asar"));
    }
    candidates
        .into_iter()
        .filter(|path| path.is_file())
        .collect()
}

fn declared_for<'a>(
    archive: &Path,
    declared: &'a [DeclaredIntegrity],
) -> Option<&'a DeclaredIntegrity> {
    let tail: Vec<String> = archive
        .components()
        .rev()
        .take(2)
        .map(|part| part.as_os_str().to_string_lossy().to_lowercase())
        .collect();
    declared.iter().find(|entry: &&DeclaredIntegrity| {
        let parts: Vec<String> = entry
            .file
            .split(['\\', '/'])
            .rev()
            .take(2)
            .map(str::to_lowercase)
            .collect();
        parts == tail
    })
}

pub(crate) fn run(
    path: PathBuf,
    asar: Vec<PathBuf>,
    info_plist: Option<PathBuf>,
    fmt: OutputFormat,
) -> miette::Result<()> {
    let bytes: Vec<u8> = read_bounded(&path)?;
    let executable: ExecutableReport = inspect_executable(&bytes);
    let mut problems: Vec<String> = Vec::new();
    let plist_path: Option<PathBuf> = info_plist.or_else(|| {
        bundle_contents(&path)
            .map(|contents| contents.join("Info.plist"))
            .filter(|plist| plist.is_file())
    });
    let mut info_plist_integrity: Vec<DeclaredIntegrity> = Vec::new();
    if let Some(plist) = &plist_path {
        match declared_integrity_from_plist(&read_bounded(plist)?) {
            Ok(entries) => info_plist_integrity = entries,
            Err(error) => problems.push(format!("{}: {error}", plist.display())),
        }
    }
    let declared: Vec<DeclaredIntegrity> = executable
        .declared_integrity
        .iter()
        .chain(&info_plist_integrity)
        .cloned()
        .collect();
    let archive_paths: Vec<PathBuf> = if asar.is_empty() {
        discover_archives(&path)
    } else {
        asar
    };
    let mut archives: Vec<ArchiveReport> = Vec::new();
    for archive in archive_paths {
        let integrity: ArchiveIntegrity = check_archive(&read_bounded(&archive)?)
            .map_err(|e| miette::miette!("DR-CLI-0418: {}: {e}", archive.display()))?;
        let expected: Option<&DeclaredIntegrity> = declared_for(&archive, &declared);
        archives.push(ArchiveReport {
            path: archive.display().to_string(),
            header_matches_declared: expected
                .map(|entry| entry.hash.eq_ignore_ascii_case(&integrity.header_sha256)),
            declared_hash: expected.map(|entry| entry.hash.clone()),
            integrity,
        });
    }
    let report: ElectronReport = ElectronReport {
        executable,
        info_plist_integrity,
        archives,
        problems,
    };
    output::emit(fmt, &report, || render(&report))?;
    Ok(())
}

const fn note(name: &str, state: FuseState) -> Option<&'static str> {
    match (name.as_bytes(), state) {
        (b"RunAsNode", FuseState::Enabled) => {
            Some("ELECTRON_RUN_AS_NODE turns the app into a plain Node.js interpreter")
        }
        (b"EnableNodeOptionsEnvironmentVariable", FuseState::Enabled) => {
            Some("NODE_OPTIONS is honoured, so the environment can inject code")
        }
        (b"EnableNodeCliInspectArguments", FuseState::Enabled) => {
            Some("--inspect arguments open a debugger port")
        }
        (b"EnableEmbeddedAsarIntegrityValidation", FuseState::Disabled) => {
            Some("app.asar is not checked against the embedded hash and can be edited")
        }
        (b"OnlyLoadAppFromAsar", FuseState::Disabled) => {
            Some("the app can also load from an unpacked app folder")
        }
        (b"EnableCookieEncryption", FuseState::Disabled) => Some("cookies are stored unencrypted"),
        (b"GrantFileProtocolExtraPrivileges", FuseState::Enabled) => {
            Some("file:// pages get extra privileges")
        }
        _ => None,
    }
}

fn render(report: &ElectronReport) {
    if report.executable.fuse_wires.is_empty() {
        println!("fuses: no fuse wire (not Electron 12 or later, or not the binary that holds it)");
    }
    for wire in &report.executable.fuse_wires {
        println!(
            "fuse wire at 0x{:x}{} version {} with {} fuses{}",
            wire.offset,
            wire.slice
                .as_deref()
                .map(|slice: &str| format!(" ({slice} slice)"))
                .unwrap_or_default(),
            wire.version,
            wire.declared_length,
            if wire.complete { "" } else { " (truncated)" }
        );
        for fuse in &wire.fuses {
            let name: String = fuse
                .name
                .map_or_else(|| format!("fuse {}", fuse.index), str::to_owned);
            let state: &str = match fuse.state {
                FuseState::Enabled => "enabled",
                FuseState::Disabled => "disabled",
                FuseState::Removed => "removed",
                FuseState::Unknown => "unknown",
            };
            let explanation: String = fuse
                .name
                .and_then(|name: &str| note(name, fuse.state))
                .map(|text: &str| format!("  ({text})"))
                .unwrap_or_default();
            println!("  {name:<40} {state}{explanation}");
        }
    }
    for declared in report
        .executable
        .declared_integrity
        .iter()
        .chain(&report.info_plist_integrity)
    {
        println!(
            "declared integrity: {} {} {} ({:?})",
            declared.file, declared.algorithm, declared.hash, declared.source
        );
    }
    for archive in &report.archives {
        let verdict: &str = match archive.header_matches_declared {
            Some(true) => "matches the declared hash",
            Some(false) => "DOES NOT match the declared hash",
            None => "no declared hash for this archive",
        };
        println!(
            "archive {}: header sha256 {} ({verdict})",
            archive.path, archive.integrity.header_sha256
        );
        let mut counts: [usize; 6] = [0; 6];
        for file in &archive.integrity.files {
            let slot: usize = match file.status {
                FileStatus::Match => 0,
                FileStatus::Mismatch => 1,
                FileStatus::NoIntegrity => 2,
                FileStatus::UnsupportedAlgorithm => 3,
                FileStatus::MalformedBlocks => 4,
                FileStatus::OutOfBounds => 5,
            };
            counts[slot] += 1;
            if file.status == FileStatus::Mismatch {
                println!(
                    "  modified: {} (blocks {:?})",
                    file.path, file.mismatched_blocks
                );
            }
        }
        println!(
            "  {} files match their integrity record, {} modified, {} without a record, {} unpacked",
            counts[0],
            counts[1],
            counts[2],
            archive.integrity.unpacked.len()
        );
        if counts[3] + counts[4] + counts[5] > 0 {
            println!(
                "  {} with an unsupported algorithm, {} with malformed block lists, {} outside the archive",
                counts[3], counts[4], counts[5]
            );
        }
    }
    for problem in report.executable.problems.iter().chain(&report.problems) {
        println!("problem: {problem}");
    }
}
