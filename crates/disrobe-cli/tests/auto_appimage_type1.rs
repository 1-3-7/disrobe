#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::subprocess::{CapturedOutput, run_captured};
use sha2::{Digest as _, Sha256};

const FIXTURE: &[u8] =
    include_bytes!("../../../corpus/binfmt/appimage-type1/AppImageAssistant.AppImage");
const MANIFEST: &str = include_str!("../../../corpus/binfmt/appimage-type1/MANIFEST.tsv");
const CLI_TIMEOUT: Duration = Duration::from_mins(1);
const CLI_CAPTURE: usize = 1usize << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MaterializedKind {
    Directory,
    Regular,
    Symlink,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MaterializedMode {
    #[cfg(unix)]
    Unix(u32),
    #[cfg(not(unix))]
    Unavailable,
}

#[derive(Debug)]
struct MaterializedEntry {
    kind: MaterializedKind,
    mode: MaterializedMode,
    bytes: Vec<u8>,
}

type MaterializedTree = BTreeMap<String, MaterializedEntry>;

struct BatchRecovery {
    complete: MaterializedTree,
    members: MaterializedTree,
}

fn run_disrobe(args: &[OsString]) -> CapturedOutput {
    let arg_refs: Vec<&OsStr> = args.iter().map(OsString::as_os_str).collect();
    let captured: Option<CapturedOutput> = run_captured(
        Path::new(env!("CARGO_BIN_EXE_disrobe")),
        &arg_refs,
        CLI_TIMEOUT,
        CLI_CAPTURE,
    )
    .expect("spawn disrobe");
    captured
        .unwrap_or_else(|| panic!("disrobe did not finish within {CLI_TIMEOUT:?}: {arg_refs:?}"))
}

#[cfg(unix)]
fn observed_mode(metadata: &std::fs::Metadata) -> MaterializedMode {
    use std::os::unix::fs::PermissionsExt as _;
    MaterializedMode::Unix(metadata.permissions().mode())
}

#[cfg(not(unix))]
const fn observed_mode(_metadata: &std::fs::Metadata) -> MaterializedMode {
    MaterializedMode::Unavailable
}

#[cfg(unix)]
fn checked_mode(metadata: &std::fs::Metadata, expected: u32, name: &str) -> MaterializedMode {
    use std::os::unix::fs::PermissionsExt as _;
    let value: u32 = metadata.permissions().mode() & 0o7777;
    assert_eq!(value, expected, "mode for {name}");
    MaterializedMode::Unix(value)
}

#[cfg(not(unix))]
const fn checked_mode(
    _metadata: &std::fs::Metadata,
    _expected: u32,
    _name: &str,
) -> MaterializedMode {
    MaterializedMode::Unavailable
}

fn collect_tree(root: &Path, current: &Path, entries: &mut MaterializedTree) {
    let directory: std::fs::ReadDir =
        std::fs::read_dir(current).expect("read materialized output directory");
    for item in directory {
        let path: PathBuf = item.expect("read materialized output entry").path();
        let relative: &Path = path.strip_prefix(root).expect("relative materialized path");
        let name: String = relative.to_string_lossy().replace('\\', "/");
        let metadata: std::fs::Metadata =
            std::fs::symlink_metadata(&path).expect("materialized metadata");
        let file_type: std::fs::FileType = metadata.file_type();
        let (kind, bytes): (MaterializedKind, Vec<u8>) = if file_type.is_symlink() {
            (
                MaterializedKind::Symlink,
                std::fs::read_link(&path)
                    .expect("read materialized link")
                    .to_string_lossy()
                    .as_bytes()
                    .to_vec(),
            )
        } else if file_type.is_dir() {
            (MaterializedKind::Directory, Vec::new())
        } else {
            (
                MaterializedKind::Regular,
                std::fs::read(&path).expect("read materialized file"),
            )
        };
        assert!(
            entries
                .insert(
                    name,
                    MaterializedEntry {
                        kind,
                        mode: observed_mode(&metadata),
                        bytes,
                    },
                )
                .is_none(),
            "duplicate materialized path"
        );
        if file_type.is_dir() {
            collect_tree(root, &path, entries);
        }
    }
}

fn materialized_tree(root: &Path) -> MaterializedTree {
    let mut entries: MaterializedTree = BTreeMap::new();
    collect_tree(root, root, &mut entries);
    entries
}

fn assert_materialized_tree(actual: &MaterializedTree, expected: &MaterializedTree, context: &str) {
    assert_eq!(actual.len(), expected.len(), "{context}: path count");
    for (path, expected_entry) in expected {
        let actual_entry: &MaterializedEntry = actual
            .get(path)
            .unwrap_or_else(|| panic!("{context}: missing path {path}"));
        assert_eq!(
            actual_entry.kind, expected_entry.kind,
            "{context}: kind for {path}"
        );
        assert_eq!(
            actual_entry.mode, expected_entry.mode,
            "{context}: mode for {path}"
        );
        assert_eq!(
            actual_entry.bytes, expected_entry.bytes,
            "{context}: bytes for {path}"
        );
    }
}

fn materialized_member_tree(root: &Path) -> MaterializedTree {
    let mut entries: MaterializedTree = BTreeMap::new();
    for row in MANIFEST.lines().skip(1) {
        let fields: Vec<&str> = row.split('\t').collect();
        assert_eq!(fields.len(), 6, "manifest row: {row}");
        let name: String = fields[0].to_owned();
        let expected_kind: &str = fields[1];
        let expected_mode: u32 = u32::from_str_radix(fields[2], 8).expect("manifest mode");
        let path: PathBuf = root.join(&name);
        let metadata: std::fs::Metadata =
            std::fs::symlink_metadata(&path).expect("materialized member metadata");
        let file_type: std::fs::FileType = metadata.file_type();
        let (kind, bytes): (MaterializedKind, Vec<u8>) = if file_type.is_symlink() {
            (
                MaterializedKind::Symlink,
                std::fs::read_link(&path)
                    .expect("read materialized member link")
                    .to_string_lossy()
                    .as_bytes()
                    .to_vec(),
            )
        } else if file_type.is_dir() {
            (MaterializedKind::Directory, Vec::new())
        } else {
            (
                MaterializedKind::Regular,
                std::fs::read(&path).expect("read materialized member"),
            )
        };
        let expected_materialized_kind: MaterializedKind = match expected_kind {
            "directory" => MaterializedKind::Directory,
            "regular" | "hardlink" => MaterializedKind::Regular,
            other => panic!("unsupported manifest kind: {other}"),
        };
        assert_eq!(kind, expected_materialized_kind, "kind for {name}");
        let mode: MaterializedMode = checked_mode(&metadata, expected_mode, &name);
        assert!(
            entries
                .insert(name, MaterializedEntry { kind, mode, bytes })
                .is_none(),
            "duplicate manifest member"
        );
    }
    entries
}

fn recover_batch(jobs: u32) -> Vec<BatchRecovery> {
    let input: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto-appimage-type1-input")
            .expect("create AppImage input directory");
    for name in ["first.AppImage", "second.AppImage"] {
        std::fs::write(input.path().join(name), FIXTURE).expect("stage AppImage fixture");
    }
    let output: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto-appimage-type1-output")
            .expect("create AppImage output directory");
    let process: CapturedOutput = run_disrobe(&[
        OsString::from("auto"),
        input.path().as_os_str().to_owned(),
        OsString::from("--out"),
        output.path().as_os_str().to_owned(),
        OsString::from("--jobs"),
        OsString::from(jobs.to_string()),
        OsString::from("--max-depth"),
        OsString::from("3"),
    ]);
    assert!(
        process.exit_code == Some(0),
        "disrobe auto failed for jobs={jobs}: {}",
        String::from_utf8_lossy(&process.stderr)
    );
    ["first.AppImage", "second.AppImage"]
        .into_iter()
        .map(|name: &str| {
            let root: PathBuf = output.path().join(name).join("extracted");
            BatchRecovery {
                complete: materialized_tree(&root),
                members: materialized_member_tree(&root),
            }
        })
        .collect()
}

#[test]
fn extract_and_auto_recover_type1_appimage_members_deterministically() {
    let input: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("extract-appimage-type1-input")
            .expect("create AppImage input directory");
    let image: PathBuf = input.path().join("AppImageAssistant.AppImage");
    std::fs::write(&image, FIXTURE).expect("stage AppImage fixture");
    let output: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("extract-appimage-type1-output")
            .expect("create AppImage output directory");
    let process: CapturedOutput = run_disrobe(&[
        OsString::from("extract"),
        image.as_os_str().to_owned(),
        OsString::from("--out"),
        output.path().as_os_str().to_owned(),
    ]);
    assert!(
        process.exit_code == Some(0),
        "disrobe extract failed: {}",
        String::from_utf8_lossy(&process.stderr)
    );
    let expected: MaterializedTree = materialized_member_tree(output.path());
    assert_eq!(expected.len(), 49);
    let app_run: &MaterializedEntry = expected.get("AppRun").expect("direct AppRun");
    assert_eq!(app_run.kind, MaterializedKind::Regular);
    assert_eq!(app_run.bytes.len(), 222);
    assert_eq!(
        format!("{:x}", Sha256::digest(&app_run.bytes)),
        "4ba7a49ad0828f43b92067ff0948de22503d90f98c32adb76b8729b0708bbc72"
    );

    let serial: Vec<BatchRecovery> = recover_batch(1);
    let parallel: Vec<BatchRecovery> = recover_batch(4);
    assert_eq!(serial.len(), 2);
    assert_eq!(parallel.len(), 2);
    for (index, (serial_recovery, parallel_recovery)) in serial.iter().zip(&parallel).enumerate() {
        let context: String = format!("batch item {index}");
        assert_materialized_tree(
            &serial_recovery.complete,
            &parallel_recovery.complete,
            &context,
        );
        assert_materialized_tree(&serial_recovery.members, &expected, &context);
        assert_materialized_tree(&parallel_recovery.members, &expected, &context);
    }
}
