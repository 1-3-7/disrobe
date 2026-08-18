#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::subprocess::{CapturedOutput, run_captured};
use sha2::{Digest as _, Sha256};

const FIXTURE: &[u8] =
    include_bytes!("../../disrobe-binfmt/tests/fixtures/stuffit/stuffit45-method13.sit");
const MANIFEST: &str = include_str!("../../disrobe-binfmt/tests/fixtures/stuffit/MANIFEST.tsv");
const CLI_TIMEOUT: Duration = Duration::from_secs(30);
const CLI_CAPTURE: usize = 1usize << 20;

type OutputTree = BTreeMap<String, Vec<u8>>;

fn collect_tree(root: &Path, current: &Path, tree: &mut OutputTree) {
    let entries: std::fs::ReadDir = std::fs::read_dir(current).expect("read output directory");
    for entry in entries {
        let path: PathBuf = entry.expect("read output entry").path();
        if path.is_dir() {
            collect_tree(root, &path, tree);
        } else {
            let relative: String = path
                .strip_prefix(root)
                .expect("relative output path")
                .to_string_lossy()
                .replace('\\', "/");
            assert!(
                tree.insert(relative, std::fs::read(path).expect("read output file"))
                    .is_none(),
                "duplicate output path"
            );
        }
    }
}

fn recover(jobs: u32, input: &Path, output: &Path) -> OutputTree {
    let args: Vec<OsString> = vec![
        OsString::from("auto"),
        input.as_os_str().to_owned(),
        OsString::from("--out"),
        output.as_os_str().to_owned(),
        OsString::from("--jobs"),
        OsString::from(jobs.to_string()),
        OsString::from("--max-depth"),
        OsString::from("3"),
        OsString::from("--capture-stages"),
    ];
    let arg_refs: Vec<&OsStr> = args.iter().map(OsString::as_os_str).collect();
    let process: CapturedOutput = run_captured(
        Path::new(env!("CARGO_BIN_EXE_disrobe")),
        &arg_refs,
        CLI_TIMEOUT,
        CLI_CAPTURE,
    )
    .expect("spawn disrobe")
    .expect("disrobe must finish within timeout");
    assert!(
        process.exit_code == Some(0),
        "disrobe auto failed for jobs={jobs}: {}",
        String::from_utf8_lossy(&process.stderr)
    );
    let mut tree: OutputTree = BTreeMap::new();
    collect_tree(output, output, &mut tree);
    tree
}

fn clear_output(output: &Path) {
    for entry in std::fs::read_dir(output).expect("read output before reset") {
        let path: PathBuf = entry.expect("read output reset entry").path();
        if path.is_dir() {
            std::fs::remove_dir_all(path).expect("remove output directory");
        } else {
            std::fs::remove_file(path).expect("remove output file");
        }
    }
}

fn recovered_members(tree: OutputTree, expected_hashes: &BTreeSet<&str>) -> OutputTree {
    tree.into_iter()
        .filter(|(_, bytes): &(String, Vec<u8>)| {
            let hash: String = format!("{:x}", Sha256::digest(bytes));
            expected_hashes.contains(hash.as_str())
        })
        .collect()
}

#[test]
fn auto_recovers_stuffit_method13_identically_at_jobs_one_and_four() {
    let input: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto-stuffit-input")
            .expect("create input directory");
    std::fs::write(input.path().join("fixture.sit"), FIXTURE).expect("stage StuffIt fixture");
    let output: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto-stuffit-output")
            .expect("create output directory");
    let expected_hashes: BTreeSet<&str> = MANIFEST
        .lines()
        .skip(1)
        .map(|row: &str| row.split('\t').nth(5).expect("manifest SHA-256"))
        .collect();
    assert_eq!(expected_hashes.len(), 9);
    let serial: OutputTree =
        recovered_members(recover(1, input.path(), output.path()), &expected_hashes);
    clear_output(output.path());
    let parallel: OutputTree =
        recovered_members(recover(4, input.path(), output.path()), &expected_hashes);
    assert_eq!(serial, parallel);
    assert_eq!(serial.len(), expected_hashes.len());
}
