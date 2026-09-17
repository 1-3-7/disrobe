#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::subprocess::{CapturedOutput, run_captured};
use sha2::{Digest as _, Sha256};

const FIXTURE_HEX: &str =
    include_str!("../../disrobe-binfmt/tests/fixtures/stuffit/stuffit-method8-xadmaster.sit.hex");
const FIXTURE_SHA256: &str = "8176bd01aeafa6c4f5dda1e0787eb6e4074a4bc500b6a17a458d6febf26e9f0c";
const DATA_SHA256: &str = "ff437f3914ede560404202c5a7587f44fbd2b3255c7db445736d998280803eec";
const RESOURCE_SHA256: &str = "b5d4045c3f466fa91fe2cc6abe79232a1a57cdf104f7a26e716e0a1e2789df78";
const CLI_TIMEOUT: Duration = Duration::from_secs(30);
const CLI_CAPTURE: usize = 1usize << 20;

type OutputTree = BTreeMap<String, Vec<u8>>;

fn decode_hex(encoded: &str) -> Vec<u8> {
    assert_eq!(encoded.len() % 2, 0);
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair: &[u8]| {
            let digits: &str = std::str::from_utf8(pair).expect("fixture hex is ASCII");
            u8::from_str_radix(digits, 16).expect("fixture hex byte is valid")
        })
        .collect()
}

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
fn auto_recovers_stuffit_method8_identically_at_jobs_one_and_four() {
    let fixture: Vec<u8> = decode_hex(FIXTURE_HEX.trim());
    assert_eq!(fixture.len(), 144);
    assert_eq!(format!("{:x}", Sha256::digest(&fixture)), FIXTURE_SHA256);
    let input: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto-stuffit-method8-input")
            .expect("create method 8 input directory");
    std::fs::write(input.path().join("fixture.sit"), fixture)
        .expect("stage StuffIt method 8 fixture");
    let output: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto-stuffit-method8-output")
            .expect("create method 8 output directory");
    let expected_hashes: BTreeSet<&str> = BTreeSet::from([DATA_SHA256, RESOURCE_SHA256]);

    let serial: OutputTree =
        recovered_members(recover(1, input.path(), output.path()), &expected_hashes);
    clear_output(output.path());
    let parallel: OutputTree =
        recovered_members(recover(4, input.path(), output.path()), &expected_hashes);

    assert_eq!(serial, parallel);
    assert_eq!(serial.len(), expected_hashes.len());
}
