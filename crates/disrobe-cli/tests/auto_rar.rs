#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::subprocess::{CapturedOutput, run_captured_with_env};
use sha2::{Digest as _, Sha256};

const FIXTURE: &[u8] = include_bytes!("../../../corpus/binfmt/rar/filter-e8-rar3.rar");
const MEMBER_PATH: &str = "filter-e8-rar3.rar/extracted/bsdcat.exe";
const MEMBER_SHA256: &str = "a961532b3a196e0b2c0126ad6f35d511c9fdfeadacbe78a1b15dc221251ad9a2";
const MEMBER_BYTES: usize = 204_288;
const CLI_TIMEOUT: Duration = Duration::from_secs(90);
const CLI_CAPTURE: usize = 1usize << 20;
const SOURCE_DATE_EPOCH: &str = "1700000000";
const RUN_SCOPED: [&str; 7] = [
    "manifest.json",
    "filter-e8-rar3.rar/report.json",
    "filter-e8-rar3.rar/report.sarif",
    "filter-e8-rar3.rar/recovery.json",
    "filter-e8-rar3.rar/chain.json",
    "report.json",
    "report.sarif",
];

type OutputTree = BTreeMap<String, Vec<u8>>;

fn differing_paths(left: &OutputTree, right: &OutputTree) -> Vec<String> {
    left.iter()
        .filter_map(|(path, bytes): (&String, &Vec<u8>)| {
            (right.get(path) != Some(bytes)).then(|| path.clone())
        })
        .chain(
            right
                .keys()
                .filter(|path: &&String| !left.contains_key(*path))
                .cloned(),
        )
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
        OsString::from("2"),
        OsString::from("--capture-stages"),
    ];
    let arg_refs: Vec<&OsStr> = args.iter().map(OsString::as_os_str).collect();
    let process: CapturedOutput = run_captured_with_env(
        Path::new(env!("CARGO_BIN_EXE_disrobe")),
        &arg_refs,
        [("SOURCE_DATE_EPOCH", SOURCE_DATE_EPOCH)],
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

fn recovered_artifacts(tree: &OutputTree) -> OutputTree {
    tree.iter()
        .filter(|(name, _): &(&String, &Vec<u8>)| !RUN_SCOPED.contains(&name.as_str()))
        .map(|(name, bytes): (&String, &Vec<u8>)| (name.clone(), bytes.clone()))
        .collect()
}

#[test]
fn auto_recovers_the_rar3_filtered_member_identically_at_jobs_one_and_four() {
    let input: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto-rar3-filter-input")
            .expect("create rar3 input directory");
    std::fs::write(input.path().join("filter-e8-rar3.rar"), FIXTURE)
        .expect("stage the rar3 filter fixture");
    let output: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto-rar3-filter-output")
            .expect("create rar3 output directory");

    let serial: OutputTree = recover(1, input.path(), output.path());
    clear_output(output.path());
    let parallel: OutputTree = recover(4, input.path(), output.path());

    assert_eq!(
        serial.keys().collect::<Vec<&String>>(),
        parallel.keys().collect::<Vec<&String>>(),
        "one worker and four workers must write the same set of output paths"
    );

    let serial_artifacts: OutputTree = recovered_artifacts(&serial);
    let parallel_artifacts: OutputTree = recovered_artifacts(&parallel);
    assert!(
        serial_artifacts.contains_key(MEMBER_PATH),
        "the compared set must include the recovered member; it held {:?}",
        serial_artifacts.keys().collect::<Vec<&String>>()
    );
    assert!(
        serial_artifacts == parallel_artifacts,
        "one worker and four workers must produce identical recovered bytes; differing paths: {:?}",
        differing_paths(&serial_artifacts, &parallel_artifacts)
    );

    let member: &Vec<u8> = serial_artifacts
        .get(MEMBER_PATH)
        .expect("the recovered member");
    assert_eq!(member.len(), MEMBER_BYTES);
    assert_eq!(
        format!("{:x}", Sha256::digest(member)),
        MEMBER_SHA256,
        "disrobe auto must publish the bytes 7-Zip extracts from the same archive"
    );
}
