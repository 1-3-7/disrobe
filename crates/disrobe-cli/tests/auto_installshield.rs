#![cfg(feature = "chain")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stderr,
    clippy::panic
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use sha2::{Digest, Sha256};

const USER1_CABINET: &str = "binfmt/installshield/wireplay-user1.cab";
const USER1_INVENTORY: &str = "binfmt/installshield/wireplay-user1.cab.tsv";
const SYS1_CABINET: &str = "binfmt/installshield/wireplay-sys1.cab";
const SYS1_INVENTORY: &str = "binfmt/installshield/wireplay-sys1.cab.tsv";
const RECOVERED: &str = "recovered";
const EXTRACTED_DIR: &str = "extracted";
const MIN_RECOVERED_MEMBERS: usize = 2;

fn workspace_root() -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path
}

fn corpus_path(relative: &str) -> PathBuf {
    workspace_root().join("corpus").join(relative)
}

fn reference_digests(inventory: &str) -> BTreeMap<String, String> {
    let path: PathBuf = corpus_path(inventory);
    assert!(
        path.is_file(),
        "this gate grades disrobe auto against the tracked unshield-derived inventory at {}; \
         without it there is no reference and the run would prove nothing",
        path.display()
    );
    let text: String = std::fs::read_to_string(&path).expect("read the reference inventory");
    let mut wanted: BTreeMap<String, String> = BTreeMap::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split('\t').collect();
        let Some(&disposition) = fields.get(1) else {
            continue;
        };
        if disposition != RECOVERED {
            continue;
        }
        let (Some(&member), Some(&digest)) = (fields.get(2), fields.get(5)) else {
            continue;
        };
        let leaf: &str = member.rsplit('/').next().unwrap_or(member);
        wanted.insert(leaf.to_ascii_lowercase(), digest.to_ascii_lowercase());
    }
    assert!(
        wanted.len() >= MIN_RECOVERED_MEMBERS,
        "the inventory declares {} recovered member(s), below the floor of {MIN_RECOVERED_MEMBERS}; \
         a shrunken reference would let this gate pass while grading almost nothing",
        wanted.len()
    );
    wanted
}

fn digest_of(bytes: &[u8]) -> String {
    let mut hasher: Sha256 = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn collect_recovered_artifact_digests(dir: &Path, found: &mut BTreeMap<String, String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path: PathBuf = entry.path();
        if path.is_dir() {
            collect_recovered_artifact_digests(&path, found);
            continue;
        }
        let Some(name) = path.file_name().and_then(|part| part.to_str()) else {
            continue;
        };
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        found.insert(name.to_ascii_lowercase(), digest_of(&bytes));
    }
}

fn run_auto(cabinet: &str, jobs: usize) -> (BTreeMap<String, String>, serde_json::Value) {
    let archive: PathBuf = corpus_path(cabinet);
    assert!(
        archive.is_file(),
        "this gate requires the tracked cabinet at {}",
        archive.display()
    );
    let output: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("auto-installshield-out")
            .expect("create output dir");
    let process: Output = Command::new(env!("CARGO_BIN_EXE_disrobe"))
        .arg("auto")
        .arg(&archive)
        .arg("--out")
        .arg(output.path())
        .arg("--jobs")
        .arg(jobs.to_string())
        .arg("--max-depth")
        .arg("3")
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error: std::io::Error| panic!("spawn disrobe auto: {error}"));
    assert!(
        process.status.success(),
        "disrobe auto failed for jobs={jobs}: {}",
        String::from_utf8_lossy(&process.stderr)
    );
    let extracted: PathBuf = output.path().join(EXTRACTED_DIR);
    assert!(
        extracted.is_dir(),
        "`disrobe auto` wrote no {EXTRACTED_DIR}/ tree for a cabinet the inventory says yields \
         members"
    );
    let mut found: BTreeMap<String, String> = BTreeMap::new();
    collect_recovered_artifact_digests(&extracted, &mut found);
    let chain_bytes: Vec<u8> =
        std::fs::read(output.path().join("chain.json")).expect("read chain.json");
    let chain: serde_json::Value = serde_json::from_slice(&chain_bytes).expect("parse chain.json");
    (found, chain)
}

fn assert_reference_digests(found: &BTreeMap<String, String>, wanted: &BTreeMap<String, String>) {
    for (member, digest) in wanted {
        let actual: Option<&String> = found.get(member);
        assert!(
            actual.is_some(),
            "the inventory names {member} as recovered, but `disrobe auto` emitted no such file; \
             emitted: {:?}",
            found.keys().collect::<Vec<&String>>()
        );
        assert_eq!(
            actual.map(String::as_str),
            Some(digest.as_str()),
            "{member} recovered with bytes that do not match the unshield-derived reference digest"
        );
    }
}

#[test]
fn auto_recovers_every_installshield_member_the_reference_inventory_names() {
    let wanted: BTreeMap<String, String> = reference_digests(USER1_INVENTORY);
    let (found, _): (BTreeMap<String, String>, serde_json::Value) = run_auto(USER1_CABINET, 1);
    assert_reference_digests(&found, &wanted);
}

#[test]
fn auto_installshield_recovery_does_not_depend_on_the_worker_count() {
    let (serial, _): (BTreeMap<String, String>, serde_json::Value) = run_auto(USER1_CABINET, 1);
    let (parallel, _): (BTreeMap<String, String>, serde_json::Value) = run_auto(USER1_CABINET, 4);
    assert!(
        !serial.is_empty(),
        "the worker-count comparison graded nothing, so it could not have caught a difference"
    );
    assert_eq!(
        serial, parallel,
        "recovered InstallShield artifacts must be byte-identical at --jobs 1 and --jobs 4"
    );
}

#[test]
fn auto_refeeds_recovered_installshield_executables_to_native_recovery() {
    let wanted: BTreeMap<String, String> = reference_digests(SYS1_INVENTORY);
    let (found, chain): (BTreeMap<String, String>, serde_json::Value) = run_auto(SYS1_CABINET, 1);
    assert_reference_digests(&found, &wanted);
    let passes: Vec<&str> = chain["nodes"]
        .as_array()
        .expect("chain nodes")
        .iter()
        .filter_map(|node: &serde_json::Value| node["pass"].as_str())
        .collect();
    assert!(
        passes.contains(&"binfmt.container"),
        "InstallShield must enter the container pass: {passes:?}"
    );
    assert!(
        passes.contains(&"native.image-classify"),
        "recovered InstallShield executables must be re-fed to native recovery: {passes:?}"
    );
}
