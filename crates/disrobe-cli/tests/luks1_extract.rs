#![allow(clippy::expect_used, clippy::panic)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const FIXTURE: &[u8] =
    include_bytes!("../../disrobe-binfmt/tests/fixtures/luks1/aes128-cbc-plain.luks1");
const RAW_VOLUME_KEY: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f";

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../disrobe-binfmt/tests/fixtures/luks1/aes128-cbc-plain.luks1")
}

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_disrobe"))
}

#[test]
fn keyless_extract_reports_a_successful_raw_volume_key_wall() {
    let output: Output = Command::new(binary())
        .args(["--json", "extract"])
        .arg(fixture_path())
        .output()
        .expect("run disrobe extract");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("keyless wall JSON");
    assert_eq!(report["format"], "luks1");
    assert_eq!(report["cipher"], "aes");
    assert_eq!(report["mode"], "cbc-plain");
    assert_eq!(report["key_derivation"], "pbkdf2-sha256");
    assert_eq!(report["wall"]["kind"], "luks1-raw-volume-key");
    assert_eq!(report["missing_input"], "raw volume key");
}

#[test]
fn raw_volume_key_file_decrypts_into_the_existing_container_pipeline() {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("cli-luks1-key-file").expect("scratch");
    let key_path: PathBuf = scratch.path().join("volume.key");
    let out_path: PathBuf = scratch.path().join("out");
    std::fs::write(&key_path, RAW_VOLUME_KEY).expect("write key");
    let output: Output = Command::new(binary())
        .args(["--json", "extract"])
        .arg(fixture_path())
        .arg("--out")
        .arg(&out_path)
        .arg("--luks1-raw-volume-key-file")
        .arg(&key_path)
        .output()
        .expect("run disrobe extract");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("extraction JSON");
    assert_eq!(report["kind"], "vhd");
    assert!(
        report["entries"]
            .as_array()
            .is_some_and(|entries| !entries.is_empty())
    );
    let combined: String = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!combined.contains(KEY_HEX));
}

#[test]
fn raw_volume_key_can_be_read_from_standard_input() {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("cli-luks1-key-stdin").expect("scratch");
    let out_path: PathBuf = scratch.path().join("out");
    let mut child: std::process::Child = Command::new(binary())
        .args(["--json", "extract"])
        .arg(fixture_path())
        .arg("--out")
        .arg(&out_path)
        .args(["--luks1-raw-volume-key-file", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn disrobe extract");
    child
        .stdin
        .take()
        .expect("stdin pipe")
        .write_all(&RAW_VOLUME_KEY)
        .expect("write raw volume key");
    let output: Output = child.wait_with_output().expect("wait for disrobe extract");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("extraction JSON");
    assert_eq!(report["kind"], "vhd");
}

#[test]
fn wrong_raw_volume_key_is_named_without_echoing_key_material() {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("cli-luks1-wrong-key").expect("scratch");
    let key_path: PathBuf = scratch.path().join("wrong.key");
    let wrong: [u8; 16] = [0x41; 16];
    std::fs::write(&key_path, wrong).expect("write wrong key");
    let output: Output = Command::new(binary())
        .arg("extract")
        .arg(fixture_path())
        .arg("--luks1-raw-volume-key-file")
        .arg(&key_path)
        .output()
        .expect("run disrobe extract");
    assert!(!output.status.success());
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(stderr.contains("DR-BINFMT-0078"), "{stderr}");
    assert!(stderr.contains("raw volume key"), "{stderr}");
    assert!(!stderr.contains(KEY_HEX));
}

#[test]
fn oversized_raw_volume_key_file_is_stopped_at_the_header_key_size() {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("cli-luks1-oversized-key").expect("scratch");
    let key_path: PathBuf = scratch.path().join("oversized.key");
    let oversized: [u8; 17] = [0x42; 17];
    std::fs::write(&key_path, oversized).expect("write oversized key");
    let output: Output = Command::new(binary())
        .arg("extract")
        .arg(fixture_path())
        .arg("--luks1-raw-volume-key-file")
        .arg(&key_path)
        .output()
        .expect("run disrobe extract");
    assert!(!output.status.success());
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    let normalized: String = stderr
        .split_whitespace()
        .filter(|token: &&str| *token != "│")
        .collect::<Vec<&str>>()
        .join(" ");
    assert!(stderr.contains("DR-EXTRACT-0065"), "{stderr}");
    assert!(stderr.contains("exactly 16 bytes"), "{stderr}");
    assert!(normalized.contains("read 17"), "{stderr}");
}

#[test]
fn unsupported_mode_names_the_exact_header_mode() {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("cli-luks1-mode").expect("scratch");
    let input_path: PathBuf = scratch.path().join("xts.luks1");
    let missing_key_path: PathBuf = scratch.path().join("missing-volume.key");
    let mut image: Vec<u8> = FIXTURE.to_vec();
    image[40..72].fill(0);
    image[40..52].copy_from_slice(b"xts-plain64\0");
    std::fs::write(&input_path, image).expect("write XTS fixture");
    let output: Output = Command::new(binary())
        .arg("extract")
        .arg(&input_path)
        .arg("--luks1-raw-volume-key-file")
        .arg(&missing_key_path)
        .output()
        .expect("run disrobe extract");
    assert!(!output.status.success());
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(stderr.contains("DR-BINFMT-0079"), "{stderr}");
    assert!(stderr.contains("aes"), "{stderr}");
    assert!(
        stderr.contains("xts-") && stderr.contains("plain64"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("cannot open raw LUKS1 volume-key file"),
        "{stderr}"
    );
}

#[test]
fn keyless_unknown_hash_is_a_typed_error_instead_of_a_wall() {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("cli-luks1-hash").expect("scratch");
    let input_path: PathBuf = scratch.path().join("unknown-hash.luks1");
    let mut image: Vec<u8> = FIXTURE.to_vec();
    image[72..104].fill(0);
    image[72..82].copy_from_slice(b"ripemd160\0");
    std::fs::write(&input_path, image).expect("write unknown-hash fixture");
    let output: Output = Command::new(binary())
        .args(["--json", "extract"])
        .arg(&input_path)
        .output()
        .expect("run disrobe extract");
    assert!(!output.status.success());
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(stderr.contains("DR-BINFMT-0080"), "{stderr}");
    assert!(stderr.contains("ripemd160"), "{stderr}");
}

#[test]
fn keyless_luks2_is_a_typed_unsupported_version() {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("cli-luks2-version").expect("scratch");
    let input_path: PathBuf = scratch.path().join("version2.luks");
    let mut image: Vec<u8> = FIXTURE.to_vec();
    image[6..8].copy_from_slice(&2_u16.to_be_bytes());
    std::fs::write(&input_path, image).expect("write LUKS2-shaped input");
    let output: Output = Command::new(binary())
        .arg("extract")
        .arg(&input_path)
        .output()
        .expect("run disrobe extract");
    assert!(!output.status.success());
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(stderr.contains("DR-BINFMT-0086"), "{stderr}");
    assert!(
        stderr.contains("unsupported LUKS header version"),
        "{stderr}"
    );
}

#[test]
fn over_cap_sparse_luks1_is_refused_from_metadata_before_key_io() {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("cli-luks1-sparse-cap").expect("scratch");
    let input_path: PathBuf = scratch.path().join("oversized.luks1");
    let missing_key_path: PathBuf = scratch.path().join("missing-volume.key");
    let mut file: std::fs::File = std::fs::File::create(&input_path).expect("create sparse input");
    file.write_all(&FIXTURE[..4096])
        .expect("write bounded header");
    file.set_len(4096 + disrobe_binfmt::containers::luks1::MAX_LUKS1_PAYLOAD_BYTES as u64 + 512)
        .expect("extend sparse input");
    drop(file);
    let output: Output = Command::new(binary())
        .arg("extract")
        .arg(&input_path)
        .arg("--luks1-raw-volume-key-file")
        .arg(&missing_key_path)
        .output()
        .expect("run disrobe extract");
    assert!(!output.status.success());
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(stderr.contains("DR-BINFMT-0083"), "{stderr}");
    assert!(
        !stderr.contains("cannot open raw LUKS1 volume-key file"),
        "{stderr}"
    );
}

#[test]
fn auto_records_the_keyless_luks1_wall_as_a_refusal() {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("cli-auto-luks1-wall").expect("scratch");
    let out_path: PathBuf = scratch.path().join("out");
    let output: Output = Command::new(binary())
        .arg("auto")
        .arg(fixture_path())
        .arg("--out")
        .arg(&out_path)
        .output()
        .expect("run disrobe auto");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let chain: String =
        std::fs::read_to_string(out_path.join("chain.json")).expect("read auto chain report");
    assert!(chain.contains("luks1"), "{chain}");
    assert!(chain.contains("container.refusals"), "{chain}");
    assert!(chain.contains("missing raw volume key"), "{chain}");
}
