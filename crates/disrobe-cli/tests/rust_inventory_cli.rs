#![cfg(feature = "nativelang")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_nativelang::rust_inventory::{RustInventory, rust_inventory};
use serde_json::Value;

const TIMEOUT: Duration = Duration::from_mins(2);
const MAX_CAPTURE_BYTES: usize = 8 * 1024 * 1024;
const ARTIFACT: &str = "corpus/native/rust-inventory/bin/pe-1.95.0-release-auditable.exe";

fn disrobe_bin() -> PathBuf {
    let bin: PathBuf = PathBuf::from(
        std::env::var_os("DISROBE_BIN")
            .expect("DISROBE_BIN must name the current disrobe binary built for this caller test"),
    );
    assert!(
        bin.is_file(),
        "DISROBE_BIN does not name a file: {}",
        bin.display()
    );
    bin
}

fn repository(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

fn disrobe(args: &[&Path]) -> CapturedOutput {
    let program: PathBuf = disrobe_bin();
    run_captured(&program, args, TIMEOUT, MAX_CAPTURE_BYTES)
        .unwrap_or_else(|error| panic!("cannot start {}: {error}", program.display()))
        .unwrap_or_else(|| panic!("{} exceeded its timeout", program.display()))
}

#[test]
fn rust_inventory_json_is_the_library_inventory() {
    let input: PathBuf = repository(ARTIFACT);
    let output: CapturedOutput = disrobe(&[
        Path::new("rust"),
        Path::new("inventory"),
        &input,
        Path::new("--json"),
    ]);
    assert_eq!(
        output.exit_code,
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let printed: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON");
    let bytes: Vec<u8> = std::fs::read(&input).expect("read the artifact");
    let library: RustInventory = rust_inventory(&bytes).expect("library inventory");
    assert_eq!(printed, serde_json::to_value(&library).expect("serialize"));
    assert_eq!(printed["rustc"][0]["release"], "1.95.0");
    assert_eq!(printed["auditable"]["status"], "present");
}

#[test]
fn rust_inventory_text_names_release_crates_and_graph() {
    let input: PathBuf = repository(ARTIFACT);
    let output: CapturedOutput = disrobe(&[Path::new("rust"), Path::new("inventory"), &input]);
    assert_eq!(
        output.exit_code,
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text: String = String::from_utf8(output.stdout).expect("UTF-8 stdout");
    for expected in [
        "rustc: 1.95.0 59807616e1fa2540724bfbac14d7976d7e4a3860",
        "regex 1.12.3  registry index.crates.io-1949cf8c6b5b557f",
        "gitdep -  git gitdep-8ea555ce1129ba1e rev 099202b",
        "pathdep -  path /build\\pathdep",
        "rustinv -  workspace rustinv",
        "rustinv 0.3.1 (local, runtime, root) -> [anyhow 1.0.102, gitdep 0.2.0, pathdep 1.4.0, regex 1.12.3, serde 1.0.228]",
        "syn 2.0.119 (crates.io, build) -> [proc-macro2 1.0.107, quote 1.0.47, unicode-ident 1.0.27]",
        "symbols: no symbol table",
    ] {
        assert!(text.contains(expected), "missing {expected:?} in\n{text}");
    }
}

#[test]
fn rust_inventory_refuses_a_non_image_with_its_code() {
    let scratch: ScratchDir = ScratchDir::create("rust-inventory-cli").expect("scratch directory");
    let input: PathBuf = scratch.path().join("not-an-image.bin");
    std::fs::write(&input, b"{\"packages\":[]}").expect("write input");
    let output: CapturedOutput = disrobe(&[Path::new("rust"), Path::new("inventory"), &input]);
    assert_ne!(output.exit_code, Some(0));
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    let squeezed: String = stderr.chars().filter(char::is_ascii_graphic).collect();
    assert!(squeezed.contains("DR-RUSTINV-0103"), "{stderr}");
    assert!(
        squeezed.contains("DR-RUSTINV-0001:inputisnotaPE,ELForMach-Oimage"),
        "{stderr}"
    );
}
